#!/usr/bin/env bash
# The early probe of N211: HTTPS HTTP/2 responses of 1 KiB on the Tokio binding, on a pair of
# hosts. Node 1 runs the interop endpoint (`h2_interop server`, route `/1k`) on each of its CPUs,
# built with frame pointers and line tables for the profile. Node 2 runs Nighthawk, the load
# generator of Envoy, at the digest below: open loop at a fixed rate, with 15 event loops and one
# connection of 100 streams for each, TLS 1.3 to `server.test` with ALPN `h2`. The traffic uses
# the private addresses of the pair. The security group of the pair must let node 2 reach TCP
# port 8443 of node 1.
#
# Run it from the checkout as the local recipe of an ephemeral pair target:
#
#   DEV_MACHINE_AWS_PLACEMENT_GROUP=dev-machines-pair \
#     ~/dev-machines/dev-machine run rsnetwork aws-pair-x64 --ephemeral --execute --local \
#     bash rsnetwork-tokio/tests/h2/probe.sh
#
# The steps:
#
# 1. Each offered rate of PROBE_RATES with X25519, until a window achieves less than 99% of its
#    offered rate or a response fails. The saturation is the highest achieved rate.
# 2. Five windows at 70% of the saturation, with X25519.
# 3. One window at that rate with X25519MLKEM768.
# 4. A profile of the server at that rate: `perf record` of 20 s, and the functions above 2%.
#
# Each window is 30 s. It prints one line: the offered and the achieved rate, p50, p99, and
# p99.9 of Nighthawk, its overflows, the requests that its sequencer blocked, the CPUs that the
# server process used, and the CPU use of the generator host. The two CPU counts cover 10 s of
# steady load, after 8 s of warm-up.
set -euo pipefail

target="${PROBE_TARGET:-aws-pair-x64}"
port=8443
workers=15
rates="${PROBE_RATES:-50000 100000 200000 300000 400000 500000 600000 800000}"
image=envoyproxy/nighthawk-dev@sha256:49354226f58b00d5a4c7b3fe8eef63dc9f725fa48ce3686b31043f88f0802dad

hosts="$(~/dev-machines/dev-machine nodes rsnetwork "$target" --live | sed -n 's/^[0-9][0-9]*=//p')"
server="$(sed -n 1p <<<"$hosts")"
client="$(sed -n 2p <<<"$hosts")"
[ -n "$server" ] && [ -n "$client" ] || { echo "the pair has no two live nodes" >&2; exit 1; }
# Runs the command `$2` on host `$1`. A command over SSH has no login shell, so it gets the path of
# the toolchain here.
on() {
	~/dev-machines/ssh-bin/ssh "ubuntu@$1" "PATH=\$HOME/.cargo/bin:\$PATH; $2"
}

echo "== hosts"
echo "revision: $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' (with local changes)')"
for host in "$server" "$client"; do on "$host" 'uname -rv; nproc; lscpu | grep -m1 "Model name"'; done
address="$(on "$server" "ip -4 -o addr show scope global | awk '!/tailscale/ { split(\$4, a, \"/\"); print a[1]; exit }'")"
echo "server address: $address"

echo "== setup"
on "$client" "sudo apt-get -qq update && sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y docker.io > /dev/null && sudo docker pull -q $image && sudo docker --version"
for group in X25519 X25519MLKEM768; do
	tls="{\"name\":\"envoy.transport_sockets.tls\",\"typed_config\":{\"@type\":\"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext\",\"sni\":\"server.test\",\"common_tls_context\":{\"tls_params\":{\"tls_minimum_protocol_version\":\"TLSv1_3\",\"tls_maximum_protocol_version\":\"TLSv1_3\",\"ecdh_curves\":[\"$group\"]},\"alpn_protocols\":[\"h2\"]}}}"
	on "$client" "cat > /tmp/tls-$group.json" <<<"$tls"
done
on "$server" "command -v perf > /dev/null || (sudo apt-get -qq update && sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y linux-tools-\$(uname -r) linux-tools-common > /dev/null); perf --version"
on "$server" 'cd ~/rsnetwork && CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS="-C force-frame-pointers=yes" cargo build --quiet --release --locked -p rsnetwork-tokio --example h2_interop'
on "$server" "cd ~/rsnetwork && (setsid nohup ./target/release/examples/h2_interop server 0.0.0.0:$port tests/tls > /tmp/probe-server.log 2>&1 &); sleep 1; cat /tmp/probe-server.log"
pid="$(on "$server" 'pgrep -x h2_interop')"
ticks="$(on "$server" 'getconf CLK_TCK')"

# Reads the JSON of Nighthawk on its input, and prints the line of a window.
parse='
import json, sys
rate, group, ticks, s0, s1, g0, g1, code = sys.argv[1:9]
d = json.load(sys.stdin)
g = next(r for r in d["results"] if r["name"] == "global")
counters = {c["name"]: int(c["value"]) for c in g["counters"]}
seconds = float(g["execution_duration"].rstrip("s"))
latency = next(s for s in g["statistics"] if s["id"] == "benchmark_http_client.request_to_response")
def at(p):
    return next((float(e["duration"].rstrip("s")) * 1e3 for e in latency["percentiles"] if e["percentile"] >= p), float("nan"))
blocked = next((int(s["count"]) for s in g["statistics"] if s["id"] == "sequencer.blocking"), 0)
achieved = counters.get("benchmark.http_2xx", 0) / seconds
failures = ("benchmark.http_4xx", "benchmark.http_5xx", "benchmark.stream_resets", "benchmark.pool_connection_failure")
failed = sum(counters.get(name, 0) for name in failures)
overflow = counters.get("benchmark.pool_overflow", 0)
curves = ",".join(name[len("ssl.curves."):] for name in counters if name.startswith("ssl.curves."))
server = (float(s1) - float(s0)) / float(ticks) / 10
a, b = ([int(x) for x in line.split()[1:]] for line in (g0, g1))
total = sum(y - x for x, y in zip(a, b))
generator = (total - (b[3] - a[3]) - (b[4] - a[4])) / total
verdict = "ok" if achieved >= 0.99 * int(rate) and failed == 0 and code == "0" else "short"
print("WINDOW group=%s handshake=%s offered=%s achieved=%.0f p50=%.3fms p99=%.3fms p999=%.3fms overflow=%d blocked=%d failed=%d server_cpus=%.2f generator_busy=%.0f%% %s" % (group, curves, rate, achieved, at(0.5), at(0.99), at(0.999), overflow, blocked, failed, server, generator * 100, verdict))
'

# Runs one window at the total offered rate `$1` with the group `$2`, and prints its line, which
# ends with `ok` when it achieved 99% of the offered rate with no failed response.
window() {
	local rate=$1 group=$2
	on "$client" "sudo docker run --rm --network host --entrypoint /usr/local/bin/nighthawk_client $image --address-family v4 --protocol http2 --open-loop --concurrency $workers --rps $((rate / workers)) --duration 30 --max-active-requests 100 --max-concurrent-streams 100 --transport-socket \"\$(cat /tmp/tls-$group.json)\" --output-format json https://$address:$port/1k > /tmp/nh.json 2> /tmp/nh.err; echo \$? > /tmp/nh.exit" &
	local load=$!
	sleep 8
	local s0 g0 s1 g1
	s0="$(on "$server" "awk '{ print \$14 + \$15 }' /proc/$pid/stat")"
	g0="$(on "$client" "head -1 /proc/stat")"
	sleep 10
	s1="$(on "$server" "awk '{ print \$14 + \$15 }' /proc/$pid/stat")"
	g1="$(on "$client" "head -1 /proc/stat")"
	wait "$load"
	on "$client" 'cat /tmp/nh.json' |
		python3 -I -c "$parse" "$rate" "$group" "$ticks" "$s0" "$s1" "$g0" "$g1" "$(on "$client" 'cat /tmp/nh.exit')"
}

echo "== saturation"
saturation=0
for rate in $rates; do
	line="$(window "$rate" X25519)"
	echo "$line"
	achieved="$(sed -n 's/.* achieved=\([0-9]*\) .*/\1/p' <<<"$line")"
	[ "${achieved:-0}" -gt "$saturation" ] && saturation=$achieved
	[[ "$line" == *" ok" ]] || break
done
echo "saturation: $saturation"
rate=$((saturation * 70 / 100))
rate=$((rate - rate % workers))

echo "== 70% of the saturation: $rate"
for run in 1 2 3 4 5; do window "$rate" X25519; done
window "$rate" X25519MLKEM768

echo "== profile at $rate"
on "$client" "sudo docker run --rm --network host --entrypoint /usr/local/bin/nighthawk_client $image --address-family v4 --protocol http2 --open-loop --concurrency $workers --rps $((rate / workers)) --duration 35 --max-active-requests 100 --max-concurrent-streams 100 --transport-socket \"\$(cat /tmp/tls-X25519.json)\" --output-format json https://$address:$port/1k > /dev/null 2>&1" &
load=$!
sleep 8
on "$server" "cd /tmp && sudo perf record -q -F 499 -g -p $pid -o /tmp/probe.perf -- sleep 20 > /dev/null 2>&1; sudo perf report -q -i /tmp/probe.perf --stdio --no-children --sort symbol --percent-limit 2 2> /dev/null | grep -E '^ +[0-9]' | head -40"
wait "$load"
on "$server" "grep -c ERROR /tmp/probe-server.log || true; pkill -x h2_interop || true"
