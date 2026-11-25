#!/usr/bin/env bash
# Runs the HTTP/2 interop matrix of N206 against the peers that peers.sh built: h2spec, curl,
# nghttp, h2load, and Chrome against the rsnetwork server, and the rsnetwork client against nginx
# and h2o. Each connection is TLS 1.3 to `server.test` on loopback, verified with the CA of
# `tests/tls`. Each cell prints `CELL <peer> <case> PASS|FAIL <detail>`, and the run exits with 1
# after a failed cell. Run it from the repository, on the E1 host of peers.sh. Arguments name the
# sections to run (h2spec curl nghttp h2load chrome nginx h2o); no argument runs each one.
# KEEP=1 keeps the logs and prints their directory.
set -uo pipefail
SECTIONS=" $* "
want() { [ "$SECTIONS" = "  " ] || [[ "$SECTIONS" == *" $1 "* ]]; }
PEERS=${PEERS:-$HOME/peers}
export PATH="$PEERS/bin:$PEERS/go/bin:$PATH"
ROOT=$(git rev-parse --show-toplevel)
TLS=$ROOT/tests/tls
OUT=$(mktemp -d)
if [ "${KEEP:-0}" = 1 ]; then
	trap 'kill $(jobs -p) 2> /dev/null; echo "logs: $OUT"' EXIT
else
	trap 'kill $(jobs -p) 2> /dev/null; rm -rf "$OUT"' EXIT
fi
failed=0

cell() {
	echo "CELL $1 $2 $3 ${4:-}"
	[ "$3" = PASS ] || failed=1
}

# The CA, the certificate, and the key of `server.test` in PEM, for the C peers.
openssl x509 -inform der -in "$TLS/ca.der" -out "$OUT/ca.pem"
openssl x509 -inform der -in "$TLS/server.der" -out "$OUT/server.pem"
openssl pkey -inform der -in "$TLS/server.key.der" -out "$OUT/server.key.pem"
grep -q ' server.test$' /etc/hosts || echo '127.0.0.1 server.test' | sudo tee -a /etc/hosts > /dev/null
mkdir -p "$HOME/.pki/nssdb"
# certutil asks for the password of a database that exists, so it gets no input.
[ -f "$HOME/.pki/nssdb/cert9.db" ] || certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password < /dev/null
certutil -d "sql:$HOME/.pki/nssdb" -A -t C,, -n rsnetwork-test -i "$OUT/ca.pem" < /dev/null

(cd "$ROOT" && cargo build --locked --quiet -p rsnetwork-tokio --example h2_interop) || exit 1
ENDPOINT=$ROOT/target/debug/examples/h2_interop

# Starts the rsnetwork server, and sets $PORT and $LOG.
start() {
	LOG=$OUT/server-$1.log
	"$ENDPOINT" server 127.0.0.1:0 "$TLS" > "$LOG" 2>&1 &
	SERVER=$!
	for _ in $(seq 50); do
		PORT=$(sed -n 's/^LISTEN 127.0.0.1://p' "$LOG")
		[ -n "$PORT" ] && return
		sleep 0.1
	done
	echo "the server did not start" >&2
	exit 1
}

# Waits until the server log has a line that matches $1, for at most $2 seconds.
expect() {
	for _ in $(seq $((${2:-10} * 10))); do
		grep -q -- "$1" "$LOG" && return 0
		sleep 0.1
	done
	return 1
}

stop() {
	kill "$SERVER" 2> /dev/null
	wait "$SERVER" 2> /dev/null
	echo "TLS of $1: $(grep -m1 '^TLS' "$LOG")"
}

URL() { echo "https://server.test:$PORT$1"; }
head -c $((1 << 20)) /dev/urandom > "$OUT/body"

if want h2spec; then
SECTION=h2spec
# h2spec: each case, then also the strict cases, with no failure and no skipped case.
start h2spec
for mode in normal strict; do
	flags=()
	[ "$mode" = strict ] && flags=(-S)
	SSL_CERT_FILE=$OUT/ca.pem h2spec -t -h server.test -p "$PORT" -o 5 "${flags[@]}" \
		-j "$OUT/h2spec-$mode.xml" > "$OUT/h2spec-$mode.txt" 2>&1
	code=$?
	summary=$(grep -E '^[0-9]+ tests, ' "$OUT/h2spec-$mode.txt" | tail -1)
	if [ $code -eq 0 ] && [[ "$summary" =~ ' 0 skipped, 0 failed' ]]; then
		cell h2spec "$mode" PASS "$summary"
	else
		cell h2spec "$mode" FAIL "exit $code: $summary"
		grep -E -B2 -A6 '× |Failures:' "$OUT/h2spec-$mode.txt" | head -80
	fi
done
stop "$SECTION"
fi

if want curl; then
SECTION=curl
# curl: a streamed upload with trailers in the response, a reset of the server beside a stream
# that goes on, a reset of curl, and a GOAWAY with a stream in flight.
start curl
C=(curl -sS --http2 --cacert "$OUT/ca.pem")
"${C[@]}" -T - "$(URL /echo)" -o "$OUT/echoed" --trace-ascii "$OUT/curl-echo.trace" < "$OUT/body"
if cmp -s "$OUT/body" "$OUT/echoed" && grep -q 'x-echo-bytes: 1048576' "$OUT/curl-echo.trace"; then
	cell curl upload-trailers PASS "$(grep -a -m1 -o 'SSL connection using.*' "$OUT/curl-echo.trace")"
else
	cell curl upload-trailers FAIL "the echo or its trailers differ"
fi
"${C[@]}" --parallel "$(URL /reset)" "$(URL /)" -o /dev/null -o "$OUT/root" 2> "$OUT/curl-reset.err"
if grep -q 'reset by server (error 0x8 CANCEL)' "$OUT/curl-reset.err" && [ "$(cat "$OUT/root")" = "rsnetwork h2spec" ]; then
	cell curl server-reset PASS "the other stream completed"
else
	cell curl server-reset FAIL "$(cat "$OUT/curl-reset.err")"
fi
"${C[@]}" --max-time 1 "$(URL /slow)" -o /dev/null 2> /dev/null
if expect 'PEER-RESET /slow' 5; then
	cell curl client-reset PASS "$(grep 'PEER-RESET /slow' "$LOG")"
else
	cell curl client-reset FAIL "the server saw no reset"
fi
"${C[@]}" --parallel "$(URL /slow)" "$(URL /shutdown)" -o "$OUT/slow" -o /dev/null
if [ "$(wc -c < "$OUT/slow")" -eq 10240 ] && expect 'REPORT' 20; then
	cell curl goaway-drain PASS "$(grep REPORT "$LOG")"
else
	cell curl goaway-drain FAIL "the stream in flight did not complete"
fi
stop "$SECTION"
fi

if want nghttp; then
SECTION=nghttp
# nghttp: request trailers, a reset of the server, and a GOAWAY with a stream in flight.
start nghttp
nghttp -n -v -d "$OUT/body" --trailer 'x-trailer: done' "$(URL /echo)" > "$OUT/nghttp-echo.txt" 2>&1
if grep -q 'ECHO 1048576 x-trailer' "$LOG" && grep -q 'x-echo-trailers: x-trailer' "$OUT/nghttp-echo.txt"; then
	cell nghttp request-trailers PASS "$(grep -m1 'ECHO' "$LOG")"
else
	cell nghttp request-trailers FAIL "$(tail -3 "$OUT/nghttp-echo.txt")"
fi
nghttp -n -v "$(URL /reset)" > "$OUT/nghttp-reset.txt" 2>&1
# nghttp prints the error code of a frame on the line after it.
if grep -A1 'recv RST_STREAM' "$OUT/nghttp-reset.txt" | grep -q 'error_code=CANCEL'; then
	cell nghttp server-reset PASS "RST_STREAM CANCEL"
else
	cell nghttp server-reset FAIL "$(tail -3 "$OUT/nghttp-reset.txt")"
fi
nghttp -n -v "$(URL /slow)" "$(URL /shutdown)" > "$OUT/nghttp-goaway.txt" 2>&1
if grep -q 'recv GOAWAY' "$OUT/nghttp-goaway.txt" && expect 'DONE /slow' 5 && expect REPORT 20; then
	cell nghttp goaway-drain PASS "$(grep -m1 'recv GOAWAY' "$OUT/nghttp-goaway.txt" | sed 's/^ *//')"
else
	cell nghttp goaway-drain FAIL "$(tail -3 "$OUT/nghttp-goaway.txt")"
fi
stop "$SECTION"
fi

if want h2load; then
SECTION=h2load
# h2load: multiplexed streams with trailers, streamed uploads, resets of the server among them, and
# a GOAWAY with each stream in flight.
start h2load
summary() { grep -E '^requests: ' "$1"; }
h2load --groups=X25519MLKEM768:X25519 -n 4000 -c 4 -m 32 "$(URL /trailers)" > "$OUT/h2load-trailers.txt" 2>&1
s=$(summary "$OUT/h2load-trailers.txt")
[[ "$s" =~ '4000 succeeded, 0 failed, 0 errored' ]] && cell h2load trailers PASS "$s $(grep -m1 'Server Temp Key' "$OUT/h2load-trailers.txt")" ||
	cell h2load trailers FAIL "$s"
h2load --groups=X25519MLKEM768:X25519 -n 200 -c 4 -m 8 -d "$OUT/body" "$(URL /echo)" > "$OUT/h2load-upload.txt" 2>&1
s=$(summary "$OUT/h2load-upload.txt")
[[ "$s" =~ '200 succeeded, 0 failed, 0 errored' ]] && cell h2load upload PASS "$s" || cell h2load upload FAIL "$s"
printf '%s\n' "$(URL /reset)" "$(URL /)" "$(URL /)" "$(URL /)" > "$OUT/uris"
h2load --groups=X25519MLKEM768:X25519 -n 400 -c 2 -m 16 -i "$OUT/uris" > "$OUT/h2load-reset.txt" 2>&1
s=$(summary "$OUT/h2load-reset.txt")
# h2load counts each stream that the server reset as failed and as errored.
[[ "$s" =~ '300 succeeded, 100 failed, 100 errored' ]] && cell h2load server-reset PASS "$s" || cell h2load server-reset FAIL "$s"
h2load --groups=X25519MLKEM768:X25519 -n 20 -c 2 -m 10 "$(URL /slow)" > "$OUT/h2load-goaway.txt" 2>&1 &
load=$!
sleep 0.5
"${C[@]}" "$(URL /shutdown)" -o /dev/null
wait $load
s=$(summary "$OUT/h2load-goaway.txt")
[[ "$s" =~ '20 succeeded, 0 failed, 0 errored' ]] && expect REPORT 20 && cell h2load goaway-drain PASS "$s" ||
	cell h2load goaway-drain FAIL "$s"
stop "$SECTION"
fi

if want chrome; then
SECTION=chrome
# Chrome: a streamed upload, trailers, a reset of the server, a reset of Chrome, and a GOAWAY with
# a stream in flight. The page posts its results.
start chrome
browse() {
	chrome --headless --no-sandbox --disable-gpu --user-data-dir="$OUT/chrome-$1" "$(URL "/$1")" > "$OUT/chrome-$1.txt" 2>&1 &
	BROWSER=$!
}
browse browser
if expect '^BROWSER ' 30; then
	result=$(sed -n 's/^BROWSER //p' "$LOG")
	echo "$result" | grep -q '"upload":"200 1048576 ordered"' && grep -q '^ECHO 1048576 $' "$LOG" &&
		cell chrome upload PASS || cell chrome upload FAIL "$result"
	echo "$result" | grep -q '"trailers":"200 65536"' && cell chrome trailers PASS || cell chrome trailers FAIL "$result"
	echo "$result" | grep -q '"server-reset":"rejected TypeError"' && cell chrome server-reset PASS || cell chrome server-reset FAIL "$result"
	if echo "$result" | grep -q '"browser-reset":"aborted AbortError"' && expect 'PEER-RESET /slow' 5; then
		cell chrome browser-reset PASS "$(grep 'PEER-RESET /slow' "$LOG")"
	else
		cell chrome browser-reset FAIL "$result"
	fi
	echo "$result" | grep -q '"after":200' && cell chrome after-reset PASS || cell chrome after-reset FAIL "$result"
else
	cell chrome page FAIL "no report: $(tail -3 "$OUT/chrome-browser.txt")"
fi
kill "$BROWSER" 2> /dev/null
browse goaway
if expect 'DONE /slow' 15 && expect REPORT 20; then
	cell chrome goaway-drain PASS "$(grep REPORT "$LOG")"
else
	cell chrome goaway-drain FAIL "the stream in flight did not complete"
fi
kill "$BROWSER" 2> /dev/null
stop "$SECTION"
fi

if want nginx || want h2o; then
# The rsnetwork client against nginx and h2o. nginx is the origin of each file, of the uploads
# (WebDAV PUT), and of the trailers (`add_trailer`). h2o serves the files, and takes its uploads
# and its slow body from nginx over HTTP/1.1. It drops the trailers of an HTTP/1.1 upstream, so its
# trailers come from the rsnetwork server over HTTP/2: h2o writes each frame to the client itself.
mkdir -p "$OUT/www/upload" "$OUT/www/small" "$OUT/nginx/logs"
echo index > "$OUT/www/index.html"
head -c $((4 << 20)) /dev/urandom > "$OUT/www/big"
cp "$OUT/www/big" "$OUT/www/trailers"
cat > "$OUT/nginx/nginx.conf" << EOF
daemon off;
pid $OUT/nginx/nginx.pid;
error_log $OUT/nginx/logs/error.log;
events { }
http {
    access_log off;
    client_body_temp_path $OUT/nginx/body;
    root $OUT/www;
    ssl_certificate $OUT/server.pem;
    ssl_certificate_key $OUT/server.key.pem;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519;
    server {
        listen 127.0.0.1:8443 ssl;
        http2 on;
        server_name server.test;
        location /trailers { add_trailer x-trailer done always; }
        location /upload/ { dav_methods PUT; client_max_body_size 64m; }
        location /small/ { dav_methods PUT; client_max_body_size 1m; }
        location /slowbig { alias $OUT/www/big; limit_rate 1m; }
    }
    server {
        listen 127.0.0.1:8444 ssl;
        http2 on;
        server_name server.test;
        keepalive_requests 3;
    }
    server {
        listen 127.0.0.1:8080;
        location /upload/ { dav_methods PUT; client_max_body_size 64m; }
        location /small/ { dav_methods PUT; client_max_body_size 1m; }
        location /slowbig { alias $OUT/www/big; limit_rate 1m; }
    }
}
EOF
nginx -p "$OUT/nginx" -c "$OUT/nginx/nginx.conf" &
NGINX=$!
sleep 1
client() { "$ENDPOINT" client "$1" "$TLS" "${@:2}"; }
if want nginx; then
# nginx 1.30.8 takes no request trailers on HTTP/2: it reads the trailer section as a new stream
# with an old identifier, a connection error. So its upload streams with no trailers.
for case in stream=/upload/file trailers=/trailers cancel=/big refused=/small/file; do
	result=$(client 127.0.0.1:8443 "$case" | tail -1)
	cell nginx "${case%%=*}" "$(echo "$result" | awk '{print $3}')" "$(echo "$result" | cut -d' ' -f4-)"
done
result=$(client 127.0.0.1:8444 goaway=/:8 | tail -1)
cell nginx goaway "$(echo "$result" | awk '{print $3}')" "$(echo "$result" | cut -d' ' -f4-)"
client 127.0.0.1:8443 drain=/slowbig > "$OUT/nginx-drain.txt" &
drain=$!
for _ in $(seq 50); do grep -q READY "$OUT/nginx-drain.txt" && break; sleep 0.1; done
kill -QUIT "$NGINX"
wait $drain
result=$(tail -1 "$OUT/nginx-drain.txt")
cell nginx goaway-drain "$(echo "$result" | awk '{print $3}')" "$(echo "$result" | cut -d' ' -f4-)"
else
	kill -QUIT "$NGINX"
fi
wait "$NGINX" 2> /dev/null
fi

if want h2o; then
nginx -p "$OUT/nginx" -c "$OUT/nginx/nginx.conf" &
NGINX=$!
start upstream
cat > "$OUT/h2o.conf" << EOF
listen:
  host: 127.0.0.1
  port: 9443
  ssl:
    certificate-file: $OUT/server.pem
    key-file: $OUT/server.key.pem
    minimum-version: TLSv1.3
http2-idle-timeout: 2
hosts:
  "server.test:9443":
    paths:
      "/upload":
        proxy.reverse.url: http://127.0.0.1:8080/upload
      "/small":
        proxy.reverse.url: http://127.0.0.1:8080/small
      "/trailers":
        proxy.reverse.url: https://server.test:$PORT/trailers
        proxy.http2.ratio: 100
        proxy.ssl.cafile: $OUT/ca.pem
        proxy.ssl.verify-peer: ON
      "/slowbig":
        proxy.reverse.url: http://127.0.0.1:8080/slowbig
      "/":
        file.dir: $OUT/www
EOF
h2o -c "$OUT/h2o.conf" > "$OUT/h2o.log" 2>&1 &
H2O=$!
sleep 1
for case in upload=/upload/file trailers=/trailers cancel=/big refused=/small/file; do
	result=$(client 127.0.0.1:9443 "$case" | tail -1)
	cell h2o "${case%%=*}" "$(echo "$result" | awk '{print $3}')" "$(echo "$result" | cut -d' ' -f4-)"
done
# SIGTERM shuts h2o down gracefully: a GOAWAY, and then each stream in flight ends.
client 127.0.0.1:9443 drain=/slowbig > "$OUT/h2o-drain.txt" &
drain=$!
for _ in $(seq 50); do grep -q READY "$OUT/h2o-drain.txt" && break; sleep 0.1; done
kill -TERM "$H2O"
wait $drain
result=$(tail -1 "$OUT/h2o-drain.txt")
cell h2o goaway-drain "$(echo "$result" | awk '{print $3}')" "$(echo "$result" | cut -d' ' -f4-)"
kill "$NGINX" 2> /dev/null
stop upstream
wait 2> /dev/null
fi

curl --version | head -1
nghttp --version
nginx -v 2>&1
h2o --version | head -1
h2spec --version
chrome --version
openssl version
exit $failed
