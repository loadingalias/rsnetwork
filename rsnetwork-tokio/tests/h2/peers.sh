#!/usr/bin/env bash
# Builds the independent HTTP/2 peers of the interop runs (N206) into $PEERS, default ~/peers, on
# an E1 host: Ubuntu 26.04 on x86_64. Each source has a pinned version, and a SHA-256 or a full
# commit hash. The C peers link the OpenSSL of the system, which must be 3.5 or later for
# X25519MLKEM768. Run it one time on each host. It prints each version at the end.
set -euo pipefail
PEERS=${PEERS:-$HOME/peers}
mkdir -p "$PEERS/src" "$PEERS/bin"
cd "$PEERS/src"
jobs=$(nproc)

sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
	build-essential cmake pkg-config libssl-dev zlib1g-dev libev-dev libc-ares-dev libpcre2-dev \
	libnss3-tools unzip xz-utils git ca-certificates curl openssl \
	libatk1.0-0t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 libxcomposite1 libxdamage1 libxfixes3 \
	libxrandr2 libgbm1 libasound2t64 > /dev/null
openssl version

# Downloads $2 into $1, and checks its SHA-256 $3.
fetch() {
	[ -f "$1" ] || curl -fsSL -o "$1" "$2"
	echo "$3  $1" | sha256sum -c --quiet
}

# A clone of $1 at the commit $2.
clone() {
	local name
	name=$(basename "$1")
	[ -d "$name" ] || git clone -q "$1" "$name"
	git -C "$name" checkout -q "$2"
	[ "$(git -C "$name" rev-parse HEAD)" = "$2" ]
}

fetch nghttp2-1.71.0.tar.xz https://github.com/nghttp2/nghttp2/releases/download/v1.71.0/nghttp2-1.71.0.tar.xz \
	c0f55121d88650e4b9227aec28cebaf664d2417ca60fe70be0f8d38829f52116
# A second run builds only the peers that are missing.
[ -x "$PEERS/bin/h2load" ] || (tar -xf nghttp2-1.71.0.tar.xz && cd nghttp2-1.71.0 && ./configure -q --prefix="$PEERS" --enable-app --disable-python-bindings \
	LDFLAGS="-Wl,-rpath,$PEERS/lib" && make -s -j"$jobs" && make -s install) > /dev/null

fetch curl-8.23.0.tar.xz https://github.com/curl/curl/releases/download/curl-8_23_0/curl-8.23.0.tar.xz \
	8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5
[ -x "$PEERS/bin/curl" ] || (tar -xf curl-8.23.0.tar.xz && cd curl-8.23.0 && PKG_CONFIG_PATH="$PEERS/lib/pkgconfig" ./configure -q --prefix="$PEERS" --with-openssl \
	--with-nghttp2="$PEERS" --without-libpsl --disable-ldap LDFLAGS="-Wl,-rpath,$PEERS/lib" &&
	make -s -j"$jobs" && make -s install) > /dev/null

fetch nginx-1.30.8.tar.gz https://github.com/nginx/nginx/releases/download/release-1.30.8/nginx-1.30.8.tar.gz \
	f867314ada32e717b949930859656c48a72dc6657aec598db58af2f98a40e1c1
[ -x "$PEERS/nginx/sbin/nginx" ] || (tar -xf nginx-1.30.8.tar.gz && cd nginx-1.30.8 && ./configure --prefix="$PEERS/nginx" --with-http_ssl_module --with-http_v2_module \
	--with-http_dav_module && make -s -j"$jobs" && make -s install) > /dev/null
ln -sf "$PEERS/nginx/sbin/nginx" "$PEERS/bin/nginx"

clone https://github.com/h2o/h2o d3e43fcf00c3e6b17826b95d2d362d646185918a
[ -x "$PEERS/bin/h2o" ] || (cd h2o && cmake -S . -B build -DCMAKE_INSTALL_PREFIX="$PEERS" -DWITH_MRUBY=OFF -DWITH_H2OLOG=OFF \
	-DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$jobs" --target h2o &&
	install -m 755 build/h2o "$PEERS/bin/h2o") > /dev/null

fetch go1.27.4.linux-amd64.tar.gz https://go.dev/dl/go1.27.4.linux-amd64.tar.gz \
	7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
rm -rf "$PEERS/go" && tar -xf go1.27.4.linux-amd64.tar.gz -C "$PEERS"
clone https://github.com/summerwind/h2spec af83a65f0b6273ef38bf778d400d98892e7653d8
(cd h2spec && GOTOOLCHAIN=local "$PEERS/go/bin/go" build -o "$PEERS/bin/h2spec" ./cmd/h2spec)

# Chrome for Testing publishes no digest, so the record keeps the digest of this download.
chrome=chrome-headless-shell-linux64.zip
[ -f "$chrome" ] || curl -fsSL -o "$chrome" \
	https://storage.googleapis.com/chrome-for-testing-public/158.0.8127.88/linux64/chrome-headless-shell-linux64.zip
sha256sum "$chrome"
rm -rf "$PEERS/chrome" && unzip -q "$chrome" -d "$PEERS/chrome"
ln -sf "$PEERS/chrome/chrome-headless-shell-linux64/chrome-headless-shell" "$PEERS/bin/chrome"
# The libraries that the headless shell links. `ldd` names each one that is missing.
missing=$(ldd "$PEERS/bin/chrome" | awk '/not found/ { print $1 }')
if [ -n "$missing" ]; then
	echo "chrome needs: $missing" >&2
	exit 1
fi

export PATH="$PEERS/bin:$PATH"
curl --version | head -1
nghttp --version
h2load --version
nginx -v 2>&1
h2o --version | head -1
h2spec --version
chrome --version
