#!/bin/sh
# Makes the certificates of the TLS tests (tests/tls.rs) with the OpenSSL command, in this
# directory. Each key is ECDSA P-256, in PKCS#8 DER. Each certificate is valid from 2026-01-01 to
# 2036-01-01; the tests set their own wall clock, so the result does not depend on the date of a
# run. Run it again only to change a certificate, and commit each file that it writes.
set -eu
cd "$(dirname "$0")"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
validity="-not_before 20260101000000Z -not_after 20360101000000Z"

key() {
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER -out "$1.key.der"
}

# A root: `ca` signs each leaf. `other-ca` signs nothing, so a chain to it does not exist.
root() {
	key "$1"
	openssl req -x509 -new -key "$1.key.der" -keyform DER -subj "/CN=rsnetwork test $1" $validity \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
		-outform DER -out "$1.der"
}

# A leaf that `ca` signs: $1 is its name, $2 its subject alternative name, $3 its extended key usage.
leaf() {
	key "$1"
	openssl req -new -key "$1.key.der" -keyform DER -subj "/CN=$1" -out "$scratch/$1.csr"
	printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
		"$3" "$2" >"$scratch/$1.ext"
	openssl x509 -req -in "$scratch/$1.csr" -CA ca.der -CAform DER -CAkey ca.key.der -CAkeyform DER \
		-set_serial "0x$(openssl rand -hex 8)" $validity -extfile "$scratch/$1.ext" -outform DER -out "$1.der"
}

root ca
root other-ca
leaf server DNS:server.test serverAuth
leaf rotated DNS:rotated.test serverAuth
leaf client DNS:client.test clientAuth
# The tests need no key of a root.
rm ca.key.der other-ca.key.der
