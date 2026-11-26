#!/bin/sh
# Makes the certificates of the TLS and QUIC tests with the OpenSSL command (3.5 or later, for
# ML-DSA), in this directory. Each key is in PKCS#8 DER: ECDSA P-256, or ML-DSA for the `mldsa`
# files. Each certificate is valid from 2026-01-01 to 2036-01-01. The tests set their own wall
# clock, so their result does not depend on the date of a run. The example
# `rsnetwork-tokio/examples/multiplexed.rs` uses the clock of the system: make the certificates
# again before 2036-01-01. Run it again only to change a certificate, and commit each file that it
# writes. `generate.sh mldsa` makes only the ML-DSA files.
set -eu
cd "$(dirname "$0")"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
validity="-not_before 20260101000000Z -not_after 20360101000000Z"

# The key of $1, with the algorithm $2: ECDSA P-256 when it is empty.
key() {
	if [ -z "${2:-}" ]; then
		openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER -out "$1.key.der"
	else
		openssl genpkey -algorithm "$2" -outform DER -out "$1.key.der"
	fi
}

# A root with the algorithm $2.
root() {
	key "$1" "${2:-}"
	openssl req -x509 -new -key "$1.key.der" -keyform DER -subj "/CN=rsnetwork test $1" $validity \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
		-outform DER -out "$1.der"
}

# A certificate that $4 signs: $1 is its name, $2 its extensions, and $3 its algorithm.
signed() {
	key "$1" "$3"
	openssl req -new -key "$1.key.der" -keyform DER -subj "/CN=$1" -out "$scratch/$1.csr"
	printf '%s\n' "$2" >"$scratch/$1.ext"
	openssl x509 -req -in "$scratch/$1.csr" -CA "$4.der" -CAform DER -CAkey "$4.key.der" -CAkeyform DER \
		-set_serial "0x$(openssl rand -hex 8)" $validity -extfile "$scratch/$1.ext" -outform DER -out "$1.der"
}

# A leaf that `ca` signs: $1 is its name, $2 its subject alternative name, $3 its extended key usage.
leaf() {
	signed "$1" "$(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s' "$3" "$2")" "" ca
}

# An ML-DSA-65 chain of the size that a PQ server sends: `mldsa-ca` signs `mldsa-intermediate`,
# which signs one leaf for `server.test` with each parameter set of ML-DSA (RFC 9881).
mldsa() {
	root mldsa-ca ML-DSA-65
	signed mldsa-intermediate "$(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign')" \
		ML-DSA-65 mldsa-ca
	for set in 44 65 87; do
		signed "mldsa$set" "$(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server.test')" \
			"ML-DSA-$set" mldsa-intermediate
	done
	rm mldsa-ca.key.der mldsa-intermediate.key.der
}

if [ "${1:-}" = mldsa ]; then
	mldsa
	exit
fi
root ca
root other-ca
leaf server DNS:server.test serverAuth
leaf rotated DNS:rotated.test serverAuth
leaf client DNS:client.test clientAuth
# The tests need no key of a root.
rm ca.key.der other-ca.key.der
mldsa
