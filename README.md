# rsnetwork

The one networking stack a Rust service needs: HTTP/1.1, HTTP/2, HTTP/3, QUIC, and TLS, for clients
and servers, on any runtime.

- **One API, the best protocol for each request.** The client selects the connection and protocol
  that will finish the request first, from what it measured, and reports why. No version flags and
  no manual fallback.
- **Its own QUIC.** A sans-I/O QUIC transport and UDP layer replace quinn, quinn-proto, and quinn-udp
  completely: GSO and GRO, connection IDs that route each packet to its core, and byte-for-byte
  replay.
- **Post-quantum by default.** Hybrid ML-KEM key exchange on each connection, and a strict mode that
  refuses classical peers. rustls runs TLS; all cryptography comes from rscrypto.
- **Any runtime.** The same protocol core runs on rsasync, on Tokio, or in your own event loop. Most
  tower and axum applications run unchanged on the Tokio binding.
- **One deadline for the whole request.** It covers connect, retries, headers, and the last body
  byte.
- **Bounded under attack.** Every byte, frame, stream, table, and timer is charged before work. Slow
  peers and floods cannot grow memory.
- **Copies counted, not hidden.** TLS decrypts in place in the receive buffer, and each remaining
  copy is reported. No C, OpenSSL, BoringSSL, or aws-lc in the build.

**The bar.** Each release measures against hyper, quinn, quiche, s2n-quic, nginx, h2o, and msquic.
HTTPS HTTP/2 small responses, HTTP/3 bulk transfer, and idle-connection memory must win by a
declared margin, and no required cell may lose. Every loss is published, and no "fastest" claim
ships without this evidence.

Status: in development. No release yet.

Part of one family on [rscrypto](https://github.com/loadingalias/rscrypto): rsasync (runtime),
rsnetwork (networking), and rsauthnz (auth). Apache-2.0. Develop with `cargo xtask fix`,
`cargo xtask test`, and `cargo xtask check`.
