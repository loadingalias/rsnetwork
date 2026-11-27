# rsnetwork

**DO NOT USE IN PRODUCTION.**

rsnetwork is a networking stack for Rust: HTTP/1.1, HTTP/2, HTTP/3, QUIC, and TLS, for clients and
servers. Its protocol core does no I/O, so it runs on rsasync, on Tokio, or in your own event loop.
It has its own QUIC. rustls runs TLS, and all cryptography comes from rscrypto, with post-quantum
key exchange by default. It has no C.

rsnetwork is in development. Each release can change the API.

To serve an existing axum router, enable the optional `tower` feature on `rsnetwork-tokio`. [Serve a Tower service](docs/content/tower.md)

rsnetwork is one part of a family of Rust libraries:
[rscrypto](https://github.com/loadingalias/rscrypto) (cryptography),
[rsasync](https://github.com/loadingalias/rsasync) (runtime),
rsnetwork (networking),
[rsauthnz](https://github.com/loadingalias/rsauthnz) (auth), and
[rscodec](https://github.com/loadingalias/rscodec) (codecs).

License: Apache-2.0.
