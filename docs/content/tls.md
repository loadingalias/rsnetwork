# Run a connection over TLS 1.3

`rsnetwork::tls` runs a protocol engine, for example the HTTP/1.1 server, over TLS 1.3. The host
moves only ciphertext. rustls decrypts each record in place, in the region that its bytes arrived
in, and the engine reads its plaintext as views of that region. All cryptography comes from
rscrypto, through the `rscrypto-rustls` provider.

rsnetwork is in development and has no release. TLS uses rustls `0.24.0-dev.3`, a development
release of rustls, until rustls 0.24.0 is released.

## Prerequisites

- The `tls` feature. It is on by default. A protocol-only build sets `default-features = false`:
  it then has no TLS and no dependency other than `rstypes`.
- For a server: its certificate chain, end-entity certificate first, and the private key of that
  certificate.
- For a client: the root certificates that it trusts. The client trusts only these roots. This
  release does not read the trust anchors of the operating system.
- A wall clock for the validity of certificates. `DefaultTimeProvider` reads the clock of the
  system. A test can give its own `TimeProvider`.

`CertificateDer` and `PrivateKeyDer` hold DER. To read PEM, use the `PemObject` trait that
`rsnetwork::tls` exports:

```rust
use rsnetwork::tls::{CertificateDer, PemObject, PrivateKeyDer};

fn identity(chain_pem: &[u8], key_pem: &[u8]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let chain = CertificateDer::pem_slice_iter(chain_pem).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem)?;
    Ok((chain, key))
}
```

`CertificateDer::pem_file_iter` and `PrivateKeyDer::from_pem_file` read a file.

## Configure each end

Make one configuration for each end, and share it with each connection. Each configuration takes
its choices explicitly, and it has its own provider. Nothing installs a provider for the process,
and rustls 0.24 has no default provider of the process.

| `ClientOptions` field | Meaning |
| --- | --- |
| `roots` | The roots that the chain of the server must reach. At least one |
| `identity` | The certificate chain and key of the client, for a server that asks for one (mTLS), or `None` |
| `protocols` | The ALPN names to offer, the most preferred first. Empty offers none |
| `resumption` | `Resumption::Off`, or `Resumption::Process(n)` (see [Resumption](#resumption)) |
| `clock` | The wall clock that checks the validity of each certificate |
| `entropy` | `Entropy::System`, or `Entropy::Seeded(generator)` (see [Replay a run](#replay-a-run)) |

| `ServerOptions` field | Meaning |
| --- | --- |
| `identity` | The certificate chain and key of the server |
| `client_roots` | `None`: the server asks for no client certificate. `Some(roots)`: each client must show a chain to one of these roots (mTLS) |
| `protocols` | The ALPN names that the server accepts, the most preferred first |
| `resumption` | `Resumption::Off`, or `Resumption::Process(n)` |
| `clock` | The wall clock that checks each client certificate and session |
| `entropy` | `Entropy::System`, or `Entropy::Seeded(generator)` |

`ClientConfig::new` and `ServerConfig::new` refuse with `Kind::Misuse` when a configuration
cannot work: no root, a certificate that does not parse, a key that does not match its
certificate, or an ALPN name that is empty or longer than 255 bytes.

The key exchange is the default hybrid profile. A client offers X25519MLKEM768 first and X25519
second, with a key share for each. A server selects X25519MLKEM768 whenever the client offers it.
It sends a HelloRetryRequest for it when the client sent no key share for it. The suites are the
TLS 1.3 suites AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305. TLS 1.2 is off. 0-RTT is off: no
end sends or accepts early data.

## Run an engine over TLS

A TLS connection has three layers:

1. The engine, with its plaintext `Inbound` and `Outbound` queues.
2. `Tls`, which owns the engine and its queues. `Tls::server` makes the server end.
   `Tls::client` makes the client end for a server name, and it writes the ClientHello at once.
3. The host `Connection`, with the ciphertext queues. The host drives it as in
   [drive a connection from your own event loop](caller-driven.md).

```rust
use core::net::SocketAddr;
use core::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, TurnLimits};
use rsnetwork::h1::{BodyLimits, Framing, Limits as HeadLimits, Server, ServerEvent};
use rsnetwork::host::Connection;
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, DefaultTimeProvider, Entropy, Identity, Limits, PrivateKeyDer, Resumption, ServerConfig, ServerOptions,
    Tls,
};
use rsnetwork::value::Status;

fn serve(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    peer: SocketAddr,
    local: SocketAddr,
    received: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // One configuration for each connection of the server.
    let config = ServerConfig::new(ServerOptions {
        identity: Identity { chain, key },
        client_roots: None,
        protocols: &[b"http/1.1"],
        resumption: Resumption::Process(NonZeroUsize::new(1024).expect("not zero")),
        clock: Arc::new(DefaultTimeProvider),
        entropy: Entropy::System,
    })?;

    // One connection: the HTTP/1.1 engine with its plaintext queues, inside `Tls`, inside the
    // host connection with its ciphertext queues. One budget pays for each part.
    let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
    let queue = NonZeroUsize::new(16).expect("not zero");
    let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
    let head = HeadLimits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
    let body = BodyLimits {
        body_bytes: 1 << 20,
        drain_bytes: 64 * 1024,
        extension_bytes: 256,
        trailer_bytes: 4 * 1024,
        trailer_fields: 16,
    };
    let (inbound, outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
    let server = Server::new(head, body, turn, &outbound, &budget)?;
    let limits = Limits { input_bytes: 32 * 1024, turn };
    let tls = Tls::server(&config, server, (inbound, outbound), limits, &budget)?;
    let (inbound, outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
    let clock = ClockDomain::new(1, Suspend::Pauses);
    let mut connection = Connection::new(tls, inbound, outbound, Some(clock))?;

    // Receive into the tail of the input region that the connection lends. A real host reads
    // its socket into the loan.
    if let Some(region) = connection.region()? {
        let mut loan = WriteLoan::new(region);
        loan.fill_from(received);
        let endpoint = Endpoint { peer, local, ecn: Ecn::NotEct, segment: None };
        connection
            .received(loan.into_inner(), endpoint, 64 * 1024)
            .map_err(|_| "the connection cannot take the region now: drive first")?;
    }

    // Drive, and answer each request through the engine inside `Tls`.
    while let Some(event) = connection.drive(Some(Instant::new(clock, 0)))? {
        if let ServerEvent::Request(_) = event {
            let (tls, _) = connection.parts();
            let (server, outbound) = tls.parts();
            let head = Backing::from(Vec::with_capacity(256));
            server.respond(outbound, Status::new(200)?, &[], Framing::Length(5), head)?;
            server.send(outbound, &Lease::from(b"hello".to_vec()))?;
            server.finish(outbound)?;
        }
    }
    Ok(())
}
```

Send each output of the connection, and acknowledge it, as without TLS. The engine encrypts its
plaintext output in the next drive, so drive again after you answer an event.

## Receive forms and their copies

`Tls::copies()` reports each byte that the connection copied, by cause. The receive form that the
host uses decides the copies of received bytes:

| Receive form | Calls | Copies |
| --- | --- | --- |
| The tail of the input region | `Connection::region()`, then `Connection::received(region, ..)` with the same region | None. A record that continues after a receive joins its first bytes in place |
| A region of the host, for example one that the kernel selected | `Connection::received(region, ..)` with that region | When a record continues into it from the region before: the rest of that record, less than one record (`partial`) |
| A read-only region | `Connection::receive(Received)` | Each byte, into a writable region (`received`) |

The plaintext of a region reaches the engine when the region freezes. When a partial record ends
the region, the connection copies the smaller part: the partial record to a new region
(`partial`), or the plaintext to its own region (`joined`). A request and its response that end at
record boundaries copy nothing. `rustls` counts plaintext that rustls gave in its own buffer.
`encrypted` counts the plaintext that encryption wrote into ciphertext, which each sent byte needs.

An idle connection keeps no input region and no ciphertext output: after its last view drops, the
budget has each of their bytes back.

## Negotiated facts

`Tls::negotiated()` gives `None` before the handshake completed. After it, it gives:

| Field | Value |
| --- | --- |
| `group` | The key-exchange group, by its IANA code point: `Group::X25519_MLKEM768` or `Group::X25519` |
| `protocol` | The ALPN name that the server selected, or `None` |
| `handshake` | `Handshake::Full`, `Handshake::Retried` (after a HelloRetryRequest), or `Handshake::Resumed` |

## Resumption

`Resumption::Process(n)` resumes sessions only in the process that made them. The process keeps at
most `n` sessions. The ticket keys are local to the process, so another instance of a server, or
the same server after a restart, runs a full handshake. `ClientConfig::resumption()` and
`ServerConfig::resumption()` report the scope. `Resumption::Off` runs a full handshake for each
connection, and the server then sends no session ticket.

## Replay a run

`Entropy::System` reads the randomness of each handshake from the operating system.
`Entropy::Seeded(generator)` takes it from a seeded `ChaCha20Rng` instead. Each connection, and each
key that the configuration loads, draws from its own child of the generator, in the order of the
calls that make them. A run with the same seed, the same configurations, and the same calls in
the same order sends the same bytes, so a recorded run replays byte for byte.

```rust
use rsnetwork::tls::{ChaCha20Rng, Entropy};

// One root seed for the run. Record it with the run, and give each process its own seed.
let root = ChaCha20Rng::from_seed([0x5a; ChaCha20Rng::SEED_SIZE]);
let client = Entropy::Seeded(root.child(b"client\0\0", 0));
let server = Entropy::Seeded(root.child(b"server\0\0", 0));
# let _ = (client, server);
```

A seed gives secret randomness only when it is secret. A draw in a copy of the process that
seeded the generator refuses, and the handshake then fails with `Kind::Unsupported`.

## Rotate the server identity

`ServerConfig::rotate(identity)` replaces the identity that each later handshake shows. A
connection that has started keeps its identity. When the new identity is not valid, for example
when its key does not match its certificate, `rotate` refuses with `Kind::Misuse` and keeps the old
identity.

## Errors

A failed handshake or record ends the connection with an [error](errors.md). The connection first
writes the alert of rustls, so send the rest of the output before the release.

| Cause | `Kind` | Reason |
| --- | --- | --- |
| The certificate of the peer expired | `Trust` | `the peer certificate expired` |
| The certificate is not valid for the name of the server | `Trust` | `the peer certificate is not valid for its name` |
| The chain reaches no root of the configuration | `Trust` | `the peer certificate chain reaches no trusted root` |
| A server that asks for a client certificate got none | `Trust` | `the peer showed no certificate` |
| The peer refused the certificate of this end | `Trust` | `the peer refused the certificate of this end` |
| The peer and this end have no group, suite, or ALPN name in common | `Unsupported` | `the peer has no TLS parameters in common with this end`, or `the peer found no TLS parameters in common` |
| The transport ended before the handshake completed | `Partial` | `the transport ended before the TLS handshake completed` |
| The transport ended inside a record | `Partial` | `the transport ended inside a TLS record` |
| A handshake message, for example a certificate chain, is larger than `input_bytes` | `Overload` | `a TLS message is larger than the input region` |
| The peer sent bytes that TLS forbids | `Malformed` | `the peer sent TLS bytes that the protocol forbids` |

A trust failure never authorizes a weaker check. Do not retry it with another configuration.

## End of input

`Tls::closure()` reports how the input of the peer ended:

- `Closure::Notified`: the peer sent `close_notify`. Its data ended there.
- `Closure::Unnotified`: the transport ended with no `close_notify`. The engine also sees the end.
  A protocol with its own framing, for example a body with a length, can tell that a message is
  incomplete. For data that ends only at the end of the connection, treat this end as partial.

When the engine ends, the connection sends `close_notify` before its terminal turn.

## Limits

| `tls::Limits` field | Bounds |
| --- | --- |
| `input_bytes` | The capacity of each input region that the connection allocates, at least `RECORD_BYTES_MAX` (16 645 bytes). It also bounds the largest handshake message, because rustls joins a message in the input region |
| `turn` | The bytes and records that one drive decrypts and encrypts |

Each input region, each ciphertext output, and each copied plaintext region is charged to the
budget of the connection: see [limits](limits.md).
