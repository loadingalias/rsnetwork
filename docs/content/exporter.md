# Bind a proof to a TLS connection

Each TLS connection can derive keying material from its regular exporter (RFC 8446, section
7.5). Both ends of one connection derive the same bytes, and another connection, label, or context
gives other bytes. Use it to bind a proof of possession to one connection, as a native session
profile of an authentication library does.

A derivation is not authorization, and it is not freshness. It proves only that both ends hold
the secrets of this connection. Give each proof a fresh context, such as an authentication
instance that the verifier names, and check the authorization of the peer on its own.

rsnetwork is in development and has no release. The exporter has run evidence over TLS 1.3 on
macOS (aarch64): on the caller-driven host in memory, and on the Tokio binding over loopback, for
HTTP/1.1, HTTP/2, and TLS streams.

## Prerequisites

- A TLS connection of rsnetwork, after its handshake: see [run a connection over TLS
  1.3](tls.md). Over TCP with no TLS, a connection has no exporter.
- A label for your protocol, and a context for each proof.

## Derive and verify a proof

The client derives a proof for one authentication instance and sends it over the connection. The
server derives the proof that it expects on its own end, and compares. Here, `client` and `server`
are the two ends of a `tls::Stream` after the handshake, and `received` holds the 32 bytes that
the server read:

```rust
use rsnetwork::tls::ExportError;

const LABEL: &[u8] = b"EXPERIMENTAL-example-possession";

// The verifier names a fresh instance for each authentication.
let context = [&b"initial "[..], &1_u64.to_be_bytes()].concat();

// The client end: the proof, which it sends over the connection.
let mut proof = [0; 32];
client.export(LABEL, &context, &mut proof)?;

// The server end: the proof that it expects for the same instance.
let mut expected = [0; 32];
server.export(LABEL, &context, &mut expected)?;
let verified = received == expected;
# Ok::<(), ExportError>(())
```

Compare the proof with a check whose time does not depend on the bytes when an attacker can
measure the time. The material is a secret for as long as your buffer holds it: wipe the buffer
at the end of its use. The exporter secret stays in rustls, and the connection drops it with its
other secrets.

A proof does not verify on another connection, also between the same client and server. It does
not verify for another context, so a renewal with a new instance needs a new proof.

## The call

| Type | Call |
| --- | --- |
| `tls::Tls`, `tls::Stream` | `export(label, context, &mut output)` |
| `client::Http1`, `client::Http2`, `server::Http` | `export(label, context, &mut output)` |
| `rsnetwork_tokio::client::Http1`, `client::Http2`, `server::Exchange`, `tls::Stream` | `export(label, context, &mut output)`, with no wait |

`export` fills `output` with `output.len()` bytes, or refuses with an `ExportError`. The call
derives from the regular exporter only, never from the early exporter: 0-RTT is off, and a
resumed connection derives from its own regular exporter.

| Input | Rule |
| --- | --- |
| `label` | 1 to `EXPORT_LABEL_MAX` (249) bytes. A label that starts with `RESERVED_LABEL_PREFIX` (`EXPERIMENTAL-rsnetwork-`) refuses: rsnetwork derives its own channels under it. Unregistered labels start with `EXPERIMENTAL` (RFC 5705, section 4) |
| `context` | 0 to `EXPORT_CONTEXT_MAX` (1,024) bytes. The exporter hashes it |
| `output` | 1 to `EXPORT_OUTPUT_MAX` (8,160) bytes: 255 blocks of SHA-256 |

## Errors

A refusal writes zeros to `output`, so the buffer holds no material.

| `ExportError` | Cause | Recovery |
| --- | --- | --- |
| `Handshake` | The handshake did not complete | Derive after it, for example after the first response or after `negotiated()` gives a value |
| `Unavailable` | The connection runs over TCP with no TLS | Use a TLS connection |
| `Closed` | The connection ended: this end closed or failed, the transport failed, or the input of the peer ended | Make a new connection, and a new proof on it |
| `Profile` | The label, the context, or the length breaks a rule of the table above | Correct the request |

On a connection that many handles share, such as `rsnetwork_tokio::client::Http2`, `export` takes
the lock of the connection for its derivation only.
