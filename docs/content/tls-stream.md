# Send a byte stream over TLS

`rsnetwork::tls::Stream` is an encrypted and authenticated byte stream over TCP, for a protocol
other than HTTP, for example a database wire protocol. It uses the TLS path of HTTP: the same
trust roots, key exchange, record layer, and backing rules. Its end tells a clean close apart from
a cut connection, and a write that ends early reports the bytes that went.

rsnetwork is in development and has no release. `Stream` does no I/O. A binding, or your own event
loop, moves the ciphertext of the socket: see [drive a connection from your own event loop](caller-driven.md).

## Prerequisites

- A host that moves bytes between the socket and the stream, for example
  [`host::Tcp`](caller-driven.md#tls-over-the-socket), and reads a monotonic clock.
- A `tls::ClientConfig` or a `tls::ServerConfig`, as on the [TLS page](tls.md#configure-each-end).
  The ALPN name of your protocol goes in its `protocols`.
- `tls::StreamLimits`: the `tls::Limits` of the connection, the size of each queue, and the
  handshake timeout.
- A budget for each part of the connection: see [limits](limits.md).

## Send a query and read the answer

`Stream::connect` makes the client end, and `Stream::accept` makes the server end. Each call takes
the time `now`. When a call has nothing to give yet, it gives `None` or `Read::Wait`. Then wait as
`stream.wait()` says, move the bytes, and call again. `host` is your loop: it waits, moves the
ciphertext with `received` and `output`, and gives the time.

```rust
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::TurnLimits;
use rsnetwork::host::Io as _;
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{ClientConfig, Limits, Stream, StreamLimits};

/// Sends `query` to the server `name`, and gives its answer, which ends with the close_notify of
/// the server.
fn ask(
    config: &ClientConfig,
    name: &str,
    query: &[u8],
    mut host: impl FnMut(&mut Stream) -> Instant,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
    let limits = StreamLimits {
        tls: Limits { input_bytes: 32 * 1024, key_records_max: u64::MAX, turn },
        queue: NonZeroUsize::new(16).expect("not zero"),
        handshake_timeout: Some(Duration::from_secs(10)),
    };
    let budget = Budget::new(NonZeroU64::new(1 << 22).expect("not zero"));
    // The clock of the host: each `now` is on it.
    let clock = ClockDomain::new(1, Suspend::Pauses);
    let mut stream = Stream::connect(config, name, limits, clock, &budget)?;
    let mut now = host(&mut stream);
    // The bytes wait for the handshake.
    stream.write(&Lease::from(query.to_vec()), now)?;
    let mut answer = Vec::new();
    loop {
        match stream.next(now)? {
            Some(Part::Data(data)) => answer.extend_from_slice(data.bytes()),
            Some(Part::End(Outcome::Complete(_))) => break,
            Some(Part::End(outcome)) => return Err(format!("the stream ended as {outcome:?}").into()),
            None => now = host(&mut stream),
        }
    }
    stream.close(now)?;
    while stream.release().is_none() {
        now = host(&mut stream);
        stream.drive(now)?;
    }
    Ok(answer)
}
```

Only `Outcome::Complete` proves that the answer is whole. When your protocol frames its own
messages, for example with a length before each one, it can also tell an incomplete message from
a `Truncated` end.

## The calls

| Call | Result |
| --- | --- |
| `Stream::connect(&config, name, limits, clock, &budget)` | The client end of a stream to `name`, a DNS name or an IP address. The ClientHello is ready at once |
| `Stream::accept(&config, limits, clock, &budget)` | The server end of a stream |
| `read_into(now, &mut region)` | Copies the next received bytes into the free capacity of the region, or gives `Read::Done(outcome)` after the last byte |
| `next(now)` | `body::Part::Data(view)`: the next received bytes as a view of their received region, with no copy. `Part::End(outcome)` at the end |
| `write(&data, now)` | Queues a view of your region, with no copy. Before the handshake completes, the bytes wait for it. A full queue makes the write drive the stream one time, which seals the bytes that wait. When the queue is still full, the write refuses with `Kind::Overload`, and takes nothing: send the output, and write again |
| `written()`, `sent()` | The bytes that `write` took, and the bytes whose records the transport accepted: see [write progress](#write-progress) |
| `close(now)` | Ends the stream: it sends `close_notify` after the bytes that it took, and reads no more. A read after it ends `Outcome::Cancelled`, unless the peer closed first |
| `drive(now)` | Drives the stream: the handshake, the encryption of the bytes that wait, and the close. Call it each time that `wait()` says. Each read and write also drives the stream |
| `negotiated()` | The security evidence after the handshake: see [evidence](#evidence) |
| `closure()` | How the input of the peer ended: `Closure::Notified`, `Unnotified`, or `Reset` |
| `wait()` | When to call again: now, when the transport gives what the stream waits for, at the handshake deadline, or never after the end |
| `received`, `receive`, `region`, `output`, `ack`, `end_input`, `reset`, `outstanding`, `release` | The transport calls, as on a [host connection](caller-driven.md). Call `end_input` when the peer closed its side, and `reset` when the transport failed |

## The end of a stream

| Outcome | Cause |
| --- | --- |
| `Outcome::Complete(None)` | The peer sent `close_notify`: its data ended there, and no byte is lost |
| `Outcome::Truncated` | The transport ended with no `close_notify`. Bytes of the peer can be lost |
| `Outcome::Reset(None)` | The transport failed, after `reset` |
| `Outcome::Cancelled` | Your code closed the stream first |

A TCP end of the peer is never a clean close by itself: it is `Truncated` until a `close_notify`
proves the end.

## Write progress

`written()` counts the bytes that `write` took. `sent()` counts the bytes whose TLS records the
transport accepted. A record counts when each of its bytes went, so `sent()` is exact to whole
records of at most 16 KiB. When the transport fails, `sent()` keeps the bytes that went, and the
bytes after them did not go. "Accepted" is the event of the transport, for example a socket that
took the bytes, not a proof that the peer read them.

The stream seals at most one written region for each entry of its queue before the transport
accepts its records. Then `write` refuses with `Kind::Overload` until output goes.

## Evidence

`negotiated()` gives `None` before the handshake completed, and then `Negotiated`:

| Field | Value |
| --- | --- |
| `group` | The key-exchange group: `Group::X25519_MLKEM768`, a post-quantum hybrid, or `Group::X25519` |
| `protocol` | The ALPN name that the server selected, or `None` |
| `handshake` | `Handshake::Full`, `Retried`, or `Resumed` |
| `peer` | `Some(Peer { certificate, authentication })` when the peer showed a certificate that your roots verified, and `None` for a client with no certificate |

`Peer::certificate` is the DER of the end-entity certificate of the peer. `Peer::authentication`
is its key algorithm, which signed the handshake: `Authentication::EcdsaP256`, `EcdsaP384`,
`Ed25519`, or `Rsa`. Each of them is a classical signature. Post-quantum key exchange and
post-quantum authentication are two guarantees, so a hybrid `group` does not make the
authentication post-quantum.

## Errors

| Cause | `Kind` | Reason |
| --- | --- | --- |
| The TLS handshake did not complete before `handshake_timeout`, from the first call | `Deadline` | `the TLS handshake did not complete before its deadline` |
| A write when the queue is full | `Overload` | `the output queue of the stream is full` |
| A write after `close` | `Misuse` | `the stream is closed` |
| A time on another clock | `Misuse` | `the time is not on the clock of the stream` |

After the handshake deadline, `release()` gives the error at once, and `outstanding()` reports the
output that did not go. The errors of TLS come through unchanged, for example a trust failure:
see [TLS](tls.md#errors). No error shows the bytes of the stream or the text of the peer.
