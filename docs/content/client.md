# Send HTTP/1.1 requests with a deadline

`rsnetwork::client::Http1` is one HTTP/1.1 client connection over TCP or TLS. You send a request
with one deadline, read the response head, and read the body. The deadline covers the TLS
handshake, the head, and each byte of the body. Each read drives the connection, so the body is
the only object that you call while it arrives.

rsnetwork is in development and has no release. `Http1` does no I/O. A binding, or your own event
loop, moves the bytes of the socket: see [drive a connection from your own event loop](caller-driven.md).
The engine under it, `h1::Client`, is on the [HTTP/1.1 page](http1.md#send-requests): use it when
you drive the queues yourself.

## Prerequisites

- A host that moves bytes between the socket and the client, and reads a monotonic clock.
- `client::Limits`: the limits of the response head and body (see [HTTP/1.1](http1.md#limits)),
  the turn limits, and the size of each queue. `head.head_bytes` is also the size of the region of
  each request head.
- A budget for each part of the connection: see [limits](limits.md).
- Over TLS: a `tls::ClientConfig` and `tls::Limits`, as on the [TLS page](tls.md). The server must
  select ALPN `http/1.1` or no protocol.

## Make the client

```rust
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::capacity::Budget;
use rsnetwork::client::{Http1, Limits};
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::time::{ClockDomain, Suspend};
use rsnetwork::tls::{ClientConfig, Limits as TlsLimits};

fn client(config: &ClientConfig) -> Result<Http1, Box<dyn std::error::Error>> {
    let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
    let limits = Limits {
        head: h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 },
        body: BodyLimits {
            body_bytes: 1 << 20,
            drain_bytes: 64 * 1024,
            extension_bytes: 256,
            trailer_bytes: 4 * 1024,
            trailer_fields: 16,
        },
        turn,
        queue: NonZeroUsize::new(16).expect("not zero"),
    };
    let tls = TlsLimits { input_bytes: 32 * 1024, key_records_max: u64::MAX, turn };
    let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
    // The clock of the host: each deadline and each `now` is on it.
    let clock = ClockDomain::new(1, Suspend::Pauses);
    Ok(Http1::tls(config, "example.com", (limits, tls), clock, &budget)?)
}
```

`Http1::plain(limits, clock, &budget)` makes a client over TCP. Each constructor refuses with
`Kind::Overload`, and allocates nothing, when the budget cannot pay.

## Send a request and read its body

Each call of the exchange takes the time `now`. When a call has nothing to give yet, it gives
`false`, `None`, or `Read::Wait`. Then wait as `client.wait()` says, move the bytes, and call
again. This function sends one GET and copies the body into `region`. `host` is your loop: it
waits, moves the bytes of the socket with `received` and `output`, and gives the time.

```rust
use rsnetwork::body::{Outcome, Read};
use rsnetwork::buffer::WriteLoan;
use rsnetwork::client::{Http1, Request};
use rsnetwork::h1::Framing;
use rsnetwork::time::{Deadline, Instant};
use rsnetwork::value::{Authority, Method, Status, Target};

fn get(
    client: &mut Http1,
    deadline: Deadline,
    region: &mut WriteLoan<Vec<u8>>,
    mut host: impl FnMut(&mut Http1) -> Instant,
) -> Result<Status, Box<dyn std::error::Error>> {
    let request = Request {
        method: Method::GET,
        target: Target::new(b"/notes")?,
        authority: Authority::new(b"example.com")?,
        fields: &[],
        body: Framing::Length(0),
    };
    let mut now = host(client);
    while !client.send(&request, deadline, now)? {
        now = host(client);
    }
    let head = loop {
        if let Some(head) = client.response(now)? {
            break head;
        }
        now = host(client);
    };
    loop {
        match client.read_into(now, region)? {
            Read::Bytes(_) => {}
            Read::Wait => now = host(client),
            Read::Full => return Err("the body is larger than the region".into()),
            Read::Done(Outcome::Complete(_trailers)) => return Ok(head.head().status()),
            Read::Done(outcome) => return Err(format!("the body ended as {outcome:?}").into()),
        }
    }
}
```

The body is complete only at `Read::Done(Outcome::Complete(trailers))`: after its last byte and
its trailers. Each other outcome leaves a part, for example `Outcome::Truncated`.

## The calls

| Call | Result |
| --- | --- |
| `send(&request, deadline, now)` | `true`: the request went out. `false`: the connection cannot take it yet, for example while it drains a body before it. A request with `Framing::Length(0)` is complete at once |
| `write(&data, now)`, `finish(now)` | The request body, with no copy, and its end, for `Framing::Length(n)` or `Framing::Chunked`. A full output queue refuses with `Kind::Overload`: send the output first |
| `response(now)` | The response head, or `None` before it. An informational (1xx) response does not count |
| `read_into(now, &mut region)` | Copies the next body bytes into the free capacity of the region, or gives `Read::Done(outcome)` after the last byte |
| `next(now)` | `body::Part::Data(view)`: the next body bytes as a view of the received region, with no copy. `Part::End(outcome)` at the end |
| `collect(now, &mut region)` | Collects the whole body into one region, whose free capacity bounds it: `Collect::Complete(trailers)`, `Collect::TooLarge`, or `Collect::More` while bytes are still to come |
| `delivered()` | The body bytes that the client gave so far |
| `cancel()` | Leaves the rest of the body unread (see [reuse](#reuse-a-connection)) |
| `close(now)` | Ends the connection. Over TLS it sends `close_notify`. Send the rest of the output, and then `release()` |
| `wait()` | When to call again: now, when the transport gives what the connection waits for, at the deadline of the exchange, or never after the end |
| `received`, `receive`, `region`, `output`, `ack`, `end_input`, `reset`, `release` | The transport calls, as on a [host connection](caller-driven.md). Call `reset` when the transport fails: a body that did not end then ends `Outcome::Reset(None)` |

## The deadline

One deadline covers the operation: the TLS handshake, the response head, and each byte of the
body until the body ends. `wait()` includes it, so your host wakes at the deadline also when no
byte arrives. At the deadline, the call fails with `Kind::Deadline`:

- `the deadline came before the response head`: no head arrived.
- `the deadline came before the end of the response`: the head arrived, and `delivered()` gives
  the bytes of the body that arrived before the deadline.

The exchange cannot complete, so the connection ends. Send the rest of the output, and make a new
client for the next request. A deadline that passed before the request went out on a clean
connection refuses the request, and the connection stays.

## Reuse a connection

The connection carries the next request only when HTTP/1.1 lets it persist: after a complete body,
with no `Connection: close` and no body that the close delimits. A body that you leave unread, with
`cancel()` or with the next `send`, drains: the connection discards the rest, up to
`drain_bytes`, and then sends the next request. When the rest is longer, or ends only with the
close, the connection closes, and the next `send` refuses. A connection with bytes of an old
response never carries a request.

## Over TLS

- The ClientHello is ready when you make the client. The handshake runs in the calls of the first
  exchange, under its deadline.
- `negotiated()` gives the group, the ALPN name, the kind of handshake, and the certificate and key
  algorithm of the server, after the handshake completed: see [negotiated facts](tls.md#negotiated-facts).
- A body that the close delimits is complete only after the `close_notify` of the server. When the
  transport ends without it, the body ends `Outcome::Truncated`, because its end is not proven.

## Errors

| Cause | `Kind` | Reason |
| --- | --- | --- |
| The deadline came before the head, or before the end of the body | `Deadline` | See [the deadline](#the-deadline) |
| A request while the response before has no head yet | `Misuse` | `the response of the request before has no head yet` |
| A read before the head, or with no body in flight | `Misuse` | `read the response head first`, or `no response body waits` |
| A request after the connection ended | `Misuse` | `the connection ended: make a new client` |
| A time or a deadline on another clock | `Misuse` | `the time is not on the clock of the client`, or `the deadline is not on the clock of the client` |
| The server selected a protocol other than HTTP/1.1 over TLS | `Unsupported` | `the server selected a protocol other than HTTP/1.1` |
| The server switched protocols (101, or a 2xx answer to CONNECT) | `Unsupported` | `the client does not switch protocols` |
| The connection closed before the response head | `Uncertain` | `the connection closed before the response`: the server may have processed the request |

The errors of the engine and of TLS come through unchanged: see [HTTP/1.1](http1.md#errors) and
[TLS](tls.md#errors). No error shows a body or the text of the peer.
