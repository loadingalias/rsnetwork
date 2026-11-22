# Send HTTP/1.1 and HTTP/2 requests with a deadline

`rsnetwork::client::Http1` is one HTTP/1.1 client connection over TCP or TLS, and
`rsnetwork::client::Http2` is one HTTP/2 connection. You send a request with one deadline, read
the response head, and read the body. The deadline covers the TLS handshake, the head, and each
byte of the body. Each read drives the connection, so the body is the only object that you call
while it arrives. Each client gives explicit control of one version, with the same message, body,
deadline, and trust rules. [HTTP/2](#http2) says where `Http2` differs.

rsnetwork is in development and has no release. The clients do no I/O. A binding, or your own event
loop, moves the bytes of the socket: see [drive a connection from your own event loop](caller-driven.md).
The engine under it, `h1::Client`, is on the [HTTP/1.1 page](http1.md#send-requests): use it when
you drive the queues yourself.

## Prerequisites

- A host that moves bytes between the socket and the client, and reads a monotonic clock.
- `client::Limits`: the limits of the HTTP/1.1 response head (see [HTTP/1.1](http1.md#limits)),
  the HTTP/2 connection (see [HTTP/2](http2.md#settings)), the body, the turn limits, and the size
  of each queue. `head.head_bytes` is also the size of the region of each request head, in each
  version.
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
use rsnetwork::h2;
use rsnetwork::time::{ClockDomain, Suspend};
use rsnetwork::tls::{ClientConfig, Limits as TlsLimits};

fn client(config: &ClientConfig) -> Result<Http1, Box<dyn std::error::Error>> {
    let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
    let settings = h2::Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..h2::Settings::INITIAL };
    let limits = Limits {
        head: h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 },
        h2: h2::Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 },
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
    let budget = Budget::new(NonZeroU64::new(1 << 22).expect("not zero"));
    // The clock of the host: each deadline and each `now` is on it.
    let clock = ClockDomain::new(1, Suspend::Pauses);
    Ok(Http1::tls(config, "example.com", (limits, tls), clock, &budget)?)
}
```

`Http1::plain(limits, clock, &budget)` makes a client over TCP. `Http2::plain` and `Http2::tls`
take the same arguments. Each constructor refuses with `Kind::Overload`, and allocates nothing,
when the budget cannot pay.

## Send a request and read its body

Each call of the exchange takes the time `now`. When a call has nothing to give yet, it gives
`false`, `None`, or `Read::Wait`. Then wait as `client.wait()` says, move the bytes, and call
again. This function sends one GET and copies the body into `region`. `host` is your loop: it
waits, moves the bytes of the socket, for example with [`host::Tcp`](caller-driven.md#bind-a-tcp-socket),
and gives the time. On Tokio, each call awaits instead: see [run the engines on Tokio](tokio.md).

```rust
use rsnetwork::body::{Outcome, Read};
use rsnetwork::buffer::WriteLoan;
use rsnetwork::client::{Http1, Request};
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
        length: Some(0),
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
            Read::Done(Outcome::Complete(_trailers)) => return Ok(head.status()),
            Read::Done(outcome) => return Err(format!("the body ended as {outcome:?}").into()),
        }
    }
}
```

The body is complete only at `Read::Done(Outcome::Complete(trailers))`: after its last byte and
its trailers. Each other outcome leaves a part, for example `Outcome::Truncated`. The head is a
`message::ResponseHead`: `status()`, `fields()`, `length()`, `version()`, and `h1()` for the facts
that only HTTP/1.1 has. Its fields are views of the received bytes on HTTP/1.1, and a copy of the
decoded lines of their exact size on HTTP/2.

## The calls

| Call | Result |
| --- | --- |
| `send(&request, deadline, now)` | `true`: the request went out. `false`: the connection cannot take it yet, for example while it drains a body before it. A request with the length `Some(0)` is complete at once |
| `write(&data, now)`, `finish(now)` | The request body, with no copy, and its end, for the length `Some(n)`, or in chunks for `None`. A full output queue makes the call drive the connection one time: over TLS, only a drive seals the plaintext that waits. When the queue is still full, the call refuses with `Kind::Overload`: send the output, and call again |
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

## HTTP/2

`client::Http2` has the calls of `Http1`. It carries many exchanges at a time, so `send` gives the
`Stream` of the request, and each call of the exchange names it:

```rust
use rsnetwork::body::Collect;
use rsnetwork::buffer::WriteLoan;
use rsnetwork::client::{Http2, Request};
use rsnetwork::time::{Deadline, Instant};
use rsnetwork::value::{Authority, Method, Target};

/// Sends two GET requests at once, and collects their bodies.
fn both(
    client: &mut Http2,
    deadline: Deadline,
    mut host: impl FnMut(&mut Http2) -> Instant,
) -> Result<[Vec<u8>; 2], Box<dyn std::error::Error>> {
    let get = |target| -> Result<Request<'static>, Box<dyn std::error::Error>> {
        Ok(Request {
            method: Method::GET,
            target: Target::new(target)?,
            authority: Authority::new(b"example.com")?,
            fields: &[],
            length: Some(0),
        })
    };
    let mut now = host(client);
    let mut streams = Vec::new();
    for request in [get(b"/a")?, get(b"/b")?] {
        let stream = loop {
            if let Some(stream) = client.send(&request, deadline, now)? {
                break stream;
            }
            now = host(client);
        };
        streams.push(stream);
    }
    let mut bodies = [Vec::new(), Vec::new()];
    for (stream, body) in streams.into_iter().zip(&mut bodies) {
        while client.response(stream, now)?.is_none() {
            now = host(client);
        }
        let mut region = WriteLoan::new(Vec::with_capacity(64 * 1024));
        loop {
            match client.collect(stream, now, &mut region)? {
                Collect::More => now = host(client),
                Collect::Complete(_trailers) => break,
                collect => return Err(format!("the body did not complete: {collect:?}").into()),
            }
        }
        *body = region.into_inner();
    }
    Ok(bodies)
}
```

| Rule | `Http2` |
| --- | --- |
| Streams | The connection carries at most the smaller of its own and the server's `SETTINGS_MAX_CONCURRENT_STREAMS`. At the limit, `send` gives `None`: wait, and send again. A stream keeps its place until you `cancel` it, or until its exchange ended, you read the end, and a new request needs the place |
| Deadline | The deadline of a request ends only its stream, with `RST_STREAM` and `CANCEL`. The connection goes on. `delivered(stream)` gives the part that arrived. Then `cancel(stream)` frees its place |
| Cancel | `cancel(stream)` resets the stream with `CANCEL`, and the connection goes on. No body drains |
| Reuse | The connection carries new requests until the server sends GOAWAY or the connection ends. Then `send` refuses with `Kind::Misuse`: make a new client |
| Not processed | A request above the last stream of a GOAWAY, or that the server resets with `REFUSED_STREAM`, ends with `Kind::Overload`: no handler ran for it, so send it again, on a new connection after a GOAWAY |
| Write | Each stream holds one chunk of its body at a time. `write` refuses with `Kind::Overload` while the chunk before waits for the output: send the output, and write again. `finish` never waits: the end goes after the last chunk |
| Idle | `drive(now)` drives the connection when no call of an exchange runs: it answers the SETTINGS and PING of the server, sends the resets of `cancel`, and reads a GOAWAY. Call it each time that `wait()` says while you have no exchange to call, because a server ends a connection whose SETTINGS get no acknowledgement |
| Close | `close(now)` ends each exchange in flight, and sends GOAWAY, and over TLS `close_notify` |
| Fields | A connection-specific field, `te` other than `trailers`, `host`, and `content-length` refuse with `Kind::Misuse`. The client sends `:method`, `:scheme`, `:authority`, and `:path`, and each field name in lowercase. CONNECT refuses with `Kind::Unsupported`: the client opens no tunnel |
| TCP | `Http2::plain` uses prior knowledge (RFC 9113, section 3.3): the server must take HTTP/2 over TCP |
| TLS | List `h2` in the protocols of the configuration. The server must select `h2`: another protocol, also no protocol, ends the client with `Kind::Unsupported` |

The client checks each response section as RFC 9113, section 8, says. A response that breaks a
rule ends its stream with `Kind::Malformed`, and a body whose DATA does not match its
`content-length` ends `Outcome::Malformed`. The other streams go on.

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
| HTTP/2: the server reset the stream before the response head | `Uncertain` | `the server reset the stream before the response` |
| HTTP/2: the server did not process the request | `Overload` | `the server did not process the request: send it again`, or `... send it again on a new connection` after a GOAWAY |
| HTTP/2: a request after the close, after a GOAWAY, or after the end | `Misuse` | `the connection takes no more requests: make a new client` |
| HTTP/2: a malformed response section | `Malformed` | `the server sent a malformed response` |
| HTTP/2: the server did not select `h2` over TLS | `Unsupported` | `the server did not select HTTP/2` |

The errors of the engine and of TLS come through unchanged: see [HTTP/1.1](http1.md#errors) and
[TLS](tls.md#errors). No error shows a body or the text of the peer.
