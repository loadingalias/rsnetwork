# Serve HTTP/1.1 requests and track their delivery

`rsnetwork::server::Http1` is one HTTP/1.1 server connection over TCP or TLS. Your handler takes
a request, reads its body, and sends a response. The server then tells how much of the response
the transport accepted, so a finished response and a delivered response are two different
results. A shutdown refuses new work, drains the exchange in flight, and closes the connection
without discarding a response that the client has not read yet.

rsnetwork is in development and has no release. `Http1` does no I/O. A binding, or your own event
loop, moves the bytes of the socket: see [drive a connection from your own event loop](caller-driven.md).
The engine under it, `h1::Server`, is on the [HTTP/1.1 page](http1.md#serve-requests): use it when
you drive the queues yourself.

## Prerequisites

- A host that moves bytes between the socket and the server, and reads a monotonic clock.
- `server::Limits`: the limits of the request head and body (see [HTTP/1.1](http1.md#limits)), the
  turn limits, the size of each queue, the head timeout, and the [linger](#linger). `head.head_bytes`
  is also the size of the region of each response head.
- A budget for each part of the connection: see [limits](limits.md).
- Over TLS: a `tls::ServerConfig` and `tls::Limits`, as on the [TLS page](tls.md). The client must
  select ALPN `http/1.1` or no protocol.

## Make the server

```rust
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rsnetwork::capacity::Budget;
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::server::{Http1, Limits, Linger};
use rsnetwork::time::{ClockDomain, Suspend};
use rsnetwork::tls::{Limits as TlsLimits, ServerConfig};

fn server(config: &ServerConfig) -> Result<Http1, Box<dyn std::error::Error>> {
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
        // 30 seconds for the TLS handshake, and 30 seconds for each request head.
        head_timeout: Some(h1::HEAD_TIMEOUT),
        // After the last output: at most 5 seconds, and at most 64 KiB.
        linger: Linger { time: Duration::from_secs(5), bytes: 64 * 1024 },
    };
    let tls = TlsLimits { input_bytes: 32 * 1024, key_records_max: u64::MAX, turn };
    let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
    // The clock of the host: each deadline and each `now` is on it.
    let clock = ClockDomain::new(1, Suspend::Pauses);
    Ok(Http1::tls(config, (limits, tls), clock, &budget)?)
}
```

`Http1::plain(limits, clock, &budget)` makes a server over TCP. Each constructor refuses with
`Kind::Overload`, and allocates nothing, when the budget cannot pay.

## Serve requests

The calls of the exchange are the handler interface. Each call takes the time `now`. When a call
has nothing to give yet, it gives `false`, `None`, `Read::Wait`, or `Collect::More`. Then wait as
`server.wait()` says, move the bytes, and call again. This function answers each request with the
bytes of its body, until the connection ends. `host` is your loop: it waits, moves the bytes of
the socket, for example with [`host::Tcp`](caller-driven.md#bind-a-tcp-socket), and gives the
time.

```rust
use rsnetwork::body::Collect;
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::h1::Framing;
use rsnetwork::host::Io as _;
use rsnetwork::server::{Closed, Http1, Response};
use rsnetwork::time::Instant;
use rsnetwork::value::Status;

fn echo(
    server: &mut Http1,
    mut host: impl FnMut(&mut Http1) -> Instant,
) -> Result<Closed, Box<dyn std::error::Error>> {
    let mut now = host(server);
    loop {
        if let Some(closed) = server.release() {
            return Ok(closed);
        }
        // `request` also drives the connection while no exchange is in flight.
        let Some(_head) = server.request(now)? else {
            now = host(server);
            continue;
        };
        let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(4096)));
        let complete = loop {
            match server.collect(now, &mut region)? {
                Collect::More => now = host(server),
                Collect::Complete(_trailers) => break true,
                Collect::TooLarge { .. } | Collect::Interrupted(_) => break false,
            }
        };
        let body = Lease::from(region.into_inner());
        let response = if complete {
            Response { status: Status::new(200)?, fields: &[], body: Framing::Length(body.initialized() as u64) }
        } else {
            Response { status: Status::new(413)?, fields: &[], body: Framing::Length(0) }
        };
        while !server.respond(&response, now)? {
            now = host(server);
        }
        if complete {
            server.write(&body, now)?;
            server.finish(now)?;
        }
        // The handler is complete. `server.delivery()` tracks the response from here.
    }
}
```

A response with `Framing::Length(0)` is finished at `respond`. The next request comes after the
transport accepted each byte of the response before it.

## The calls

| Call | Result |
| --- | --- |
| `request(now)` | The next request head, or `None` when none is ready. It drives the connection while no exchange is in flight, also during a close. It refuses while the response of the request before is not finished |
| `read_into(now, &mut region)` | Copies the next bytes of the request body into the free capacity of the region, or gives `Read::Done(outcome)` after the last byte |
| `next(now)` | `body::Part::Data(view)`: the next body bytes as a view of the received region, with no copy. `Part::End(outcome)` at the end |
| `collect(now, &mut region)` | Collects the whole body into one region, whose free capacity bounds it: `Collect::Complete(trailers)`, `Collect::TooLarge`, `Collect::Interrupted(outcome)`, or `Collect::More` while bytes are still to come |
| `respond(&response, now)` | `true`: the response head went out. `false`: the transport still holds the regions of the heads before |
| `write(&data, now)`, `finish(now)` | The response body, with no copy, and its end. A full output queue makes the call drive the connection one time: over TLS, only a drive seals the plaintext that waits. When the queue is still full, the call refuses with `Kind::Overload`: send the output, and call again |
| `finish_with_trailers(&fields, now)` | Ends a chunked body with trailers. `false` as for `respond` |
| `cancel()` | Ends the exchange in flight. The client sees an incomplete response, and the connection ends with `Kind::Cancelled` |
| `delivery()` | How much of the last response the transport accepted: see [delivery](#delivery) |
| `shutdown(deadline, now)` | Closes the connection: see [close](#close) |
| `negotiated()` | Over TLS, the group, the ALPN name, the kind of handshake, and the client certificate when the client showed one, after the handshake completed: see [negotiated facts](tls.md#negotiated-facts) |
| `wait()` | When to call again: now, when the transport gives what the connection waits for, at a deadline, during the linger, or never after the end |
| `reset()` | The transport failed: see [reset](#reset) |
| `release()` | The end of the connection when it can drop, as `Closed`, and `None` before it |
| `received`, `receive`, `region`, `output`, `ack`, `end_input`, `outstanding` | The transport calls, as on a [host connection](caller-driven.md) |

The first body read accepts the body. A request that waits for `100 Continue` gets it then. When
you respond and do not read the body, the server reads and discards it, up to `drain_bytes`, or
the connection closes after the response.

## Delivery

A finished response is not a delivered one: the bytes can still wait in the socket buffer, and the
client can reset the connection. `delivery()` names one event, "the transport accepted the bytes",
for example a socket write that took them. It is not a proof that the client read them.

| `Delivery` | Meaning |
| --- | --- |
| `Sending { finished, accepted }` | The transport has not accepted each byte of the response yet. `finished` tells whether your handler finished it |
| `Complete { accepted }` | Your handler finished the response, and the transport accepted each of its bytes |
| `Partial { finished, accepted, error }` | The response ended before the transport accepted each of its bytes, for the cause `error`. With `finished` true, the handler completed, and the delivery did not |

`accepted` counts body bytes, never the head or the chunk framing. Over TCP the count is exact.
Over TLS a record counts when the transport accepted each of its bytes, so the count is in whole
records of at most 16 KiB. When the key changes inside one write, which is rare, the bytes of that
write count when its last record went.

## Close

`shutdown(deadline, now)` closes the connection in four steps, and each one is its own event:

1. **Refuse new work.** The server takes no new request. A request that arrived and that your
   handler did not see gets `503` with `connection: close`. The client can send it again, because
   no handler ran for it. Bytes of a request after it stay unread.
2. **Drain the exchange in flight.** Your handler goes on. Its response gets `connection: close`
   when its head is not out yet.
3. **Close the protocol.** Over TLS, the server sends `close_notify`. Then the [linger](#linger)
   half-closes the transport.
4. **Release.** `release()` gives `Closed` when the transport accepted each output and the linger
   ended.

At `deadline`, the server ends whatever remains: the exchange in flight is cancelled, and
`release()` gives `Closed` at once, with `cleanup` as `Kind::Deadline`. `outstanding()` then
reports the output that did not go: drop it with the connection.

The server also closes by itself, for example after a request with `connection: close`, after an
error response, or after a response that leaves too much of the request body unread. The same
steps 3 and 4 follow.

### Linger

When a server closes a TCP connection while bytes of the client are still unread, the operating
system can send a reset, and the client can then lose a response that it has not read. So after
the last output, `wait()` gives `Wait::Linger { deadline }`:

1. Half-close the transport once, for example with `shutdown(Shutdown::Write)` on a socket.
2. Give each byte that still arrives, as before. The server reads and discards it.
3. Call `request(now)` at the deadline.

The linger ends at the end of input, at `linger.time`, or when it discarded more than
`linger.bytes`. A zero `time` turns it off. For reference, nginx lingers for at most 30 seconds in
total (`lingering_time`), and for at most 5 seconds with no byte (`lingering_timeout`).

### The report

`Closed { result, cleanup }` keeps the first failure of the connection as `result`. A failure of
the drain or of the close comes after it as `cleanup`, and never replaces it. For example, a
request with a malformed field gets 400, and the client reads nothing before the shutdown
deadline: `result` is `Kind::Malformed`, and `cleanup` is `Kind::Deadline`.

## Reset

Call `reset()` when the socket reports a reset, or a write fails: no byte comes or goes after it.

- A response that the transport has not accepted becomes `Delivery::Partial`, with `Kind::Partial`.
- `release()` gives `Closed` at once, with no linger. `outstanding()` reports the output that did
  not go.
- Your handler can still read the request bytes that arrived, and then the outcome of the body.
  A body that did not end is `Outcome::Reset(None)`, never `Truncated` or complete. Each response
  call then refuses.

## Over TLS

- The head timeout also bounds the TLS handshake, from the first call of `request`. A client that
  never completes the handshake ends the connection with `Kind::Deadline`.
- `negotiated()` gives what the handshake negotiated.
- The response of a shutdown ends with `close_notify` before the half-close, so the client can
  tell a complete close from a cut connection.

## Errors

| Cause | `Kind` | Reason |
| --- | --- | --- |
| A request while the response of the request before is not finished | `Misuse` | `the response of the request before is not finished` |
| A response, or a read of the body, with no request in flight | `Misuse` | `no request waits for a response`, or `no request body waits` |
| A body write before `respond` | `Misuse` | `respond first` |
| A second response to one request | `Misuse` | `the request in flight has its response` |
| A 101 response, or a 2xx response to CONNECT | `Unsupported` | `the server does not change the protocol` |
| A time or a deadline on another clock | `Misuse` | `the time is not on the clock of the server`, or `the deadline is not on the clock of the server` |
| The TLS handshake did not complete before the head timeout | `Deadline` | `the TLS handshake did not complete before its deadline` |
| The client selected a protocol other than HTTP/1.1 over TLS | `Unsupported` | `ALPN selected a protocol other than HTTP/1.1` |
| The shutdown deadline came first | `Deadline`, in `cleanup` | `the shutdown deadline came before the connection closed` |
| The transport failed | `Partial` | `the transport failed before the connection closed` |
| Your handler cancelled the response | `Cancelled` | `the application cancelled the response` |

The errors of the engine and of TLS come through unchanged: see [HTTP/1.1](http1.md#errors) and
[TLS](tls.md#errors). No error shows a body or the text of the peer.
