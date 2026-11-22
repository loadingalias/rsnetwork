# Serve HTTP/1.1 and HTTP/2 requests and track their delivery

`rsnetwork::server::Http` is one server connection over TCP or TLS, for HTTP/1.1 and HTTP/2. Your
handler takes a request on a stream, reads its body, and sends a response. The server then tells
how much of the response the transport accepted, so a finished response and a delivered response
are two different results. A shutdown refuses new work, drains the streams in flight, and closes
the connection without discarding a response that the client has not read yet.

The handler code is the same for each version. Over TLS, ALPN selects the version. Over TCP,
`Limits::cleartext` selects it. HTTP/2 carries many streams at a time, and HTTP/1.1 carries one.

rsnetwork is in development and has no release. `Http` does no I/O. A binding, or your own event
loop, moves the bytes of the socket: see [drive a connection from your own event loop](caller-driven.md).
The engines under it are `h1::Server`, on the [HTTP/1.1 page](http1.md#serve-requests), and
`h2::Connection`, on the [HTTP/2 page](http2.md): use them when you drive the queues yourself.

## Prerequisites

- A host that moves bytes between the socket and the server, and reads a monotonic clock.
- `server::Limits`:
  - `head`: the limits of an HTTP/1.1 request head (see [HTTP/1.1](http1.md#limits)).
    `head.head_bytes` is also the size of the region of each response head and trailer section,
    in each version.
  - `h2`: the settings and windows of an HTTP/2 connection (see [HTTP/2](http2.md#settings)).
  - `body`: the request body. `body_bytes` applies to each version. The drain, extension, and
    trailer limits are for HTTP/1.1.
  - `turn`, `queue`, `head_timeout`, and the [linger](#linger).
  - `cleartext`: the version of a connection over TCP, `Cleartext::Http1` or `Cleartext::Http2`.
- A budget for each part of the connection: see [limits](limits.md).
- Over TLS: a `tls::ServerConfig` and `tls::Limits`, as on the [TLS page](tls.md). List `h2` in
  the protocols of the configuration to serve HTTP/2, and `http/1.1` to serve HTTP/1.1.

## Make the server

```rust
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rsnetwork::capacity::Budget;
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::server::{Cleartext, Http, Limits, Linger};
use rsnetwork::time::{ClockDomain, Suspend};
use rsnetwork::tls::{Limits as TlsLimits, ServerConfig};

fn server(config: &ServerConfig) -> Result<Http, Box<dyn std::error::Error>> {
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
        // 30 seconds for the TLS handshake, and 30 seconds for each request head.
        head_timeout: Some(h1::HEAD_TIMEOUT),
        // After the last output: at most 5 seconds, and at most 64 KiB.
        linger: Linger { time: Duration::from_secs(5), bytes: 64 * 1024 },
        cleartext: Cleartext::Http1,
    };
    let tls = TlsLimits { input_bytes: 32 * 1024, key_records_max: u64::MAX, turn };
    let budget = Budget::new(NonZeroU64::new(1 << 22).expect("not zero"));
    // The clock of the host: each deadline and each `now` is on it.
    let clock = ClockDomain::new(1, Suspend::Pauses);
    Ok(Http::tls(config, (limits, tls), clock, &budget)?)
}
```

`Http::plain(limits, clock, &budget)` makes a server over TCP, of the version of
`limits.cleartext`. `Cleartext::Http2` takes HTTP/2 with prior knowledge (RFC 9113, section 3.3):
the client sends the HTTP/2 preface first. HTTP/2 has no upgrade from HTTP/1.1. Each constructor
refuses with `Kind::Overload`, and allocates nothing, when the budget cannot pay. Over TLS, the
server charges the engine of the selected version after the handshake.

## Serve requests

The calls of the exchange are the handler interface. Each call takes the time `now`, and each
call of an exchange names its `Stream`. When a call has nothing to give yet, it gives `false`,
`None`, `Read::Wait`, or `Collect::More`. Then wait as `server.wait()` says, move the bytes, and
call again. This function answers each request with the bytes of its body, one at a time, until
the connection ends. `host` is your loop: it waits, moves the bytes of the socket, for example with
[`host::Tcp`](caller-driven.md#bind-a-tcp-socket), and gives the time. On Tokio, each call awaits
instead, and a `Server` runs a handler for each request: see [run the engines on Tokio](tokio.md).

```rust
use rsnetwork::body::Collect;
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::host::Io as _;
use rsnetwork::server::{Closed, Http, Response};
use rsnetwork::time::Instant;
use rsnetwork::value::Status;

fn echo(
    server: &mut Http,
    mut host: impl FnMut(&mut Http) -> Instant,
) -> Result<Closed, Box<dyn std::error::Error>> {
    let mut now = host(server);
    loop {
        if let Some(closed) = server.release() {
            return Ok(closed);
        }
        // `request` also drives the connection while no exchange is in flight.
        let Some((stream, _head)) = server.request(now)? else {
            now = host(server);
            continue;
        };
        let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(4096)));
        let complete = loop {
            match server.collect(stream, now, &mut region)? {
                Collect::More => now = host(server),
                Collect::Complete(_trailers) => break true,
                Collect::TooLarge { .. } | Collect::Interrupted(_) => break false,
            }
        };
        let body = Lease::from(region.into_inner());
        let response = if complete {
            Response { status: Status::new(200)?, fields: &[], length: Some(body.initialized() as u64) }
        } else {
            Response { status: Status::new(413)?, fields: &[], length: Some(0) }
        };
        while !server.respond(stream, &response, now)? {
            now = host(server);
        }
        if complete && body.initialized() > 0 {
            server.write(stream, &body, now)?;
            server.finish(stream, now)?;
        }
        // The response is finished. `server.delivery(stream)` tracks it from here, until the close.
        server.close(stream);
    }
}
```

A response with the length `Some(0)` is finished at `respond`. A response of unknown length,
`None`, goes in chunks on HTTP/1.1, to an HTTP/1.0 client until the close, and on HTTP/2 until the
end of its stream.

## Streams

Each request has its own `Stream`. The stream keeps its place from its request until you
[close](#the-calls) it. Close each stream when its handler ends.

- **HTTP/2** carries at most `h2.settings.max_concurrent_streams` streams at a time, open or not
  closed yet. `request` gives each new request at once, so one handler can serve many streams, and
  a slow stream holds back only itself. At the limit, the server reads no new request until you
  close a stream: `wait()` gives `Blocked::Streams`.
- **HTTP/1.1** carries one stream at a time. The next request comes after you closed the stream
  before it and the transport accepted each byte of its response.

`stream.id()` is the HTTP/2 stream identifier, or the count of the HTTP/1.1 exchange.

## The calls

| Call | Result |
| --- | --- |
| `request(now)` | The next request head and its stream, or `None` when none is ready. It drives the connection, also during a close |
| `read_into(stream, now, &mut region)` | Copies the next bytes of the request body into the free capacity of the region, or gives `Read::Done(outcome)` after the last byte |
| `next(stream, now)` | `body::Part::Data(view)`: the next body bytes as a view of the received region, with no copy. `Part::End(outcome)` at the end |
| `collect(stream, now, &mut region)` | Collects the whole body into one region, whose free capacity bounds it: `Collect::Complete(trailers)`, `Collect::TooLarge`, `Collect::Interrupted(outcome)`, or `Collect::More` while bytes are still to come |
| `respond(stream, &response, now)` | `true`: the response head went out. `false`: the transport still holds the regions of the heads before |
| `write(stream, &data, now)`, `finish(stream, now)` | The response body, with no copy, and its end. A call that finds no room drives the connection one time: over TLS, only a drive seals the plaintext that waits. When there is still no room, the call refuses with `Kind::Overload`: send the output, and call again |
| `finish_with_trailers(stream, &fields, now)` | Ends the body with a trailer section. `false` as for `respond`. On HTTP/1.1, only a body of unknown length, in chunks, has trailers |
| `cancel(stream)` | Ends the exchange: see [cancel](#cancel) |
| `close(stream)` | Ends the handler of the stream, and frees its place. A response that is not finished is cancelled |
| `delivery(stream)` | How much of the response the transport accepted: see [delivery](#delivery) |
| `shutdown(deadline, now)` | Closes the connection: see [close](#close) |
| `negotiated()` | Over TLS, the group, the ALPN name, the kind of handshake, and the client certificate when the client showed one, after the handshake completed: see [negotiated facts](tls.md#negotiated-facts) |
| `export(label, context, &mut output)` | Over TLS, keying material from the regular exporter of the connection: see [bind a proof to a TLS connection](exporter.md). Over TCP, `ExportError::Unavailable` |
| `changed(each)` | Gives `each` each stream whose exchange changed since the last call: a part or the end of its request body, its last chunk went to the output, it ended, or its request is new. A binding that shares the connection among handles wakes only their handles. The end of the connection changes each stream |
| `wait()` | When to call again: now, when the transport gives what the connection waits for, at a deadline, during the linger, or never after the end |
| `reset()` | The transport failed: see [reset](#reset) |
| `release()` | The end of the connection when it can drop, as `Closed`, and `None` before it |
| `received`, `receive`, `region`, `output`, `ack`, `end_input`, `outstanding` | The transport calls, as on a [host connection](caller-driven.md) |

The request head is a `message::RequestHead`: see [message heads](#message-heads). On HTTP/1.1,
the first body read accepts the body: a request that waits for `100 Continue` gets it then. When
you respond and do not read the body, the server reads and discards it, up to `drain_bytes`, or
the connection closes after the response. On HTTP/2, a stream whose handler you close before the
end of its request body gets `RST_STREAM` with `NO_ERROR` after the response (RFC 9113, section
8.1), and no body drains.

## Message heads

`message::RequestHead` has one meaning in each version:

| Call | HTTP/1.1 | HTTP/2 |
| --- | --- | --- |
| `method()` | The method of the request line | `:method` |
| `target()` | The request target, in its exact bytes | `:path`, or the `:authority` of CONNECT |
| `authority()` | The authority of the target, or the Host field | `:authority`, or the Host field |
| `scheme()` | The scheme of an absolute-form target | `:scheme` |
| `fields()` | The field lines, in order, in their case | The fields, in order, in lowercase. The pseudo-header fields are not fields |
| `length()` | `Some(n)` for a Content-Length, `None` for chunks | `Some(n)` for a `content-length`, `None` with no length |
| `version()` | `Version::Http10` or `Version::Http11` | `Version::Http2` |
| `h1()` | The HTTP/1.1 head, with its facts: persistence, `100 Continue`, upgrade | `None` |

The HTTP/1.1 head is a view of the received bytes, with no copy. The HTTP/2 head copies the
decoded lines into a charged region of their exact size, so its memory follows the size of the
head. `message::ResponseHead` is the head of a response at the [client](client.md).

## Delivery

A finished response is not a delivered one: the bytes can still wait in the socket buffer, and the
client can reset the connection or the stream. `delivery(stream)` names one event, "the transport
accepted the bytes", for example a socket write that took them. It is not a proof that the client
read them.

| `Delivery` | Meaning |
| --- | --- |
| `Sending { finished, accepted }` | The transport has not accepted each byte of the response yet. `finished` tells whether your handler finished it |
| `Complete { accepted }` | Your handler finished the response, and the transport accepted each of its bytes |
| `Partial { finished, accepted, error }` | The response ended before the transport accepted each of its bytes, for the cause `error`. With `finished` true, the handler completed, and the delivery did not |

`accepted` counts body bytes, never the head, the chunk framing, or the frame headers of HTTP/2.
Over TCP the count is exact. Over TLS a record counts when the transport accepted each of its
bytes, so the count is in whole records of at most 16 KiB. When the key changes inside one write,
which is rare, the bytes of that write count when its last record went.

On HTTP/1.1, `delivery` gives the delivery of the last exchange until the next request. On
HTTP/2, it gives the delivery of the stream until you close it, and then `None`. A client that
resets the stream makes the delivery `Partial` with `Kind::Partial`.

## Cancel

`cancel(stream)` ends one exchange, so the client sees an incomplete response, never a complete
one.

- **HTTP/2.** The stream resets with `RST_STREAM` and `CANCEL`, and the connection goes on with its
  other streams. The client reads the body as `Outcome::Reset`.
- **HTTP/1.1.** Only the close of the connection can end a response before its end. So the
  connection closes after the bytes that it queued, and it ends with `Kind::Cancelled`.

## Close

`shutdown(deadline, now)` closes the connection in four steps, and each one is its own event:

1. **Refuse new work.** The server takes no new request, and the client learns which requests it
   did not process. The client can send each of these requests again, also a POST, because no
   handler ran for it.
   - On HTTP/1.1, the response in flight gets `connection: close` when its head is not out yet: a
     server that sends `close` processes no later request (RFC 9112, section 9.6). Else the next
     request whose head arrived whole gets `503` with `connection: close`, also when the server
     did not read its bytes yet. Bytes of a request after it, and a part of a head, stay unread.
   - On HTTP/2, the server sends GOAWAY with the last stream 2^31 - 1 and a PING. At the answer of
     the PING, it sends GOAWAY with the last stream that went up (RFC 9113, section 6.8). A request
     that came before that and that your handler did not see gets `RST_STREAM` with
     `REFUSED_STREAM`.
2. **Drain the streams in flight.** Your handlers go on. The server does not reset a stream that
   your handler has.
3. **Close the protocol.** Over TLS, the server sends `close_notify`. Then the [linger](#linger)
   half-closes the transport.
4. **Release.** `release()` gives `Closed` when the transport accepted each output and the linger
   ended.

At `deadline`, the server ends whatever remains: each exchange in flight is cancelled, and
`release()` gives `Closed` at once, with `cleanup` as `Kind::Deadline`. `outstanding()` then
reports the output that did not go: drop it with the connection.

The server also closes by itself. On HTTP/1.1, for example after a request with
`connection: close`, after an error response, or after a response that leaves too much of the
request body unread. On HTTP/2, after the GOAWAY of the client, when the streams drained, and
after `head_timeout` with no stream, with GOAWAY. The same steps 3 and 4 follow.

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

- Each response that the transport has not accepted becomes `Delivery::Partial`, with
  `Kind::Partial`.
- `release()` gives `Closed` at once, with no linger. `outstanding()` reports the output that did
  not go.
- Your handler can still read the request bytes that arrived, and then the outcome of each body.
  A body that did not end is `Outcome::Reset(None)`, never `Truncated` or complete. Each response
  call then refuses.

## HTTP/2 messages

The server checks each request section as RFC 9113, section 8, says. A request that breaks a rule
never goes to your handler:

| Request | Answer |
| --- | --- |
| A field name with an uppercase letter or that is not a token, a value that is not a field value, a pseudo-header field after a field or unknown, repeated, or of a response, a missing `:method`, `:scheme`, `:path`, or authority, a CONNECT with `:scheme` or `:path`, a Host that names another authority, a connection-specific field, `te` other than `trailers`, or a `content-length` that is not one number | `RST_STREAM` with `PROTOCOL_ERROR` |
| A header list larger than `h2.settings.max_header_list_size` | `431`, with no body |
| A `content-length` larger than `body.body_bytes` | `413`, with no body |
| A request that the budget cannot copy | `RST_STREAM` with `REFUSED_STREAM`: the client can send it again |

Each answer ends only its stream, and the connection goes on. A body whose DATA does not match
its `content-length` ends `Outcome::Malformed`, and its stream resets with `PROTOCOL_ERROR`. A
body of unknown length past `body_bytes` ends `Outcome::Malformed`, and its stream resets with
`CANCEL`.

The response fields follow the same rules: `respond` refuses a connection-specific field, `te`
other than `trailers`, `host`, and `content-length` with `Kind::Misuse`. The server writes
`content-length` from the length, and sends each field name in lowercase. A response to HEAD, and
a 204 or 304 response, ends its stream at the head.

## Over TLS

- ALPN selects the version after the handshake: `h2` for HTTP/2, and `http/1.1` or no protocol
  for HTTP/1.1. A client that selects another protocol ends the connection with
  `Kind::Unsupported`.
- The head timeout also bounds the TLS handshake, from the first call of `request`. A client that
  never completes the handshake ends the connection with `Kind::Deadline`.
- `negotiated()` gives what the handshake negotiated.
- The response of a shutdown ends with `close_notify` before the half-close, so the client can
  tell a complete close from a cut connection.

## Errors

| Cause | `Kind` | Reason |
| --- | --- | --- |
| A call on a stream that the server does not carry, or that you closed | `Misuse` | `the stream is not open`, or `no request of the stream waits for a response` |
| A read of the body of a stream with no request in flight | `Misuse` | `no request body of the stream waits` |
| A body write before `respond` | `Misuse` | `respond first` |
| A second response to one request | `Misuse` | `the request in flight has its response` |
| A body longer or shorter than its length, on HTTP/2 | `Misuse` | `the body passes the length of the response`, or `the body is shorter than the length of the response` |
| A field that HTTP/2 forbids in a response | `Misuse` | ``HTTP/2 has no connection-specific fields, and `te` can only be `trailers` `` |
| A response head larger than `head.head_bytes`, on HTTP/2 | `Overload` | `the response head is larger than the head region: give a larger head_bytes` |
| A response call after the client reset the stream | `Partial` | `the stream ended before the end of the response` |
| A 101 response, or a 2xx response to CONNECT | `Unsupported` | `the server does not change the protocol` |
| A time or a deadline on another clock | `Misuse` | `the time is not on the clock of the server`, or `the deadline is not on the clock of the server` |
| The TLS handshake did not complete before the head timeout | `Deadline` | `the TLS handshake did not complete before its deadline` |
| The client selected another protocol over TLS | `Unsupported` | `ALPN selected a protocol other than HTTP/1.1 and HTTP/2` |
| The shutdown deadline came first | `Deadline`, in `cleanup` | `the shutdown deadline came before the connection closed` |
| The transport failed | `Partial` | `the transport failed before the connection closed` |
| Your handler cancelled the response | `Cancelled` | `the application cancelled the response` |

The errors of the engines and of TLS come through unchanged: see [HTTP/1.1](http1.md#errors),
[HTTP/2](http2.md), and [TLS](tls.md#errors). No error shows a body or the text of the peer.
