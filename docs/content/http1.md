# Run HTTP/1.1 connections with no I/O

The `rsnetwork::h1` module runs HTTP/1.1 connections for servers and clients, also with HTTP/1.0
peers. It does no I/O and starts nothing, so any runtime, or your own event loop, can drive it.

rsnetwork is in development and has no release. The buffer, capacity, and time types come from
the runtime family: `rsnetwork::buffer` is the same module as `rsasync::buffer`. The method,
target, authority, field, and status types are the [checked values](values.md).

## The model

`h1::Server` and `h1::Client` are the engines of one connection. They run on the queues of
[the drive interface](drive.md):

1. Your host receives bytes from the transport and pushes each region into an `Inbound` queue.
2. Each `drive` call reads the queued bytes in place and gives one event, or none.
3. The application answers each event with calls that push output into an `Outbound` queue.
4. The host sends each `Output` and acknowledges the bytes that the transport accepted.
5. When the drive gives a terminal turn, the host sends the rest of the `Outbound` queue and
   closes the connection.

Body bytes are views of the received regions, with no copy. The engines allocate nothing after
construction, except for a head or a trailer section that continues in the next received region:
you give the region of each head that you send, and the size line of each chunk comes from a pool
of the engine. When the transport reports that the peer closed its side, call `Inbound::end`.
When the transport fails, for example with a reset, call `Inbound::reset`: a body that did not end
then ends `Outcome::Reset(None)`, never complete.

## Example

A server reads one request and answers it. The code runs in a function that returns
`Result<(), Box<dyn std::error::Error>>`. The module documentation of `rsnetwork::h1` runs the
same example as a test.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::body::Outcome;
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::value::{Field, Status};

let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
let body = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};
let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let queue = NonZeroUsize::new(16).expect("not zero");
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024, visits: 4096 };
let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
let mut server = Server::new(limits, body, turn, &outbound, &budget)?;
// The time of the host, on its monotonic clock. The engine waits 30 seconds for a head.
let now = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

// The transport received a request, and the host queues it.
let endpoint = Endpoint {
    peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
    local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
    ecn: Ecn::NotEct,
    segment: None,
};
let region = Lease::from(b"POST /notes HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec());
inbound.push(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");

// Each drive gives one event: the head, the body bytes, and the end of the body.
let (Some(ServerEvent::Request(request)), _) = server.drive(&mut inbound, &mut outbound, now) else {
    panic!("a request head")
};
assert_eq!(request.head().target().as_bytes(), b"/notes");
let (Some(ServerEvent::Data(data)), _) = server.drive(&mut inbound, &mut outbound, now) else {
    panic!("body bytes")
};
assert_eq!(data.bytes(), b"hello");
let (Some(ServerEvent::End(Outcome::Complete(None))), _) = server.drive(&mut inbound, &mut outbound, now) else {
    panic!("the end of the body")
};

// The answer: its head in a region of the caller, then the body with no copy.
let fields = [Field::new(b"Content-Type", b"text/plain")?];
let head = Backing::from(Vec::with_capacity(256));
server.respond(&mut outbound, Status::new(201)?, &fields, Framing::Length(2), head)?;
server.send(&mut outbound, &Lease::from(b"ok".to_vec()))?;
server.finish(&mut outbound)?;

// The host sends each output and acknowledges the bytes that the transport accepted.
let mut sent = Vec::new();
while let Some(output) = outbound.submit() {
    sent.extend_from_slice(output.region.bytes());
    outbound.ack(output.id, output.region.initialized())?;
}
assert_eq!(sent, b"HTTP/1.1 201 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
```

## Serve requests

For a server over TCP or TLS that tracks the delivery of each response and closes without losing
one, use the [server](server.md). It runs this engine. Use the engine directly when you drive its
queues yourself:

1. Make one `Server` for each connection with `Server::new(limits, body, turn, &outbound, &budget)`.
   It makes its pool of chunk-size lines there, with one 16-byte slot for each `Outbound` entry.
   The budget pays for the pool: see [admission](limits.md#admission).
2. Call `server.drive(&mut inbound, &mut outbound, now)` until it gives no event. Drive again when more
   bytes arrive or after the application answers.
3. For `ServerEvent::Request(head)`, answer with `respond(outbound, status, fields, framing,
   region)`. Then send the body with `send(outbound, &data)`, and end it with `finish(outbound)`
   or `finish_with_trailers(outbound, trailers, region)`. Call `finish` also when the response has
   no body.
4. Read the request body from `ServerEvent::Data(data)` and `ServerEvent::End(outcome)`. Keep the
   views, or copy them into your own regions with a [consumer](body.md).

| Server call | Result |
| --- | --- |
| `respond` | Writes the final response head into your region and queues it. The engine adds the `connection` field that the connection needs |
| `send` | Queues a view of `data` as the next body bytes. A chunked body sends each call as one chunk |
| `finish`, `finish_with_trailers` | Ends the body. A chunked body gets its last chunk, with trailers or with none |
| `accept_body` | Sends `100 Continue` to a request that waits for it, and starts the read of its body |
| `inform` | Sends an informational response with a status from 102 to 199, for example 103 |
| `cancel` | Stops the response with no end of its body. A request body that did not end gets `End(Outcome::Cancelled)`. The connection then ends |
| `shutdown` | Takes no new request, and the application sees none after it. The response in flight gets `connection: close` when its head is not out yet. Else, after the exchange in flight or at once, the next request head that arrived whole gets `503` with `connection: close`, and then the connection ends. A part of a head stays unread. The next drive takes the step |
| `hold_body(hold)` | While `hold` is true, a drive gives no event of the request body, and its bytes wait in the queue. Hold the body while your code cannot take a part of it. A drain goes on |

`send` and `finish` refuse with `Kind::Overload` when the `Outbound` queue or the pool is full,
and change nothing. Acknowledge output, then call again. A call in the wrong state, for example
`send` before `respond`, refuses with `Kind::Misuse`.

## Send requests

For a request with a deadline over TCP or TLS, and body reads that drive the connection, use the
[client](client.md). It runs this engine. Use the engine directly when you drive its queues yourself:

1. Make one `Client` for each connection with `Client::new(limits, body, turn, &outbound, &budget)`.
2. Call `client.request(outbound, method, target, authority, fields, framing, region)`. The engine
   writes `authority` as the Host field, the first field line. Do not give a Host field yourself.
3. Send the body with `send`, and end it with `finish` or `finish_with_trailers`. Call `finish`
   also when the request has no body.
4. Call `client.drive(&mut inbound)` until it gives no event. It gives
   `ClientEvent::Informational(head)` for each 1xx response, then `ClientEvent::Response(head)`,
   `ClientEvent::Data(data)`, and `ClientEvent::End(outcome)`. The [body page](body.md) explains
   the outcomes.
5. Send the next request after the end of the response, also in direct answer to the `End` event.
   The client sends one request at a time.

| Client call | Result |
| --- | --- |
| `cancel_upload` | Sends no more request body bytes and no end of the body. The response can still arrive, and then the connection closes |
| `cancel_response` | Ends the response body with `End(Outcome::Cancelled)`, and gives no more of it. The engine reads and discards the rest, up to `drain_bytes`, to reuse the connection. Above it, the connection closes at once |
| `ready` | Whether the engine takes a request now: no exchange is in flight, a drain is complete, and the connection has not ended |
| `close` | Ends the connection: no more requests, and an exchange in flight ends with it. The next turn is terminal, so a TLS connection sends `close_notify` |
| `hold_body(hold)` | While `hold` is true, a drive gives no event of the response body, and its bytes wait in the queue. A drain goes on |

## Limits

`Limits` bounds each head, also a response head:

| Limit | Bounds |
| --- | --- |
| `head_bytes` | The bytes of the head, from the first byte of the start line to the end of the empty line. For the server, the empty lines before a request line count too |
| `fields` | The number of field lines |
| `name_bytes` | The bytes of each field name |
| `value_bytes` | The bytes of each field value, with no whitespace at its start or end |

`BodyLimits` bounds each body and the drain:

| Limit | Bounds |
| --- | --- |
| `body_bytes` | The bytes of a body: its Content-Length, or the sum of its chunk sizes. A body over it refuses before its data |
| `drain_bytes` | The unread body bytes that an engine reads and discards to reuse the connection |
| `extension_bytes` | The chunk extensions of one chunk line |
| `trailer_bytes` | The bytes of a trailer section |
| `trailer_fields` | The number of trailer field lines |

`TurnLimits` bounds the work of each drive call: see [limits](limits.md).

## Framing and connection rules

The body length follows RFC 9112, section 6.3:

| Message | Body |
| --- | --- |
| A request with `Content-Length: n`, or a response with it | `n` bytes |
| A message whose `Transfer-Encoding` field lines have one coding, `chunked`. Empty list elements do not count (RFC 9110, section 5.6.1) | Chunks, then trailers |
| A request with no framing field | No body |
| A response to HEAD, a 1xx, 204, or 304 response, or a 2xx response to CONNECT | No body, whatever the framing fields say |
| A response with no framing field | Each byte until the close |

These messages refuse, because two readers could read two different bodies:

- `Content-Length` and `Transfer-Encoding` together.
- More than one `Content-Length`, or a length that is not a decimal `u64`.
- A transfer coding other than one `chunked` (501).
- A `Transfer-Encoding` field in an HTTP/1.0 message (RFC 9112, section 6.1).
- A `Content-Length` or `Transfer-Encoding` field in a trailer section. A sender must not send it
  (RFC 9110, section 6.5.1), and a peer that merges the trailers could frame by it.
- A chunk size that is not 1 to 16 hexadecimal digits, a chunk extension outside the grammar of
  RFC 9112, section 7.1.1, a line end that is not CR LF, or chunk data that CR LF does not end.

A connection persists after each exchange when the request and the response permit it (RFC 9112,
section 9.3): an HTTP/1.1 message with no `close` connection option, or an HTTP/1.0 message with
the `keep-alive` option. A response that the close ends does not persist.

| Case | Behavior |
| --- | --- |
| A head or a trailer section that continues in the next received region | The engine copies its bytes into one region of at most `head_bytes` or `trailer_bytes`. This is one counted copy, which the budget pays for until the last view of the head drops. Each new region adds only its new bytes, and the bytes after the section keep their region. When the budget cannot pay, the turn is `Blocked(Blocked::Capacity(n))`. Thus the budget bounds the memory of many slow partial heads, and the head timeout of the server bounds their time |
| The head timeout of the server | From when the server waits for a request head, after the connection starts or after a response, to the end of the head. At its deadline, a connection with no byte of a head closes with no error, and one with part of a head gets `408` and ends with `Kind::Deadline`. The default is `HEAD_TIMEOUT`, 30 seconds: the default header read timeout of the hyper HTTP/1 server, and half of the 60-second `client_header_timeout` of nginx. Change it with `Server::head_timeout`, and turn it off with `None` |
| Obsolete line folding in a response head | The client replaces each folding with SP before it reads the fields (RFC 9112, section 5.2). This is one counted copy: the head goes into a join of at most `head_bytes`, which the budget pays for, as a head that continues in the next region does. A head with no folding has no copy. The server refuses a request with a folding with `400`, as section 5.2 permits |
| Empty lines (CR LF) before a request line | The server ignores them (RFC 9112, section 2.2). A bare LF refuses, as in a head |
| Pipelined requests | The server reads the next request only after the response before it is complete, so the responses go in the order of the requests |
| A response before the end of the request body | The server reads and discards the rest, up to `drain_bytes`, then reads the next request. A Content-Length body that is longer gets `connection: close`, and a chunked body that passes the limit closes the connection |
| An HTTP/1.0 request | Its response has an HTTP/1.1 status line, and never chunks: a chunked response becomes one that the close ends. It has `connection: keep-alive` when the connection persists, and `connection: close` when it does not. A request with no Host field is served. Its `Expect: 100-continue` and its Upgrade field have no effect, so `expects_continue()` and `upgrade()` are false, the server reads its body at once, and a 101 refuses (RFC 9110, sections 10.1.1 and 7.8) |
| `Expect: 100-continue` | The server reads no body byte until `accept_body`. A final response before it closes the connection, because the client can send its body or not (RFC 9110, section 10.1.1) |
| A 101 response to an upgrade request, or a 2xx response to CONNECT | After the request, the engine gives `Handoff`. The front of the `Inbound` queue is then exactly the bytes after the message, for the new protocol |
| A cancelled response | No last chunk and no remaining Content-Length bytes: the peer sees an incomplete message, never a complete one |
| The end of input between exchanges | The connection ends with no error |
| The end of input inside a body with a length or chunks | `End(Outcome::Truncated)`, and then `Kind::Partial` |
| The end of input in a body that the close delimits | `End(Outcome::Complete(None))`: the body is complete |
| A chunk framing error inside a body | `End(Outcome::Malformed)`, and then the refusal |
| The end of input before a response | `Kind::Uncertain`: the server can have processed the request |
| Response bytes with no request in flight | `Kind::Malformed`: each later response would be unclear |
| Bytes in the queue after the end of a response, on a connection that persists | The client gives the `End` of the body, and then the connection ends with `Kind::Malformed`, "bytes after the response". A request in answer to the `End` refuses with `Kind::Misuse`. The bytes arrived before the next request existed, so they cannot be its response: a server that sends a body after its response to HEAD would otherwise give a forged response to the next request |

## Errors

A refused head or body is a `ParseError`. The server sends the response that it names, with
`connection: close`, when no response head was out. Then the connection ends. When the output
queue has no room for the response, the turn is `Blocked(Blocked::Output)`, and the response waits
until the transport accepts output. The 408 of the head timeout waits in the same way. After the
end, each call that writes refuses with `Kind::Misuse` and queues nothing, so the error response is
the last output. `From` converts a
`ParseError` into the [error](errors.md) of the engine, with its kind.

| `ParseError` | Cause | Response | Kind |
| --- | --- | --- | --- |
| `HeadTooLarge` | The head or the trailer section is longer than its limit | 431 | `Overload` |
| `TooManyFields` | The head or the trailer section has more field lines than its limit | 431 | `Overload` |
| `FieldTooLarge` | A field name or a field value is longer than its limit | 431 | `Overload` |
| `Malformed` | The start line, a field line, or a line end does not obey RFC 9112. Or the method does not permit the form of the target, or the Host fields are not valid for the version | 400 | `Malformed` |
| `Version` | The version is not HTTP/1.0 or HTTP/1.1 | 505 | `Unsupported` |
| `Framing` | The body framing is not clear | 400 | `Malformed` |
| `TransferCoding` | The message has a transfer coding other than `chunked` | 501 | `Unsupported` |
| `BodyTooLarge` | The body is longer than `body_bytes` | 413 | `Overload` |
| `ExtensionTooLarge` | The chunk extensions are longer than `extension_bytes` | 400 | `Overload` |

`ParseError::status` gives the response status of a refusal.

## Parsers and writers

The engines use these parts, which are public for a host that needs only a part:

| Item | Use |
| --- | --- |
| `RequestParser`, `ResponseParser` | Parse a head in the received bytes, with no copy. Give all of the bytes of the head each time that more arrive. `ResponseParser::parse` takes the method of the request |
| `RequestHead`, `ResponseHead` | The checked head: its values, `version`, `framing`, `persistent`, and `consumed`. `retain(&lease)` keeps it after the call as a view of its backing |
| `ChunkDecoder` | Decodes a chunked body in any pieces and gives the position of each run of data |
| `write_head`, `write_request` | Write a response or a request head into the free capacity of a `WriteLoan`. A refusal writes nothing |
| `begin_chunk`, `end_chunk`, `last_chunk` | Write the framing of a chunked body. `last_chunk` writes the trailers |

A complete head in one receive needs no allocation. The parser checks each field value while it finds the line end.
If `parse` returns `Ok(None)`, append more bytes and call the same parser with the full prefix.
After success, `&input[head.consumed()..]` holds the body or the next message. A field iterator borrows the received bytes.

## Debug output

The `Debug` output of a head, an event, an engine, a field, and an error contains no peer text,
so a log line does not show a credential.
