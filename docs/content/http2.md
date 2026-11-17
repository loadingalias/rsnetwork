# Run an HTTP/2 connection with no I/O

The `rsnetwork::h2` module is HTTP/2 (RFC 9113). It has two parts:

- `h2::frame`, the frame codec: a parser and a writer for each frame type, with the checks of
  RFC 9113, sections 4 and 6.
- `h2::Connection`, the engine of one connection, for a client or a server. It sends and checks the
  connection preface, applies and acknowledges SETTINGS, answers PING, and decodes each header
  block. It keeps the state of each stream, flow control at the stream and the connection level,
  and the drain after a GOAWAY. It ends the connection with a GOAWAY of the RFC 9113 code of each
  connection error, and resets a stream with the code of each stream error.

rsnetwork is in development and has no release. The client and server APIs of HTTP/2 come later.
The engine gives HTTP messages as header sections and body bytes. It does not check pseudo-header
fields or `content-length` (RFC 9113, sections 8.1.1 and 8.3), so check them before you use a
message.

## The model

`h2::Connection` runs on the queues of [the drive interface](drive.md), as the
[HTTP/1.1 engines](http1.md) do:

1. `Connection::new` queues the preface in your `Outbound` queue.
2. Your host pushes each received region into an `Inbound` queue.
3. Each `drive` call reads the queued frames in place and gives one `Event`, or none.
4. You answer with `open`, `headers`, `data`, `reset`, `release`, `ping`, and `shutdown`, which
   push frames into the `Outbound` queue.
5. The host sends each `Output` and acknowledges the bytes that the transport accepted.
6. When the drive gives a terminal turn, the host sends the rest of the `Outbound` queue and closes
   the connection.

Each drive also takes a `hpack::Lines`: the space for the decoded lines of a header block, which
the `Headers` and `Trailers` events borrow. Make it with
`Lines::new(connection.header_limits(), &budget)`. You can take one from a pool for each drive, so
an idle connection keeps no decode space.

## Example

A server reads the client preface and one request, and sends its response. The code runs in a
function that returns `Result<(), Box<dyn std::error::Error>>`. The module documentation of
`rsnetwork::h2` runs the same example as a test.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::{FieldLine, Lines};
use rsnetwork::time::{ClockDomain, Instant, Suspend};

let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let queue = NonZeroUsize::new(16).expect("not zero");
let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
let settings = Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..Settings::INITIAL };
let limits = Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 };
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
// The server sends its SETTINGS frame, and a WINDOW_UPDATE that raises the connection window.
let mut server = Connection::new(Role::Server, limits, turn, &mut outbound, &budget)?;
let mut lines = Lines::new(server.header_limits(), &budget)?;
let now = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

// The client preface, its empty SETTINGS frame, and a request on stream 1: a HEADERS frame
// whose block is RFC 7541, C.3.1 (GET http://www.example.com/).
let mut input = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0".to_vec();
input.extend_from_slice(b"\0\0\x14\x01\x05\0\0\0\x01");
input.extend_from_slice(b"\x82\x86\x84\x41\x0fwww.example.com");
let endpoint = Endpoint {
    peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
    local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
    ecn: Ecn::NotEct,
    segment: None,
};
inbound.push(Received { region: Lease::from(input), endpoint, capacity: 64 * 1024 }).expect("room");

// The first drive applies the peer's settings and acknowledges them.
let (Some(Event::Settings(peer)), _) = server.drive(&mut inbound, &mut outbound, &mut lines, now) else {
    panic!("the peer's settings")
};
assert_eq!(peer, Settings::INITIAL);
let (Some(Event::Headers { stream: 1, end_stream: true, lines: Some(block) }), _) =
    server.drive(&mut inbound, &mut outbound, &mut lines, now)
else {
    panic!("a request")
};
let fields: Vec<_> = block.lines().map(|line| (line.name, line.value)).collect();
assert_eq!(fields[3], (&b":authority"[..], &b"www.example.com"[..]));

// The response on stream 1: a header section, and its body in one DATA frame that ends it.
let status = FieldLine { name: b":status", value: b"200", never_indexed: false };
server.headers(&mut outbound, 1, [status].into_iter(), false, Backing::from(Vec::with_capacity(64)))?;
assert_eq!(server.data(&mut outbound, 1, &Lease::from(b"hello".to_vec()), true)?, 5);

// The output: the server's SETTINGS frame and WINDOW_UPDATE, the acknowledgement of the
// client's SETTINGS frame, the HEADERS frame, and last the DATA frame.
let mut sent = Vec::new();
while let Some(output) = outbound.submit() {
    sent.extend_from_slice(output.region.bytes());
    outbound.ack(output.id, output.region.initialized())?;
}
assert!(sent.ends_with(b"\0\0\x05\0\x01\0\0\0\x01hello"));
```

## Start a connection

`Connection::new(role, limits, turn, &mut outbound, &budget)` makes the connection and queues its
preface (RFC 9113, section 3.4):

- A client sends the 24 bytes of `frame::PREFACE` and a SETTINGS frame.
- A server sends a SETTINGS frame.

The SETTINGS frame has each setting of `limits.settings` that is not its initial value, in the
order of the identifiers. A client then adds `SETTINGS_ENABLE_PUSH` 0, so a server never pushes.
When `limits.connection_window` is above 65,535, a WINDOW_UPDATE on stream 0 follows: see
[flow control](#flow-control). The output queue needs at least 3 entries.

The peer's first frame must be a SETTINGS frame without the flag ACK. A server first reads the 24
bytes of the client preface. A wrong preface ends the connection with `PROTOCOL_ERROR`.

### Settings

`Settings` holds the five settings of RFC 9113, section 6.5.2. `Settings::INITIAL` holds their
initial values. `u32::MAX` is the initial value of `max_concurrent_streams` and
`max_header_list_size`, which start with no limit.

| Setting | Effect on this endpoint |
| --- | --- |
| `header_table_size` | The dynamic table of the HPACK decoder. The decoder holds at least 4096 bytes, because the peer's encoder can use 4096 until the peer acknowledges the settings (RFC 9113, section 4.3.1). After the acknowledgement of a smaller size, the next block must start with a size update to it, or the connection ends with `COMPRESSION_ERROR` |
| `max_concurrent_streams` | The size of the stream table, which `Connection::new` charges to your budget. A server takes at most this many streams of the peer. A client opens at most this many streams, and also obeys the peer's value. Give a finite value: `u32::MAX` asks for a table that no budget can pay for |
| `initial_window_size` | The bytes of each stream that your consumer admits: the receive window of each stream. At most 2^31 - 1 |
| `max_frame_size` | Each received frame larger than it ends the connection with `FRAME_SIZE_ERROR`, from its 9-byte header. From 2^14 to 2^24 - 1 |
| `max_header_list_size` | The list limit of the HPACK decoder. A larger decoded block goes up with `lines: None` |

The connection applies each SETTINGS frame of the peer in its order, with each setting in its
order. It ignores a setting that it does not know. Then it queues the acknowledgement and gives
`Event::Settings` with the values now in effect. `peer_settings()` gives them too. The peer's
`SETTINGS_HEADER_TABLE_SIZE` limits the HPACK encoder from that acknowledgement on. The peer's
`SETTINGS_INITIAL_WINDOW_SIZE` changes the send window of each stream by the difference (RFC 9113,
section 6.9.2), so a window can become negative.

### Settings timeout

The peer must acknowledge the SETTINGS frame of the preface within the settings timeout. At its
deadline, the connection ends with `SETTINGS_TIMEOUT` and `Kind::Deadline` (RFC 9113, section
6.5.3). The timeout starts at the first drive, and the turn gives its deadline. Drive the
connection at the deadline, also with no input. The default is `h2::SETTINGS_TIMEOUT`, 10 seconds,
the default of nghttpx. Change it with `Connection::settings_timeout`, and turn it off with
`None`. The timeout needs the time of the host: with it on, a drive with `now: None` ends the
connection with `Kind::Unsupported`.

## Read frames

Each drive gives at most one event. A frame with no event, such as a PING, a PRIORITY, a frame of
an unknown type, or a frame on a closed stream, gives none, and the drive reads the next frame. A
header block that gives no event ends the turn as `Pending`: drive again with no wait.

| Event | Frame | What to do |
| --- | --- | --- |
| `Headers { stream, end_stream, lines }` | A header section: HEADERS and its CONTINUATION frames, decoded | For a server, a request on a new stream. For a client, an interim (1xx) response or the final response. `end_stream` tells that the message has no body. `lines` is `None` when the decoded lines are larger than `max_header_list_size`: refuse the stream, for example with a 431 response (RFC 9113, section 10.5.1) |
| `Trailers { stream, lines }` | The trailer section: a header block with END_STREAM after the header section | The body is complete. `lines` is `None` when the lines are too large: the message is not complete |
| `Data { stream, data, end_stream }` | A DATA frame | `data` is a view of a received region, with no padding. A frame gives one event for each region that holds its bytes. `end_stream` is on the last event of the frame that ends the body. Call `release` when the consumer is done with the bytes |
| `Reset { stream, code }` | RST_STREAM of the peer | The stream ended. End its body with `Outcome::Reset` |
| `StreamError { stream, code }` | A frame that is a stream error | The connection reset the stream with RST_STREAM of `code`. The body is malformed. See [stream errors](#stream-errors) |
| `WindowUpdate { stream, increment }` | WINDOW_UPDATE | The peer gave more send credit: send the rest of a body. Stream 0 is the connection |
| `Settings(settings)` | SETTINGS | The peer's settings now in effect |
| `PingAck(opaque)` | PING with the flag ACK | The answer to your `ping` |
| `GoAway { last_stream, code }` | GOAWAY | The peer processes no stream of yours after `last_stream`. See [shutdown](#shutdown-and-drain) |

The connection answers each PING with a PING with the flag ACK and the same data, and each SETTINGS
frame with one acknowledgement. Unused flags and the reserved bit are ignored (RFC 9113, section
4.1). A frame of a type that RFC 9113 does not define is discarded with its payload, with no copy.
Non-zero padding is accepted: RFC 9113 does not oblige a receiver to check it. The additional debug
data of a GOAWAY is discarded with no copy, because it is peer text.

### Header blocks

A header block is a HEADERS frame and the CONTINUATION frames after it, up to the flag
END_HEADERS. The connection decodes each block, also of a stream that it refuses or that is
closed, so the HPACK state stays in step (RFC 9113, section 4.3). A block that the decode cannot
do within `limits.work` ends the connection with `COMPRESSION_ERROR`.

A block in one HEADERS frame inside one received region decodes in place, with no copy. Another
block joins into one buffer, because the HPACK decoder reads one contiguous block: a block in one
frame joins its own bytes, and a block that continues reserves `limits.work` bytes. The budget pays
for the join until the decode. When the budget cannot pay, the turn is
`Blocked(Blocked::Capacity(n))`, and the connection tries again in a later drive.

## Streams

Push is off, so only a client opens streams. A client stream has an odd identifier, larger than
each stream that the client opened before (RFC 9113, section 5.1.1). A stream is idle until its
first header section, open after it, half-closed when one side sent END_STREAM, and closed when
both sides did or a side reset it (section 5.1). The connection keeps state only for open and
half-closed streams.

| Frame of the peer | Idle stream | Open or half-closed (local) | Half-closed (remote) | Closed |
| --- | --- | --- | --- | --- |
| HEADERS | A server opens the stream. On a client, or on an even stream: connection error `PROTOCOL_ERROR` | A header section, or the trailer section | Stream error `STREAM_CLOSED` | Decoded and discarded |
| DATA | Connection error `PROTOCOL_ERROR` | Goes up | Stream error `STREAM_CLOSED` | Counted toward the connection window, and discarded |
| RST_STREAM | Connection error `PROTOCOL_ERROR` | The stream closes: `Reset` | The stream closes: `Reset` | Ignored |
| WINDOW_UPDATE | Connection error `PROTOCOL_ERROR` | Applied, or ignored after your END_STREAM | Applied | Ignored |
| PRIORITY | Ignored, and the stream stays idle | Ignored | Ignored | Ignored |

When a client opens a stream, each idle stream below it closes. A HEADERS frame on such a skipped
stream is a frame on a closed stream: it decodes and is discarded. The connection gives each frame
on a closed stream this minimal processing (RFC 9113, section 5.1), the rule of nghttp2. Thus the
frames that the peer sent before it read your RST_STREAM are not errors, and the connection keeps
no state for a closed stream. The cost: a faulty client that sends a request on a lower stream
than its last gets no response and no error, where section 5.1.1 permits `PROTOCOL_ERROR`.

A server takes at most `max_concurrent_streams` streams. It refuses each new stream past the limit
with RST_STREAM and no event. The code is `REFUSED_STREAM` before the peer acknowledges your
settings, so the client can retry the request. After the acknowledgement, the peer knows the
limit, and the code is `PROTOCOL_ERROR` (RFC 9113, section 5.1.2). This is the rule of nghttp2 and
Go. The block of a refused stream still decodes.

### Messages

A message on a stream is a header section, DATA frames, and an optional trailer section (RFC 9113,
section 8.1). Before the final response, a server can send interim (1xx) responses. The engine
reads the first line of a response, which is its `:status`, to find an interim response.

| Received | Result |
| --- | --- |
| A header section after the header section, with END_STREAM | `Trailers` |
| A header section after the header section, with no END_STREAM | Stream error `PROTOCOL_ERROR` |
| DATA before the final response | Stream error `PROTOCOL_ERROR` |
| An interim response with END_STREAM | Stream error `PROTOCOL_ERROR` |

The send calls refuse the same messages with `Kind::Misuse`, so you cannot send a malformed
message.

## Flow control

Only DATA counts toward flow control, with its pad length and padding (RFC 9113, section 6.1). Each
level has its own window: each stream, and the connection.

### Receive credit

The peer gets receive credit only for capacity that your consumer admits:

- Each stream starts with `settings.initial_window_size`. Until the peer acknowledges your
  settings, it can use 65,535, the initial value of RFC 9113, and at the acknowledgement each
  window changes by the difference (section 6.9.2).
- The connection starts with `limits.connection_window`.
- Call `release(&mut outbound, stream, bytes)` when the consumer is done with `bytes` data bytes
  of a stream, for example after it copied them out or dropped their views. The connection gives
  their credit back at the stream level and at the connection level.
- Bytes that no consumer holds come back with no release: padding, and DATA that the connection
  discards.

A WINDOW_UPDATE goes out when the free credit reaches the credit that the peer still has. This is
the rule of nghttp2, so no small increment goes out. No WINDOW_UPDATE goes on a stream after its
END_STREAM. Thus the peer can make you hold at most the window of each stream, and
`connection_window` in all.

Release the bytes of a stream that ended too: they still count at the connection level. `release`
refuses with `Kind::Misuse`, and changes nothing, when the consumer holds fewer bytes.

DATA past a window is a `FLOW_CONTROL_ERROR`: a stream error past the stream window, and a
connection error past the connection window (the rule of nghttp2).

### Send credit

`data` sends at most the smaller of the two send windows and the peer's `SETTINGS_MAX_FRAME_SIZE`,
and gives the number of bytes that it sent. Send the rest after a `WindowUpdate` event. A window
can be negative after the peer makes its initial window smaller: then `data` sends nothing until
WINDOW_UPDATE frames make it positive. A WINDOW_UPDATE that takes a window past 2^31 - 1 is a
stream error or a connection error of type `FLOW_CONTROL_ERROR` (RFC 9113, section 6.9.1).

## Send frames

| Call | Frames | Refusal |
| --- | --- | --- |
| `open(&mut outbound, lines, end_stream, region)` | A client opens the next odd stream with a request, and gets its identifier | A server, no free stream in the table or under the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`, or a GOAWAY that went or came (`Kind::Overload`, or `Kind::Misuse` for a server). Each refusal of `headers` |
| `headers(&mut outbound, stream, lines, end_stream, region)` | A header section on an open stream: HEADERS, and CONTINUATION frames when the block is larger than the peer's `SETTINGS_MAX_FRAME_SIZE` | The region or the output queue has too little room (`Kind::Overload`). The stream is not open or sent its end, an interim response has `end_stream`, or a trailer section has none (`Kind::Misuse`) |
| `data(&mut outbound, stream, &data, end_stream)` | One DATA frame with the start of `data`. `end_stream` sets END_STREAM when the frame holds each byte | The output queue or the frame pool is full (`Kind::Overload`). The stream is not open, sent its end, or sent no header section (`Kind::Misuse`) |
| `reset(&mut outbound, stream, code)` | RST_STREAM, and the stream closes | The output queue or the frame pool is full (`Kind::Overload`). The stream is not open, or a server gives `REFUSED_STREAM` (`Kind::Misuse`) |
| `release(&mut outbound, stream, bytes)` | WINDOW_UPDATE frames when credit is due | The consumer holds fewer bytes (`Kind::Misuse`). The output queue or the pool has no room for the frames (`Kind::Overload`) |
| `ping(&mut outbound, opaque)` | One PING | The output queue or the frame pool is full (`Kind::Overload`) |
| `shutdown(&mut outbound)` | GOAWAY: see [shutdown](#shutdown-and-drain) | The output queue or the frame pool is full (`Kind::Overload`) |

A refusal writes and changes nothing, so you can call again later. After the end of the
connection, each call refuses with `Kind::Misuse`.

A server cannot reset a stream with `REFUSED_STREAM`, because each stream that it knows went up to
it: a client can retry a refused request on a new connection, also a POST (RFC 9113, section 8.7).

`headers` and `open` write the frames into the free capacity of your region: the HPACK block after
a frame header, and the header of each CONTINUATION frame after the block. They go out as views of
that region, with no copy. The region needs room for the longest block of the lines and 9 bytes for
each frame. `data` sends a 9-byte frame header from the frame pool, and then a view of your data
with no copy. Keep the rest of your data, from the offset that `data` gives, for the next call.

The connection keeps at most one answer that the output queue has no room for: a SETTINGS
acknowledgement, a PING answer, a RST_STREAM, a WINDOW_UPDATE, or a GOAWAY. While it keeps one, it
reads no frame, and the turn is `Blocked(Blocked::Output)`. Each send first queues that answer, so
the frames stay in their order.

## Shutdown and drain

`shutdown(&mut outbound)` stops new streams and lets each open stream complete (RFC 9113, section
6.8):

1. A client sends GOAWAY with `NO_ERROR` and the last stream 0, and opens no more streams.
2. A server sends GOAWAY with `NO_ERROR` and the last stream 2^31 - 1, and a PING with the data
   `h2::SHUTDOWN_PING`. A request in flight still opens its stream.
3. At the answer to that PING, the server sends GOAWAY with the last stream that went up to it.
   Each later stream of the peer is discarded with no reset, and its header block decodes.
4. When no stream is open, the turn is `Terminal(Ok(()))`.

The connection takes the answer to `SHUTDOWN_PING` as its own, so do not give that data to `ping`.

A GOAWAY of the peer gives `Event::GoAway`. For a client, each stream above its `last_stream`
ends, with no event: the server did not process it, so you can retry it on a new connection. No
new stream opens. A later GOAWAY with a larger last stream is a connection error
`PROTOCOL_ERROR` (the rule of nghttp2). When no stream is open, the connection sends its own GOAWAY
with `NO_ERROR`, if it did not send one, and the turn is `Terminal(Ok(()))`.

The last stream of each GOAWAY of a server is the highest stream that went up to it. A stream that
it refused or discarded does not count, so the client can retry it.

## Errors

### Connection errors

A frame that breaks RFC 9113 ends the connection. The connection queues a GOAWAY with the code of
the error and the last stream of the peer that went up. The turn is terminal when the GOAWAY is in
the queue, and `Blocked(Blocked::Output)` until the queue has room for it. A wrong preface gets a
GOAWAY too.

| Code | Causes | Kind |
| --- | --- | --- |
| `PROTOCOL_ERROR` | A wrong preface. A frame with the wrong stream 0 or non-zero stream for its type. A pad length past the payload. A frame inside a header block, a CONTINUATION after no block, or a CONTINUATION of another stream. A PUSH_PROMISE, in each role. A SETTINGS acknowledgement when no SETTINGS frame waits for one. A HEADERS or PRIORITY that depends on its own stream. `SETTINGS_ENABLE_PUSH` above 1, or 1 from a server. `SETTINGS_MAX_FRAME_SIZE` outside 2^14 to 2^24 - 1. A WINDOW_UPDATE of 0 on the connection. DATA, RST_STREAM, or WINDOW_UPDATE on an idle stream. A HEADERS frame on an even stream, or to a client on a stream that it did not open. A GOAWAY with a larger last stream than the GOAWAY before it | `Malformed` |
| `FRAME_SIZE_ERROR` | A frame larger than `max_frame_size`. A frame too short for its fixed fields, or a PING, PRIORITY, RST_STREAM, or WINDOW_UPDATE of another length. A SETTINGS frame whose length is not a multiple of 6, or an acknowledgement with a setting | `Malformed` |
| `FLOW_CONTROL_ERROR` | `SETTINGS_INITIAL_WINDOW_SIZE` above 2^31 - 1, or a value that takes a send window past it. DATA past the connection window. A WINDOW_UPDATE that takes the connection window past 2^31 - 1 | `Malformed` |
| `COMPRESSION_ERROR` | A block that breaks RFC 7541, or a block with no size update after the acknowledgement of a smaller table | `Malformed` |
| `COMPRESSION_ERROR` | A header block larger than `limits.work`, which the connection refuses at the header of the frame that passes it, before any copy. A block that needs more HPACK work than `limits.work` | `Overload` |
| `SETTINGS_TIMEOUT` | No acknowledgement of the settings before their deadline | `Deadline` |

RFC 9113 makes a PRIORITY frame of a wrong length a stream error. Its stream can be idle, where a
reset is not permitted, so the connection ends it as a connection error, which section 5.4.1
permits. RFC 9113 removed the rule against a stream that depends on itself, and the connection
keeps it from RFC 7540.

The end of the input at a frame boundary with no open stream ends the connection with no error.
The end inside a frame or a header block, or with an open stream, ends it with `Kind::Partial`, and
no GOAWAY: an open stream cannot be retried (RFC 9113, section 5.4.3).

### Stream errors

A stream error resets one stream with RST_STREAM, and the connection goes on (RFC 9113, section
5.4.2). The stream closes, and the drive gives `Event::StreamError` with the code.

| Code | Causes |
| --- | --- |
| `STREAM_CLOSED` | DATA or a HEADERS frame on a stream whose peer sent END_STREAM |
| `PROTOCOL_ERROR` | A WINDOW_UPDATE of 0 on a stream. A trailer section with no END_STREAM, DATA before the final response, or an interim response with END_STREAM |
| `FLOW_CONTROL_ERROR` | DATA past the stream window. A WINDOW_UPDATE that takes the stream window past 2^31 - 1 |

A new stream past the stream limit gets RST_STREAM with `REFUSED_STREAM` or `PROTOCOL_ERROR`, and
no event: see [streams](#streams).

## Limits

`h2::Limits` sets the limits of a connection:

| Limit | Bounds |
| --- | --- |
| `settings` | The settings that the endpoint sends, which bound the peer: see [settings](#settings) |
| `work` | The largest header block, and the HPACK work of one block: its bytes and each byte that the decoder copies |
| `encoder_table_bytes` | The dynamic table of the HPACK encoder. The encoder uses at most the smaller of it and the peer's `SETTINGS_HEADER_TABLE_SIZE` |
| `connection_window` | The DATA bytes of all streams that your consumers admit: the connection receive window, from 65,535 to 2^31 - 1 |

`Connection::new` charges the HPACK decoder, the HPACK encoder, the stream table, and the frame
pool to your budget: one slot of 64 bytes for each entry of the output queue, and one more.
`TurnLimits` bounds the work of each drive: `frames` counts each frame header, and `bytes` each
received byte that the drive reads. See [limits](limits.md).

## Frame codec

`Frame::parse(bytes, max_frame_size)` reads one complete frame from one slice and gives it with its
length, or `Ok(None)` when the slice holds only a part of a valid frame. It checks the header
before the payload, so a frame that is too large refuses from its 9 bytes. A refusal is a
`FrameError`: `Connection(code)`, or `Stream(code)` for a complete frame whose stream breaks a
rule. `Frame::write(&mut out)` writes a frame into the free capacity of a `WriteLoan`, with zero
padding and no unused flag. A refusal writes nothing. `Head::parse` reads a 9-byte frame header,
and `ErrorCode` holds the codes of RFC 9113, section 7. A code that the crate does not know keeps
its value.

The connection uses the same checks, and reads frames across received regions. Use the codec when
you need only a part, for example to read frames that you captured.

## Debug output

The `Debug` output of a frame, an event, and a connection shows the length of each byte field, not
its bytes, so a log line does not show a credential or the debug data of a GOAWAY.
