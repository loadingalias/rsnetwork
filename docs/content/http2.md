# Run the HTTP/2 frame and connection layer with no I/O

The `rsnetwork::h2` module is HTTP/2 (RFC 9113). Today it has two parts:

- `h2::frame`, the frame codec: a parser and a writer for each frame type, with the checks of
  RFC 9113, sections 4 and 6.
- `h2::Connection`, the frame and connection layer of one connection, for a client or a server. It
  sends and checks the connection preface, applies and acknowledges SETTINGS, answers PING, joins
  each header block across HEADERS and CONTINUATION frames into one HPACK decode, and ends the
  connection with a GOAWAY of the RFC 9113 code of each connection error.

rsnetwork is in development and has no release. The stream state, flow control, and drain are not
in the core yet: the connection gives each stream frame to you, and you apply the stream rules of
RFC 9113, sections 5.1 and 5.2. The client and server APIs of HTTP/2 come later.

## The model

`h2::Connection` runs on the queues of [the drive interface](drive.md), as the
[HTTP/1.1 engines](http1.md) do:

1. `Connection::new` queues the preface in your `Outbound` queue.
2. Your host pushes each received region into an `Inbound` queue.
3. Each `drive` call reads the queued frames in place and gives one `Event`, or none.
4. You answer with `headers`, `data`, and `ping`, which push frames into the `Outbound` queue.
5. The host sends each `Output` and acknowledges the bytes that the transport accepted.
6. When the drive gives a terminal turn, the host sends the rest of the `Outbound` queue and closes
   the connection.

Each drive also takes a `hpack::Lines`: the space for the decoded lines of a header block, which
the `Headers` event borrows. Make it with `Lines::new(connection.header_limits(), &budget)`. You can
take one from a pool for each drive, so an idle connection keeps no decode space.

## Example

A server reads the client preface and one request. The code runs in a function that returns
`Result<(), Box<dyn std::error::Error>>`. The module documentation of `rsnetwork::h2` runs the same
example as a test.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::Lines;
use rsnetwork::time::{ClockDomain, Instant, Suspend};

let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let queue = NonZeroUsize::new(16).expect("not zero");
let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
let settings = Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..Settings::INITIAL };
let limits = Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096 };
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
// The server sends its SETTINGS frame at once.
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

// The output: the server's SETTINGS frame, then the acknowledgement of the client's.
let mut sent = Vec::new();
while let Some(output) = outbound.submit() {
    sent.extend_from_slice(output.region.bytes());
    outbound.ack(output.id, output.region.initialized())?;
}
assert_eq!(sent[sent.len() - 9..], [0, 0, 0, 0x04, 0x01, 0, 0, 0, 0]);
```

## Start a connection

`Connection::new(role, limits, turn, &mut outbound, &budget)` makes the connection and queues its
preface (RFC 9113, section 3.4):

- A client sends the 24 bytes of `frame::PREFACE` and a SETTINGS frame.
- A server sends a SETTINGS frame.

The SETTINGS frame has each setting of `limits.settings` that is not its initial value, in the
order of the identifiers. A client then adds `SETTINGS_ENABLE_PUSH` 0, so a server never pushes.
The output queue needs at least 2 entries.

The peer's first frame must be a SETTINGS frame without the flag ACK. A server first reads the 24
bytes of the client preface. A wrong preface ends the connection with `PROTOCOL_ERROR`.

### Settings

`Settings` holds the five settings of RFC 9113, section 6.5.2. `Settings::INITIAL` holds their
initial values. `u32::MAX` is the initial value of `max_concurrent_streams` and
`max_header_list_size`, which start with no limit.

| Setting | Effect on this endpoint |
| --- | --- |
| `header_table_size` | The dynamic table of the HPACK decoder. The decoder holds at least 4096 bytes, because the peer's encoder can use 4096 until the peer acknowledges the settings (RFC 9113, section 4.3.1). After the acknowledgement of a smaller size, the next block must start with a size update to it, or the connection ends with `COMPRESSION_ERROR` |
| `max_concurrent_streams` | Sent to the peer. The stream layer applies it |
| `initial_window_size` | Sent to the peer, at most 2^31 - 1. The stream layer applies it |
| `max_frame_size` | Each received frame larger than it ends the connection with `FRAME_SIZE_ERROR`, from its 9-byte header. From 2^14 to 2^24 - 1 |
| `max_header_list_size` | The list limit of the HPACK decoder. A larger decoded block goes up as `Headers` with `lines: None` |

The connection applies each SETTINGS frame of the peer in its order, with each setting in its
order. It ignores a setting that it does not know. Then it queues the acknowledgement and gives
`Event::Settings` with the values now in effect. `peer_settings()` gives them too. The peer's
`SETTINGS_HEADER_TABLE_SIZE` limits the HPACK encoder from that acknowledgement on.

### Settings timeout

The peer must acknowledge the SETTINGS frame of the preface within the settings timeout. At its
deadline, the connection ends with `SETTINGS_TIMEOUT` and `Kind::Deadline` (RFC 9113, section
6.5.3). The timeout starts at the first drive, and the turn gives its deadline. Drive the
connection at the deadline, also with no input. The default is `h2::SETTINGS_TIMEOUT`, 10 seconds,
the default of nghttpx. Change it with `Connection::settings_timeout`, and turn it off with
`None`. The timeout needs the time of the host: with it on, a drive with `now: None` ends the
connection with `Kind::Unsupported`.

## Read frames

Each drive gives at most one event. A frame with no event, such as a PING, a PRIORITY, or a frame
of an unknown type, gives none, and the drive reads the next frame.

| Event | Frame | What to do |
| --- | --- | --- |
| `Headers { stream, end_stream, lines }` | A HEADERS frame and its CONTINUATION frames, decoded | `lines` is `Some(block)`, or `None` when the decoded lines are larger than `max_header_list_size`. The HPACK state is in step in both cases. Refuse a stream with `None`, for example with a 431 response (RFC 9113, section 10.5.1). The PRIORITY fields are discarded |
| `Data { stream, data, flow, end_stream }` | A DATA frame | `data` is a view of a received region. A frame gives one event for each region that holds its bytes. `flow` counts against flow control: the whole payload with its padding on the first event of a frame, and 0 on the later events. `end_stream` is on the last event of the frame |
| `Reset { stream, code }` | RST_STREAM | End the stream |
| `WindowUpdate { stream, increment }` | WINDOW_UPDATE | Stream 0 is the connection. An increment past the window is the stream layer's check |
| `Settings(settings)` | SETTINGS | The peer's settings now in effect |
| `PingAck(opaque)` | PING with the flag ACK | The answer to your `ping` |
| `GoAway { last_stream, code }` | GOAWAY | The peer processes no stream of yours after `last_stream`. The additional debug data is discarded with no copy, because it is peer text. A later release can give it through a bounded diagnostic sink |
| `StreamError { stream, code }` | A WINDOW_UPDATE of 0 on a stream | A stream error (RFC 9113, section 5.4.2): reset the stream with `code`, or end the connection when its state requires it |

The connection answers each PING with a PING with the flag ACK and the same data, and each SETTINGS
frame with one acknowledgement. Unused flags and the reserved bit are ignored (RFC 9113, section
4.1). A frame of a type that RFC 9113 does not define is discarded with its payload, with no copy.
Non-zero padding is accepted: RFC 9113 does not oblige a receiver to check it.

### Header blocks

A header block is a HEADERS frame and the CONTINUATION frames after it, up to the flag
END_HEADERS. The connection decodes each block, also of a stream that you refuse, so the HPACK
state stays in step (RFC 9113, section 4.3).

A block in one HEADERS frame inside one received region decodes in place, with no copy. Another
block joins into one buffer, because the HPACK decoder reads one contiguous block: a block in one
frame joins its own bytes, and a block that continues reserves `limits.work` bytes. The budget pays
for the join until the decode. When the budget cannot pay, the turn is
`Blocked(Blocked::Capacity(n))`, and the connection tries again in a later drive.

## Send frames

| Call | Frames | Refusal |
| --- | --- | --- |
| `headers(&mut outbound, stream, lines, end_stream, region)` | A HEADERS frame and, when the HPACK block is larger than the peer's `SETTINGS_MAX_FRAME_SIZE`, CONTINUATION frames | The region has too little free capacity (`Kind::Overload`), the output queue has too few entries (`Kind::Overload`), or the stream is 0 or past 2^31 - 1 (`Kind::Misuse`) |
| `data(&mut outbound, stream, &data, end_stream)` | One DATA frame | The data is larger than the peer's `SETTINGS_MAX_FRAME_SIZE`, or the stream is not valid (`Kind::Misuse`). The output queue or the frame pool is full (`Kind::Overload`) |
| `ping(&mut outbound, opaque)` | One PING | The output queue or the frame pool is full (`Kind::Overload`) |

A refusal writes and changes nothing, so you can call again later. After the end of the
connection, each call refuses with `Kind::Misuse`.

`headers` writes the frames into the free capacity of your region: the HPACK block after a frame
header, and the header of each CONTINUATION frame after the block. They go out as views of that
region, with no copy. The region needs room for the longest block of the lines and 9 bytes for
each frame. `data` sends a 9-byte frame header from the frame pool, and then a view of your data
with no copy. Flow control is the stream layer's: `data` does not check a window.

The connection keeps at most one answer that the output queue has no room for: an acknowledgement,
a PING answer, or a GOAWAY. While it keeps one, it reads no frame, and the turn is
`Blocked(Blocked::Output)`. Each send first queues that answer, so the frames stay in their order.

## Connection errors

A frame that breaks RFC 9113 ends the connection. The connection queues a GOAWAY with the code of
the error and the last stream of the peer whose header block went up. The turn is terminal when the
GOAWAY is in the queue, and `Blocked(Blocked::Output)` until the queue has room for it. A wrong
preface gets a GOAWAY too.

| Code | Causes | Kind |
| --- | --- | --- |
| `PROTOCOL_ERROR` | A wrong preface. A frame with the wrong stream 0 or non-zero stream for its type. A pad length past the payload. A frame inside a header block, a CONTINUATION after no block, or a CONTINUATION of another stream. A PUSH_PROMISE, in each role. A SETTINGS acknowledgement when no SETTINGS frame waits for one. A HEADERS or PRIORITY that depends on its own stream. `SETTINGS_ENABLE_PUSH` above 1, or 1 from a server. `SETTINGS_MAX_FRAME_SIZE` outside 2^14 to 2^24 - 1. A WINDOW_UPDATE of 0 on the connection | `Malformed` |
| `FRAME_SIZE_ERROR` | A frame larger than `max_frame_size`. A frame too short for its fixed fields, or a PING, PRIORITY, RST_STREAM, or WINDOW_UPDATE of another length. A SETTINGS frame whose length is not a multiple of 6, or an acknowledgement with a setting | `Malformed` |
| `FLOW_CONTROL_ERROR` | `SETTINGS_INITIAL_WINDOW_SIZE` above 2^31 - 1 | `Malformed` |
| `COMPRESSION_ERROR` | A block that breaks RFC 7541, or a block with no size update after the acknowledgement of a smaller table | `Malformed` |
| `COMPRESSION_ERROR` | A header block larger than `limits.work`, which the connection refuses at the header of the frame that passes it, before any copy. A block that needs more HPACK work than `limits.work` | `Overload` |
| `SETTINGS_TIMEOUT` | No acknowledgement of the settings before their deadline | `Deadline` |

RFC 9113 makes a PRIORITY frame of a wrong length a stream error. Its stream can be idle, where a
reset is not permitted, so the connection ends it as a connection error, which section 5.4.1
permits. RFC 9113 removed the rule against a stream that depends on itself, and the connection
keeps it from RFC 7540.

The end of the input at a frame boundary ends the connection with no error. The end inside a frame
or a header block ends it with `Kind::Partial`, and no GOAWAY.

## Limits

`h2::Limits` sets the limits of a connection:

| Limit | Bounds |
| --- | --- |
| `settings` | The settings that the endpoint sends, which bound the peer: see [settings](#settings) |
| `work` | The largest header block, and the HPACK work of one block: its bytes and each byte that the decoder copies |
| `encoder_table_bytes` | The dynamic table of the HPACK encoder. The encoder uses at most the smaller of it and the peer's `SETTINGS_HEADER_TABLE_SIZE` |

`Connection::new` charges the HPACK decoder, the HPACK encoder, and the frame pool to your budget:
one slot of 64 bytes for each entry of the output queue, and one more. `TurnLimits` bounds the work
of each drive: `frames` counts each frame header, and `bytes` each received byte that the drive
reads. See [limits](limits.md).

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
