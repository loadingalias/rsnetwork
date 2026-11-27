# Compress HTTP/3 field lines with QPACK

The `rsnetwork::qpack` module is QPACK (RFC 9204), the field compression of HTTP/3. An `Encoder`
writes the field lines of a request or a response as one field section. A `Decoder` reads a field
section and gives its field lines. Each is the one owner of its dynamic table: the table of recent
field lines that a section can name with one small index.

The HTTP/3 connection drives the codec for each request, response, and trailer section.
For direct codec use, supply instruction bytes and complete field sections. The codec writes its output into your regions. [Drive an HTTP/3 connection](http3.md)

## The three kinds of bytes

QPACK keeps the two dynamic tables of a connection in step with two streams of their own:

| Bytes | From | To | What they carry |
| --- | --- | --- | --- |
| Field section | Encoder | Decoder | The lines of one header or trailer section, in the payload of a HEADERS frame |
| Encoder stream | Encoder | Decoder | The insertions into the dynamic table |
| Decoder stream | Decoder | Encoder | The acknowledgements of sections, the cancellations of streams, and the count of insertions that arrived |

QUIC does not order bytes of different streams. Thus a section can arrive before the insertions
that it names. Its stream is then blocked: the section waits until the insertions arrive.

## Example

The code runs in a function that returns `Result<(), Box<dyn std::error::Error>>`. The module
documentation of `rsnetwork::qpack` runs the same example as a test.

```rust
use core::num::NonZeroU64;

use rsnetwork::buffer::{Backing, Buffer as _, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::qpack::{Decoder, Encoder, EncoderLimits, FieldLine, Limits, Lines, Settings};

let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let limits = Limits { table_bytes: 4096, blocked_streams: 16, list_bytes: 16 * 1024, work: 64 * 1024 };
let mut decoder = Decoder::new(limits, &budget)?;
let mut lines = Lines::new(limits, &budget)?;
let mut encoder = Encoder::new(EncoderLimits { table_bytes: 4096, sections: 64 }, &budget)?;
// The settings that the peer's decoder sent.
encoder.set_peer(Settings { table_bytes: 4096, blocked_streams: 16 })?;

let line = |name, value| FieldLine { name, value, never_indexed: false };
let request = [line(b":method", b"GET"), line(b":path", b"/notes"), line(b"x-trace", b"7f3a")];
let region = || WriteLoan::new(Backing::from(Vec::with_capacity(256)));
let (mut section, mut encoder_stream, mut decoder_stream) = (region(), region(), region());
let prefix = encoder.encode(0, request.iter().copied(), &mut section, &mut encoder_stream)?;
// A field section is its prefix and then its lines.
let bytes = [prefix.bytes(), section.filled()].concat();

decoder.receive(encoder_stream.filled(), &mut decoder_stream)?;
let block = decoder.decode(0, &bytes, &mut lines, &mut decoder_stream)?;
let decoded: Vec<_> = block.lines().map(|line| (line.name, line.value)).collect();
assert_eq!(decoded[2], (&b"x-trace"[..], &b"7f3a"[..]));
// The acknowledgement goes back to the encoder on the decoder stream.
encoder.receive(decoder_stream.filled())?;
```

## Encode a field section

1. Make one encoder for each connection with `Encoder::new(limits, &budget)`. Until the next step,
   the encoder uses only the static table and literals, as RFC 9204 requires before the peer's
   settings arrive.
2. When the peer's SETTINGS frame arrives, give `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
   `SETTINGS_QPACK_BLOCKED_STREAMS` to `encoder.set_peer(Settings { table_bytes, blocked_streams })`.
   Give them once. A second call refuses with `EncodeError::Settings`.
3. Encode the lines of each section with
   `encoder.encode(stream, lines, &mut section, &mut encoder_stream)`. `lines` is an iterator of
   `FieldLine` that the encoder can clone, because it reads the lines two times.
4. Send the returned `Prefix` and then the bytes of `section` as the field section. The prefix
   depends on each line, so the encoder gives it after the lines. Put it in the region of the frame
   header, so the section needs no copy.
5. Send the new bytes of `encoder_stream` on the encoder stream. Give each byte of the peer's
   decoder stream to `encoder.receive(bytes)`.

The encoder writes each line in its shortest form that the state of the connection permits:

- A line that a table entry has, with its name and value, is one index.
- Another line goes into the dynamic table when the table has room and `encoder_stream` has room
  for the whole instruction. The section then names the new entry, if the peer permits one more
  blocked stream.
- Else the line is a literal. It names the entry of its name when an entry has the name.
- A string is Huffman coded only when that makes it shorter.

The encoder names an entry that the decoder did not acknowledge only when the stream waits
already, or while fewer sections wait than the peer's `blocked_streams`. It evicts an entry only after the decoder acknowledged it, and
when no section that waits names it. It writes an instruction only whole. Thus a section always
encodes, also when the encoder stream has no room: it then uses literals.

`encode` first calculates the longest lines that the section can have. If `section` has fewer free
bytes, it refuses with `EncodeError::Full(Full { needed, available })`, and it writes and changes
nothing. QPACK carries any bytes, so the encoder does not check names or values. HTTP/3 needs
lowercase names (RFC 9114, section 4.2).

## Decode field sections

1. Make one decoder for each connection with `Decoder::new(limits, &budget)`. Send the first three
   limits in your SETTINGS frame: see [Limits](#limits).
2. Make the space for the decoded lines with `Lines::new(limits, &budget)`, with the limits of the
   decoder. One `Lines` serves one decode at a time.
3. Give each byte of the encoder stream, in its order, to
   `decoder.receive(bytes, &mut decoder_stream)`. It gives the number of bytes that it read. When
   that is less than `bytes`, the call stopped at its work limit: give the rest in a later call.
4. Give each complete field section to `decoder.decode(stream, &section, &mut lines, &mut decoder_stream)`.
   On success, `block.lines()` gives the field lines in their order.
5. When `decode` gives `DecodeError::Blocked`, keep the bytes of the section. After each
   `receive`, call `decoder.unblocked()` until it gives `None`, and decode the section of each
   stream that it gives.
6. When a stream ends before each of its sections decoded, call `decoder.cancel(stream, &mut decoder_stream)`.
   The reason can be a reset by the peer, or that you stop reading the stream. The encoder then
   stops waiting for the acknowledgements of that stream.
7. Send the new bytes of `decoder_stream` on the decoder stream.

The decoder writes its instructions into the region that you give to each call. A Section
Acknowledgment goes out after each section that names the dynamic table. An Insert Count
Increment goes out as soon as new entries arrive and the region has room. A Stream Cancellation
goes out for each `cancel`. The decoder queues no bytes of its own. Thus you bound the bytes that
wait on the decoder stream: RFC 9204, section 7.3, asks you to do so.

When a region has no room for an acknowledgement or a cancellation, the call refuses with `Full`,
and it changes nothing. Send the decoder stream, and call again with room. An instruction has at
most 11 bytes.

The block borrows the `Lines`. Copy each value that you keep before the next decode into them. A
line has the `never_indexed` mark when the peer sent it as a literal that is never indexed.

## Limits

`qpack::Limits` sets the limits of a decoder, and `qpack::EncoderLimits` the limits of an encoder.
Each codec charges all of its memory to your budget when you make it, and no other call
allocates. A budget that cannot pay refuses `Decoder::new`, `Lines::new`, or `Encoder::new` with
`Kind::Overload`, and nothing is allocated.

| Limit | Bounds | Memory that it sets |
| --- | --- | --- |
| `Limits::table_bytes` | The capacity of the dynamic table. Send it as your `SETTINGS_QPACK_MAX_TABLE_CAPACITY`. A larger capacity on the encoder stream is an error of the encoder stream | `Decoder::new` charges `table_bytes` for the table, the positions of at most `table_bytes / 32` entries, and `table_bytes` for the entry that an instruction inserts |
| `Limits::blocked_streams` | The streams that wait for insertions at one time. Send it as your `SETTINGS_QPACK_BLOCKED_STREAMS`. One stream more is a connection error | `Decoder::new` charges 16 bytes for each blocked stream |
| `Limits::list_bytes` | The decoded lines of one section, in the size of RFC 9114, section 4.2.2: each name and value, and 32 for each line. Send it as your `SETTINGS_MAX_FIELD_SECTION_SIZE` | `Lines::new` charges `list_bytes`, and the positions of at most `list_bytes / 32` lines |
| `Limits::work` | The work of one call to `receive`: the bytes that it reads, and each byte that it copies to the dynamic table | None |
| `EncoderLimits::table_bytes` | The capacity of the encoder's table. The encoder uses the smaller of it and the peer's capacity | `Encoder::new` charges `table_bytes` and the positions of at most `table_bytes / 32` entries |
| `EncoderLimits::sections` | The sections with references to the dynamic table that wait for their acknowledgement. When this many wait, the next sections use only the static table and literals | `Encoder::new` charges 24 bytes for each section |

A call to `receive` stops at the first step after its work reaches `work`, and then it read fewer
bytes than you gave. A step is one part of an instruction, and it copies at most two entries of the
table. Thus a call does at most `work` and two times `table_bytes`. Each call makes at least one
step, so a small limit slows the encoder stream but cannot stop it. A field section copies at most
`list_bytes`, so the frame size of the section and `list_bytes` bound the work of `decode`.

The encoder reads each decoder instruction with at most one pass over the sections that wait, so
`sections` bounds the work of each byte of the decoder stream.

## Refusals

| Refusal | Cause | What to do |
| --- | --- | --- |
| `DecodeError::Blocked` | The section names insertions that did not arrive | Keep the section, and decode it when `unblocked` gives its stream |
| `DecodeError::TooLarge` | The decoded lines are larger than `list_bytes` | Refuse the stream, for example with a 431 response. The decoder wrote the Section Acknowledgment, so the connection continues |
| `DecodeError::TooManyBlocked` | The section would block one stream more than `blocked_streams` | End the connection with `QPACK_DECOMPRESSION_FAILED` |
| `DecodeError::Malformed` | The section breaks RFC 9204: an index past a table, a reference to an evicted entry or at the Required Insert Count, a Base below zero, a string past the end, an EOS symbol or bad padding in a Huffman string, or a Required Insert Count that is not one more than the largest reference. It also follows a refused encoder stream | End the connection with `QPACK_DECOMPRESSION_FAILED` |
| `DecodeError::Full` | The region for the decoder stream has no room for the Section Acknowledgment | Send the decoder stream, and decode again |
| `DecodeError::Misuse` | The `Lines` are smaller than the limits of the decoder need | Make the lines with `Lines::new` and the limits of the decoder |
| `StreamError::Encoder` | An encoder instruction breaks RFC 9204: a capacity above `table_bytes`, an entry larger than the capacity, a reference to no entry, or a bad integer or Huffman string | End the connection with `QPACK_ENCODER_STREAM_ERROR` |
| `StreamError::Decoder` | A decoder instruction breaks RFC 9204: an acknowledgement of a stream with no section that waits, or an Insert Count Increment of zero or past the insertions | End the connection with `QPACK_DECODER_STREAM_ERROR` |
| `EncodeError::Full` | The region for the section has fewer free bytes than the longest lines | Encode again into a region with at least `needed` free bytes |

After `StreamError`, the state of the table is not known, and the codec refuses each later call.
No refusal allocates. A string or an integer that goes past the end of its bytes refuses before
the decoder copies it.

RFC 9204, section 2.2.1, lets a decoder accept a Required Insert Count that is larger than the
largest reference needs. The decoder refuses it as `Malformed`, selected on 2026-11-18: a
conformant encoder never sends one.

## Sensitive field lines

A sensitive line is sent as a literal that is never indexed (RFC 9204, section 7.1.3). It never
goes into a dynamic table, so a peer that can add lines to the same connection cannot find the
value by the size of the sections. The encoder uses the rule of [HPACK](hpack.md#sensitive-field-lines):
your `FieldLine::never_indexed` mark, `authorization` and `proxy-authorization`, and a `cookie` or
`set-cookie` value shorter than 20 bytes.

The decoder keeps the `never_indexed` mark of each line that it receives. If you forward the line,
give it to the encoder with the mark, so it goes in the same form, as RFC 9204 requires.

## Compression contexts

Each encoder and decoder belongs to one connection, and no connection shares its dynamic table.
A line can name only an entry that the same connection sent before. Do not send the requests of
two principals, or of two privacy partitions, on one connection.
