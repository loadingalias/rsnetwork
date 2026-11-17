# Compress HTTP/2 field lines with HPACK

The `rsnetwork::hpack` module is HPACK (RFC 7541), the header compression of HTTP/2. An
`Encoder` writes the field lines of a request or a response as one header block. A `Decoder`
reads a header block and gives its field lines. Each is the one owner of its dynamic table: the
table of recent field lines that a block can name with one small index.

rsnetwork is in development and has no release. The [HTTP/2 engine](http2.md) owns one
encoder and one decoder for each connection and calls them for you. Call them yourself when you
need HPACK alone.

## Example

The code runs in a function that returns `Result<(), Box<dyn std::error::Error>>`. The module
documentation of `rsnetwork::hpack` runs the same example as a test.

```rust
use core::num::NonZeroU64;

use rsnetwork::buffer::{Backing, Buffer as _, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::hpack::{Decoder, Encoder, FieldLine, Limits, Lines};

let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let mut encoder = Encoder::new(4096, &budget)?;
let limits = Limits { table_bytes: 4096, list_bytes: 16 * 1024, work: 64 * 1024 };
let mut decoder = Decoder::new(limits, &budget)?;
// The space for the decoded lines of one block, which a host can take from a pool for each block.
let mut lines = Lines::new(limits, &budget)?;

let line = |name, value| FieldLine { name, value, never_indexed: false };
let request = [
    line(b":method", b"GET"),
    line(b":path", b"/notes"),
    line(b"authorization", b"Bearer mF_9.B5f-4.1JqM"),
];
let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(256)));
encoder.encode(request.iter().copied(), &mut out)?;

let block = decoder.decode(out.filled(), &mut lines)?;
let decoded: Vec<_> = block.lines().map(|line| (line.name, line.value, line.never_indexed)).collect();
assert_eq!(decoded[1], (&b":path"[..], &b"/notes"[..], false));
// The rule sent the credential as never indexed, and the decoder keeps the mark.
assert_eq!(decoded[2], (&b"authorization"[..], &b"Bearer mF_9.B5f-4.1JqM"[..], true));
```

## Encode a header block

1. Make one encoder for each connection with `Encoder::new(table_bytes, &budget)`. Its dynamic
   table holds at most `table_bytes`.
2. When the peer sends `SETTINGS_HEADER_TABLE_SIZE`, give the value to
   `encoder.set_peer_limit(limit)`. The table uses the smaller of the two limits. The peer's limit
   starts at 4096, the initial value of HTTP/2.
3. Encode the lines of each block, in their order, with `encoder.encode(lines, &mut out)`. `lines`
   is an iterator of `FieldLine` that the encoder can clone, because it reads the lines two times.
   `out` is a `WriteLoan` over your region, and the block goes after its filled bytes.

The encoder writes each line in its shortest form:

- A line that a table entry has, with its name and value, is one index.
- Another line is a literal. It names the entry of its name when an entry has the name, and it
  goes into the dynamic table when it fits there.
- A string is Huffman coded only when that makes it shorter.
- When the size of the table changed, the next block starts with the size updates of RFC 7541,
  section 4.2.

`encode` first calculates the longest block that the lines can give. If your region has fewer
free bytes, it refuses with `EncodeError::Full { needed, available }`, and it writes and changes
nothing. Encode again into a region with at least `needed` free bytes. HPACK carries any bytes, so
the encoder does not check names or values. HTTP/2 needs lowercase names (RFC 9113, section 8.2).

## Decode a header block

1. Make one decoder for each connection with `Decoder::new(limits, &budget)`.
2. Make the space for the decoded lines with `Lines::new(limits, &budget)`, with the limits of the
   decoder. One `Lines` serves one decode at a time. Keep one for each connection, or take one from
   a pool for each block and give it back after you read the lines.
3. Join the payloads of a HEADERS frame and its CONTINUATION frames into one block.
4. Call `decoder.decode(&block, &mut lines)`. On success, `block.lines()` gives the field lines in
   their order.
5. When the peer acknowledges a new `SETTINGS_HEADER_TABLE_SIZE`, give it to
   `Decoder::set_limit(limit)`, at most `table_bytes`. The HTTP/2 engine calls it for
   you. A later size update above it is malformed.
   When the table is larger than the new limit, the next block must start with a size update to at
   most the limit (RFC 9113, section 4.3.1), or it is malformed.

The block borrows the `Lines`. Copy each value that you keep before the next decode into them. A line has the
`never_indexed` mark when the peer sent it as a literal that is never indexed. HPACK carries any
bytes, so check the names and the values of a block for HTTP/2 after the decode.

## Limits

`hpack::Limits` sets the limits of a decoder. `Decoder::new` and `Lines::new` charge their memory
to your budget when you make them, and a decode never allocates. Between blocks, a connection needs
only its decoder, so an idle connection holds only its dynamic table there.

| Limit | Bounds | Memory that it sets |
| --- | --- | --- |
| `table_bytes` | The dynamic table. Send it as your `SETTINGS_HEADER_TABLE_SIZE`. A size update above it, or above the limit of `set_limit`, is malformed | `Decoder::new` charges `table_bytes`, and the positions of at most `table_bytes / 32` entries |
| `list_bytes` | The decoded lines of one block, in the size of RFC 7541, section 4.1: each name and value, and 32 for each line. Send it as your `SETTINGS_MAX_HEADER_LIST_SIZE` | `Lines::new` charges the larger of `list_bytes` and `table_bytes`, and the positions of at most `list_bytes / 32` lines. A line on its way to the dynamic table also uses this space, so it has at least `table_bytes` |
| `work` | The work of one block: its bytes, and each byte that the decoder copies to the decoded lines and to the dynamic table | None. The decoder checks the work before each copy |

A block of lines that fit in `list_bytes` costs at most its own bytes and two times `list_bytes`.
Set `work` to at least that sum for your largest block. The work limit stops a block that copies a
large table entry again and again, for example one literal after another that each names a long
entry. A block decodes in one call, so `work` also bounds that call.

`Encoder::new(table_bytes, &budget)` charges `table_bytes` and the positions of at most
`table_bytes / 32` entries. A budget that cannot pay refuses `Encoder::new`, `Decoder::new`, or
`Lines::new` with `Kind::Overload`, and nothing is allocated.

## Refusals

`decode` refuses a block with a `DecodeError`. A refusal never allocates, because the decoder and
the lines hold all of their memory from when you made them. A string or an integer that goes past
the end of the block refuses before the decoder copies it.

| `DecodeError` | Cause | What to do |
| --- | --- | --- |
| `TooLarge` | The decoded lines are larger than `list_bytes` | Refuse the stream, for example with a 431 response (RFC 9113, section 10.5.1). The block still changed the dynamic table as the encoder expects, so the connection continues, and the next block decodes |
| `Malformed` | The block breaks RFC 7541: a bad index, a string or an integer past the end of the block, an EOS symbol or bad padding in a Huffman string, a size update after a line or above the limit, or no size update at the start of the block after `set_limit` lowered the limit below the table | End the connection with `COMPRESSION_ERROR` |
| `Overload` | The block needs more work than `work` | End the connection: the table cannot stay in step with the encoder |
| `Misuse` | The `Lines` are smaller than the limits of the decoder need | Make the lines with `Lines::new` and the limits of the decoder. The decoder did not change, so decode the block again |

After `Malformed` or `Overload`, the state of the table is not known. The decoder then gives the
same error for each later block.

A block that names one large entry many times with one byte each costs only its own bytes after
its lines pass `list_bytes`. The decoder copies no more of them, and it gives `TooLarge`.

## Sensitive field lines

A sensitive line is sent as a literal that is never indexed (RFC 7541, section 6.2.3). It never
goes into a dynamic table. Thus a peer that can add lines to the same connection cannot find the
value by the size of the blocks (RFC 7541, section 7.1.3).

The encoder sends a line as never indexed when one of these is true:

- You set `FieldLine::never_indexed`. Set it on each line that holds a secret, for example an API
  key.
- The name is `authorization` or `proxy-authorization`, in any case.
- The name is `cookie` or `set-cookie`, and the value is shorter than 20 bytes. A short value has
  little entropy, so a peer can guess it. A longer value is indexed.

The encoder never sends a never-indexed line as an index, also when a table entry has the same
name and value. The rule applies to each line separately. HTTP/2 permits a `cookie` field to go as
one line for each crumb (RFC 9113, section 8.2.3), and the encoder does not split it, so give
each crumb as its own line.

The decoder keeps the `never_indexed` mark of each line that it receives. If you forward the line,
give it to the encoder with the mark, so it goes in the same form, as RFC 7541 requires.

## Compression contexts

Each encoder and decoder belongs to one connection, and no connection shares its dynamic table.
A line can name only an entry that the same connection sent before. Do not send the requests of
two principals, or of two privacy partitions, on one connection.
