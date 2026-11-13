# Parse HTTP/1.1 requests and write responses with no I/O

The `rsnetwork::h1` module parses the head of an HTTP/1.1 request and writes the head of a
response. It reads the bytes that you received and writes into a region that you own. It does no
I/O and starts nothing, so any runtime, or your own event loop, can drive it. It is for servers.

rsnetwork is in development and has no release. The buffer types come from the runtime family:
`rsnetwork::buffer` is the same module as `rsasync::buffer`.

## Inputs and outputs

| Operation | Input | Output |
| --- | --- | --- |
| `RequestParser::parse` | All of the received bytes of one head, from its first byte | `Ok(Some(RequestHead))` for a complete head, `Ok(None)` for a partial head, or `Err(ParseError)` |
| `write_head` | A `WriteLoan` over a region that you own, a status, fields, and a `Framing` | The head bytes after the bytes that the region holds, or `Err(WriteError)` with nothing written |
| `begin_chunk`, `end_chunk`, `last_chunk` | A `WriteLoan` and, for `begin_chunk`, the size of the chunk | The framing of a chunked body, or `Err(WriteError::Full)` with nothing written |

A `RequestHead` holds views of the received bytes, and the parser allocates nothing:

- `method()` gives the method as bytes. An unknown method stays as it is.
- `target()` gives the request target as bytes.
- `fields()` gives each field line in its received order, as a `Field` with a name and a value.
  Repeated names stay as separate fields. Names keep their received case.
- `consumed()` gives the number of bytes of the head. The body starts there.
- `framing()` gives the end of the body: `Framing::Length(n)` or `Framing::Chunked`. A request
  with no framing field has `Length(0)`.

## Parse a request head

1. Make one `RequestParser` with your `Limits` for each connection.
2. Receive bytes into a region. Give all of the received bytes of the head to `parse`.
3. If `parse` gives `Ok(None)`, receive more bytes after the others. Then call `parse` again with
   all of them.
4. If `parse` gives a head, read the body from `consumed()`, as `framing()` tells.
5. If `parse` gives an error, send the response that the error names. Then close the connection.

The parser records how far it searched. Thus it searches each byte one time, also when the bytes
arrive one at a time. After a complete head, the parser starts again. Give it the bytes of the
next request from their first byte.

The head borrows the received bytes. To keep a part of them, such as the body, freeze the region
into a `Lease` and take a `view`. A view keeps the region alive with no copy.

## Write a response head

1. Make a `WriteLoan` over a region with enough free capacity for the head.
2. Make each field with `Field::new`, which refuses a name or a value that can split the line.
3. Call `write_head` with the status, the fields, and the framing.
4. Write the body after the head, or send it from a region of its own.

`write_head` writes the status line `HTTP/1.1 <status> ` with no reason phrase, which RFC 9112
permits. Then it writes the fields in their order, the framing field, and the empty line.
`Length(n)` writes `content-length: n`. `Chunked` writes `transfer-encoding: chunked`. For a 204
or a 304 response, give `Length(0)`: the head then has no framing field, as RFC 9110 requires.
Do not give `Content-Length` or `Transfer-Encoding` as a field, because `framing` writes it.

For a chunked body, call `begin_chunk` with the chunk size, write or send the chunk bytes, and call
`end_chunk`. Do this for each chunk. Then call `last_chunk`.

## Example

The bytes of a request arrive in two receives. The first parse gives `None`, and the second gives
the head. The body stays in the received region. The code runs in a function that returns
`Result<(), Box<dyn std::error::Error>>`. The module documentation of `rsnetwork::h1` runs the same
example as a test.

```rust
use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
use rsnetwork::h1::{Field, Framing, Limits, RequestParser, write_head};

let mut parser = RequestParser::new(Limits { head_bytes: 8 * 1024, fields: 64 });

// The bytes of a request arrive in two receives into one region.
let mut received = WriteLoan::new(Vec::with_capacity(8 * 1024));
received.fill_from(b"PUT /notes/7 HTTP/1.1\r\nHost: exa");
assert!(parser.parse(received.filled())?.is_none()); // not complete: receive more
received.fill_from(b"mple.com\r\nContent-Length: 5\r\n\r\nhello");

// Freeze the region. Views of a `Lease` can go to other owners with no copy.
let received = Lease::from(received.into_inner());
let head = parser.parse(received.bytes())?.expect("the head is complete");
assert_eq!(head.method(), b"PUT");
assert_eq!(head.target(), b"/notes/7");
let host = head.fields().find(|field| field.name().eq_ignore_ascii_case(b"host"));
assert_eq!(host.map(|field| field.value()), Some(&b"example.com"[..]));

// The body follows the head in the same region.
assert_eq!(head.framing(), Framing::Length(5));
let body = received.view(head.consumed()..head.consumed() + 5).expect("the body is in the region");
assert_eq!(body.bytes(), b"hello");

// Write the response head into the free capacity of an owned region, then the body after it.
let mut out = WriteLoan::new(Vec::with_capacity(256));
let fields = [Field::new(b"Content-Type", b"text/plain")?];
write_head(&mut out, 200, &fields, Framing::Length(2))?;
out.fill_from(b"ok");
assert_eq!(out.into_inner(), b"HTTP/1.1 200 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
```

## What the parser checks

- Each line ends with CR LF. A CR that is not before an LF, or an LF that is not after a CR,
  refuses as soon as it arrives.
- The request line has three parts with one space between them. The method is a token. The target
  is one or more visible ASCII bytes. The version is `HTTP/1.1`.
- Each field name is a token, with no whitespace before the colon. A line that starts with
  whitespace refuses, also a folded line.
- A field value has no control byte except HTAB. The parser removes the spaces and HTABs at its
  start and end. Bytes above 0x7F stay as they are.
- The framing is clear. Both `Content-Length` and `Transfer-Encoding` refuse. More than one
  `Content-Length`, or a length that is not a `u64`, refuses. The only transfer coding is one
  `chunked`.
- The head is not longer than `Limits::head_bytes`, and it has not more field lines than
  `Limits::fields`. A head refuses as soon as `head_bytes` bytes have no end of the head in them.

The parser does not check the `Host` field. It does not decode chunks or read trailers, and it
refuses HTTP/1.0 requests. It does not ignore an empty line before the request line.

## Errors

The connection cannot continue after a `ParseError`, because the end of the request is not
known. Send the response, then close the connection.

| `ParseError` | Cause | Response |
| --- | --- | --- |
| `HeadTooLarge` | The head is longer than `Limits::head_bytes` | 431 |
| `TooManyFields` | The head has more field lines than `Limits::fields` | 431 |
| `Malformed` | The request line, a field line, or a line end does not obey RFC 9112 | 400 |
| `Version` | The version is not HTTP/1.1 | 505 |
| `Framing` | The body framing is not clear | 400 |
| `TransferCoding` | The codings end with `chunked` but have one more coding | 501 |

A `WriteError` writes nothing, so the region holds no partial head.

| `WriteError` | Cause | Correction |
| --- | --- | --- |
| `Full { needed, available }` | The region has fewer free bytes than the write needs | Write into a region with at least `needed` free bytes |
| `Status` | The status is not in 200 to 599, or a 204 or 304 has framing other than `Length(0)` | Give a status in the range, and `Length(0)` for 204 and 304 |
| `FramingField` | A field is `Content-Length` or `Transfer-Encoding` | Remove the field, and give the framing as `framing` |

The `Debug` output of a head, a field, and an error contains no peer text, so a log line does not
show a credential.
