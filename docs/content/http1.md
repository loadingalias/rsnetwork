# Parse HTTP/1.1 requests and write responses with no I/O

The `rsnetwork::h1` module parses the head of an HTTP/1.1 request and writes the head of a
response. It reads the bytes that you received and writes into a region that you own. It does no
I/O and starts nothing, so any runtime, or your own event loop, can drive it. It is for servers.

rsnetwork is in development and has no release. The buffer types come from the runtime family:
`rsnetwork::buffer` is the same module as `rsasync::buffer`. The method, target, authority,
field, and status types are the [checked values](values.md) of `rsnetwork::value`.

## Inputs and outputs

| Operation | Input | Output |
| --- | --- | --- |
| `RequestParser::parse` | All of the received bytes of one head, from its first byte | `Ok(Some(RequestHead))` for a complete head, `Ok(None)` for a partial head, or `Err(ParseError)` |
| `RequestHead::retain` | The frozen `Lease` whose bytes the parser read | `Some(RetainedHead)`, a head that keeps the backing, or `None` if the head is not in the lease |
| `write_head` | A `WriteLoan` over a region that you own, a `Status`, fields, and a `Framing` | The head bytes after the bytes that the region holds, or `Err(WriteError)` with nothing written |
| `begin_chunk`, `end_chunk`, `last_chunk` | A `WriteLoan` and, for `begin_chunk`, the size of the chunk | The framing of a chunked body, or `Err(WriteError::Full)` with nothing written |

A `RequestHead` holds views of the received bytes, and the parser allocates nothing:

- `method()` gives the `Method`. An unknown method stays as it is.
- `target()` gives the `Target`, with its exact bytes and its form.
- `authority()` gives the `Authority` of the request: that of an absolute-form or authority-form
  target, or else the value of the Host field (RFC 9112, section 3.3).
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

`Limits` has four limits, which you set:

| Limit | Bounds |
| --- | --- |
| `head_bytes` | The bytes of the head, from the first byte of the request line to the end of the empty line |
| `fields` | The number of field lines |
| `name_bytes` | The bytes of each field name |
| `value_bytes` | The bytes of each field value, with no whitespace at its start or end |

## Keep a head after the call

A `RequestHead` borrows the received bytes, so it lives only while you hold them. To keep the head
longer, for example to give it to another task:

1. Freeze the received region into a `Lease`. Parse the bytes of the lease.
2. Call `head.retain(&lease)`. It gives a `RetainedHead`, which holds a view of the backing of
   the lease, with no copy.
3. Read the head with `retained.head()`, which gives a `RequestHead` of the retained bytes.

The retained head keeps the whole backing alive, also after the lease drops. Each view of one
backing shares its one charge: two retained heads of pipelined requests in one pool slot hold one
slot. The slot returns to its pool when the last view drops. A pool slot needs no allocation for
the retained head. To keep a small part of a large backing without the backing, copy that part
into a new buffer.

To keep a part of the region, such as the body, take a `view` of the lease. A view keeps the
region alive with no copy.

## Write a response head

1. Make a `WriteLoan` over a region with enough free capacity for the head.
2. Make each field with `Field::new`, which refuses a name or a value that can split the line.
3. Make the status with `Status::new`. Call `write_head` with the status, the fields, and the
   framing.
4. Write the body after the head, or send it from a region of its own.

`write_head` writes the status line `HTTP/1.1 <status> ` with no reason phrase, which RFC 9112
permits. Then it writes the fields in their order, the framing field, and the empty line.
`Length(n)` writes `content-length: n`. `Chunked` writes `transfer-encoding: chunked`. For a 204
or a 304 response, give `Length(0)`: the head then has no framing field, as RFC 9110 requires.
Do not give `Content-Length` or `Transfer-Encoding` as a field, because `framing` writes it.
`write_head` does not write informational (1xx) responses.

For a chunked body, call `begin_chunk` with the chunk size, write or send the chunk bytes, and call
`end_chunk`. Do this for each chunk. Then call `last_chunk`.

## Example

The bytes of a request arrive in two receives. The first parse gives `None`, and the second gives
the head. The body stays in the received region, and the head stays after the region drops. The
code runs in a function that returns `Result<(), Box<dyn std::error::Error>>`. The module
documentation of `rsnetwork::h1` runs the same example as a test.

```rust
use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
use rsnetwork::h1::{Framing, Limits, RequestParser, write_head};
use rsnetwork::value::{Field, Host, Method, Status, TargetForm};

let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
let mut parser = RequestParser::new(limits);

// The bytes of a request arrive in two receives into one region.
let mut received = WriteLoan::new(Vec::with_capacity(8 * 1024));
received.fill_from(b"PUT /notes/7 HTTP/1.1\r\nHost: exa");
assert!(parser.parse(received.filled())?.is_none()); // not complete: receive more
received.fill_from(b"mple.com\r\nContent-Length: 5\r\n\r\nhello");

// Freeze the region. Views of a `Lease` can go to other owners with no copy.
let received = Lease::from(received.into_inner());
let head = parser.parse(received.bytes())?.expect("the head is complete");
assert_eq!(head.method(), Method::PUT);
assert!(matches!(head.target().form(), TargetForm::Origin { path: b"/notes/7", query: None }));
assert_eq!(head.authority().host(), Host::Name(b"example.com"));

// The body follows the head in the same region.
assert_eq!(head.framing(), Framing::Length(5));
let body = received.view(head.consumed()..head.consumed() + 5).expect("the body is in the region");
assert_eq!(body.bytes(), b"hello");

// Keep the head after the region drops. It holds a view of the same backing, with no copy.
let kept = head.retain(&received).expect("the head is in the region");
drop(received);
assert_eq!(kept.head().method(), Method::PUT);

// Write the response head into the free capacity of an owned region, then the body after it.
let mut out = WriteLoan::new(Vec::with_capacity(256));
let fields = [Field::new(b"Content-Type", b"text/plain")?];
write_head(&mut out, Status::new(200)?, &fields, Framing::Length(2))?;
out.fill_from(b"ok");
assert_eq!(out.into_inner(), b"HTTP/1.1 200 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
```

## What the parser checks

- Each line ends with CR LF. A CR that is not before an LF, or an LF that is not after a CR,
  refuses as soon as it arrives.
- The request line has three parts with one space between them. The method is a `Method`. The
  target is a `Target` in one of the four forms. The version is `HTTP/1.1`.
- The method permits the form of the target. Only CONNECT has the authority form, and a CONNECT
  has no other form. Only OPTIONS has the asterisk form.
- The request has exactly one Host field, and its value is an `Authority` (RFC 9112, section 3.2).
  This is the HTTP/1.1 rule. When the target has an authority, the Host field must still be valid,
  but the authority of the request comes from the target.
- Each field name is a token, with no whitespace before the colon. A line that starts with
  whitespace refuses, also a folded line.
- A field value has no control byte except HTAB. The parser removes the spaces and HTABs at its
  start and end. Bytes above 0x7F stay as they are.
- The framing is clear. Both `Content-Length` and `Transfer-Encoding` refuse. More than one
  `Content-Length`, or a length that is not a `u64`, refuses. The only transfer coding is one
  `chunked`.
- The head is within each of the `Limits`. A head refuses as soon as `head_bytes` bytes have no
  end of the head in them.

The parser does not decode chunks or read trailers, and it refuses HTTP/1.0 requests. It does not
ignore an empty line before the request line.

## Errors

The connection cannot continue after a `ParseError`, because the end of the request is not
known. Send the response, then close the connection. `From` converts a `ParseError` into the
[error](errors.md) of an engine, with its kind.

| `ParseError` | Cause | Response |
| --- | --- | --- |
| `HeadTooLarge` | The head is longer than `Limits::head_bytes` | 431 |
| `TooManyFields` | The head has more field lines than `Limits::fields` | 431 |
| `FieldTooLarge` | A field name is longer than `Limits::name_bytes`, or a field value is longer than `Limits::value_bytes` | 431 |
| `Malformed` | The request line, a field line, or a line end does not obey RFC 9112. Or the method does not permit the form of the target, or the request does not have exactly one Host field with a valid authority | 400 |
| `Version` | The version is not HTTP/1.1 | 505 |
| `Framing` | The body framing is not clear | 400 |
| `TransferCoding` | The codings end with `chunked` but have one more coding | 501 |

A `WriteError` writes nothing, so the region holds no partial head.

| `WriteError` | Cause | Correction |
| --- | --- | --- |
| `Full { needed, available }` | The region has fewer free bytes than the write needs | Write into a region with at least `needed` free bytes |
| `Status` | The status is informational (100 to 199), or a 204 or 304 has framing other than `Length(0)` | Give a final status, and `Length(0)` for 204 and 304 |
| `FramingField` | A field is `Content-Length` or `Transfer-Encoding` | Remove the field, and give the framing as `framing` |

The `Debug` output of a head, a retained head, a field, a value, and an error contains no peer
text, so a log line does not show a credential.
