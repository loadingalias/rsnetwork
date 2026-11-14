//! The head writers and the chunk framing.

use core::fmt;
use core::num::NonZeroUsize;

use rstypes::buffer::{BufferMut, WriteLoan};

use super::Framing;
use crate::value::{Field, Method, Status, Target};

/// Writes a response head into the free capacity of `out`, after the bytes that it holds.
///
/// The head is the status line `HTTP/1.1 <status> `, the field lines of `fields` in their order,
/// the framing field, and the empty line. The status line has no reason phrase, which RFC 9112,
/// section 4, permits. `Length(n)` writes `content-length: n`, `Chunked` writes
/// `transfer-encoding: chunked`, and `Close` writes no framing field: the close of the connection
/// ends the body. A 1xx, 204, or 304 response has no body: give `Length(0)`, and the head then has
/// no framing field, as RFC 9110, sections 8.6 and 15.2, require.
///
/// Refuses, and writes nothing, if a 1xx, 204, or 304 has other framing, if a field is a framing
/// field, or if `out` has too little free capacity.
pub fn write_head<B: BufferMut>(
    out: &mut WriteLoan<B>,
    status: Status,
    fields: &[Field<'_>],
    framing: Framing,
) -> Result<(), WriteError> {
    write_response(out, status, fields, framing, None)
}

/// Writes a response head as [`write_head`] does, with the field `connection: <option>` after
/// `fields` when `connection` is `Some`.
pub(super) fn write_response<B: BufferMut>(
    out: &mut WriteLoan<B>,
    status: Status,
    fields: &[Field<'_>],
    framing: Framing,
    connection: Option<&[u8]>,
) -> Result<(), WriteError> {
    let code = status.code();
    let no_body = code < 200 || matches!(code, 204 | 304);
    if no_body && framing != Framing::Length(0) {
        return Err(WriteError::Status);
    }
    let mut status_digits = [0; 20];
    let status = digits(u64::from(code), 10, &mut status_digits);
    let start = [b"HTTP/1.1 ", status, b" \r\n"];
    write_message(out, start, None, fields, connection, (!no_body).then_some(framing))
}

/// Writes a request head into the free capacity of `out`, after the bytes that it holds.
///
/// The head is the request line `<method> <target> HTTP/1.1`, the field lines of `fields` in
/// their order, the framing field, and the empty line. Give the Host field in `fields`: RFC 9112,
/// section 3.2, requires it. `Length(n)` writes `content-length: n`, and `Chunked` writes
/// `transfer-encoding: chunked`. `Length(0)` writes no framing field for GET, HEAD, DELETE,
/// OPTIONS, TRACE, and CONNECT, whose content has no meaning, and `content-length: 0` for other
/// methods (RFC 9110, section 8.6).
///
/// Refuses, and writes nothing, if the framing is `Close`, which a request cannot have, if a
/// field is a framing field, or if `out` has too little free capacity.
pub fn write_request<B: BufferMut>(
    out: &mut WriteLoan<B>,
    method: Method<'_>,
    target: Target<'_>,
    fields: &[Field<'_>],
    framing: Framing,
) -> Result<(), WriteError> {
    write_request_head(out, method, target, None, fields, framing)
}

/// Writes a request head as [`write_request`] does, with `host` as its first field line when it
/// is `Some`, as RFC 9112, section 3.2, advises.
pub(super) fn write_request_head<B: BufferMut>(
    out: &mut WriteLoan<B>,
    method: Method<'_>,
    target: Target<'_>,
    host: Option<Field<'_>>,
    fields: &[Field<'_>],
    framing: Framing,
) -> Result<(), WriteError> {
    if framing == Framing::Close {
        return Err(WriteError::Framing);
    }
    let no_content = framing == Framing::Length(0)
        && [
            Method::GET,
            Method::HEAD,
            Method::DELETE,
            Method::OPTIONS,
            Method::TRACE,
            Method::CONNECT,
        ]
        .contains(&method);
    let start = [method.as_bytes(), b" ", target.as_bytes(), b" HTTP/1.1\r\n"];
    write_message(out, start, host, fields, None, (!no_content).then_some(framing))
}

/// Writes a head: the pieces of `start`, the field line of `first`, the field lines of `fields`,
/// the `connection` field of `connection`, the framing field of `framing`, and the empty line.
/// Refuses a field that is a framing field.
fn write_message<B: BufferMut, const N: usize>(
    out: &mut WriteLoan<B>,
    start: [&[u8]; N],
    first: Option<Field<'_>>,
    fields: &[Field<'_>],
    connection: Option<&[u8]>,
    framing: Option<Framing>,
) -> Result<(), WriteError> {
    let framing_field = |field: &Field<'_>| {
        field.name.eq_ignore_ascii_case(b"content-length") || field.name.eq_ignore_ascii_case(b"transfer-encoding")
    };
    if fields.iter().any(framing_field) {
        return Err(WriteError::FramingField);
    }
    let mut length_digits = [0; 20];
    let framing: [&[u8]; 3] = match framing {
        None | Some(Framing::Close) => [b"", b"", b""],
        Some(Framing::Length(length)) => [b"content-length: ", digits(length, 10, &mut length_digits), b"\r\n"],
        Some(Framing::Chunked) => [b"transfer-encoding: chunked\r\n", b"", b""],
    };
    write(out, |put| {
        for piece in start {
            put(piece);
        }
        for field in first.iter().chain(fields) {
            put(field.name);
            put(b": ");
            put(field.value);
            put(b"\r\n");
        }
        if let Some(option) = connection {
            put(b"connection: ");
            put(option);
            put(b"\r\n");
        }
        for piece in framing {
            put(piece);
        }
        put(b"\r\n");
    })
}

/// Writes the size line of a chunk of `len` bytes into `out`: the size in hexadecimal and CR LF.
///
/// The `len` bytes of the chunk come next, in `out` or in a region of their own, and then
/// [`end_chunk`]. Refuses, and writes nothing, if `out` has too little free capacity.
pub fn begin_chunk<B: BufferMut>(out: &mut WriteLoan<B>, len: NonZeroUsize) -> Result<(), WriteError> {
    let mut hex = [0; 20];
    let size = digits(len.get() as u64, 16, &mut hex);
    write(out, |put| {
        put(size);
        put(b"\r\n");
    })
}

/// Writes the CR LF that ends the bytes of a chunk into `out`. Refuses, and writes nothing, if
/// `out` has too little free capacity.
pub fn end_chunk<B: BufferMut>(out: &mut WriteLoan<B>) -> Result<(), WriteError> {
    write(out, |put| put(b"\r\n"))
}

/// Writes the last chunk and the trailer section of `trailers` into `out`: `0`, CR LF, the
/// trailer field lines in their order, and the empty line. With no trailer, it is `0\r\n\r\n`.
///
/// Refuses, and writes nothing, if a trailer is a framing field, or if `out` has too little free
/// capacity.
pub fn last_chunk<B: BufferMut>(out: &mut WriteLoan<B>, trailers: &[Field<'_>]) -> Result<(), WriteError> {
    write_message(out, [b"0\r\n"], None, trailers, None, None)
}

/// Writes the pieces that `pieces` gives into `out`, or refuses and writes nothing if they do not
/// fit. `pieces` runs two times: first to count the bytes, then to write them.
fn write<B: BufferMut>(out: &mut WriteLoan<B>, pieces: impl Fn(&mut dyn FnMut(&[u8]))) -> Result<(), WriteError> {
    let mut needed = 0_usize;
    pieces(&mut |piece| needed = needed.saturating_add(piece.len()));
    let available = out.capacity() - out.filled().len();
    if needed > available {
        return Err(WriteError::Full { needed, available });
    }
    pieces(&mut |piece| {
        out.fill_from(piece);
    });
    Ok(())
}

/// Writes `value` in `radix`, 10 or 16, at the end of `buf`, and gives the digits.
#[expect(
    clippy::cast_possible_truncation,
    reason = "a digit is less than the radix, which is at most 16"
)]
fn digits(mut value: u64, radix: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut start = buf.len();
    loop {
        start -= 1;
        buf[start] = b"0123456789abcdef"[(value % radix) as usize];
        value /= radix;
        if value == 0 {
            return &buf[start..];
        }
    }
}

/// A refusal to write. A refusal writes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output region has fewer free bytes than the write needs. Write into a region with at
    /// least `needed` free bytes.
    Full {
        /// The bytes that the write needs.
        needed: usize,
        /// The free bytes of the output region.
        available: usize,
    },
    /// A 1xx, 204, or 304 response has framing other than `Length(0)`.
    Status,
    /// A field is `Content-Length` or `Transfer-Encoding`. The framing argument writes the
    /// framing field.
    FramingField,
    /// The framing does not fit the message: a request cannot have `Close`.
    Framing,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { needed, available } => write!(
                f,
                "the write needs {needed} bytes, but the output region has only {available} free bytes"
            ),
            Self::Status => f.write_str("the status does not permit the framing"),
            Self::FramingField => f.write_str("a field is a framing field, which the framing argument writes"),
            Self::Framing => f.write_str("the framing does not fit the message"),
        }
    }
}

impl core::error::Error for WriteError {}
