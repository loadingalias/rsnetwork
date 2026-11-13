//! The response head writer and the chunk framing.

use core::fmt;
use core::num::NonZeroUsize;

use rstypes::buffer::{BufferMut, WriteLoan};

use super::{Field, Framing};

/// Writes a response head into the free capacity of `out`, after the bytes that it holds.
///
/// The head is the status line `HTTP/1.1 <status> `, the field lines of `fields` in their order,
/// the framing field, and the empty line. The status line has no reason phrase, which RFC 9112,
/// section 4, permits. `Length(n)` writes `content-length: n`, and `Chunked` writes
/// `transfer-encoding: chunked`. A 204 or 304 response has no body: give `Length(0)`, and the
/// head then has no framing field, as RFC 9110, section 8.6, requires.
///
/// Refuses, and writes nothing, if the status is not in 200 to 599, if a 204 or 304 has other
/// framing, if a field is a framing field, or if `out` has too little free capacity.
pub fn write_head<B: BufferMut>(
    out: &mut WriteLoan<B>,
    status: u16,
    fields: &[Field<'_>],
    framing: Framing,
) -> Result<(), WriteError> {
    let no_body = matches!(status, 204 | 304);
    if !(200..=599).contains(&status) || (no_body && framing != Framing::Length(0)) {
        return Err(WriteError::Status);
    }
    let framing_field = |field: &Field<'_>| {
        field.name.eq_ignore_ascii_case(b"content-length") || field.name.eq_ignore_ascii_case(b"transfer-encoding")
    };
    if fields.iter().any(framing_field) {
        return Err(WriteError::FramingField);
    }
    let mut status_digits = [0; 20];
    let status = digits(u64::from(status), 10, &mut status_digits);
    let mut length_digits = [0; 20];
    let framing: [&[u8]; 3] = match framing {
        _ if no_body => [b"", b"", b""],
        Framing::Length(length) => [b"content-length: ", digits(length, 10, &mut length_digits), b"\r\n"],
        Framing::Chunked => [b"transfer-encoding: chunked\r\n", b"", b""],
    };
    write(out, |put| {
        put(b"HTTP/1.1 ");
        put(status);
        put(b" \r\n");
        for field in fields {
            put(field.name);
            put(b": ");
            put(field.value);
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

/// Writes the last chunk, which ends a chunked body with no trailer, into `out`. Refuses, and
/// writes nothing, if `out` has too little free capacity.
pub fn last_chunk<B: BufferMut>(out: &mut WriteLoan<B>) -> Result<(), WriteError> {
    write(out, |put| put(b"0\r\n\r\n"))
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
    /// The status is not in 200 to 599, or a 204 or 304 response has framing other than
    /// `Length(0)`.
    Status,
    /// A field is `Content-Length` or `Transfer-Encoding`. The framing argument writes the
    /// framing field.
    FramingField,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { needed, available } => write!(
                f,
                "the write needs {needed} bytes, but the output region has only {available} free bytes"
            ),
            Self::Status => f.write_str("the status is not in 200 to 599, or it does not permit the framing"),
            Self::FramingField => f.write_str("a field is a framing field, which the framing argument writes"),
        }
    }
}

impl core::error::Error for WriteError {}
