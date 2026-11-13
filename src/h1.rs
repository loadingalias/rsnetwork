//! HTTP/1.1 for servers, with no I/O: a request head parser and a response head writer.
//!
//! The caller receives bytes into its own region and gives them to a [`RequestParser`]. The
//! parser reads them in place and allocates nothing. A complete head gives the checked method,
//! target, and field lines as views of the received bytes, the exact number of bytes that the
//! head consumed, and the [`Framing`] of the body that follows it. The body and any next request
//! stay in the received region, at their offsets after the head.
//!
//! [`write_head`] writes a response head and its framing field into the free capacity of an owned
//! output region, through a [`WriteLoan`]. [`begin_chunk`], [`end_chunk`], and [`last_chunk`]
//! write the framing of a chunked body. The chunk bytes can follow in the same region or stay in
//! a region of their own.
//!
//! ```
//! use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
//! use rsnetwork::h1::{Field, Framing, Limits, RequestParser, write_head};
//!
//! let mut parser = RequestParser::new(Limits { head_bytes: 8 * 1024, fields: 64 });
//!
//! // The bytes of a request arrive in two receives into one region.
//! let mut received = WriteLoan::new(Vec::with_capacity(8 * 1024));
//! received.fill_from(b"PUT /notes/7 HTTP/1.1\r\nHost: exa");
//! assert!(parser.parse(received.filled())?.is_none()); // not complete: receive more
//! received.fill_from(b"mple.com\r\nContent-Length: 5\r\n\r\nhello");
//!
//! // Freeze the region. Views of a `Lease` can go to other owners with no copy.
//! let received = Lease::from(received.into_inner());
//! let head = parser.parse(received.bytes())?.expect("the head is complete");
//! assert_eq!(head.method(), b"PUT");
//! assert_eq!(head.target(), b"/notes/7");
//! let host = head.fields().find(|field| field.name().eq_ignore_ascii_case(b"host"));
//! assert_eq!(host.map(|field| field.value()), Some(&b"example.com"[..]));
//!
//! // The body follows the head in the same region.
//! assert_eq!(head.framing(), Framing::Length(5));
//! let body = received.view(head.consumed()..head.consumed() + 5).expect("the body is in the region");
//! assert_eq!(body.bytes(), b"hello");
//!
//! // Write the response head into the free capacity of an owned region, then the body after it.
//! let mut out = WriteLoan::new(Vec::with_capacity(256));
//! let fields = [Field::new(b"Content-Type", b"text/plain")?];
//! write_head(&mut out, 200, &fields, Framing::Length(2))?;
//! out.fill_from(b"ok");
//! assert_eq!(out.into_inner(), b"HTTP/1.1 200 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! This part of the core is for servers. It accepts HTTP/1.1 requests only. It does not check the
//! `Host` field, decode chunks, read trailers, or apply a keepalive policy.
//!
//! [`WriteLoan`]: crate::buffer::WriteLoan

use core::fmt;

mod parse;
mod write;

pub use parse::{Fields, Limits, ParseError, RequestHead, RequestParser};
pub use write::{WriteError, begin_chunk, end_chunk, last_chunk, write_head};

/// The framing of a message body: how its end is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// The body has exactly this many bytes. A request with no framing field has `Length(0)`.
    Length(u64),
    /// The body is a sequence of chunks, and a chunk of size zero ends it.
    Chunked,
}

/// One checked field line: a name and a value, as bytes.
///
/// The name is a token (RFC 9110, section 5.1), in the case that it was given or received. The
/// value has no CR, LF, NUL, or other control byte except HTAB, and no whitespace at its start or
/// end (RFC 9110, section 5.5). Bytes above 0x7F stay as they are.
///
/// Its `Debug` output shows neither the name nor the value, because they can be credentials or
/// other peer text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> Field<'a> {
    /// Checks a field line, or refuses it.
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Result<Self, InvalidField> {
        let edge = |byte: Option<&u8>| matches!(byte, Some(b' ' | b'\t'));
        let value_ok = !edge(value.first())
            && !edge(value.last())
            && value
                .iter()
                .all(|&byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f));
        if is_token(name) && value_ok {
            Ok(Self { name, value })
        } else {
            Err(InvalidField)
        }
    }

    /// The name, in the case that it was given or received. Compare names with
    /// [`eq_ignore_ascii_case`](slice::eq_ignore_ascii_case), because the case has no meaning.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The value, as bytes.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field").finish_non_exhaustive()
    }
}

/// A refusal of [`Field::new`]: the name is not a token, or the value has a forbidden byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidField;

impl fmt::Display for InvalidField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the field name is not a token, or the field value has a forbidden byte")
    }
}

impl core::error::Error for InvalidField {}

/// Whether `bytes` is a token: one or more of the characters of RFC 9110, section 5.6.2.
fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
}

#[cfg(test)]
mod tests;
