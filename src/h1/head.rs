//! The parts that request and response heads share: the limits, the version, the end of a head,
//! the field lines and their facts, and the refusals.

use core::fmt;

use rstypes::buffer::{Buffer as _, Lease};

use crate::drive::{Error, Kind};
use crate::value::{Field, decimal};

/// The limits of one head, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest head, in bytes, from the first byte of the start line to the end of the empty
    /// line that ends the head.
    pub head_bytes: usize,
    /// The largest number of field lines in the head.
    pub fields: usize,
    /// The longest field name, in bytes.
    pub name_bytes: usize,
    /// The longest field value, in bytes, with no whitespace at its start or end.
    pub value_bytes: usize,
}

/// The version of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0 (RFC 9112, appendix C.2).
    Http10,
    /// HTTP/1.1.
    Http11,
}

impl Version {
    /// Reads `HTTP/1.0` or `HTTP/1.1`. Another version in the same syntax refuses as
    /// [`ParseError::Version`], and other bytes as [`ParseError::Malformed`].
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        match bytes {
            b"HTTP/1.1" => Ok(Self::Http11),
            b"HTTP/1.0" => Ok(Self::Http10),
            [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
                Err(ParseError::Version)
            }
            _ => Err(ParseError::Malformed),
        }
    }
}

/// Finds the end of a head in the bytes that arrive. It records how far it searched, so it
/// searches each byte one time, also when the bytes arrive one at a time.
#[derive(Clone, Debug)]
pub(super) struct Search {
    /// The number of bytes that earlier calls searched with no end of the head in them.
    searched: usize,
}

impl Search {
    pub(super) const fn new() -> Self {
        Self { searched: 0 }
    }

    /// Gives the complete head at the start of `input`, or `None` while it is not complete.
    ///
    /// Refuses a head that is longer than `limit` as soon as that many bytes have no end of the
    /// head in them. A line end that is not CR LF refuses as soon as it arrives. A complete head
    /// resets the search for the next head.
    pub(super) fn head<'a>(&mut self, input: &'a [u8], limit: usize) -> Result<Option<&'a [u8]>, ParseError> {
        let window = input.get(..limit).unwrap_or(input);
        let Some(end) = self.find_end(window)? else {
            if input.len() >= limit {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        };
        self.searched = 0;
        Ok(Some(&window[..end]))
    }

    /// Finds the end of the head in `window`: the position after its empty line. Refuses a CR
    /// that is not before an LF, and an LF that is not after a CR.
    fn find_end(&mut self, window: &[u8]) -> Result<Option<usize>, ParseError> {
        let start = self.searched.min(window.len());
        let mut previous = start.checked_sub(1).and_then(|at| window.get(at)).copied();
        for (at, &byte) in window.iter().enumerate().skip(start) {
            if byte == b'\n' {
                if previous != Some(b'\r') {
                    return Err(ParseError::Malformed);
                }
                if window[..=at].ends_with(b"\r\n\r\n") {
                    return Ok(Some(at + 1));
                }
            } else if previous == Some(b'\r') {
                return Err(ParseError::Malformed);
            }
            previous = Some(byte);
        }
        self.searched = window.len();
        Ok(None)
    }
}

/// Splits a complete head into its start line and its field lines, each with its CR LF.
pub(super) fn split_head(head: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let lines = head.strip_suffix(b"\r\n").unwrap_or(head);
    split_line(lines).ok_or(ParseError::Malformed)
}

/// The transfer codings of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Coding {
    /// Exactly one `chunked`, in one field line.
    Chunked,
    /// Codings that end with `chunked`, with one more coding before it.
    ChunkedLast,
    /// Codings that do not end with `chunked`.
    Other,
}

/// The facts that the field lines of a head give.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Facts<'a> {
    /// The value of the one Content-Length field.
    pub(super) length: Option<u64>,
    pub(super) coding: Option<Coding>,
    /// The value of the one Host field.
    pub(super) host: Option<&'a [u8]>,
    /// The Connection field has the `close` option.
    pub(super) close: bool,
    /// The Connection field has the `keep-alive` option.
    pub(super) keep_alive: bool,
    /// The Connection field has the `upgrade` option, and the head has an Upgrade field.
    pub(super) upgrade: bool,
    /// The Expect field is `100-continue`.
    pub(super) expect_continue: bool,
}

/// Checks each field line of `block` within `limits`, and gives their facts.
///
/// Refuses a second Content-Length field, a length that is not a `u64`, and a second Host field.
pub(super) fn scan<'a>(block: &'a [u8], limits: &Limits) -> Result<Facts<'a>, ParseError> {
    let mut facts = Facts::default();
    let mut count = 0_usize;
    let mut coding = None;
    let mut coding_lines = 0_usize;
    let (mut upgrade_option, mut upgrade_field) = (false, false);
    let mut rest = block;
    while let Some((line, next)) = split_line(rest) {
        rest = next;
        count += 1;
        if count > limits.fields {
            return Err(ParseError::TooManyFields);
        }
        let (name, value) = field_parts(line).ok_or(ParseError::Malformed)?;
        if name.len() > limits.name_bytes || value.len() > limits.value_bytes {
            return Err(ParseError::FieldTooLarge);
        }
        let field = Field::new(name, value).map_err(|_| ParseError::Malformed)?;
        let named = |known: &[u8]| field.name.eq_ignore_ascii_case(known);
        if named(b"content-length") {
            if facts.length.is_some() {
                return Err(ParseError::Framing);
            }
            facts.length = Some(decimal(field.value).ok_or(ParseError::Framing)?);
        } else if named(b"transfer-encoding") {
            coding = Some(field.value);
            coding_lines += 1;
        } else if named(b"host") {
            if facts.host.replace(field.value).is_some() {
                return Err(ParseError::Malformed);
            }
        } else if named(b"connection") {
            for option in list(field.value) {
                facts.close |= option.eq_ignore_ascii_case(b"close");
                facts.keep_alive |= option.eq_ignore_ascii_case(b"keep-alive");
                upgrade_option |= option.eq_ignore_ascii_case(b"upgrade");
            }
        } else if named(b"upgrade") {
            upgrade_field = true;
        } else if named(b"expect") {
            facts.expect_continue |= field.value.eq_ignore_ascii_case(b"100-continue");
        }
    }
    facts.upgrade = upgrade_option && upgrade_field;
    facts.coding = coding.map(|value| {
        if coding_lines == 1 && value.eq_ignore_ascii_case(b"chunked") {
            Coding::Chunked
        } else if list(value)
            .next_back()
            .is_some_and(|last| last.eq_ignore_ascii_case(b"chunked"))
        {
            Coding::ChunkedLast
        } else {
            Coding::Other
        }
    });
    Ok(facts)
}

/// The elements of a comma-separated list, with no whitespace around them and no empty element
/// (RFC 9110, section 5.6.1).
fn list(value: &[u8]) -> impl DoubleEndedIterator<Item = &[u8]> {
    value
        .split(|&byte| byte == b',')
        .map(trim_whitespace)
        .filter(|element| !element.is_empty())
}

/// Splits the first line from `bytes` at its LF. The line has no CR LF.
pub(super) fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let lf = bytes.iter().position(|&byte| byte == b'\n')?;
    let line = &bytes[..lf];
    Some((line.strip_suffix(b"\r").unwrap_or(line), &bytes[lf + 1..]))
}

/// Splits a field line at its first colon into the name and the value with no whitespace around it.
fn field_parts(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.iter().position(|&byte| byte == b':')?;
    Some((&line[..colon], trim_whitespace(&line[colon + 1..])))
}

/// Removes the spaces and HTABs at the start and at the end of `bytes`.
fn trim_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// The position of `part` in `head`, of which it is a part.
pub(super) fn offset(head: &[u8], part: &[u8]) -> usize {
    part.as_ptr().addr() - head.as_ptr().addr()
}

/// A view of exactly the bytes of `head` in `region`, or `None` if they are not in its bytes.
pub(super) fn view_of(region: &Lease, head: &[u8]) -> Option<Lease> {
    let start = head.as_ptr().addr().checked_sub(region.as_ptr().addr())?;
    region.view(start..start.checked_add(head.len())?)
}

/// An iterator over the field lines of a head, in their received order.
#[derive(Clone)]
pub struct Fields<'a> {
    /// The field lines that remain, each with its CR LF. The parser checked each of them.
    pub(super) block: &'a [u8],
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        let (line, rest) = split_line(self.block)?;
        self.block = rest;
        let (name, value) = field_parts(line)?;
        Some(Field { name, value })
    }
}

impl fmt::Debug for Fields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fields").finish_non_exhaustive()
    }
}

/// A refusal of a head.
///
/// The connection cannot continue after a refusal, because the end of the message is not known.
/// A server sends the response that the variant names, and then closes the connection. A client
/// closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The head is longer than [`Limits::head_bytes`]. Respond with 431.
    HeadTooLarge,
    /// The head has more field lines than [`Limits::fields`]. Respond with 431.
    TooManyFields,
    /// A field name is longer than [`Limits::name_bytes`], or a field value is longer than
    /// [`Limits::value_bytes`]. Respond with 431.
    FieldTooLarge,
    /// The start line, a field line, or a line end does not obey RFC 9112. Or the method does not
    /// permit the form of the target, or the Host fields of the request are not valid for its
    /// version. Respond with 400.
    Malformed,
    /// The version is not HTTP/1.0 or HTTP/1.1. Respond with 505.
    Version,
    /// The body framing is not clear: both `Content-Length` and `Transfer-Encoding`, more than one
    /// `Content-Length`, a length that is not a `u64`, codings that do not end with `chunked` in a
    /// request, or a `Transfer-Encoding` in an HTTP/1.0 message. Respond with 400.
    Framing,
    /// The message has a transfer coding other than `chunked`, which this parser does not decode.
    /// Respond with 501.
    TransferCoding,
}

impl ParseError {
    /// The fixed text of the refusal.
    pub(super) const fn reason(self) -> &'static str {
        match self {
            Self::HeadTooLarge => "the head is longer than its limit",
            Self::TooManyFields => "the head has more field lines than its limit",
            Self::FieldTooLarge => "a field name or a field value is longer than its limit",
            Self::Malformed => "the head does not obey the HTTP/1.1 syntax",
            Self::Version => "the version is not HTTP/1.0 or HTTP/1.1",
            Self::Framing => "the body framing is not clear",
            Self::TransferCoding => "the message uses a transfer coding other than chunked",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

/// A head over a limit is an overload, a version or a coding that the parser does not have is
/// unsupported, and each other refusal is malformed peer input.
impl From<ParseError> for Error {
    fn from(error: ParseError) -> Self {
        let kind = match error {
            ParseError::HeadTooLarge | ParseError::TooManyFields | ParseError::FieldTooLarge => Kind::Overload,
            ParseError::Version | ParseError::TransferCoding => Kind::Unsupported,
            ParseError::Malformed | ParseError::Framing => Kind::Malformed,
        };
        Self::new(kind, error.reason())
    }
}

impl core::error::Error for ParseError {}
