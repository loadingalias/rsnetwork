//! The parts that request and response heads share: the limits, the version, the end of a head,
//! the field lines and their facts, and the refusals.

use core::fmt;

use rstypes::buffer::{Buffer as _, Lease};

use crate::drive::{Error, Kind};
use crate::message::Version;
use crate::value::{Field, Status, byte_position, decimal, field_text_len, is_token};

/// The limits of one head, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest head, in bytes, from the first byte of the start line to the end of the empty
    /// line that ends the head. For the server, the empty lines before a request line count too.
    pub head_bytes: usize,
    /// The largest number of field lines in the head.
    pub fields: usize,
    /// The longest field name, in bytes.
    pub name_bytes: usize,
    /// The longest field value, in bytes, with no whitespace at its start or end.
    pub value_bytes: usize,
}

/// The limits of the body of one message and of a connection's drain, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyLimits {
    /// The largest body, in bytes: its Content-Length, or the sum of its chunk sizes.
    pub body_bytes: u64,
    /// The most unread body bytes that an engine reads and discards to reuse the connection.
    /// Above it, the engine closes the connection.
    pub drain_bytes: u64,
    /// The longest chunk extensions of one chunk line, in bytes.
    pub extension_bytes: usize,
    /// The largest trailer section, in bytes, from its first field line to the end of its empty
    /// line.
    pub trailer_bytes: usize,
    /// The largest number of trailer field lines.
    pub trailer_fields: usize,
}

/// Reads `HTTP/1.0` or `HTTP/1.1`. Another version in the same syntax refuses as
/// [`ParseError::Version`], and other bytes as [`ParseError::Malformed`].
pub(super) fn parse_version(bytes: &[u8]) -> Result<Version, ParseError> {
    match bytes {
        b"HTTP/1.1" => Ok(Version::Http11),
        b"HTTP/1.0" => Ok(Version::Http10),
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
            Err(ParseError::Version)
        }
        _ => Err(ParseError::Malformed),
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

    /// Parses a complete head directly. On a partial head, resume the line-end search on each arrival.
    pub(super) fn parse<'a, T>(
        &mut self,
        input: &'a [u8],
        limit: usize,
        check: impl FnOnce(&'a [u8]) -> Result<T, ParseError>,
    ) -> Result<Option<T>, ParseError> {
        if self.searched == 0 {
            let window = input.get(..limit).unwrap_or(input);
            return match check(window) {
                Ok(head) => Ok(Some(head)),
                // Report grammar errors only after a full head. Line-end and size errors take precedence.
                Err(error) => self.head(input, limit)?.map(|_| Err(error)).transpose(),
            };
        }
        self.head(input, limit)?.map(check).transpose()
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
        let mut rest = &window[self.searched.min(window.len())..];
        while let Some((&byte, tail)) = rest.split_first() {
            let at = window.len() - rest.len();
            if window[..at].ends_with(b"\r") {
                if byte != b'\n' {
                    return Err(ParseError::Malformed);
                }
                if window[..at].ends_with(b"\r\n\r") {
                    return Ok(Some(at + 1));
                }
                rest = tail;
            } else if byte == b'\n' {
                return Err(ParseError::Malformed);
            } else {
                rest = &rest[byte_position(rest, |b| (b == b'\r') | (b == b'\n')).max(1)..];
            }
        }
        self.searched = window.len();
        Ok(None)
    }
}

/// Splits off a line at CR LF. Its caller checks the grammar of the line.
pub(super) fn raw_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (line, rest) = bytes.split_once(|&byte| byte == b'\n')?;
    Some((line.strip_suffix(b"\r")?, rest))
}

/// The transfer codings of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Coding {
    /// Exactly one coding, `chunked`.
    Chunked,
    /// Codings that end with `chunked`, with more codings before it.
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

/// Checks the fields through the empty line. Gives their facts and the bytes after the head.
///
/// Refuses a second Content-Length field, a length that is not a `u64`, and a second Host field.
pub(super) fn scan<'a>(mut rest: &'a [u8], limits: &Limits) -> Result<(Facts<'a>, &'a [u8]), ParseError> {
    let mut facts = Facts::default();
    let mut count = 0_usize;
    // The codings of each Transfer-Encoding field line, as one list (RFC 9110, section 5.3).
    let (mut coded, mut codings, mut last) = (false, 0_usize, None);
    let (mut upgrade_option, mut upgrade_field) = (false, false);
    while !rest.starts_with(b"\r\n") {
        count += 1;
        if count > limits.fields {
            return Err(ParseError::TooManyFields);
        }
        let (text, end) = rest.split_at(field_text_len(rest));
        let checked = end.strip_prefix(b"\r\n");
        // An oversized field keeps its size error even when its text contains a forbidden byte.
        let (line, next) = checked
            .map(|next| (text, next))
            .or_else(|| raw_line(rest))
            .ok_or(ParseError::Malformed)?;
        rest = next;
        let (name, value) = field_parts(line).ok_or(ParseError::Malformed)?;
        if name.len() > limits.name_bytes || value.len() > limits.value_bytes {
            return Err(ParseError::FieldTooLarge);
        }
        if checked.is_none() || !is_token(name) {
            return Err(ParseError::Malformed);
        }
        let named = |known: &[u8]| name.eq_ignore_ascii_case(known);
        if named(b"content-length") {
            if facts.length.is_some() {
                return Err(ParseError::Framing);
            }
            facts.length = Some(decimal(value).ok_or(ParseError::Framing)?);
        } else if named(b"transfer-encoding") {
            coded = true;
            for coding in list(value) {
                codings += 1;
                last = Some(coding);
            }
        } else if named(b"host") {
            if facts.host.replace(value).is_some() {
                return Err(ParseError::Malformed);
            }
        } else if named(b"connection") {
            for option in list(value) {
                facts.close |= option.eq_ignore_ascii_case(b"close");
                facts.keep_alive |= option.eq_ignore_ascii_case(b"keep-alive");
                upgrade_option |= option.eq_ignore_ascii_case(b"upgrade");
            }
        } else if named(b"upgrade") {
            upgrade_field = true;
        } else if named(b"expect") {
            facts.expect_continue |= value.eq_ignore_ascii_case(b"100-continue");
        }
    }
    facts.upgrade = upgrade_option && upgrade_field;
    facts.coding = coded.then(|| match last {
        Some(last) if last.eq_ignore_ascii_case(b"chunked") && codings == 1 => Coding::Chunked,
        Some(last) if last.eq_ignore_ascii_case(b"chunked") => Coding::ChunkedLast,
        _ => Coding::Other,
    });
    Ok((facts, &rest[2..]))
}

/// The elements of a comma-separated list, with no whitespace around them and no empty element
/// (RFC 9110, section 5.6.1).
fn list(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|&byte| byte == b',')
        .map(trim_whitespace)
        .filter(|element| !element.is_empty())
}

/// Takes one field from a block that the protocol has already checked.
pub(crate) fn next_field<'a>(block: &mut &'a [u8]) -> Option<Field<'a>> {
    let (name, rest) = block.split_once(|&byte| byte == b':')?;
    let (value, end) = rest.split_at(byte_position(rest, |b| b == b'\r'));
    *block = end.strip_prefix(b"\r\n")?;
    Some(Field {
        name,
        value: trim_whitespace(value),
    })
}

/// Splits a field line at its first colon into the name and the value with no whitespace around it.
fn field_parts(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let (name, value) = line.split_once(|&byte| byte == b':')?;
    Some((name, trim_whitespace(value)))
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

/// A refusal of a head.
///
/// The connection cannot continue after a refusal, because the end of the message is not known.
/// A server sends the response that the variant names, and then closes the connection. A client
/// closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The head is longer than [`Limits::head_bytes`], or the trailer section is longer than
    /// [`BodyLimits::trailer_bytes`]. Respond with 431.
    HeadTooLarge,
    /// The head has more field lines than [`Limits::fields`], or the trailer section has more
    /// than [`BodyLimits::trailer_fields`]. Respond with 431.
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
    /// request, a `Transfer-Encoding` in an HTTP/1.0 message, or a framing field in a trailer
    /// section. Respond with 400.
    Framing,
    /// The message has a transfer coding other than `chunked`, which this parser does not decode.
    /// Respond with 501.
    TransferCoding,
    /// The body is longer than [`BodyLimits::body_bytes`]. Respond with 413.
    BodyTooLarge,
    /// The chunk extensions of a chunk line are longer than [`BodyLimits::extension_bytes`].
    /// Respond with 400.
    ExtensionTooLarge,
}

impl ParseError {
    /// The status of the response that a server sends for the refusal, before it closes the
    /// connection.
    pub const fn status(self) -> Status {
        Status(match self {
            Self::HeadTooLarge | Self::TooManyFields | Self::FieldTooLarge => 431,
            Self::Malformed | Self::Framing | Self::ExtensionTooLarge => 400,
            Self::Version => 505,
            Self::TransferCoding => 501,
            Self::BodyTooLarge => 413,
        })
    }

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
            Self::BodyTooLarge => "the body is longer than its limit",
            Self::ExtensionTooLarge => "the chunk extensions are longer than their limit",
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
            ParseError::HeadTooLarge
            | ParseError::TooManyFields
            | ParseError::FieldTooLarge
            | ParseError::BodyTooLarge
            | ParseError::ExtensionTooLarge => Kind::Overload,
            ParseError::Version | ParseError::TransferCoding => Kind::Unsupported,
            ParseError::Malformed | ParseError::Framing => Kind::Malformed,
        };
        Self::new(kind, error.reason())
    }
}

impl core::error::Error for ParseError {}
