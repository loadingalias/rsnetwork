//! The request head parser.

use core::fmt;

use super::{Field, Framing, is_token};

/// The limits of one request head, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest head, in bytes, from the first byte of the request line to the end of the
    /// empty line that ends the head.
    pub head_bytes: usize,
    /// The largest number of field lines in the head.
    pub fields: usize,
}

/// Parses HTTP/1.1 request heads in received bytes, with no copy and no allocation.
///
/// Give [`parse`](Self::parse) all of the received bytes of a head each time that more arrive.
/// The parser records how far it searched for the end of the head. Thus each byte is searched one
/// time, also when the bytes arrive one at a time.
#[derive(Clone, Debug)]
pub struct RequestParser {
    limits: Limits,
    /// The number of bytes that earlier calls searched with no end of the head in them.
    searched: usize,
}

impl RequestParser {
    /// Makes a parser for heads within `limits`.
    pub const fn new(limits: Limits) -> Self {
        Self { limits, searched: 0 }
    }

    /// Parses the request head at the start of `input`.
    ///
    /// Gives `Ok(None)` while the head is not complete. Then receive more bytes after `input` and
    /// call again with all of them: the same bytes as before, with the new bytes after them. A
    /// complete head resets the parser for the next head, which starts at the first byte of the
    /// next input.
    ///
    /// Refuses a head that is longer than [`Limits::head_bytes`] as soon as that many bytes have
    /// no end of the head in them. A line end that is not CR LF refuses as soon as it arrives.
    pub fn parse<'a>(&mut self, input: &'a [u8]) -> Result<Option<RequestHead<'a>>, ParseError> {
        let window = input.get(..self.limits.head_bytes).unwrap_or(input);
        let Some(end) = self.find_end(window)? else {
            if input.len() >= self.limits.head_bytes {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        };
        self.searched = 0;
        check(&window[..end], self.limits.fields).map(Some)
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

/// Checks a complete head. `head` ends with its empty line, and each of its CRs is before an LF.
fn check(head: &[u8], max_fields: usize) -> Result<RequestHead<'_>, ParseError> {
    let lines = head.strip_suffix(b"\r\n").unwrap_or(head);
    let (request_line, block) = split_line(lines).ok_or(ParseError::Malformed)?;
    let mut parts = request_line.splitn(3, |&byte| byte == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ParseError::Malformed);
    };
    if !is_token(method) || target.is_empty() || !target.iter().all(u8::is_ascii_graphic) {
        return Err(ParseError::Malformed);
    }
    if version != b"HTTP/1.1" {
        return Err(match version {
            [b'H', b'T', b'T', b'P', b'/', major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => {
                ParseError::Version
            }
            _ => ParseError::Malformed,
        });
    }

    let mut count = 0;
    let mut length = None;
    let mut coding = None;
    let mut coding_lines = 0_usize;
    let mut rest = block;
    while let Some((line, next)) = split_line(rest) {
        rest = next;
        count += 1;
        if count > max_fields {
            return Err(ParseError::TooManyFields);
        }
        let (name, value) = field_parts(line).ok_or(ParseError::Malformed)?;
        let field = Field::new(name, value).map_err(|_| ParseError::Malformed)?;
        if field.name.eq_ignore_ascii_case(b"content-length") {
            if length.is_some() {
                return Err(ParseError::Framing);
            }
            length = Some(decimal(field.value).ok_or(ParseError::Framing)?);
        } else if field.name.eq_ignore_ascii_case(b"transfer-encoding") {
            coding = Some(field.value);
            coding_lines += 1;
        }
    }

    let framing = match (coding, length) {
        (None, length) => Framing::Length(length.unwrap_or(0)),
        (Some(_), Some(_)) => return Err(ParseError::Framing),
        (Some(value), None) if coding_lines == 1 && value.eq_ignore_ascii_case(b"chunked") => Framing::Chunked,
        (Some(value), None) => {
            let last = value.rsplit(|&byte| byte == b',').next().map(trim_whitespace);
            return Err(if last.is_some_and(|last| last.eq_ignore_ascii_case(b"chunked")) {
                ParseError::TransferCoding
            } else {
                ParseError::Framing
            });
        }
    };
    Ok(RequestHead {
        method,
        target,
        fields: block,
        consumed: head.len(),
        framing,
    })
}

/// Splits the first line from `bytes` at its LF. The line has no CR LF.
fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
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

/// The value of one or more decimal digits, if it fits in a `u64`.
fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, &digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

/// A checked HTTP/1.1 request head: views of the received bytes.
///
/// Its `Debug` output shows only the consumed length and the framing, because the method, the
/// target, and the fields are peer text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestHead<'a> {
    method: &'a [u8],
    target: &'a [u8],
    /// The field lines, each with its CR LF.
    fields: &'a [u8],
    consumed: usize,
    framing: Framing,
}

impl<'a> RequestHead<'a> {
    /// The method, a token. Its case is significant, and an unknown method stays as it is.
    pub fn method(&self) -> &'a [u8] {
        self.method
    }

    /// The request target: one or more visible ASCII bytes.
    pub fn target(&self) -> &'a [u8] {
        self.target
    }

    /// The field lines, in their received order. Repeated names stay as separate fields.
    ///
    /// Each call reads the checked field lines again. It allocates nothing.
    pub fn fields(&self) -> Fields<'a> {
        Fields { block: self.fields }
    }

    /// The number of bytes of the head, from the first byte of the input. The body starts there.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// The framing of the body after the head.
    pub fn framing(&self) -> Framing {
        self.framing
    }
}

impl fmt::Debug for RequestHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("consumed", &self.consumed)
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

/// An iterator over the field lines of a [`RequestHead`].
#[derive(Clone)]
pub struct Fields<'a> {
    /// The field lines that remain, each with its CR LF. The parser checked each of them.
    block: &'a [u8],
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

/// A refusal of a request head.
///
/// The connection cannot continue after a refusal, because the end of the request is not known.
/// Send the response that the variant names, and then close the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The head is longer than [`Limits::head_bytes`]. Respond with 431.
    HeadTooLarge,
    /// The head has more field lines than [`Limits::fields`]. Respond with 431.
    TooManyFields,
    /// The request line, a field line, or a line end does not obey RFC 9112. Respond with 400.
    Malformed,
    /// The version is not HTTP/1.1. Respond with 505.
    Version,
    /// The body framing is not clear: both `Content-Length` and `Transfer-Encoding`, more than one
    /// `Content-Length`, a length that is not a `u64`, or codings that do not end with `chunked`.
    /// Respond with 400.
    Framing,
    /// The codings end with `chunked`, but they have one more coding, which this parser does not
    /// decode. Respond with 501.
    TransferCoding,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HeadTooLarge => "the request head is longer than its limit",
            Self::TooManyFields => "the request head has more field lines than its limit",
            Self::Malformed => "the request head does not obey the HTTP/1.1 syntax",
            Self::Version => "the request version is not HTTP/1.1",
            Self::Framing => "the request body framing is not clear",
            Self::TransferCoding => "the request uses a transfer coding other than chunked",
        })
    }
}

impl core::error::Error for ParseError {}
