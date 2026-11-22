//! The response head parser.

use core::fmt;

use rstypes::buffer::{Buffer as _, Lease};

use super::Framing;
use super::head::{Coding, Facts, Limits, ParseError, Search, offset, parse_version, scan, split_head, view_of};
use crate::message::{Fields, Version};
use crate::value::{Method, Status};

/// Parses HTTP/1.1 and HTTP/1.0 response heads in received bytes, with no copy and no
/// allocation.
///
/// Give [`parse`](Self::parse) all of the received bytes of a head each time that more arrive, as
/// for a [`RequestParser`](super::RequestParser).
#[derive(Clone, Debug)]
pub struct ResponseParser {
    limits: Limits,
    search: Search,
}

impl ResponseParser {
    /// Makes a parser for heads within `limits`.
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            search: Search::new(),
        }
    }

    /// Parses the response head at the start of `input`, for a request with `method`.
    ///
    /// The method decides the framing of some responses: a response to HEAD has no body, and a
    /// 2xx response to CONNECT starts a tunnel. Gives `Ok(None)` while the head is not complete,
    /// with the same rules as [`RequestParser::parse`](super::RequestParser::parse).
    pub fn parse<'a>(&mut self, input: &'a [u8], method: Method<'_>) -> Result<Option<ResponseHead<'a>>, ParseError> {
        match self.search.head(input, self.limits.head_bytes)? {
            Some(head) => check(head, &self.limits, method).map(Some),
            None => Ok(None),
        }
    }
}

/// Checks a complete head. `head` ends with its empty line, and each of its CRs is before an LF.
fn check<'a>(head: &'a [u8], limits: &Limits, method: Method<'_>) -> Result<ResponseHead<'a>, ParseError> {
    let (status_line, block) = split_head(head)?;
    // status-line = HTTP-version SP status-code SP [ reason-phrase ] (RFC 9112, section 4). The
    // parser also accepts no space after the status code, as sent by some servers.
    let (version, rest) = status_line.split_at_checked(8).ok_or(ParseError::Malformed)?;
    let version = parse_version(version)?;
    let [b' ', hundreds, tens, ones, rest @ ..] = rest else {
        return Err(ParseError::Malformed);
    };
    let digits = [*hundreds, *tens, *ones];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(ParseError::Malformed);
    }
    let code = digits
        .iter()
        .fold(0_u16, |code, &digit| code * 10 + u16::from(digit - b'0'));
    let status = Status::new(code).map_err(|_| ParseError::Malformed)?;
    let reason = match rest {
        [] => rest,
        [b' ', reason @ ..] => reason,
        _ => return Err(ParseError::Malformed),
    };
    // reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
    if !reason.iter().all(|&byte| byte == b'\t' || byte >= b' ' && byte != 0x7f) {
        return Err(ParseError::Malformed);
    }

    let facts = scan(block, limits)?;
    let framing = framing(version, status, method, &facts)?;
    Ok(ResponseHead {
        bytes: head,
        layout: Layout {
            status,
            reason: (offset(head, reason), offset(head, reason) + reason.len()),
            fields: offset(head, block),
            framing,
            version,
            persistent: !facts.close && framing != Framing::Close && (version == Version::Http11 || facts.keep_alive),
        },
    })
}

/// The framing of a response body (RFC 9112, section 6.3).
///
/// A response to HEAD, a 1xx, 204, or 304 response, and a 2xx response to CONNECT have no body,
/// whatever their framing fields say. Content-Length and Transfer-Encoding together refuse,
/// although RFC 9112 lets Transfer-Encoding win, because two readers can read two different
/// bodies. A Transfer-Encoding field in an HTTP/1.0 message makes its framing faulty (section
/// 6.1). A coding other than one `chunked` refuses, because the parser does not decode it. With no
/// framing field, the close of the connection ends the body.
fn framing(version: Version, status: Status, method: Method<'_>, facts: &Facts<'_>) -> Result<Framing, ParseError> {
    let code = status.code();
    let tunnel = method == Method::CONNECT && (200..300).contains(&code);
    if method == Method::HEAD || code < 200 || code == 204 || code == 304 || tunnel {
        return Ok(Framing::Length(0));
    }
    match (facts.coding, facts.length) {
        (None, Some(length)) => Ok(Framing::Length(length)),
        (None, None) => Ok(Framing::Close),
        (Some(_), _) if version == Version::Http10 => Err(ParseError::Framing),
        (Some(_), Some(_)) => Err(ParseError::Framing),
        (Some(Coding::Chunked), None) => Ok(Framing::Chunked),
        (Some(Coding::ChunkedLast | Coding::Other), None) => Err(ParseError::TransferCoding),
    }
}

/// A checked response head: views of the received bytes.
///
/// Its `Debug` output shows only the version, the status, the consumed length, and the framing,
/// because the reason and the fields are peer text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResponseHead<'a> {
    /// The head, from the first byte of the status line to the end of the empty line.
    bytes: &'a [u8],
    layout: Layout,
}

/// The positions of the checked parts of a head, from its first byte, and its facts.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Layout {
    status: Status,
    /// The start and the end of the reason phrase.
    reason: (usize, usize),
    /// The start of the field lines.
    fields: usize,
    framing: Framing,
    version: Version,
    persistent: bool,
}

impl<'a> ResponseHead<'a> {
    /// The status.
    pub fn status(&self) -> Status {
        self.layout.status
    }

    /// The reason phrase, as bytes. It can be empty. A client ignores it (RFC 9112, section 4).
    pub fn reason(&self) -> &'a [u8] {
        let (start, end) = self.layout.reason;
        &self.bytes[start..end]
    }

    /// The version of the response.
    pub fn version(&self) -> Version {
        self.layout.version
    }

    /// The field lines, in their received order. Repeated names stay as separate fields.
    pub fn fields(&self) -> Fields<'a> {
        Fields {
            block: &self.bytes[self.layout.fields..self.bytes.len() - 2],
        }
    }

    /// The number of bytes of the head, from the first byte of the input. The body starts there.
    pub fn consumed(&self) -> usize {
        self.bytes.len()
    }

    /// The framing of the body after the head.
    pub fn framing(&self) -> Framing {
        self.layout.framing
    }

    /// Whether the connection can carry another request after this response (RFC 9112, section
    /// 9.3): an HTTP/1.1 response with no `close` connection option, or an HTTP/1.0 response with
    /// the `keep-alive` option, and a body that the close of the connection does not end.
    pub fn persistent(&self) -> bool {
        self.layout.persistent
    }

    /// Keeps this head after the call, as a view of the backing of `region`, with no copy, as
    /// [`RequestHead::retain`](super::RequestHead::retain) does.
    pub fn retain(&self, region: &Lease) -> Option<RetainedResponse> {
        Some(RetainedResponse {
            region: view_of(region, self.bytes)?,
            layout: self.layout,
        })
    }
}

impl fmt::Debug for ResponseHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseHead")
            .field("version", &self.layout.version)
            .field("status", &self.layout.status)
            .field("consumed", &self.consumed())
            .field("framing", &self.layout.framing)
            .finish_non_exhaustive()
    }
}

/// A response head that keeps the backing of its received region alive, from
/// [`ResponseHead::retain`]. It holds one view of the backing, with no copy.
#[derive(Clone)]
pub struct RetainedResponse {
    /// A view of exactly the bytes of the head.
    region: Lease,
    layout: Layout,
}

impl RetainedResponse {
    /// The head, with its values as views of the retained bytes.
    pub fn head(&self) -> ResponseHead<'_> {
        ResponseHead {
            bytes: self.region.bytes(),
            layout: self.layout,
        }
    }
}

impl fmt::Debug for RetainedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RetainedResponse").field(&self.head()).finish()
    }
}
