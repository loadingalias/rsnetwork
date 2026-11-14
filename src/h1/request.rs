//! The request head parser.

use core::fmt;

use rstypes::buffer::{Buffer as _, Lease};

use super::Framing;
use super::head::{Coding, Facts, Fields, Limits, ParseError, Search, Version, offset, scan, split_head, view_of};
use crate::value::{Authority, Method, Target, TargetForm};

/// Parses HTTP/1.1 and HTTP/1.0 request heads in received bytes, with no copy and no allocation.
///
/// Give [`parse`](Self::parse) all of the received bytes of a head each time that more arrive.
/// The parser records how far it searched for the end of the head. Thus each byte is searched one
/// time, also when the bytes arrive one at a time.
#[derive(Clone, Debug)]
pub struct RequestParser {
    limits: Limits,
    search: Search,
}

impl RequestParser {
    /// Makes a parser for heads within `limits`.
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            search: Search::new(),
        }
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
        match self.search.head(input, self.limits.head_bytes)? {
            Some(head) => check(head, &self.limits).map(Some),
            None => Ok(None),
        }
    }
}

/// Checks a complete head. `head` ends with its empty line, and each of its CRs is before an LF.
fn check<'a>(head: &'a [u8], limits: &Limits) -> Result<RequestHead<'a>, ParseError> {
    let (request_line, block) = split_head(head)?;
    let mut parts = request_line.splitn(3, |&byte| byte == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ParseError::Malformed);
    };
    let (Ok(method), Ok(target)) = (Method::new(method), Target::new(target)) else {
        return Err(ParseError::Malformed);
    };
    let version = Version::parse(version)?;
    // Only CONNECT has the authority form, and only OPTIONS has the asterisk form (RFC 9112,
    // section 3.2). A CONNECT request has the authority form (RFC 9110, section 9.3.6).
    let form = target.form();
    let form_ok = match form {
        TargetForm::Authority(_) => method == Method::CONNECT,
        TargetForm::Asterisk => method == Method::OPTIONS,
        TargetForm::Origin { .. } | TargetForm::Absolute { .. } => method != Method::CONNECT,
    };
    if !form_ok {
        return Err(ParseError::Malformed);
    }

    let facts = scan(block, limits)?;
    let framing = framing(version, &facts)?;
    // The Host point. An HTTP/1.1 request has one Host field, and an HTTP/1.0 request has one or
    // none (RFC 9112, section 3.2, and appendix C.2). Its value is an authority. A target with an
    // authority gives the authority of the request, and the Host value then has no effect (RFC
    // 9112, sections 3.2.2 and 3.3).
    let host = match (facts.host, version) {
        (Some(value), _) => Some(Authority::new(value).map_err(|_| ParseError::Malformed)?),
        (None, Version::Http10) => None,
        (None, Version::Http11) => return Err(ParseError::Malformed),
    };
    let authority = match form {
        TargetForm::Absolute { authority, .. } | TargetForm::Authority(authority) => Some(authority),
        TargetForm::Origin { .. } | TargetForm::Asterisk => host,
    };
    let span = |part: &[u8]| (offset(head, part), offset(head, part) + part.len());
    Ok(RequestHead {
        bytes: head,
        layout: Layout {
            method: method.as_bytes().len(),
            target: span(target.as_bytes()),
            fields: offset(head, block),
            authority: authority.map(|authority| span(authority.as_bytes())),
            framing,
            version,
            persistent: !facts.close && (version == Version::Http11 || facts.keep_alive),
            expect_continue: facts.expect_continue,
            upgrade: facts.upgrade,
        },
    })
}

/// The framing of a request body (RFC 9112, section 6.3).
///
/// A Transfer-Encoding field in an HTTP/1.0 message makes its framing faulty (RFC 9112, section
/// 6.1). Content-Length and Transfer-Encoding together refuse, because two readers can read two
/// different bodies. Codings that do not end with `chunked` refuse, and other codings before
/// `chunked` are not decoded.
fn framing(version: Version, facts: &Facts<'_>) -> Result<Framing, ParseError> {
    match (facts.coding, facts.length) {
        (None, length) => Ok(Framing::Length(length.unwrap_or(0))),
        (Some(_), _) if version == Version::Http10 => Err(ParseError::Framing),
        (Some(_), Some(_)) | (Some(Coding::Other), None) => Err(ParseError::Framing),
        (Some(Coding::Chunked), None) => Ok(Framing::Chunked),
        (Some(Coding::ChunkedLast), None) => Err(ParseError::TransferCoding),
    }
}

/// A checked request head: views of the received bytes.
///
/// Its `Debug` output shows only the version, the consumed length, and the framing, because the
/// method, the target, and the fields are peer text.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestHead<'a> {
    /// The head, from the first byte of the request line to the end of the empty line.
    bytes: &'a [u8],
    layout: Layout,
}

/// The positions of the checked parts of a head, from its first byte, and its facts.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Layout {
    /// The end of the method, which starts at the first byte.
    method: usize,
    /// The start and the end of the target.
    target: (usize, usize),
    /// The start of the field lines.
    fields: usize,
    /// The start and the end of the authority: in the target, or in the Host field.
    authority: Option<(usize, usize)>,
    framing: Framing,
    version: Version,
    persistent: bool,
    expect_continue: bool,
    upgrade: bool,
}

impl<'a> RequestHead<'a> {
    /// The method. An unknown method stays as it is.
    pub fn method(&self) -> Method<'a> {
        Method(&self.bytes[..self.layout.method])
    }

    /// The request target, in its exact bytes.
    pub fn target(&self) -> Target<'a> {
        let (start, end) = self.layout.target;
        Target(&self.bytes[start..end])
    }

    /// The version of the request.
    pub fn version(&self) -> Version {
        self.layout.version
    }

    /// The authority of the request: that of an absolute-form or authority-form target, or else
    /// the value of the Host field (RFC 9112, section 3.3).
    ///
    /// The parser refuses an HTTP/1.1 request that does not have exactly one Host field with a
    /// valid authority (RFC 9112, section 3.2), also when the target gives the authority. An
    /// HTTP/1.0 request can have no Host field, and then an origin-form or asterisk-form target
    /// gives `None`.
    pub fn authority(&self) -> Option<Authority<'a>> {
        let (start, end) = self.layout.authority?;
        Some(Authority(&self.bytes[start..end]))
    }

    /// The field lines, in their received order. Repeated names stay as separate fields.
    ///
    /// Each call reads the checked field lines again. It allocates nothing.
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

    /// Whether the connection can carry another request after this one (RFC 9112, section 9.3):
    /// an HTTP/1.1 request with no `close` connection option, or an HTTP/1.0 request with the
    /// `keep-alive` option.
    pub fn persistent(&self) -> bool {
        self.layout.persistent
    }

    /// Whether the request has `Expect: 100-continue` (RFC 9110, section 10.1.1).
    pub fn expects_continue(&self) -> bool {
        self.layout.expect_continue
    }

    /// Whether the request asks to change the protocol: it has an Upgrade field and the `upgrade`
    /// connection option (RFC 9110, section 7.8).
    pub fn upgrade(&self) -> bool {
        self.layout.upgrade
    }

    /// Keeps this head after the call, as a view of the backing of `region`, with no copy.
    ///
    /// Give the frozen region whose bytes the parser read. The retained head keeps the backing
    /// alive, and it shares the one charge of the backing with each other view of it. A pool slot
    /// needs no allocation for it. Gives `None` if this head is not in the bytes of `region`.
    pub fn retain(&self, region: &Lease) -> Option<RetainedRequest> {
        Some(RetainedRequest {
            region: view_of(region, self.bytes)?,
            layout: self.layout,
        })
    }
}

impl fmt::Debug for RequestHead<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("version", &self.layout.version)
            .field("consumed", &self.consumed())
            .field("framing", &self.layout.framing)
            .finish_non_exhaustive()
    }
}

/// A request head that keeps the backing of its received region alive, from
/// [`RequestHead::retain`].
///
/// It holds one view of the backing. Thus it keeps no copy, and its values count the backing one
/// time. The backing returns or frees its region when its last view drops.
#[derive(Clone)]
pub struct RetainedRequest {
    /// A view of exactly the bytes of the head.
    region: Lease,
    layout: Layout,
}

impl RetainedRequest {
    /// The head, with its values as views of the retained bytes.
    pub fn head(&self) -> RequestHead<'_> {
        RequestHead {
            bytes: self.region.bytes(),
            layout: self.layout,
        }
    }
}

impl fmt::Debug for RetainedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RetainedRequest").field(&self.head()).finish()
    }
}
