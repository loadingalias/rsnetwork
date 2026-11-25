//! The messages of HTTP/2 (RFC 9113, section 8): the checks of a received header section, the
//! heads that keep their decoded lines, and the lines of a message to send.
//!
//! A received header section is malformed (section 8.1.1) when a field name has an uppercase
//! letter or is not a token, a value is not a field value, a pseudo-header field comes after a
//! field or is unknown, repeated, or of the wrong message, a required pseudo-header field is
//! missing, a field is connection-specific (section 8.2.2), or `content-length` is not one
//! decimal number. Its stream ends with a stream error `PROTOCOL_ERROR`.
//!
//! A checked head copies its decoded lines into one charged region of their exact size: the
//! values of its pseudo-header fields, and then each field as `name: value` and CR LF, which
//! [`Fields`] reads. The HPACK decoder of the connection keeps its own buffer for the next block.

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Permit};

use crate::drive::{Error, Kind};
use crate::hpack::{Block, FieldLine};
use crate::message::Fields;
use crate::value::{Authority, Field, Method, Scheme, Status, Target, TargetForm, decimal};

/// Why a received header section has no head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The section breaks RFC 9113, section 8. Reset the stream with `PROTOCOL_ERROR`.
    Malformed,
    /// The budget cannot pay for the copy of the lines. The stream did not go up: reset it with
    /// `REFUSED_STREAM`, so the peer can send it again.
    Capacity,
}

/// The fields that RFC 9113, section 8.2.2, forbids, because they are specific to a connection.
/// `te` is allowed only with the value `trailers`.
/// The refusal of a write while the chunk before waits for the output, which the vocabularies of
/// both roles give.
pub(crate) const CHUNK_WAITS: Error = Error::new(
    Kind::Overload,
    "the chunk before waits for the output: send the output, and write again",
);

const CONNECTION_FIELDS: [&[u8]; 5] = [
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// A place in the bytes of a head.
#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    end: usize,
}

/// The bytes of a head: one charged region of their exact size.
struct Owned {
    bytes: Vec<u8>,
    _charge: Permit,
}

impl AsRef<[u8]> for Owned {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A received request head: its pseudo-header values and fields, in one charged region.
#[derive(Clone)]
pub(crate) struct Request {
    bytes: Lease,
    method: Span,
    /// The `:path`, or the `:authority` of a CONNECT request.
    target: Span,
    authority: Option<Span>,
    scheme: Option<Span>,
    fields: Span,
    length: Option<u64>,
}

impl Request {
    fn part(&self, span: Span) -> &[u8] {
        &self.bytes.bytes()[span.start..span.end]
    }

    pub(crate) fn method(&self) -> Method<'_> {
        Method(self.part(self.method))
    }

    pub(crate) fn target(&self) -> Target<'_> {
        Target(self.part(self.target))
    }

    pub(crate) fn authority(&self) -> Option<Authority<'_>> {
        self.authority.map(|span| Authority(self.part(span)))
    }

    pub(crate) fn scheme(&self) -> Option<Scheme<'_>> {
        self.scheme.map(|span| Scheme(self.part(span)))
    }

    pub(crate) fn fields(&self) -> Fields<'_> {
        Fields {
            block: self.part(self.fields),
        }
    }

    pub(crate) fn length(&self) -> Option<u64> {
        self.length
    }
}

/// A received final response head.
#[derive(Clone)]
pub(crate) struct Response {
    bytes: Lease,
    status: Status,
    length: Option<u64>,
}

impl Response {
    pub(crate) fn status(&self) -> Status {
        self.status
    }

    pub(crate) fn fields(&self) -> Fields<'_> {
        Fields {
            block: self.bytes.bytes(),
        }
    }

    pub(crate) fn length(&self) -> Option<u64> {
        self.length
    }

    /// The response to a HEAD request: its body has no byte, whatever its `content-length`.
    pub(crate) fn bodiless(mut self) -> Self {
        self.length = Some(0);
        self
    }
}

/// A received response section: an interim (1xx) response, which the client discards, or the
/// final response.
pub(crate) enum Answer {
    Interim,
    Final(Response),
}

/// The facts of the fields of a section, after the checks of each field.
#[derive(Default)]
struct Facts<'a> {
    length: Option<u64>,
    host: Option<&'a [u8]>,
    /// The bytes of the fields as `name: value` and CR LF.
    bytes: usize,
}

/// Checks the field (not pseudo-header) `line`, and adds its facts.
fn field<'a>(line: FieldLine<'a>, facts: &mut Facts<'a>) -> Result<(), Refusal> {
    let (name, value) = (line.name, line.value);
    if Field::new(name, value).is_err() || name.iter().any(u8::is_ascii_uppercase) {
        return Err(Refusal::Malformed);
    }
    if CONNECTION_FIELDS.contains(&name) || (name == b"te" && value != b"trailers") {
        return Err(Refusal::Malformed);
    }
    if name == b"content-length" {
        let length = decimal(value).ok_or(Refusal::Malformed)?;
        if facts.length.is_some_and(|earlier| earlier != length) {
            return Err(Refusal::Malformed);
        }
        facts.length = Some(length);
    }
    if name == b"host" {
        if facts.host.is_some() {
            return Err(Refusal::Malformed);
        }
        facts.host = Some(value);
    }
    facts.bytes = facts
        .bytes
        .saturating_add(name.len())
        .saturating_add(value.len())
        .saturating_add(4);
    Ok(())
}

/// The pseudo-header fields of `block`, which come first, and the facts of its other fields.
/// `pseudo` takes each pseudo-header field, and refuses one that the message does not have.
fn section<'a>(
    block: Block<'a>,
    mut pseudo: impl FnMut(&'a [u8], &'a [u8]) -> Result<(), Refusal>,
) -> Result<Facts<'a>, Refusal> {
    let mut facts = Facts::default();
    let mut fields = false;
    for line in block.lines() {
        if let Some(name) = line.name.strip_prefix(b":") {
            if fields {
                return Err(Refusal::Malformed);
            }
            pseudo(name, line.value)?;
        } else {
            fields = true;
            field(line, &mut facts)?;
        }
    }
    Ok(facts)
}

/// Sets `slot` to `value`, and refuses a pseudo-header field that came before.
fn once<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Refusal> {
    if slot.replace(value).is_some() {
        return Err(Refusal::Malformed);
    }
    Ok(())
}

/// Checks the request section `block` (RFC 9113, section 8.3.1), and copies it into a head
/// charged to `budget`.
pub(crate) fn request(block: Block<'_>, budget: &Budget) -> Result<Request, Refusal> {
    let (mut method, mut scheme, mut authority, mut path) = (None, None, None, None);
    let facts = section(block, |name, value| match name {
        b"method" => once(&mut method, value),
        b"scheme" => once(&mut scheme, value),
        b"authority" => once(&mut authority, value),
        b"path" => once(&mut path, value),
        _ => Err(Refusal::Malformed),
    })?;
    let method = method.ok_or(Refusal::Malformed)?;
    Method::new(method).map_err(|_| Refusal::Malformed)?;
    let connect = method == Method::CONNECT.as_bytes();
    // A CONNECT request has only the method and the authority (section 8.5).
    if connect && (scheme.is_some() || path.is_some() || authority.is_none()) {
        return Err(Refusal::Malformed);
    }
    if let Some(scheme) = scheme {
        Scheme::new(scheme).map_err(|_| Refusal::Malformed)?;
    }
    if !connect {
        let (Some(scheme), Some(path)) = (scheme, path) else {
            return Err(Refusal::Malformed);
        };
        let target = Target::new(path).map_err(|_| Refusal::Malformed)?;
        match target.form() {
            TargetForm::Origin { .. } => {}
            TargetForm::Asterisk if method == Method::OPTIONS.as_bytes() => {}
            _ => return Err(Refusal::Malformed),
        }
        // A scheme with an authority component needs an authority (RFC 9110, section 7.2).
        let web = Scheme(scheme) == Scheme::HTTP || Scheme(scheme) == Scheme::HTTPS;
        if web && authority.is_none() && facts.host.is_none() {
            return Err(Refusal::Malformed);
        }
    }
    // The Host field gives the authority when the request has no `:authority`, and it must not
    // name another one.
    match (authority, facts.host) {
        (Some(authority), Some(host)) if !authority.eq_ignore_ascii_case(host) => return Err(Refusal::Malformed),
        _ => {}
    }
    let authority = authority.or(facts.host);
    if let Some(authority) = authority {
        let valid = Authority::new(authority).map_err(|_| Refusal::Malformed)?;
        if connect && valid.port().is_none() {
            return Err(Refusal::Malformed);
        }
    }
    let mut out = Out::new(
        [Some(method), path, authority, scheme]
            .into_iter()
            .flatten()
            .map(<[u8]>::len)
            .sum::<usize>()
            .saturating_add(facts.bytes),
        budget,
    )?;
    let method = out.put(method);
    let path = path.map(|path| out.put(path));
    let authority = authority.map(|authority| out.put(authority));
    let scheme = scheme.map(|scheme| out.put(scheme));
    let fields = out.fields(block);
    Ok(Request {
        method,
        target: path.or(authority).unwrap_or(method),
        authority,
        scheme,
        fields,
        length: facts.length,
        bytes: out.lease(),
    })
}

/// Checks the response section `block` (RFC 9113, section 8.3.2). A final response copies into
/// a head charged to `budget`. A 204 or 304 response has the length 0.
pub(crate) fn response(block: Block<'_>, budget: &Budget) -> Result<Answer, Refusal> {
    let mut status = None;
    let facts = section(block, |name, value| match name {
        b"status" => once(&mut status, value),
        _ => Err(Refusal::Malformed),
    })?;
    let status = status
        .filter(|status| status.len() == 3)
        .and_then(decimal)
        .and_then(|code| u16::try_from(code).ok())
        .and_then(|code| Status::new(code).ok())
        .ok_or(Refusal::Malformed)?;
    // HTTP/2 has no 101 (section 8.6).
    match status.code() {
        101 => return Err(Refusal::Malformed),
        100..=199 => return Ok(Answer::Interim),
        _ => {}
    }
    let mut out = Out::new(facts.bytes, budget)?;
    out.fields(block);
    let length = if matches!(status.code(), 204 | 304) {
        Some(0)
    } else {
        facts.length
    };
    Ok(Answer::Final(Response {
        bytes: out.lease(),
        status,
        length,
    }))
}

/// Checks the trailer section `block` (RFC 9113, section 8.1), which has no pseudo-header field,
/// and copies its fields into a region charged to `budget`, as `name: value` and CR LF.
pub(crate) fn trailers(block: Block<'_>, budget: &Budget) -> Result<Lease, Refusal> {
    let facts = section(block, |_, _| Err(Refusal::Malformed))?;
    let mut out = Out::new(facts.bytes, budget)?;
    out.fields(block);
    Ok(out.lease())
}

/// The region of one head, which takes exactly the bytes that its checks counted.
struct Out {
    bytes: Vec<u8>,
    charge: Permit,
}

impl Out {
    fn new(len: usize, budget: &Budget) -> Result<Self, Refusal> {
        let charge = budget.reserve(len as u64).map_err(|_| Refusal::Capacity)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len).map_err(|_| Refusal::Capacity)?;
        Ok(Self { bytes, charge })
    }

    fn put(&mut self, part: &[u8]) -> Span {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(part);
        Span {
            start,
            end: self.bytes.len(),
        }
    }

    /// Writes each field of `block`, which the checks passed.
    fn fields(&mut self, block: Block<'_>) -> Span {
        let start = self.bytes.len();
        for line in block.lines().filter(|line| !line.name.starts_with(b":")) {
            for part in [line.name, b": ", line.value, b"\r\n"] {
                self.bytes.extend_from_slice(part);
            }
        }
        Span {
            start,
            end: self.bytes.len(),
        }
    }

    fn lease(self) -> Lease {
        charged(self.bytes, self.charge)
    }
}

/// A lease of `bytes`, which keeps `charge` until its last view drops.
pub(crate) fn charged(bytes: Vec<u8>, charge: Permit) -> Lease {
    let capacity = bytes.capacity();
    Lease::from_owner(Owned { bytes, _charge: charge }, capacity)
}

/// Refuses each field of `fields` that a sender of HTTP/2 must not send (RFC 9113, section
/// 8.2.2), and each field that the connection writes itself: `host`, which the authority gives,
/// and `content-length`, which the length gives.
pub(crate) fn sendable(fields: &[Field<'_>]) -> Result<(), Error> {
    for field in fields {
        let is = |name: &[u8]| field.name.eq_ignore_ascii_case(name);
        if CONNECTION_FIELDS.iter().any(|name| is(name))
            || (is(b"te") && !field.value.eq_ignore_ascii_case(b"trailers"))
        {
            return Err(Error::new(
                Kind::Misuse,
                "HTTP/2 has no connection-specific fields, and `te` can only be `trailers`",
            ));
        }
        if is(b"host") || is(b"content-length") {
            return Err(Error::new(
                Kind::Misuse,
                "the connection writes `host` and `content-length` from the authority and the length",
            ));
        }
    }
    Ok(())
}

/// The lines of `fields`, which [`sendable`] passed.
pub(crate) fn lines<'a>(fields: &'a [Field<'a>]) -> impl Iterator<Item = FieldLine<'a>> + Clone {
    fields.iter().map(|field| FieldLine {
        name: field.name,
        value: field.value,
        never_indexed: false,
    })
}

#[cfg(test)]
mod tests;
