//! Native views of application-owned HTTP types.

use core::alloc::Layout;
use core::fmt;
use std::borrow::Cow;

use super::{
    Adapter, Error, FIELD, HeaderMap, Kind, OriginalTarget, ROOM, Request, Response, Target, URI, Uri, Version,
};
use crate::capacity::Permit;
use crate::value::{Authority, Field, Method, Status, decimal};
use crate::{client, server};

const FRAMING: Error = Error::new(
    Kind::Misuse,
    "the HTTP headers give invalid or conflicting body framing",
);
const AUTHORITY: Error = Error::new(Kind::Misuse, "the request needs one valid authority");
const VERSION: Error = Error::new(Kind::Unsupported, "the HTTP version has no native representation");

fn version(version: Version) -> Result<(), Error> {
    match version {
        Version::HTTP_10 | Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3 => Ok(()),
        _ => Err(VERSION),
    }
}

/// The slices that `Uri::fmt` would write, in order.
fn parts(uri: &Uri) -> [&[u8]; 6] {
    [
        uri.scheme_str().unwrap_or("").as_bytes(),
        if uri.scheme().is_some() { b"://" } else { b"" },
        uri.authority().map_or(b"", |a| a.as_str().as_bytes()),
        uri.path().as_bytes(),
        if uri.query().is_some() { b"?" } else { b"" },
        uri.query().unwrap_or("").as_bytes(),
    ]
}

pub(super) fn same_target(target: Target<'_>, uri: &Uri) -> bool {
    let mut raw = target.as_bytes();
    for part in parts(uri) {
        let Some(rest) = raw.strip_prefix(part) else {
            return false;
        };
        raw = rest;
    }
    raw.is_empty()
}

/// The exact target of an ecosystem URI. An absolute target can need one contiguous allocation.
pub struct UriTarget<'a> {
    raw: Cow<'a, [u8]>,
    _charge: Option<Permit>,
}

impl<'a> UriTarget<'a> {
    fn borrowed(raw: &'a [u8]) -> Result<Self, Error> {
        Target::new(raw).map_err(|_| URI)?;
        Ok(Self {
            raw: Cow::Borrowed(raw),
            _charge: None,
        })
    }

    /// The checked native target.
    pub fn target(&self) -> Target<'_> {
        Target(&self.raw)
    }
}

impl fmt::Debug for UriTarget<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UriTarget").finish_non_exhaustive()
    }
}

/// Native field descriptors. The names and values borrow the original header map.
#[derive(Debug)]
pub struct Fields<'a> {
    lines: Vec<Field<'a>>,
    _charge: Permit,
}

impl<'a> Fields<'a> {
    /// The field lines, in header-map iteration order.
    pub fn as_slice(&self) -> &[Field<'a>] {
        &self.lines
    }
}

/// A request ready for a native client. Its method and fields borrow the ecosystem request.
#[derive(Debug)]
pub struct RequestView<'a> {
    method: Method<'a>,
    target: UriTarget<'a>,
    authority: Authority<'a>,
    fields: Fields<'a>,
    length: Option<u64>,
}

impl RequestView<'_> {
    /// The native request to give to the client.
    pub fn head(&self) -> client::Request<'_> {
        client::Request {
            method: self.method,
            target: self.target.target(),
            authority: self.authority,
            fields: self.fields.as_slice(),
            length: self.length,
        }
    }
}

/// A response ready for a native server. Its fields borrow the ecosystem response.
#[derive(Debug)]
pub struct ResponseView<'a> {
    status: Status,
    fields: Fields<'a>,
    length: Option<u64>,
}

impl ResponseView<'_> {
    /// The native head to give to the server.
    pub fn head(&self) -> server::Response<'_> {
        server::Response {
            status: self.status,
            fields: self.fields.as_slice(),
            length: self.length,
        }
    }
}

/// The length declared by the framing fields.
#[derive(Default)]
struct Framing {
    length: Option<u64>,
    chunked: bool,
}

impl Framing {
    fn take(&mut self, field: Field<'_>, version: Version) -> Result<bool, Error> {
        match field.name() {
            b"content-length" => {
                for value in field.value().split(|&b| b == b',') {
                    let n = decimal(value.trim_ascii()).ok_or(FRAMING)?;
                    if self.chunked || self.length.replace(n).is_some_and(|previous| previous != n) {
                        return Err(FRAMING);
                    }
                }
            }
            b"transfer-encoding" => {
                if version != Version::HTTP_11
                    || self.chunked
                    || self.length.is_some()
                    || !field.value().eq_ignore_ascii_case(b"chunked")
                {
                    return Err(FRAMING);
                }
                self.chunked = true;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn length(&self, hint: Option<u64>) -> Option<u64> {
        if self.chunked { None } else { self.length.or(hint) }
    }
}

impl Adapter {
    /// Converts a URI into a native target. Absolute targets join the URI components in one charged allocation.
    pub fn target<'a>(&self, uri: &'a Uri) -> Result<UriTarget<'a>, Error> {
        if uri.scheme().is_none() {
            let raw = if let Some(a) = uri.authority() {
                a.as_str()
            } else {
                uri.path_and_query().ok_or(URI)?.as_str()
            };
            if raw.len() > self.limits.head_bytes {
                return Err(ROOM);
            }
            return UriTarget::borrowed(raw.as_bytes());
        }
        let parts = parts(uri);
        let len = parts
            .iter()
            .try_fold(0usize, |n, p| n.checked_add(p.len()))
            .ok_or(ROOM)?;
        if len > self.limits.head_bytes {
            return Err(ROOM);
        }
        let charge = self.budget.reserve(len as u64).map_err(|_| ROOM)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(len).map_err(|_| ROOM)?;
        for part in parts {
            raw.extend_from_slice(part);
        }
        Target::new(&raw).map_err(|_| URI)?;
        Ok(UriTarget {
            raw: Cow::Owned(raw),
            _charge: Some(charge),
        })
    }

    /// Borrows all the fields of a header map. Only the array of field descriptors needs storage.
    pub fn fields<'a>(&self, headers: &'a HeaderMap) -> Result<Fields<'a>, Error> {
        self.read_fields(headers, 0, |_| Ok(false))
    }

    /// Borrows native trailer fields from a completed body. The values keep their original backing.
    pub fn trailers<'a>(&self, trailers: &'a crate::body::Trailers) -> Result<Fields<'a>, Error> {
        let lines = trailers.fields();
        let count = lines.clone().take(self.limits.fields.saturating_add(1)).count();
        let mut fields = self.descriptors(count)?;
        let mut size = 0;
        for (i, field) in lines.enumerate() {
            self.check_field(&mut size, i, field.name(), field.value())?;
            fields.lines.push(field);
        }
        Ok(fields)
    }

    fn descriptors<'a>(&self, n: usize) -> Result<Fields<'a>, Error> {
        if n > self.limits.fields {
            return Err(ROOM);
        }
        let size = Layout::array::<Field<'_>>(n).map_err(|_| ROOM)?.size();
        let charge = self.budget.reserve(size as u64).map_err(|_| ROOM)?;
        let mut lines = Vec::new();
        lines.try_reserve_exact(n).map_err(|_| ROOM)?;
        Ok(Fields { lines, _charge: charge })
    }

    fn read_fields<'a>(
        &self,
        headers: &'a HeaderMap,
        mut size: usize,
        mut take: impl FnMut(Field<'a>) -> Result<bool, Error>,
    ) -> Result<Fields<'a>, Error> {
        if size > self.limits.head_bytes {
            return Err(ROOM);
        }
        let mut fields = self.descriptors(headers.len())?;
        for (i, (name, value)) in headers.iter().enumerate() {
            let name = name.as_str().as_bytes();
            self.check_field(&mut size, i, name, value.as_bytes())?;
            let field = Field::new(name, value.as_bytes()).map_err(|_| FIELD)?;
            // Native encoders have a fixed never-index policy. A stricter marker must survive conversion.
            if value.is_sensitive() && !crate::hpack::sensitive(name, value.as_bytes()) {
                return Err(Error::new(
                    Kind::Unsupported,
                    "the native field cannot retain this sensitive marker",
                ));
            }
            if !take(field)? {
                fields.lines.push(field);
            }
        }
        Ok(fields)
    }

    /// Converts an application request for a native client. The URI authority or Host field supplies its destination.
    /// `body_length` supplies the length when the request has no framing fields.
    pub fn native_request<'a, B>(
        &self,
        request: &'a Request<B>,
        body_length: Option<u64>,
    ) -> Result<RequestView<'a>, Error> {
        version(request.version())?;
        let uri = request.uri();
        let size = parts(uri)
            .iter()
            .try_fold(request.method().as_str().len(), |n, part| n.checked_add(part.len()))
            .ok_or(ROOM)?;
        if size > self.limits.head_bytes {
            return Err(ROOM);
        }
        let method: Method<'_> = request.method().try_into()?;
        let target = if matches!(request.version(), Version::HTTP_2 | Version::HTTP_3) && method != Method::CONNECT {
            let path = uri.path_and_query().ok_or(URI)?.as_str().as_bytes();
            if path.len() > self.limits.head_bytes {
                return Err(ROOM);
            }
            UriTarget::borrowed(path)?
        } else if let Some(original) = request.extensions().get::<OriginalTarget>()
            && parts(&original.uri) == parts(uri)
        {
            UriTarget::borrowed(&original.raw)?
        } else {
            self.target(uri)?
        };
        let mut framing = Framing::default();
        let size = size.max(target.raw.len().checked_add(method.as_bytes().len()).ok_or(ROOM)?);
        let mut host = None;
        let fields = self.read_fields(request.headers(), size, |f| {
            if f.name() != b"host" {
                return framing.take(f, request.version());
            }
            let value = Authority::new(f.value()).map_err(|_| AUTHORITY)?;
            if host.replace(value).is_some() {
                return Err(AUTHORITY);
            }
            Ok(true)
        })?;
        let authority = uri
            .authority()
            .map(|a| Authority::new(a.as_str().as_bytes()).map_err(|_| AUTHORITY))
            .transpose()?;
        if let (Some(a), Some(h)) = (authority, host)
            && !a.as_bytes().eq_ignore_ascii_case(h.as_bytes())
        {
            return Err(AUTHORITY);
        }
        Ok(RequestView {
            method,
            target,
            authority: authority.or(host).ok_or(AUTHORITY)?,
            fields,
            length: framing.length(body_length),
        })
    }

    /// Converts an application response for a native server. Framing fields set the length before `body_length`.
    pub fn native_response<'a, B>(
        &self,
        response: &'a Response<B>,
        body_length: Option<u64>,
    ) -> Result<ResponseView<'a>, Error> {
        version(response.version())?;
        let status = response.status().try_into()?;
        let mut framing = Framing::default();
        let fields = self.read_fields(response.headers(), 3, |f| framing.take(f, response.version()))?;
        Ok(ResponseView {
            status,
            fields,
            length: framing.length(body_length),
        })
    }
}
