//! Convert checked messages to the `http` 1.x types at the application boundary.
//!
//! An [`Adapter`] takes the head limits and the budget for native field descriptors.
//! A converted request or response owns its header map. Its values share the charged
//! backing of the received head. Its body keeps the type and the ownership that the caller gives.

mod native;

use core::fmt;
use core::future::Future;

pub use ::http::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version, header, request, response};
use bytes::Bytes;

use crate::body::{Outcome, Part};
use crate::buffer::Lease;
use crate::capacity::Budget;
use crate::drive::{Error, Kind};
use crate::h1::Limits;
use crate::message::{self, RequestHead, ResponseHead};
use crate::value::{self, Field, Target};

pub use native::{Fields, RequestView, ResponseView, UriTarget};

const ROOM: Error = Error::new(
    Kind::Overload,
    "the HTTP conversion exceeds the head limits or the available capacity",
);
const URI: Error = Error::new(Kind::Unsupported, "the URI cannot represent this request target");
const FIELD: Error = Error::new(Kind::Misuse, "the field cannot be represented in the target message");
const METHOD: Error = Error::new(
    Kind::Unsupported,
    "the method cannot be represented in the target message",
);
const STATUS: Error = Error::new(Kind::Unsupported, "the status is outside the supported HTTP range");

/// Converts messages under the caller's limits. Each call finishes before the next protocol turn.
#[derive(Clone, Debug)]
pub struct Adapter {
    limits: Limits,
    budget: Budget,
}

impl Adapter {
    /// Uses `limits` for conversion work and `budget` for native field and target storage.
    pub fn new(limits: Limits, budget: &Budget) -> Self {
        Self {
            limits,
            budget: budget.clone(),
        }
    }

    /// Converts a received head and transfers `body` unchanged. HTTP/2 and HTTP/3 expose their URI pseudo-fields.
    /// An [`OriginalTarget`] extension keeps an HTTP/1 target whose spelling the URI changes.
    pub fn request<B>(&self, head: &RequestHead, body: B) -> Result<Request<B>, Error> {
        let target = head.target();
        let multiplexed = matches!(head.version(), message::Version::Http2 | message::Version::Http3);
        let method = head.method();
        let mut size = method
            .as_bytes()
            .len()
            .checked_add(target.as_bytes().len())
            .ok_or(ROOM)?;
        let origin = if multiplexed && method != value::Method::CONNECT {
            let scheme = head.scheme().ok_or(URI)?;
            let authority = head.authority().ok_or(URI)?;
            size = size
                .checked_add(scheme.as_bytes().len())
                .and_then(|n| n.checked_add(authority.as_bytes().len()))
                .ok_or(ROOM)?;
            Some((scheme, authority))
        } else {
            None
        };
        if size > self.limits.head_bytes {
            return Err(ROOM);
        }
        let backing = Bytes::from_owner(head.backing().clone());
        let mut request = Request::new(body);
        *request.version_mut() = head.version().into();
        *request.method_mut() = method.try_into()?;
        let raw = backing.slice_ref(target.as_bytes());
        let uri = if let Some((scheme, authority)) = origin {
            Uri::builder()
                .scheme(scheme.as_bytes())
                .authority(
                    ::http::uri::Authority::from_maybe_shared(backing.slice_ref(authority.as_bytes()))
                        .map_err(|_| URI)?,
                )
                .path_and_query(::http::uri::PathAndQuery::from_maybe_shared(raw).map_err(|_| URI)?)
                .build()
                .map_err(|_| URI)?
        } else {
            let uri = Uri::from_maybe_shared(raw.clone()).map_err(|_| URI)?;
            if !native::same_target(target, &uri) {
                request
                    .extensions_mut()
                    .insert(OriginalTarget { raw, uri: uri.clone() });
            }
            uri
        };
        *request.uri_mut() = uri;
        *request.headers_mut() = self.map(head.fields(), size, Some(&backing))?;
        Ok(request)
    }

    /// Mounts an `http`-typed handler on a received request. The host supplies its body handle and drives the result.
    pub fn handle<B, T>(&self, head: &RequestHead, body: B, handler: impl FnOnce(Request<B>) -> T) -> Result<T, Error> {
        Ok(handler(self.request(head, body)?))
    }

    /// Converts a received response, including its version, and transfers `body` unchanged.
    pub fn response<B>(&self, head: &ResponseHead, body: B) -> Result<Response<B>, Error> {
        let mut response = Response::new(body);
        *response.status_mut() = head.status().try_into()?;
        *response.version_mut() = head.version().into();
        let backing = head.fields().next().map(|_| Bytes::from_owner(head.backing().clone()));
        *response.headers_mut() = self.map(head.fields(), 3, backing.as_ref())?;
        Ok(response)
    }

    /// Builds a header map from borrowed fields. The map copies the values and preserves repetition within each name.
    pub fn headers(&self, fields: &[Field<'_>]) -> Result<HeaderMap, Error> {
        self.map(fields.iter().copied(), 0, None)
    }

    fn map<'a>(
        &self,
        fields: impl Iterator<Item = Field<'a>> + Clone,
        initial: usize,
        backing: Option<&Bytes>,
    ) -> Result<HeaderMap, Error> {
        let mut size = initial;
        if size > self.limits.head_bytes {
            return Err(ROOM);
        }
        let mut count = 0;
        for field in fields.clone() {
            self.check_field(&mut size, count, field.name(), field.value())?;
            count += 1;
        }
        let mut headers = HeaderMap::try_with_capacity(count).map_err(|_| ROOM)?;
        for field in fields {
            let name = core::str::from_utf8(field.name()).map_err(|_| FIELD)?;
            let mut value = match backing {
                Some(bytes) => header::HeaderValue::from_maybe_shared(bytes.slice_ref(field.value())),
                None => header::HeaderValue::from_bytes(field.value()),
            }
            .map_err(|_| FIELD)?;
            value.set_sensitive(crate::hpack::sensitive(field.name(), field.value()));
            match headers.try_entry(name).map_err(|_| FIELD)? {
                header::Entry::Occupied(mut entry) => entry.append(value),
                header::Entry::Vacant(entry) => {
                    entry.try_insert(value).map_err(|_| ROOM)?;
                }
            }
        }
        Ok(headers)
    }

    fn check_field(&self, size: &mut usize, count: usize, name: &[u8], value: &[u8]) -> Result<(), Error> {
        *size = size
            .checked_add(name.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(ROOM)?;
        if count >= self.limits.fields
            || name.len() > self.limits.name_bytes
            || value.len() > self.limits.value_bytes
            || *size > self.limits.head_bytes
        {
            return Err(ROOM);
        }
        Ok(())
    }
}

/// The exact HTTP/1 target when an ecosystem URI normalizes its spelling. The bytes share the received backing.
#[derive(Clone)]
pub struct OriginalTarget {
    raw: Bytes,
    uri: Uri,
}

impl OriginalTarget {
    /// The checked target before URI normalization.
    pub fn target(&self) -> Target<'_> {
        Target(&self.raw)
    }
}

impl fmt::Debug for OriginalTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalTarget").finish_non_exhaustive()
    }
}

impl crate::server::Http {
    /// Calls an `http` handler on the next caller-driven exchange. Its request body is its native stream handle.
    /// Drive the returned response under the same stream's backpressure. A conversion refusal closes the exchange.
    pub fn handle_http<T>(
        &mut self,
        adapter: &Adapter,
        now: crate::time::Instant,
        handler: impl FnOnce(Request<message::Stream>) -> T,
    ) -> Result<Option<(message::Stream, T)>, Error> {
        let Some((stream, head)) = self.request(now)? else {
            return Ok(None);
        };
        match adapter.handle(&head, stream, handler) {
            Ok(result) => Ok(Some((stream, result))),
            Err(error) => {
                self.close(stream);
                Err(error)
            }
        }
    }
}

impl TryFrom<value::Method<'_>> for Method {
    type Error = Error;
    fn try_from(method: value::Method<'_>) -> Result<Self, Error> {
        Self::from_bytes(method.as_bytes()).map_err(|_| METHOD)
    }
}

impl<'a> TryFrom<&'a Method> for value::Method<'a> {
    type Error = Error;
    fn try_from(method: &'a Method) -> Result<Self, Error> {
        Self::new(method.as_str().as_bytes()).map_err(|_| METHOD)
    }
}

impl TryFrom<value::Status> for StatusCode {
    type Error = Error;
    fn try_from(status: value::Status) -> Result<Self, Error> {
        Self::from_u16(status.code()).map_err(|_| STATUS)
    }
}

impl TryFrom<StatusCode> for value::Status {
    type Error = Error;
    fn try_from(status: StatusCode) -> Result<Self, Error> {
        Self::new(status.as_u16()).map_err(|_| STATUS)
    }
}

impl TryFrom<Target<'_>> for Uri {
    type Error = Error;
    fn try_from(target: Target<'_>) -> Result<Self, Error> {
        let uri = Self::try_from(target.as_bytes()).map_err(|_| URI)?;
        native::same_target(target, &uri).then_some(uri).ok_or(URI)
    }
}

impl From<message::Version> for Version {
    fn from(version: message::Version) -> Self {
        match version {
            message::Version::Http10 => Self::HTTP_10,
            message::Version::Http11 => Self::HTTP_11,
            message::Version::Http2 => Self::HTTP_2,
            message::Version::Http3 => Self::HTTP_3,
        }
    }
}

/// A streaming response body for an asynchronous handler. Each read yields one native region or its terminal outcome.
pub trait Body {
    /// The size of the remaining body if known. A response can also declare its content length in its headers.
    fn length(&self) -> Option<u64> {
        None
    }

    /// Waits for the next region or the terminal outcome. Stop reading after [`Part::End`].
    fn next(&mut self) -> impl Future<Output = Result<Part, Error>>;
}

impl Body for () {
    fn length(&self) -> Option<u64> {
        Some(0)
    }
    async fn next(&mut self) -> Result<Part, Error> {
        Ok(Part::End(Outcome::Complete(None)))
    }
}

impl Body for Option<Lease> {
    fn length(&self) -> Option<u64> {
        Some(self.as_ref().map_or(0, |bytes| bytes.as_ref().len() as u64))
    }
    async fn next(&mut self) -> Result<Part, Error> {
        Ok(self.take().map_or(Part::End(Outcome::Complete(None)), Part::Data))
    }
}
