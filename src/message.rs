//! The message model that each protocol shares: the head of a received request and of a received
//! response, their fields, their version, and the stream of each exchange.
//!
//! A [`RequestHead`] and a [`ResponseHead`] have one meaning in each version. Their values are
//! the checked values of [`value`](crate::value), and their fields keep their order, also when a
//! name repeats. The version shows where the protocols differ:
//!
//! - **HTTP/1.1.** The head is a view of the received bytes, with no copy. The field names keep
//!   their case. [`RequestHead::h1`] and [`ResponseHead::h1`] give the facts that only HTTP/1.1
//!   has, such as persistence and `100 Continue`.
//! - **HTTP/2 and HTTP/3.** The connection decodes field sections with HPACK or QPACK.
//!   The head copies the decoded lines into a charged region of their exact size, so its memory
//!   follows the size of the head. The field names are lowercase.
//!
//! [`length`](RequestHead::length) is the length of the body when the sender declared it, and
//! `None` when the body ends with its stream or with its last chunk.

use core::fmt;

use crate::h1::{self, RetainedRequest, RetainedResponse};
use crate::h2::message::{Request as H2Request, Response as H2Response};
use crate::value::{Authority, Field, Method, Scheme, Status, Target, TargetForm};

/// The version of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0 (RFC 9112, appendix C.2).
    Http10,
    /// HTTP/1.1 (RFC 9112).
    Http11,
    /// HTTP/2 (RFC 9113).
    Http2,
    /// HTTP/3 (RFC 9114).
    Http3,
}

/// The stream of one exchange on a connection: one request and its response.
///
/// On HTTP/2, it is the stream identifier of RFC 9113. On HTTP/1.1, the exchanges of a connection
/// count from 1, and one is open at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stream(pub(crate) u64);

impl Stream {
    /// The number of the stream: the HTTP/2 stream identifier, or the count of the HTTP/1.1
    /// exchange.
    pub const fn id(self) -> u64 {
        self.0
    }
}

/// An iterator over the field lines of a head or a trailer section, in their received order.
/// Repeated names stay as separate fields.
#[derive(Clone)]
pub struct Fields<'a> {
    /// The field lines that remain, each as `name: value` and CR LF. The parser or the decoder
    /// checked each of them.
    pub(crate) block: &'a [u8],
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        h1::next_field(&mut self.block)
    }
}

impl fmt::Debug for Fields<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fields").finish_non_exhaustive()
    }
}

/// The head of a received request.
///
/// Its `Debug` output shows only the version and the length, because the method, the target,
/// and the fields are peer text.
#[derive(Clone)]
pub struct RequestHead(RequestForm);

#[derive(Clone)]
enum RequestForm {
    H1(RetainedRequest),
    Multiplexed(H2Request, Version),
}

impl RequestHead {
    #[cfg(feature = "http")]
    pub(crate) fn backing(&self) -> &crate::buffer::Lease {
        match &self.0 {
            RequestForm::H1(head) => &head.region,
            RequestForm::Multiplexed(head, _) => &head.bytes,
        }
    }

    pub(crate) fn h1_form(head: RetainedRequest) -> Self {
        Self(RequestForm::H1(head))
    }

    pub(crate) fn h2_form(head: H2Request) -> Self {
        Self(RequestForm::Multiplexed(head, Version::Http2))
    }

    #[cfg(feature = "tls")]
    pub(crate) fn h3_form(head: H2Request) -> Self {
        Self(RequestForm::Multiplexed(head, Version::Http3))
    }

    /// The method. An unknown method stays as it is.
    pub fn method(&self) -> Method<'_> {
        match &self.0 {
            RequestForm::H1(head) => head.head().method(),
            RequestForm::Multiplexed(head, _) => head.method(),
        }
    }

    /// The request target, in its exact bytes: on HTTP/2 and HTTP/3, the `:path`, and the authority of a
    /// CONNECT request, which has no `:path`.
    pub fn target(&self) -> Target<'_> {
        match &self.0 {
            RequestForm::H1(head) => head.head().target(),
            RequestForm::Multiplexed(head, _) => head.target(),
        }
    }

    /// The authority of the request: on HTTP/1.1, that of the target or of the Host field
    /// (RFC 9112, section 3.3), and on HTTP/2 and HTTP/3, the `:authority`, or else the Host field (RFC 9113,
    /// section 8.3.1). `None` when the request has none.
    pub fn authority(&self) -> Option<Authority<'_>> {
        match &self.0 {
            RequestForm::H1(head) => head.head().authority(),
            RequestForm::Multiplexed(head, _) => head.authority(),
        }
    }

    /// The scheme of the target URI: on HTTP/2 and HTTP/3, the `:scheme`, and on HTTP/1.1, the scheme of an
    /// absolute-form target. `None` when the request does not give it.
    pub fn scheme(&self) -> Option<Scheme<'_>> {
        match &self.0 {
            RequestForm::H1(head) => match head.head().target().form() {
                TargetForm::Absolute { scheme, .. } => Some(scheme),
                _ => None,
            },
            RequestForm::Multiplexed(head, _) => head.scheme(),
        }
    }

    /// The fields, in their received order. On HTTP/2 and HTTP/3, the pseudo-header fields are not fields:
    /// the other calls give their values.
    pub fn fields(&self) -> Fields<'_> {
        match &self.0 {
            RequestForm::H1(head) => head.head().fields(),
            RequestForm::Multiplexed(head, _) => head.fields(),
        }
    }

    /// The length of the body that the sender declared, or `None` when the body ends with its
    /// last chunk or with its stream.
    pub fn length(&self) -> Option<u64> {
        match &self.0 {
            RequestForm::H1(head) => match head.head().framing() {
                h1::Framing::Length(length) => Some(length),
                h1::Framing::Chunked | h1::Framing::Close => None,
            },
            RequestForm::Multiplexed(head, _) => head.length(),
        }
    }

    /// The version of the request.
    pub fn version(&self) -> Version {
        match &self.0 {
            RequestForm::H1(head) => head.head().version(),
            RequestForm::Multiplexed(_, version) => *version,
        }
    }

    /// The HTTP/1.1 head, with the facts that only HTTP/1.1 has, or `None` on HTTP/2 and HTTP/3.
    pub fn h1(&self) -> Option<h1::RequestHead<'_>> {
        match &self.0 {
            RequestForm::H1(head) => Some(head.head()),
            RequestForm::Multiplexed(..) => None,
        }
    }
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestHead")
            .field("version", &self.version())
            .field("length", &self.length())
            .finish_non_exhaustive()
    }
}

/// The head of a received final response.
///
/// Its `Debug` output shows only the version, the status, and the length, because the fields
/// are peer text.
#[derive(Clone)]
pub struct ResponseHead(ResponseForm);

#[derive(Clone)]
enum ResponseForm {
    H1(RetainedResponse),
    Multiplexed(H2Response, Version),
}

impl ResponseHead {
    #[cfg(feature = "http")]
    pub(crate) fn backing(&self) -> &crate::buffer::Lease {
        match &self.0 {
            ResponseForm::H1(head) => &head.region,
            ResponseForm::Multiplexed(head, _) => &head.bytes,
        }
    }

    pub(crate) fn h1_form(head: RetainedResponse) -> Self {
        Self(ResponseForm::H1(head))
    }

    pub(crate) fn h2_form(head: H2Response) -> Self {
        Self(ResponseForm::Multiplexed(head, Version::Http2))
    }

    #[cfg(feature = "tls")]
    pub(crate) fn h3_form(head: H2Response) -> Self {
        Self(ResponseForm::Multiplexed(head, Version::Http3))
    }

    /// The status.
    pub fn status(&self) -> Status {
        match &self.0 {
            ResponseForm::H1(head) => head.head().status(),
            ResponseForm::Multiplexed(head, _) => head.status(),
        }
    }

    /// The fields, in their received order. On HTTP/2 and HTTP/3, use `status` for the `:status` pseudo-header.
    pub fn fields(&self) -> Fields<'_> {
        match &self.0 {
            ResponseForm::H1(head) => head.head().fields(),
            ResponseForm::Multiplexed(head, _) => head.fields(),
        }
    }

    /// The length of the body that the server declared, or `None` when the body ends with its
    /// last chunk, with its stream, or with the close of the connection. A response to HEAD, and
    /// a 204 or 304 response, has `Some(0)`.
    pub fn length(&self) -> Option<u64> {
        match &self.0 {
            ResponseForm::H1(head) => match head.head().framing() {
                h1::Framing::Length(length) => Some(length),
                h1::Framing::Chunked | h1::Framing::Close => None,
            },
            ResponseForm::Multiplexed(head, _) => head.length(),
        }
    }

    /// The version of the response.
    pub fn version(&self) -> Version {
        match &self.0 {
            ResponseForm::H1(head) => head.head().version(),
            ResponseForm::Multiplexed(_, version) => *version,
        }
    }

    /// The HTTP/1.1 head, with the facts that only HTTP/1.1 has, or `None` on HTTP/2 and HTTP/3.
    pub fn h1(&self) -> Option<h1::ResponseHead<'_>> {
        match &self.0 {
            ResponseForm::H1(head) => Some(head.head()),
            ResponseForm::Multiplexed(..) => None,
        }
    }
}

impl fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseHead")
            .field("version", &self.version())
            .field("status", &self.status())
            .field("length", &self.length())
            .finish_non_exhaustive()
    }
}
