//! HTTP/1.1 for servers, with no I/O: a request head parser and a response head writer.
//!
//! The caller receives bytes into its own region and gives them to a [`RequestParser`]. The
//! parser reads them in place and allocates nothing. A complete head gives the checked
//! [values](crate::value) of the request as views of the received bytes, the exact number of
//! bytes that the head consumed, and the [`Framing`] of the body that follows it. The body and
//! any next request stay in the received region, at their offsets after the head. A
//! [`RetainedRequest`] keeps a head after the call, with no copy, as a view of the backing of the
//! region.
//!
//! [`write_head`] writes a response head and its framing field into the free capacity of an owned
//! output region, through a [`WriteLoan`]. [`begin_chunk`], [`end_chunk`], and [`last_chunk`]
//! write the framing of a chunked body. The chunk bytes can follow in the same region or stay in
//! a region of their own.
//!
//! ```
//! use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
//! use rsnetwork::h1::{Framing, Limits, RequestParser, write_head};
//! use rsnetwork::value::{Field, Host, Method, Status, TargetForm};
//!
//! let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
//! let mut parser = RequestParser::new(limits);
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
//! assert_eq!(head.method(), Method::PUT);
//! assert!(matches!(head.target().form(), TargetForm::Origin { path: b"/notes/7", query: None }));
//! assert_eq!(head.authority().map(|authority| authority.host()), Some(Host::Name(b"example.com")));
//!
//! // The body follows the head in the same region.
//! assert_eq!(head.framing(), Framing::Length(5));
//! let body = received.view(head.consumed()..head.consumed() + 5).expect("the body is in the region");
//! assert_eq!(body.bytes(), b"hello");
//!
//! // Keep the head after the region drops. It holds a view of the same backing, with no copy.
//! let kept = head.retain(&received).expect("the head is in the region");
//! drop(received);
//! assert_eq!(kept.head().method(), Method::PUT);
//!
//! // Write the response head into the free capacity of an owned region, then the body after it.
//! let mut out = WriteLoan::new(Vec::with_capacity(256));
//! let fields = [Field::new(b"Content-Type", b"text/plain")?];
//! write_head(&mut out, Status::new(200)?, &fields, Framing::Length(2))?;
//! out.fill_from(b"ok");
//! assert_eq!(out.into_inner(), b"HTTP/1.1 200 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! This part of the core is for servers. It accepts HTTP/1.1 requests only. It does not decode
//! chunks, read trailers, or apply a keepalive policy.
//!
//! [`WriteLoan`]: crate::buffer::WriteLoan

mod body;
mod chunked;
mod client;
mod head;
mod request;
mod response;
mod server;
mod write;

pub use body::Trailers;
pub use chunked::{ChunkDecoder, ChunkStep};
pub use client::{Client, ClientEvent};
pub use head::{BodyLimits, Fields, Limits, ParseError, Version};
pub use request::{RequestHead, RequestParser, RetainedRequest};
pub use response::{ResponseHead, ResponseParser, RetainedResponse};
pub use server::{Server, ServerEvent};
pub use write::{WriteError, begin_chunk, end_chunk, last_chunk, write_head, write_request};

/// The framing of a message body: how its end is found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// The body has exactly this many bytes. A request with no framing field has `Length(0)`.
    Length(u64),
    /// The body is a sequence of chunks, and a chunk of size zero ends it.
    Chunked,
    /// The close of the connection ends the body. Only a response has this framing.
    Close,
}

#[cfg(test)]
mod tests;
