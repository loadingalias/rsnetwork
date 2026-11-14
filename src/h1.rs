//! HTTP/1.1, with HTTP/1.0 peers, for servers and clients, with no I/O.
//!
//! [`Server`] and [`Client`] are the engines of one connection. They run in drives on the queues
//! of [`drive`](crate::drive): the host puts the received regions into an `Inbound` queue, and
//! each drive reads them in place and gives one event. The application answers with calls that
//! push the output into an `Outbound` queue, and the host sends it. Body bytes are views of the
//! received regions, with no copy. A drive also gives the turn: what the engine needs next, or
//! the end of the connection.
//!
//! The engines apply the framing and the connection rules of RFC 9112: Content-Length and the
//! chunked coding, informational responses, persistence and reuse, pipelined requests, the drain
//! of an unread body, cancellation, and the handoff after an upgrade or a CONNECT tunnel. The
//! caller gives the region of each head that the engine writes, and the size line of each chunk
//! comes from a small pool of the engine. Thus an engine allocates only for a received head or
//! trailer section that continues in the next region, which it joins into one region that the
//! caller's budget pays for.
//!
//! The parsers and writers that the engines use are public too: [`RequestParser`],
//! [`ResponseParser`], [`ChunkDecoder`], [`write_head`], [`write_request`], and the chunk
//! functions.
//!
//! ```
//! use core::net::{Ipv4Addr, SocketAddr};
//! use core::num::{NonZeroU64, NonZeroUsize};
//!
//! use rsnetwork::body::Outcome;
//! use rsnetwork::buffer::{Backing, Buffer as _, Lease};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
//! use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
//! use rsnetwork::value::{Field, Status};
//!
//! let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
//! let body = BodyLimits {
//!     body_bytes: 1 << 20,
//!     drain_bytes: 64 * 1024,
//!     extension_bytes: 256,
//!     trailer_bytes: 4 * 1024,
//!     trailer_fields: 16,
//! };
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let queue = NonZeroUsize::new(16).expect("not zero");
//! let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
//! let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
//! let mut server = Server::new(limits, body, turn, &outbound, &budget)?;
//!
//! // The transport received a request, and the host queues it.
//! let endpoint = Endpoint {
//!     peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
//!     local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
//!     ecn: Ecn::NotEct,
//!     segment: None,
//! };
//! let region = Lease::from(b"POST /notes HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec());
//! inbound.push(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");
//!
//! // Each drive gives one event: the head, the body bytes, and the end of the body.
//! let (Some(ServerEvent::Request(request)), _) = server.drive(&mut inbound, &mut outbound) else {
//!     panic!("a request head")
//! };
//! assert_eq!(request.head().target().as_bytes(), b"/notes");
//! let (Some(ServerEvent::Data(data)), _) = server.drive(&mut inbound, &mut outbound) else {
//!     panic!("body bytes")
//! };
//! assert_eq!(data.bytes(), b"hello");
//! let (Some(ServerEvent::End(Outcome::Complete(None))), _) = server.drive(&mut inbound, &mut outbound) else {
//!     panic!("the end of the body")
//! };
//!
//! // The answer: its head in a region of the caller, then the body with no copy.
//! let fields = [Field::new(b"Content-Type", b"text/plain")?];
//! let head = Backing::from(Vec::with_capacity(256));
//! server.respond(&mut outbound, Status::new(201)?, &fields, Framing::Length(2), head)?;
//! server.send(&mut outbound, &Lease::from(b"ok".to_vec()))?;
//! server.finish(&mut outbound)?;
//!
//! // The host sends each output and acknowledges the bytes that the transport accepted.
//! let mut sent = Vec::new();
//! while let Some(output) = outbound.submit() {
//!     sent.extend_from_slice(output.region.bytes());
//!     outbound.ack(output.id, output.region.initialized())?;
//! }
//! assert_eq!(sent, b"HTTP/1.1 201 \r\nContent-Type: text/plain\r\ncontent-length: 2\r\n\r\nok");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod body;
mod chunked;
mod client;
mod head;
mod join;
mod request;
mod response;
mod server;
mod write;

use crate::body::Body;

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

/// The framing of a body to send: its length when it is known, and chunks when it is not.
impl From<&Body> for Framing {
    fn from(body: &Body) -> Self {
        body.length().map_or(Self::Chunked, Self::Length)
    }
}

#[cfg(test)]
mod tests;
