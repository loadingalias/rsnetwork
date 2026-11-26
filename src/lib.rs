//! Sans-I/O HTTP and QUIC networking. This crate is in development.
//!
//! [`value`] holds the checked values of HTTP: methods, request targets, statuses, field lines,
//! authorities, and schemes. Each protocol of the core uses them. [`message`] is the message model
//! that each protocol shares: the heads of a received request and response, and the stream of
//! each exchange. [`priority`] is the priority of a response (RFC 9218), which HTTP/2 and HTTP/3
//! schedule by.
//!
//! [`client`] and [`server`] are the application API: an HTTP/1.1 client and an HTTP/2 client, and
//! one server for HTTP/1.1 and HTTP/2. Each is one connection with no I/O.
//!
//! [`h1`] is HTTP/1.1, with HTTP/1.0 peers, for servers and clients: a server engine and a client
//! engine, and the parsers and writers that they use. It does no I/O, so any runtime or event
//! loop can drive it.
//!
//! [`drive`] is the interface that each protocol engine shares: received and output regions,
//! their exact acknowledgements, the result of each drive, and the errors. [`body`] is the body
//! model that each protocol shares: terminal outcomes, trailers, a consumer that reads a body
//! into regions of the caller, bounded collection, and the bodies that a sender gives.
//!
//! [`hpack`] is the header compression of HTTP/2: an encoder and a decoder, each the one owner of
//! its dynamic table. [`h2`] is HTTP/2: the frame codec, and the engine of one connection with
//! its streams and flow control. [`qpack`] is the field compression of HTTP/3, with its encoder
//! and decoder streams.
//!
//! [`tls`] is TLS 1.3 (the default `tls` feature): the configuration of each end, and the engine
//! that runs an HTTP engine over TLS records, with the cryptography of rscrypto.
//!
//! [`host`] is the caller-driven host: one connection that the application drives from its own
//! event loop, with no runtime.
//!
//! [`buffer`], [`capacity`], and [`time`] are the buffer, capacity, and time modules of the
//! runtime family, which the public API uses. They are the same modules that `rsasync` gives, so
//! a value from either path is the same type.
//!
//! The `tcp` feature adds [`host::Tcp`], which binds a connection to a nonblocking std TCP socket.

// The TCP binding reads into uninitialized memory with no zeroing, and aborts a connection with a
// reset. Each feature leaves when std makes it stable.
#![cfg_attr(feature = "tcp", feature(read_buf, core_io_borrowed_buf, tcp_linger))]
// The QUIC listener can refuse the allocation of a connection.
#![cfg_attr(feature = "tls", feature(allocator_ext))]

pub use rstypes::{buffer, capacity, time};

pub mod body;
pub mod client;
pub mod drive;
pub mod h1;
pub mod h2;
pub mod host;
pub mod hpack;
mod link;
pub mod message;
pub mod priority;
pub mod qpack;
#[cfg(feature = "tls")]
pub mod quic;
pub mod server;
mod structured;
#[cfg(feature = "tls")]
pub mod tls;
pub mod value;
