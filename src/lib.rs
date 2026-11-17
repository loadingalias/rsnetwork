//! Sans-I/O HTTP and QUIC networking. This crate is in development.
//!
//! [`value`] holds the checked values of HTTP: methods, request targets, statuses, field lines,
//! authorities, and schemes. Each protocol of the core uses them.
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
//! its streams and flow control.
//!
//! [`host`] is the caller-driven host: one connection that the application drives from its own
//! event loop, with no runtime.
//!
//! [`buffer`], [`capacity`], and [`time`] are the buffer, capacity, and time modules of the
//! runtime family, which the public API uses. They are the same modules that `rsasync` gives, so
//! a value from either path is the same type.

pub use rstypes::{buffer, capacity, time};

pub mod body;
pub mod drive;
pub mod h1;
pub mod h2;
pub mod host;
pub mod hpack;
pub mod value;
