//! Sans-I/O HTTP and QUIC networking. This crate is in development.
//!
//! [`h1`] parses HTTP/1.1 request heads in the received bytes and writes response heads into an
//! owned output region. It does no I/O, so any runtime or event loop can drive it.
//!
//! [`buffer`] is the buffer module of the runtime family, which the public API uses. It is the
//! same module that `rsasync::buffer` gives, so a buffer from either path is the same type.

pub use rstypes::buffer;

pub mod h1;
