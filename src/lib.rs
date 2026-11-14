//! Sans-I/O HTTP and QUIC networking. This crate is in development.
//!
//! [`value`] holds the checked values of HTTP: methods, request targets, statuses, field lines,
//! authorities, and schemes. Each protocol of the core uses them.
//!
//! [`h1`] parses HTTP/1.1 request heads in the received bytes and writes response heads into an
//! owned output region. It does no I/O, so any runtime or event loop can drive it.
//!
//! [`drive`] is the interface that each protocol engine shares: received and output regions,
//! their exact acknowledgements, the result of each drive, and the errors.
//!
//! [`buffer`] and [`time`] are the buffer and time modules of the runtime family, which the
//! public API uses. They are the same modules that `rsasync` gives, so a value from either path
//! is the same type.

pub use rstypes::{buffer, time};

pub mod drive;
pub mod h1;
pub mod value;
