//! HTTP/3 wire framing (RFC 9114).
//!
//! Each request, push, and control stream has its own [frame decoder](frame::Decoder).
//! A unidirectional stream starts with a [stream type](frame::StreamType).
//! The QPACK streams carry instructions for the connection's [QPACK codec](crate::qpack).
//!
//! A DATA frame can span two input regions. The decoder borrows each part from its region.
//!
//! ```
//! use rsnetwork::h3::frame::{Decoder, Header, Kind, Part, Stream};
//!
//! let mut frames = Decoder::new(Stream::Response);
//! // The application already processed the response HEADERS on this stream.
//! let mut first = &[0x00, 0x03, b'a'][..];
//! assert_eq!(frames.next(&mut first)?, Some(Part::Header(Header { kind: Kind::DATA, len: 3 })));
//! assert_eq!(frames.next(&mut first)?, Some(Part::Bytes { kind: Kind::DATA, bytes: b"a", end: false }));
//! let mut rest = &b"bc"[..];
//! assert_eq!(frames.next(&mut rest)?, Some(Part::Bytes { kind: Kind::DATA, bytes: b"bc", end: true }));
//! frames.finish()?;
//! # Ok::<(), rsnetwork::h3::frame::Error>(())
//! ```

pub mod frame;
