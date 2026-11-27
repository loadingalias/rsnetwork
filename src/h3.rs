//! HTTP/3 messages and wire framing (RFC 9114).
//!
//! With the default `tls` feature, `h3::Connection` exchanges requests and responses over one QUIC connection.
//! Drive the engine with each QUIC event. It reports informational heads, the final head, body regions, and the terminal outcome.
//! The host supplies time and drives QUIC datagrams. The frame decoder also works without TLS.
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

#[cfg(feature = "tls")]
mod connection;
#[cfg(feature = "tls")]
mod send;
#[cfg(feature = "tls")]
pub use connection::{Code, Connection, Error, Event, Limits, Settings, Step};

#[cfg(feature = "tls")]
pub(crate) fn check_transport(limits: &crate::quic::Limits) -> Result<(), crate::drive::Error> {
    if limits.streams_uni_max < 3
        || limits.stream_bytes_max == 0
        || limits.data_bytes_max == 0
        || limits.send_bytes_max == 0
    {
        return Err(crate::drive::Error::new(
            crate::drive::Kind::Misuse,
            "HTTP/3 needs three unidirectional streams and nonzero byte windows",
        ));
    }
    Ok(())
}
