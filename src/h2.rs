//! HTTP/2 (RFC 9113): the frame codec and the engine of one connection, with no I/O.
//!
//! [`frame`] reads and writes each frame of RFC 9113, with each check of sections 4 and 6.
//! [`Connection`] is the engine of one connection. It sends and checks the connection preface,
//! exchanges and acknowledges SETTINGS, answers PING, and joins a header block across HEADERS and
//! CONTINUATION frames into one HPACK decode. It keeps the state of each stream (section 5.1),
//! flow control at the stream and the connection level (sections 5.2 and 6.9), and the drain
//! after a GOAWAY (section 6.8). A connection error sends a GOAWAY with its RFC 9113 code, and
//! then the connection ends. A stream error resets its stream. Server push is off: a client sends
//! `SETTINGS_ENABLE_PUSH` 0, and a PUSH_PROMISE is a connection error in each role.
//!
//! A stream that a reset ended keeps its slot in the stream table until the application closes
//! it, when its handler ends. Thus a peer that opens and resets streams at line rate starts at
//! most `SETTINGS_MAX_CONCURRENT_STREAMS` handlers at a time (CVE-2023-44487).
//!
//! The engine reads frames in place in the received regions: a DATA payload goes up as views of
//! the regions, with no copy. A header block in one HEADERS frame inside one region decodes in
//! place. Other blocks join into one buffer that the caller's budget pays for, because the HPACK
//! decoder reads one contiguous block. The receive credit follows the consumer: the peer gets
//! more credit only for the bytes that the consumer releases.
//!
//! The application gives the body of each stream in chunks. In each drive, the send scheduler
//! sends one DATA frame of at most 16,384 bytes for each stream in turn, within the two send
//! windows, as views of the chunks. A stream with no send credit waits in its own slot, so a slow
//! consumer of the peer holds back only its stream.
//!
//! ```
//! use core::net::{Ipv4Addr, SocketAddr};
//! use core::num::{NonZeroU64, NonZeroUsize};
//!
//! use rsnetwork::buffer::{Backing, Buffer as _, Lease};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
//! use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
//! use rsnetwork::hpack::{FieldLine, Lines};
//! use rsnetwork::time::{ClockDomain, Instant, Suspend};
//!
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let queue = NonZeroUsize::new(16).expect("not zero");
//! let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
//! // Local settings choose each bound that the budget pays for. RFC 9113, section 6.5.2,
//! // recommends at least 100 concurrent streams. A header list of 16 KiB costs lines of 32 KiB.
//! let settings = Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..Settings::INITIAL };
//! let limits = Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 };
//! let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
//! // The server sends its SETTINGS frame, and a WINDOW_UPDATE that raises the connection window.
//! let mut server = Connection::new(Role::Server, limits, turn, &mut outbound, &budget)?;
//! let mut lines = Lines::new(server.header_limits(), &budget)?;
//! let now = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));
//!
//! // The client preface, its empty SETTINGS frame, and a request on stream 1: a HEADERS frame
//! // whose block is RFC 7541, C.3.1 (GET http://www.example.com/).
//! let mut input = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0".to_vec();
//! input.extend_from_slice(b"\0\0\x14\x01\x05\0\0\0\x01");
//! input.extend_from_slice(b"\x82\x86\x84\x41\x0fwww.example.com");
//! let endpoint = Endpoint {
//!     peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
//!     local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
//!     ecn: Ecn::NotEct,
//!     segment: None,
//! };
//! inbound.push(Received { region: Lease::from(input), endpoint, capacity: 64 * 1024 }).expect("room");
//!
//! // The first drive applies the peer's settings and acknowledges them.
//! let (Some(Event::Settings(peer)), _) = server.drive(&mut inbound, &mut outbound, &mut lines, now) else {
//!     panic!("the peer's settings")
//! };
//! assert_eq!(peer, Settings::INITIAL);
//! let (Some(Event::Headers { stream: 1, end_stream: true, lines: Some(block) }), _) =
//!     server.drive(&mut inbound, &mut outbound, &mut lines, now)
//! else {
//!     panic!("a request")
//! };
//! let fields: Vec<_> = block.lines().map(|line| (line.name, line.value)).collect();
//! assert_eq!(fields[3], (&b":authority"[..], &b"www.example.com"[..]));
//!
//! // The response on stream 1: a header section, and its body, which ends the stream. The next
//! // drive sends the body in one DATA frame.
//! let status = FieldLine { name: b":status", value: b"200", never_indexed: false };
//! server.headers(&mut outbound, 1, [status].into_iter(), false, Backing::from(Vec::with_capacity(64)))?;
//! server.data(&mut outbound, 1, Lease::from(b"hello".to_vec()), true)?;
//! assert!(server.drive(&mut inbound, &mut outbound, &mut lines, now).0.is_none());
//!
//! // The output: the server's SETTINGS frame and WINDOW_UPDATE, the acknowledgement of the
//! // client's SETTINGS frame, the HEADERS frame, and last the DATA frame.
//! let mut sent = Vec::new();
//! while let Some(output) = outbound.submit() {
//!     sent.extend_from_slice(output.region.bytes());
//!     outbound.ack(output.id, output.region.initialized())?;
//! }
//! assert!(sent.ends_with(b"\0\0\x05\0\x01\0\0\0\x01hello"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod connection;
pub mod frame;
pub(crate) mod message;
pub(crate) mod session;
mod stream;

use core::time::Duration;

pub use connection::{Connection, Event, SHUTDOWN_PING};

use frame::{HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE};

/// The default settings timeout of a [`Connection`]: 10 seconds, the default of nghttpx. The peer
/// acknowledges the SETTINGS frame of the connection preface within it, or the connection ends
/// with `SETTINGS_TIMEOUT` (RFC 9113, section 6.5.3).
pub const SETTINGS_TIMEOUT: Duration = Duration::from_secs(10);

/// The role of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The client: it sends the client preface and opens streams.
    Client,
    /// The server.
    Server,
}

/// The settings of one endpoint (RFC 9113, section 6.5.2).
///
/// The settings of an endpoint bound what its peer sends. [`INITIAL`](Self::INITIAL) holds the
/// initial values, which hold until the peer sends others. `u32::MAX` is the initial value of
/// the two settings that start with no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `SETTINGS_HEADER_TABLE_SIZE`: the largest dynamic table of the endpoint's HPACK decoder.
    pub header_table_size: u32,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`: the most streams that the peer can have open. The
    /// connection of the endpoint has a stream table of this size, so a client also opens at
    /// most this many streams. Push is off, so the value has no other effect for a client.
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: the initial flow-control window of each stream, at most
    /// 2^31 - 1. For the endpoint, it is the bytes of each stream that the consumer admits.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload that the endpoint receives, from
    /// 2^14 to 2^24 - 1.
    pub max_frame_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest decoded header list, in the size of RFC 7541,
    /// section 4.1.
    pub max_header_list_size: u32,
}

impl Settings {
    /// The initial values of RFC 9113, section 6.5.2: the settings of a peer before its SETTINGS
    /// frame. Local settings must give `max_concurrent_streams` and `max_header_list_size`
    /// finite values, because the budget pays for them: [`Connection::new`] charges a stream
    /// table of `max_concurrent_streams` entries, and [`Lines::new`](crate::hpack::Lines::new)
    /// charges space for a header list of `max_header_list_size` bytes. With `u32::MAX`, the
    /// budget refuses.
    pub const INITIAL: Self = Self {
        header_table_size: 4096,
        max_concurrent_streams: u32::MAX,
        initial_window_size: 65_535,
        max_frame_size: frame::MIN_FRAME_SIZE,
        max_header_list_size: u32::MAX,
    };

    /// Each setting with its identifier, in the order of the identifiers.
    const fn entries(&self) -> [(u16, u32); 5] {
        [
            (HEADER_TABLE_SIZE, self.header_table_size),
            (MAX_CONCURRENT_STREAMS, self.max_concurrent_streams),
            (INITIAL_WINDOW_SIZE, self.initial_window_size),
            (MAX_FRAME_SIZE, self.max_frame_size),
            (MAX_HEADER_LIST_SIZE, self.max_header_list_size),
        ]
    }

    /// Sets the setting `id` to `value`. An identifier that this crate does not know changes
    /// nothing.
    fn apply(&mut self, id: u16, value: u32) {
        match id {
            HEADER_TABLE_SIZE => self.header_table_size = value,
            MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = value,
            INITIAL_WINDOW_SIZE => self.initial_window_size = value,
            MAX_FRAME_SIZE => self.max_frame_size = value,
            MAX_HEADER_LIST_SIZE => self.max_header_list_size = value,
            _ => {}
        }
    }
}

/// The limits of a [`Connection`], which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The settings that the endpoint sends in its preface. Its HPACK decoder has a table of
    /// `header_table_size` and a list limit of `max_header_list_size`, so give a list limit that
    /// the budget can pay for. The connection refuses each frame larger than `max_frame_size`.
    pub settings: Settings,
    /// The most work of one header block, and the largest header block. The size of a block is
    /// the bytes of its fragments and 9 bytes for each CONTINUATION frame, so empty CONTINUATION
    /// frames cannot continue a block forever. The work is the bytes of the block and each byte
    /// that the HPACK decoder copies. A block past it ends the connection at the header of the
    /// frame that passes it, before the connection copies it.
    pub work: usize,
    /// The largest dynamic table of the HPACK encoder. The encoder uses at most the smaller of it
    /// and the peer's `SETTINGS_HEADER_TABLE_SIZE`.
    pub encoder_table_bytes: usize,
    /// The connection receive window: the DATA bytes of all streams that the consumers admit,
    /// from 65,535 to 2^31 - 1. A larger value than 65,535, the initial window of RFC 9113, goes
    /// to the peer in a WINDOW_UPDATE after the preface.
    pub connection_window: u32,
}
