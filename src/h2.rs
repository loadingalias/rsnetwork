//! HTTP/2 (RFC 9113): the frame codec and the frame and connection layer of the engine, with no
//! I/O.
//!
//! [`frame`] reads and writes each frame of RFC 9113, with each check of sections 4 and 6.
//! [`Connection`] is the frame and connection layer of one connection. It sends and checks the
//! connection preface, exchanges and acknowledges SETTINGS, answers PING, frames GOAWAY, and joins
//! a header block across HEADERS and CONTINUATION frames into one HPACK decode. A connection error
//! sends a GOAWAY with its RFC 9113 code, and then the connection ends. Server push is off: a
//! client sends `SETTINGS_ENABLE_PUSH` 0, and a PUSH_PROMISE is a connection error in each role.
//!
//! The layer reads frames in place in the received regions: a DATA payload goes up as views of the
//! regions, with no copy. A header block in one HEADERS frame inside one region decodes in place.
//! Other blocks join into one buffer that the caller's budget pays for, because the HPACK decoder
//! reads one contiguous block. The stream state, flow control, and drain are the layer above.
//!
//! ```
//! use core::net::{Ipv4Addr, SocketAddr};
//! use core::num::{NonZeroU64, NonZeroUsize};
//!
//! use rsnetwork::buffer::{Buffer as _, Lease};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
//! use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
//! use rsnetwork::hpack::Lines;
//! use rsnetwork::time::{ClockDomain, Instant, Suspend};
//!
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let queue = NonZeroUsize::new(16).expect("not zero");
//! let (mut inbound, mut outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
//! let settings = Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..Settings::INITIAL };
//! let limits = Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096 };
//! let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
//! // The server sends its SETTINGS frame at once.
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
//! // The output: the server's SETTINGS frame, then the acknowledgement of the client's.
//! let mut sent = Vec::new();
//! while let Some(output) = outbound.submit() {
//!     sent.extend_from_slice(output.region.bytes());
//!     outbound.ack(output.id, output.region.initialized())?;
//! }
//! assert_eq!(sent[sent.len() - 9..], [0, 0, 0, 0x04, 0x01, 0, 0, 0, 0]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod connection;
pub mod frame;

use core::time::Duration;

pub use connection::{Connection, Event};

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
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`: the most streams that the peer can have open.
    pub max_concurrent_streams: u32,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`: the initial flow-control window of each stream, at most
    /// 2^31 - 1.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE`: the largest frame payload that the endpoint receives, from
    /// 2^14 to 2^24 - 1.
    pub max_frame_size: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`: the largest decoded header list, in the size of RFC 7541,
    /// section 4.1.
    pub max_header_list_size: u32,
}

impl Settings {
    /// The initial values of RFC 9113, section 6.5.2.
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
    /// The most work of one header block, and the largest header block. The work is the bytes of
    /// the block and each byte that the HPACK decoder copies. A block of HEADERS and CONTINUATION
    /// fragments past it ends the connection before the connection copies it.
    pub work: usize,
    /// The largest dynamic table of the HPACK encoder. The encoder uses at most the smaller of it
    /// and the peer's `SETTINGS_HEADER_TABLE_SIZE`.
    pub encoder_table_bytes: usize,
}
