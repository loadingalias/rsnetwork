//! The contracts of the HTTP/2 engine: the preface, SETTINGS and their acknowledgement, PING,
//! GOAWAY and drain, header blocks across CONTINUATION frames, each connection error with its RFC
//! 9113 code, frames that parse in place, the stream states, and flow control at both levels.
//! Each expected byte and code comes from RFC 9113 or RFC 7541, as each test states, not from the
//! code under test.

use core::assert_matches;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h2::frame::{ErrorCode, PREFACE};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::{Block, FieldLine, Lines};
use rsnetwork::time::{ClockDomain, Instant, Suspend};

mod counting;

use counting::allocations;

const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

/// The time of the host, which most tests keep at the start of their clock.
const NOW: Option<Instant> = Some(Instant::new(CLOCK, 0));

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The settings of each endpoint in the tests: a stream limit, a list limit, and the initial
/// values.
const SETTINGS: Settings = Settings {
    max_concurrent_streams: 100,
    max_header_list_size: 16 * 1024,
    ..Settings::INITIAL
};

/// The limits of each endpoint in the tests. The connection window is the initial window of RFC
/// 9113, so the preface has no WINDOW_UPDATE.
const LIMITS: Limits = Limits {
    settings: SETTINGS,
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 65_535,
};

/// An empty SETTINGS frame (RFC 9113, section 6.5).
const EMPTY_SETTINGS: &[u8] = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// A SETTINGS frame with the flag ACK (RFC 9113, section 6.5).
const SETTINGS_ACK: &[u8] = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00";

/// The header block of RFC 7541, C.3.1: `GET http://www.example.com/`.
const C31: &[u8] = b"\x82\x86\x84\x41\x0fwww.example.com";

/// The lines of RFC 7541, C.3.1.
const C31_LINES: [(&str, &str); 4] = [
    (":method", "GET"),
    (":scheme", "http"),
    (":path", "/"),
    (":authority", "www.example.com"),
];

/// A frame header (RFC 9113, figure 1).
fn head(length: u32, kind: u8, flags: u8, stream: u32) -> Vec<u8> {
    let mut head = length.to_be_bytes()[1..].to_vec();
    head.extend_from_slice(&[kind, flags]);
    head.extend_from_slice(&stream.to_be_bytes());
    head
}

/// A frame: its header and its payload.
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("a short payload");
    [head(length, kind, flags, stream), payload.to_vec()].concat()
}

/// A GOAWAY with no debug data (RFC 9113, figure 10).
fn goaway(last_stream: u32, code: ErrorCode) -> Vec<u8> {
    frame(0x7, 0, 0, &[last_stream.to_be_bytes(), code.0.to_be_bytes()].concat())
}

/// A HEADERS frame on `stream` with END_HEADERS and the block of RFC 7541, C.3.1, and END_STREAM
/// when `end_stream` (RFC 9113, figure 7).
fn request(stream: u32, end_stream: bool) -> Vec<u8> {
    frame(0x1, 0x4 | u8::from(end_stream), stream, C31)
}

/// A DATA frame with no padding (RFC 9113, figure 3).
fn data(stream: u32, end_stream: bool, bytes: &[u8]) -> Vec<u8> {
    frame(0x0, u8::from(end_stream), stream, bytes)
}

/// A RST_STREAM (RFC 9113, figure 6).
fn rst(stream: u32, code: ErrorCode) -> Vec<u8> {
    frame(0x3, 0, stream, &code.0.to_be_bytes())
}

/// A WINDOW_UPDATE (RFC 9113, figure 12).
fn window_update(stream: u32, increment: u32) -> Vec<u8> {
    frame(0x8, 0, stream, &increment.to_be_bytes())
}

/// The frames of `bytes`, each as its type, its stream, and its payload.
fn frames(mut bytes: &[u8]) -> Vec<(u8, u32, Vec<u8>)> {
    let mut frames = Vec::new();
    while let Some((head, rest)) = bytes.split_first_chunk::<9>() {
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
        frames.push((head[3], stream, rest[..length].to_vec()));
        bytes = &rest[length..];
    }
    assert!(bytes.is_empty(), "the output ends inside a frame");
    frames
}

/// The increments of the WINDOW_UPDATE frames on `stream` in `bytes`.
fn grants(bytes: &[u8], stream: u32) -> Vec<u32> {
    frames(bytes)
        .into_iter()
        .filter(|(kind, id, _)| *kind == 0x8 && *id == stream)
        .map(|(_, _, payload)| u32::from_be_bytes(payload[..4].try_into().expect("4 bytes")))
        .collect()
}

/// What the layer above saw: each event, with its bytes copied.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Headers(u32, bool, Option<Vec<(Vec<u8>, Vec<u8>)>>),
    Trailers(u32, Option<Vec<(Vec<u8>, Vec<u8>)>>),
    Data(u32, Vec<u8>, bool),
    Reset(u32, ErrorCode),
    WindowUpdate(u32, u32),
    Settings(Settings),
    PingAck([u8; 8]),
    GoAway(u32, ErrorCode),
    StreamError(u32, ErrorCode),
}

fn seen(event: Event<'_>) -> Seen {
    let copy = |lines: Option<Block<'_>>| {
        lines.map(|block| {
            block
                .lines()
                .map(|line| (line.name.to_vec(), line.value.to_vec()))
                .collect()
        })
    };
    match event {
        Event::Headers {
            stream,
            end_stream,
            lines,
        } => Seen::Headers(stream, end_stream, copy(lines)),
        Event::Trailers { stream, lines } => Seen::Trailers(stream, copy(lines)),
        Event::Data {
            stream,
            data,
            end_stream,
        } => Seen::Data(stream, data.bytes().to_vec(), end_stream),
        Event::Reset { stream, code } => Seen::Reset(stream, code),
        Event::WindowUpdate { stream, increment } => Seen::WindowUpdate(stream, increment),
        Event::Settings(settings) => Seen::Settings(settings),
        Event::PingAck(opaque) => Seen::PingAck(opaque),
        Event::GoAway { last_stream, code } => Seen::GoAway(last_stream, code),
        Event::StreamError { stream, code } => Seen::StreamError(stream, code),
    }
}

fn lines(lines: &[(&str, &str)]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    Some(
        lines
            .iter()
            .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect(),
    )
}

/// One endpoint, its queues, and the lines of its drives.
struct Peer {
    budget: Budget,
    connection: Connection,
    inbound: Inbound,
    outbound: Outbound,
    lines: Lines,
    now: Option<Instant>,
}

impl Peer {
    fn new(role: Role, limits: Limits) -> Self {
        let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
        let queue = NonZeroUsize::new(64).expect("not zero");
        let inbound = Inbound::new(queue, &budget).expect("the budget pays for the queue");
        let mut outbound = Outbound::new(queue, &budget).expect("the budget pays for the queue");
        let connection =
            Connection::new(role, limits, TURN, &mut outbound, &budget).expect("the budget pays for the connection");
        let lines = Lines::new(connection.header_limits(), &budget).expect("the budget pays for the lines");
        Self {
            budget,
            connection,
            inbound,
            outbound,
            lines,
            now: NOW,
        }
    }

    /// A server that read the client preface with an empty SETTINGS frame, and sent its
    /// acknowledgement.
    fn server() -> Self {
        Self::server_with(LIMITS)
    }

    fn server_with(limits: Limits) -> Self {
        let mut server = Self::new(Role::Server, limits);
        server.receive(&[PREFACE.as_slice(), EMPTY_SETTINGS].concat());
        assert_eq!(server.run(), (vec![Seen::Settings(Settings::INITIAL)], WAIT));
        assert!(server.sent().ends_with(SETTINGS_ACK), "the acknowledgement");
        server
    }

    fn receive(&mut self, bytes: &[u8]) {
        let received = Received {
            region: Lease::from(bytes.to_vec()),
            endpoint: ENDPOINT,
            capacity: 1 << 20,
        };
        assert!(self.inbound.push(received).is_ok(), "the queue has room");
    }

    fn drive(&mut self) -> (Option<Seen>, Progress) {
        let (event, turn) = self
            .connection
            .drive(&mut self.inbound, &mut self.outbound, &mut self.lines, self.now);
        (event.map(seen), turn.progress)
    }

    /// Drives until the connection waits or ends, and gives each event and the last progress.
    fn run(&mut self) -> (Vec<Seen>, Progress) {
        let mut events = Vec::new();
        for _ in 0..10_000 {
            match self.drive() {
                (Some(event), _) => events.push(event),
                (None, Progress::Pending) => {}
                (None, progress) => return (events, progress),
            }
        }
        panic!("the connection makes no progress")
    }

    /// A server that also read the acknowledgement of its settings.
    fn acknowledged(limits: Limits) -> Self {
        let mut server = Self::server_with(limits);
        server.receive(SETTINGS_ACK);
        assert_eq!(server.run(), (vec![], WAIT));
        server
    }

    /// A client that read the empty SETTINGS frame of a server, and sent its acknowledgement.
    fn client() -> Self {
        let mut client = Self::new(Role::Client, LIMITS);
        client.receive(EMPTY_SETTINGS);
        assert_eq!(client.run(), (vec![Seen::Settings(Settings::INITIAL)], WAIT));
        client.sent();
        client
    }

    /// Opens a stream of a client with the lines of RFC 7541, C.3.1.
    fn open(&mut self, end_stream: bool) -> u32 {
        let lines = C31_LINES.map(|(name, value)| FieldLine {
            name: name.as_bytes(),
            value: value.as_bytes(),
            never_indexed: false,
        });
        let region = Backing::from(Vec::with_capacity(256));
        self.connection
            .open(&mut self.outbound, lines.into_iter(), end_stream, region)
            .expect("the connection opens the stream")
    }

    /// Sends a header section with the single line `name: value` on `stream`.
    fn section(&mut self, stream: u32, name: &str, value: &str, end_stream: bool) -> Result<(), Kind> {
        let line = FieldLine {
            name: name.as_bytes(),
            value: value.as_bytes(),
            never_indexed: false,
        };
        let region = Backing::from(Vec::with_capacity(256));
        self.connection
            .headers(&mut self.outbound, stream, [line].into_iter(), end_stream, region)
            .map_err(|error| error.kind())
    }

    /// Sends `bytes` on `stream` as DATA, and gives the number of bytes that went out.
    fn send(&mut self, stream: u32, bytes: &[u8], end_stream: bool) -> Result<usize, Kind> {
        let lease = Lease::from(bytes.to_vec());
        self.connection
            .data(&mut self.outbound, stream, &lease, end_stream)
            .map_err(|error| error.kind())
    }

    /// Releases `bytes` bytes of `stream` that the consumer held.
    fn release(&mut self, stream: u32, bytes: u32) -> Result<(), Kind> {
        self.connection
            .release(&mut self.outbound, stream, bytes)
            .map_err(|error| error.kind())
    }

    /// The bytes of each output, which the transport accepts in full.
    fn sent(&mut self) -> Vec<u8> {
        let mut sent = Vec::new();
        while let Some(output) = self.outbound.submit() {
            sent.extend_from_slice(output.region.bytes());
            self.outbound
                .ack(output.id, output.region.initialized())
                .expect("the output is outstanding");
        }
        sent
    }
}

const WAIT: Progress = Progress::Blocked(Blocked::Input);

/// The end of a connection after an error of `kind`.
fn ended(progress: Progress, kind: Kind) {
    match progress {
        Progress::Terminal(Err(error)) => assert_eq!(error.kind(), kind, "{error}"),
        other => panic!("the connection did not end: {other:?}"),
    }
}

/// A client preface is the 24 bytes of RFC 9113, section 3.4, and a SETTINGS frame that sets
/// `SETTINGS_ENABLE_PUSH` to 0, so a server never pushes (RFC 9113, section 8.4). A server
/// preface is one SETTINGS frame. Each lists the settings that differ from their initial values.
#[test]
fn each_preface_has_its_settings_and_a_client_disables_push() {
    let mut client = Peer::new(Role::Client, LIMITS);
    // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) 100, SETTINGS_MAX_HEADER_LIST_SIZE (0x6) 16384, then
    // SETTINGS_ENABLE_PUSH (0x2) 0.
    let settings = b"\x00\x03\x00\x00\x00\x64\x00\x06\x00\x00\x40\x00";
    assert_eq!(
        client.sent(),
        [
            &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
            &frame(0x4, 0, 0, &[&settings[..], b"\x00\x02\x00\x00\x00\x00"].concat()),
        ]
        .concat()
    );
    // A connection window of 1 MiB follows the SETTINGS frame as a WINDOW_UPDATE on stream 0 of
    // 2^20 - 65,535 (RFC 9113, section 6.9.2).
    let mut server = Peer::new(
        Role::Server,
        Limits {
            connection_window: 1 << 20,
            ..LIMITS
        },
    );
    assert_eq!(
        server.sent(),
        [frame(0x4, 0, 0, settings), window_update(0, (1 << 20) - 65_535)].concat()
    );
}

/// An invalid preface is a connection error of type PROTOCOL_ERROR (RFC 9113, section 3.4): the
/// bytes of an HTTP/1.1 request, and a first frame that is not a SETTINGS frame in each role.
#[test]
fn a_wrong_preface_ends_the_connection_with_protocol_error() {
    let ping = frame(0x6, 0, 0, &[0; 8]);
    let cases: [(Role, Vec<u8>); 4] = [
        (Role::Server, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()),
        (Role::Server, [PREFACE.as_slice(), ping.as_slice()].concat()),
        (Role::Server, [PREFACE.as_slice(), SETTINGS_ACK].concat()),
        (Role::Client, frame(0x1, 0x5, 1, C31)),
    ];
    for (role, input) in cases {
        let mut peer = Peer::new(role, LIMITS);
        peer.sent();
        peer.receive(&input);
        let (events, progress) = peer.run();
        assert_eq!(events, [], "{role:?} {input:02x?}");
        ended(progress, Kind::Malformed);
        assert_eq!(
            peer.sent(),
            goaway(0, ErrorCode::PROTOCOL_ERROR),
            "{role:?} {input:02x?}"
        );
    }
}

/// Each frame that breaks a rule of RFC 9113, sections 4 to 8, ends the connection with a GOAWAY
/// of the code that the rule names. Each case follows a valid client preface.
#[test]
fn each_frame_that_breaks_rfc_9113_ends_the_connection_with_its_code() {
    let protocol = ErrorCode::PROTOCOL_ERROR;
    let size = ErrorCode::FRAME_SIZE_ERROR;
    let open = frame(0x1, 0x0, 1, &C31[..3]);
    let cases: Vec<(&str, Vec<u8>, ErrorCode)> = vec![
        ("6.1 DATA on stream 0", frame(0x0, 0, 0, b"x"), protocol),
        ("4.2 PADDED DATA with no pad length", frame(0x0, 0x8, 1, b""), size),
        (
            "6.1 a pad length of the payload length",
            frame(0x0, 0x8, 1, b"\x02x"),
            protocol,
        ),
        ("6.2 HEADERS on stream 0", frame(0x1, 0x4, 0, C31), protocol),
        (
            "6.2 a pad length past the fragment",
            frame(0x1, 0xc, 1, b"\x05abc"),
            protocol,
        ),
        (
            "4.2 PRIORITY flag with 4 bytes",
            frame(0x1, 0x24, 1, b"\x00\x00\x00\x03"),
            size,
        ),
        (
            "5.3.1 of RFC 7540 HEADERS that depends on itself",
            frame(0x1, 0x24, 1, b"\x00\x00\x00\x01\x0f"),
            protocol,
        ),
        (
            "6.3 PRIORITY on stream 0",
            frame(0x2, 0, 0, b"\x00\x00\x00\x01\x0f"),
            protocol,
        ),
        ("6.3 PRIORITY of 4 bytes", frame(0x2, 0, 3, b"\x00\x00\x00\x01"), size),
        (
            "5.3.1 of RFC 7540 PRIORITY that depends on itself",
            frame(0x2, 0, 3, b"\x00\x00\x00\x03\x0f"),
            protocol,
        ),
        (
            "6.4 RST_STREAM on stream 0",
            frame(0x3, 0, 0, b"\x00\x00\x00\x08"),
            protocol,
        ),
        ("6.4 RST_STREAM of 3 bytes", frame(0x3, 0, 1, b"\x00\x00\x08"), size),
        ("6.5 SETTINGS on stream 1", frame(0x4, 0, 1, b""), protocol),
        (
            "6.5 SETTINGS of 5 bytes",
            frame(0x4, 0, 0, b"\x00\x01\x00\x00\x00"),
            size,
        ),
        (
            "6.5 SETTINGS ACK with a setting",
            frame(0x4, 0x1, 0, b"\x00\x01\x00\x00\x00\x00"),
            size,
        ),
        (
            "6.5.2 SETTINGS_ENABLE_PUSH 2",
            frame(0x4, 0, 0, b"\x00\x02\x00\x00\x00\x02"),
            protocol,
        ),
        (
            "6.5.2 SETTINGS_INITIAL_WINDOW_SIZE 2^31",
            frame(0x4, 0, 0, b"\x00\x04\x80\x00\x00\x00"),
            ErrorCode::FLOW_CONTROL_ERROR,
        ),
        (
            "6.5.2 SETTINGS_MAX_FRAME_SIZE 2^14 - 1",
            frame(0x4, 0, 0, b"\x00\x05\x00\x00\x3f\xff"),
            protocol,
        ),
        (
            "6.5.2 SETTINGS_MAX_FRAME_SIZE 2^24",
            frame(0x4, 0, 0, b"\x00\x05\x01\x00\x00\x00"),
            protocol,
        ),
        (
            "8.4 PUSH_PROMISE to a server",
            frame(0x5, 0x4, 1, b"\x00\x00\x00\x02\x82"),
            protocol,
        ),
        (
            "6.6 PUSH_PROMISE on stream 0",
            frame(0x5, 0x4, 0, b"\x00\x00\x00\x02\x82"),
            protocol,
        ),
        ("6.7 PING on stream 1", frame(0x6, 0, 1, &[0; 8]), protocol),
        ("6.7 PING of 7 bytes", frame(0x6, 0, 0, &[0; 7]), size),
        ("6.8 GOAWAY on stream 1", frame(0x7, 0, 1, &[0; 8]), protocol),
        ("6.8 GOAWAY of 7 bytes", frame(0x7, 0, 0, &[0; 7]), size),
        ("6.9 WINDOW_UPDATE of 3 bytes", frame(0x8, 0, 0, b"\x00\x00\x01"), size),
        (
            "6.9 WINDOW_UPDATE of 0 on the connection",
            frame(0x8, 0, 0, b"\x00\x00\x00\x00"),
            protocol,
        ),
        ("6.10 CONTINUATION on stream 0", frame(0x9, 0x4, 0, b"\x82"), protocol),
        (
            "6.10 CONTINUATION after no header block",
            frame(0x9, 0x4, 1, b"\x82"),
            protocol,
        ),
        (
            "6.2 PING inside a header block",
            [open.clone(), frame(0x6, 0, 0, &[0; 8])].concat(),
            protocol,
        ),
        (
            "6.2 DATA inside a header block",
            [open.clone(), frame(0x0, 0, 1, b"x")].concat(),
            protocol,
        ),
        (
            "6.10 CONTINUATION of another stream",
            [open.clone(), frame(0x9, 0x4, 3, &C31[3..])].concat(),
            protocol,
        ),
        (
            "5.5 an unknown type inside a header block",
            [open, frame(0xfa, 0, 0, b"")].concat(),
            protocol,
        ),
        (
            "4.3 a header block that breaks RFC 7541",
            frame(0x1, 0x5, 1, b"\xff"),
            ErrorCode::COMPRESSION_ERROR,
        ),
    ];
    for (rule, input, code) in cases {
        let mut server = Peer::server();
        server.receive(&input);
        let (events, progress) = server.run();
        assert_eq!(events, [], "{rule}");
        ended(progress, Kind::Malformed);
        assert_eq!(server.sent(), goaway(0, code), "{rule}");
    }
}

/// A frame larger than `SETTINGS_MAX_FRAME_SIZE` is a FRAME_SIZE_ERROR (RFC 9113, section 4.2),
/// and the connection refuses it from its 9-byte header: the drive that reads it allocates
/// nothing.
#[test]
fn a_frame_over_the_declared_size_refuses_before_any_allocation() {
    for kind in [0x0, 0x1, 0xfa] {
        let mut server = Peer::server();
        server.receive(&head(SETTINGS.max_frame_size + 1, kind, 0x4, 1));
        let ((event, turn), count) = allocations(|| {
            let (event, turn) =
                server
                    .connection
                    .drive(&mut server.inbound, &mut server.outbound, &mut server.lines, NOW);
            (event.is_some(), turn)
        });
        assert_eq!(count, 0, "type {kind}");
        assert!(!event, "type {kind}");
        ended(turn.progress, Kind::Malformed);
        assert_eq!(server.sent(), goaway(0, ErrorCode::FRAME_SIZE_ERROR), "type {kind}");
    }
}

/// A header block past its bound ends the connection with COMPRESSION_ERROR, which RFC 9113,
/// section 4.3, requires when a receiver does not decode a block. The connection refuses at the
/// header of the frame that passes the bound, before it copies a byte or allocates.
#[test]
fn a_header_block_past_its_bound_refuses_before_any_allocation() {
    let limits = Limits { work: 1024, ..LIMITS };
    // One HEADERS frame past the bound, and a block whose CONTINUATION passes it.
    let cases = [
        (Vec::new(), head(1025, 0x1, 0x4, 1)),
        (frame(0x1, 0, 1, &[0x82; 600]), head(600, 0x9, 0x4, 1)),
    ];
    for (before, header) in cases {
        let mut server = Peer::server_with(limits);
        server.receive(&before);
        assert_eq!(server.run(), (vec![], WAIT));
        server.receive(&header);
        let (turn, count) = allocations(|| {
            server
                .connection
                .drive(&mut server.inbound, &mut server.outbound, &mut server.lines, NOW)
                .1
        });
        assert_eq!(count, 0);
        ended(turn.progress, Kind::Overload);
        assert_eq!(server.sent(), goaway(0, ErrorCode::COMPRESSION_ERROR));
    }
}

/// A header block that joins is charged before its copy (RFC 9113, section 10.5.1, and the drive
/// contract of admission). When the budget cannot pay, the turn waits for capacity with no
/// allocation, and the block decodes when the budget can pay.
#[test]
fn a_joined_header_block_is_charged_before_its_copy() {
    let mut server = Peer::server();
    server.receive(&[frame(0x1, 0x1, 1, &C31[..3]), frame(0x9, 0x4, 1, &C31[3..])].concat());
    let hold = server
        .budget
        .reserve(server.budget.available())
        .expect("the rest of the budget");
    let (turn, count) = allocations(|| {
        server
            .connection
            .drive(&mut server.inbound, &mut server.outbound, &mut server.lines, NOW)
            .1
    });
    assert_eq!(count, 0);
    // A block that continues reserves the bound of a block: the work limit.
    assert_eq!(turn.progress, Progress::Blocked(Blocked::Capacity(64 * 1024)));
    drop(hold);
    assert_eq!(server.run(), (vec![Seen::Headers(1, true, lines(&C31_LINES))], WAIT));
}

/// A header block split over HEADERS and CONTINUATION frames decodes as one block (RFC 9113,
/// section 4.3), with the lines of RFC 7541, C.3.1. The HEADERS frame has padding and the
/// deprecated priority fields, which the connection skips. The input arrives in one region and
/// one byte at a time, and both give one event.
#[test]
fn a_header_block_over_continuation_frames_decodes_as_one_block() {
    // PADDED and PRIORITY: pad length 2, dependency 0, weight 15, 3 bytes of the block, 2 bytes
    // of padding. END_STREAM, and no END_HEADERS.
    let headers = frame(
        0x1,
        0x29,
        1,
        &[&b"\x02\x00\x00\x00\x00\x0f"[..], &C31[..3], &b"\x00\x00"[..]].concat(),
    );
    let input = [
        headers,
        frame(0x9, 0, 1, &C31[3..13]),
        frame(0x9, 0, 1, b""),
        frame(0x9, 0x4, 1, &C31[13..]),
    ]
    .concat();
    let expected = vec![Seen::Headers(1, true, lines(&C31_LINES))];
    let mut whole = Peer::server();
    whole.receive(&input);
    assert_eq!(whole.run(), (expected, WAIT));
    let mut cut = Peer::server();
    let mut events = Vec::new();
    for byte in &input {
        cut.receive(&[*byte]);
        let (seen, progress) = cut.run();
        assert_eq!(progress, WAIT);
        events.extend(seen);
    }
    assert_eq!(events, [Seen::Headers(1, true, lines(&C31_LINES))]);
}

/// Frames parse in place: a header block in one HEADERS frame decodes with no allocation, and a
/// DATA payload goes up as a view of the received region, with no copy.
#[test]
fn frames_parse_in_place_with_no_copy() {
    let mut server = Peer::server();
    let data = frame(0x0, 0x1, 1, b"hello");
    server.receive(&[frame(0x1, 0x4, 1, C31), data].concat());
    let address = server.inbound.front().expect("a region").region.as_ptr();
    let (headers, count) = allocations(|| {
        let (event, _) = server
            .connection
            .drive(&mut server.inbound, &mut server.outbound, &mut server.lines, NOW);
        matches!(
            event,
            Some(Event::Headers {
                stream: 1,
                lines: Some(_),
                ..
            })
        )
    });
    assert!(headers, "the header block");
    assert_eq!(count, 0);
    let (event, _) = server
        .connection
        .drive(&mut server.inbound, &mut server.outbound, &mut server.lines, NOW);
    let Some(Event::Data { data, .. }) = event else {
        panic!("the data")
    };
    assert_eq!(data.bytes(), b"hello");
    // The DATA frame follows the 29 bytes of the HEADERS frame, and its payload its 9-byte header.
    assert_eq!(data.as_ptr(), address.wrapping_add(29 + 9));
}

/// The bytes of a DATA frame go up in order as each region arrives, with no padding, and the
/// last event of the frame has its END_STREAM (RFC 9113, section 6.1).
#[test]
fn data_goes_up_in_pieces_and_the_last_has_the_end() {
    let mut server = Peer::server();
    server.receive(&request(1, false));
    assert_eq!(server.run(), (vec![Seen::Headers(1, false, lines(&C31_LINES))], WAIT));
    // PADDED and END_STREAM: pad length 3, "abcdef", 3 bytes of padding.
    let data = frame(0x0, 0x9, 1, b"\x03abcdef\x00\x00\x00");
    server.receive(&data[..12]);
    assert_eq!(server.run(), (vec![Seen::Data(1, b"ab".to_vec(), false)], WAIT));
    server.receive(&data[12..18]);
    assert_eq!(server.run(), (vec![Seen::Data(1, b"cdef".to_vec(), false)], WAIT));
    server.receive(&data[18..]);
    assert_eq!(server.run(), (vec![Seen::Data(1, Vec::new(), true)], WAIT));
}

/// A PING gets a PING with the flag ACK and the same data (RFC 9113, section 6.7). A PING with
/// the flag ACK gets no answer: it goes up. A frame of an unknown type is discarded with its
/// payload (RFC 9113, section 4.1), also across regions.
#[test]
fn a_ping_gets_its_answer_and_an_unknown_frame_is_discarded() {
    let mut server = Peer::server();
    let unknown = frame(0xfa, 0xff, 7, b"opaque");
    server.receive(&unknown[..12]);
    assert_eq!(server.run(), (vec![], WAIT));
    server.receive(&unknown[12..]);
    // The vectors of Go TestWritePing and TestWritePingAck.
    server.receive(b"\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08");
    server.receive(b"\x00\x00\x08\x06\x01\x00\x00\x00\x00\x08\x07\x06\x05\x04\x03\x02\x01");
    assert_eq!(server.run(), (vec![Seen::PingAck([8, 7, 6, 5, 4, 3, 2, 1])], WAIT));
    assert_eq!(
        server.sent(),
        b"\x00\x00\x08\x06\x01\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"
    );
}

/// The peer's SETTINGS apply in order, and an unknown setting is ignored (RFC 9113, section
/// 6.5.2). Each SETTINGS frame gets one acknowledgement (section 6.5.3), and an acknowledgement
/// with no SETTINGS frame of the endpoint is a PROTOCOL_ERROR.
#[test]
fn settings_apply_in_order_and_each_gets_one_acknowledgement() {
    let mut server = Peer::server();
    // SETTINGS_MAX_FRAME_SIZE 32768 and then 20000, an unknown setting 0x99, and
    // SETTINGS_MAX_CONCURRENT_STREAMS 7.
    let settings = b"\x00\x05\x00\x00\x80\x00\x00\x05\x00\x00\x4e\x20\x00\x99\x00\x00\x00\x01\x00\x03\x00\x00\x00\x07";
    server.receive(&[frame(0x4, 0, 0, settings), EMPTY_SETTINGS.to_vec()].concat());
    let applied = Settings {
        max_frame_size: 20_000,
        max_concurrent_streams: 7,
        ..Settings::INITIAL
    };
    assert_eq!(
        server.run(),
        (vec![Seen::Settings(applied), Seen::Settings(applied)], WAIT)
    );
    assert_eq!(server.connection.peer_settings(), applied);
    assert_eq!(server.sent(), [SETTINGS_ACK, SETTINGS_ACK].concat());
    // The client acknowledges the server's settings one time, and then once more.
    server.receive(SETTINGS_ACK);
    assert_eq!(server.run(), (vec![], WAIT));
    server.receive(SETTINGS_ACK);
    ended(server.run().1, Kind::Malformed);
    assert_eq!(server.sent(), goaway(0, ErrorCode::PROTOCOL_ERROR));
}

/// A client refuses `SETTINGS_ENABLE_PUSH` 1 from a server, and each PUSH_PROMISE, with
/// PROTOCOL_ERROR (RFC 9113, sections 6.5.2 and 6.6).
#[test]
fn a_client_refuses_push_with_protocol_error() {
    let push = frame(0x4, 0, 0, b"\x00\x02\x00\x00\x00\x01");
    // The vector of Go TestWritePushPromise.
    let promise = b"\x00\x00\x07\x05\x00\x00\x00\x00*\x00\x00\x00*abc".to_vec();
    for input in [push, [EMPTY_SETTINGS, promise.as_slice()].concat()] {
        let mut client = Peer::new(Role::Client, LIMITS);
        client.sent();
        client.receive(&input);
        let (_, progress) = client.run();
        ended(progress, Kind::Malformed);
        assert!(
            client.sent().ends_with(&goaway(0, ErrorCode::PROTOCOL_ERROR)),
            "{input:02x?}"
        );
    }
}

/// RST_STREAM, WINDOW_UPDATE, and GOAWAY go up with their fields. The debug data of a GOAWAY is
/// discarded, also across regions. A WINDOW_UPDATE of 0 on a stream is a stream error of type
/// PROTOCOL_ERROR: a RST_STREAM ends the stream, and the connection goes on (RFC 9113, section
/// 6.9). After the GOAWAY, no stream is open, so the connection sends its own GOAWAY and ends
/// (section 6.8).
#[test]
fn stream_and_control_frames_go_up_with_their_fields() {
    let mut server = Peer::server();
    server.receive(&[request(1, false), request(3, false)].concat());
    assert_eq!(server.run().0.len(), 2, "two requests");
    let away = frame(0x7, 0, 0, b"\x00\x00\x00\x05\x00\x00\x00\x0bdebug data");
    server.receive(
        &[
            rst(1, ErrorCode::CANCEL),
            frame(0x8, 0, 0, b"\x80\x00\x10\x00"),
            window_update(3, 0),
            away[..20].to_vec(),
        ]
        .concat(),
    );
    server.receive(&away[20..]);
    assert_eq!(
        server.run(),
        (
            vec![
                Seen::Reset(1, ErrorCode::CANCEL),
                // The reserved bit of the increment is ignored.
                Seen::WindowUpdate(0, 0x1000),
                Seen::StreamError(3, ErrorCode::PROTOCOL_ERROR),
                Seen::GoAway(5, ErrorCode::ENHANCE_YOUR_CALM),
            ],
            Progress::Terminal(Ok(()))
        )
    );
    assert_eq!(
        server.sent(),
        [rst(3, ErrorCode::PROTOCOL_ERROR), goaway(3, ErrorCode::NO_ERROR)].concat()
    );
}

/// The decoder table can hold 4096 bytes until the peer acknowledges a smaller
/// `SETTINGS_HEADER_TABLE_SIZE`. After the acknowledgement, the next block must start with a size
/// update to at most the new size, or the connection ends with COMPRESSION_ERROR (RFC 9113,
/// section 4.3.1).
#[test]
fn a_smaller_table_holds_after_the_acknowledgement() {
    let limits = Limits {
        settings: Settings {
            header_table_size: 256,
            ..SETTINGS
        },
        ..LIMITS
    };
    // A literal with incremental indexing (RFC 7541, section 6.2.1): the name `x-a` and a value
    // of 300 bytes. Its entry has 335 bytes, so it fits only in the initial table of 4096.
    let value = vec![b'v'; 300];
    let insert = [b"\x40\x03x-a\x7f\xad\x01".as_slice(), value.as_slice()].concat();
    let line = vec![(b"x-a".to_vec(), value)];
    // Index 62 is the newest entry of the dynamic table (RFC 7541, section 2.3.3).
    let reference = frame(0x1, 0x5, 3, b"\xbe");
    let expected = vec![
        Seen::Headers(1, true, Some(line.clone())),
        Seen::Headers(3, true, Some(line)),
    ];
    // A size update to 256 (RFC 7541, section 6.3), and then `:method: GET`.
    let updated = frame(0x1, 0x5, 5, b"\x3f\xe1\x01\x82");
    for (after, result) in [
        (updated, Ok(Seen::Headers(5, true, lines(&[(":method", "GET")])))),
        (frame(0x1, 0x5, 5, b"\x82"), Err(ErrorCode::COMPRESSION_ERROR)),
    ] {
        let mut server = Peer::server_with(limits);
        server.receive(&[frame(0x1, 0x5, 1, &insert), reference.clone()].concat());
        assert_eq!(server.run(), (expected.clone(), WAIT));
        server.receive(&[SETTINGS_ACK, after.as_slice()].concat());
        let (events, progress) = server.run();
        match result {
            Ok(seen) => assert_eq!((events, progress), (vec![seen], WAIT)),
            Err(code) => {
                ended(progress, Kind::Malformed);
                assert_eq!(server.sent(), goaway(3, code));
            }
        }
    }
}

/// A peer that does not acknowledge the settings within the settings timeout ends the connection
/// with SETTINGS_TIMEOUT (RFC 9113, section 6.5.3), with no more input. A peer that acknowledges
/// them in time keeps the connection.
#[test]
fn settings_with_no_acknowledgement_end_the_connection_at_their_deadline() {
    let mut late = Peer::server();
    let mut prompt = Peer::server();
    prompt.receive(SETTINGS_ACK);
    assert_eq!(prompt.run(), (vec![], WAIT));
    let (_, turn) = late
        .connection
        .drive(&mut late.inbound, &mut late.outbound, &mut late.lines, NOW);
    let deadline = turn.deadline.expect("a deadline").instant();
    assert_eq!(deadline, Instant::new(CLOCK, 10_000_000_000));
    for peer in [&mut late, &mut prompt] {
        peer.now = Some(deadline);
        peer.sent();
    }
    ended(late.run().1, Kind::Deadline);
    assert_eq!(late.sent(), goaway(0, ErrorCode::SETTINGS_TIMEOUT));
    assert_eq!(prompt.run(), (vec![], WAIT));
    let off = Peer::new(Role::Server, LIMITS);
    let mut off = Peer {
        connection: off.connection.settings_timeout(None),
        now: None,
        ..off
    };
    off.receive(&[PREFACE.as_slice(), EMPTY_SETTINGS].concat());
    assert_eq!(off.run(), (vec![Seen::Settings(Settings::INITIAL)], WAIT));
}

/// The end of the input at a frame boundary ends the connection with no error. The end inside a
/// frame or a header block, or with an open stream, ends it as partial: an open stream cannot be
/// retried (RFC 9113, section 5.4.3).
#[test]
fn the_end_of_the_input_inside_a_frame_or_a_stream_is_partial() {
    let headers = frame(0x1, 0x0, 1, &C31[..3]);
    for (input, partial) in [
        (Vec::new(), false),
        (frame(0x6, 0, 0, &[0; 8])[..12].to_vec(), true),
        (headers, true),
        (request(1, true), true),
    ] {
        let mut server = Peer::server();
        server.receive(&input);
        server.inbound.end();
        let (_, progress) = server.run();
        if partial {
            ended(progress, Kind::Partial);
        } else {
            assert_eq!(progress, Progress::Terminal(Ok(())));
        }
    }
}

/// A turn reads at most its frame limit, then gives the remaining work as pending, and the next
/// turn goes on (the drive contract of `TurnLimits`).
#[test]
fn a_turn_stops_at_its_frame_limit() {
    let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
    let queue = NonZeroUsize::new(64).expect("not zero");
    let mut inbound = Inbound::new(queue, &budget).expect("the budget pays");
    let mut outbound = Outbound::new(queue, &budget).expect("the budget pays");
    let turn = TurnLimits {
        bytes: 1 << 20,
        frames: 3,
    };
    let mut server = Connection::new(Role::Server, LIMITS, turn, &mut outbound, &budget).expect("the budget pays");
    let mut lines = Lines::new(server.header_limits(), &budget).expect("the budget pays");
    let unknown = frame(0xfa, 0, 0, b"");
    let input = [PREFACE.as_slice(), EMPTY_SETTINGS, &unknown.repeat(10)[..]].concat();
    let received = Received {
        region: Lease::from(input),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    assert!(inbound.push(received).is_ok(), "the queue has room");
    let (event, _) = server.drive(&mut inbound, &mut outbound, &mut lines, NOW);
    assert_matches!(event, Some(Event::Settings(_)), "the peer's settings");
    // Ten frames of 9 bytes, in turns of 3 frames: 3, 3, 3, and then the last frame and a wait.
    for left in [63, 36, 9] {
        let (event, turn) = server.drive(&mut inbound, &mut outbound, &mut lines, NOW);
        assert!(event.is_none());
        assert_eq!(turn.progress, Progress::Pending);
        assert_eq!(inbound.front().map(|front| front.region.initialized()), Some(left));
    }
    let (_, turn) = server.drive(&mut inbound, &mut outbound, &mut lines, NOW);
    assert_eq!(turn.progress, WAIT);
}

/// A header block larger than the peer's `SETTINGS_MAX_FRAME_SIZE` goes out as a HEADERS frame
/// and CONTINUATION frames of at most that size, from one region (RFC 9113, section 4.3). A peer
/// decodes them as the same lines.
#[test]
fn a_large_header_block_goes_out_as_continuation_frames() {
    let mut client = Peer::new(Role::Client, LIMITS);
    // A value of 40000 bytes that Huffman coding does not shorten, so the block has 3 frames.
    let value = vec![b'~'; 40_000];
    let sent = [
        FieldLine {
            name: b":method",
            value: b"GET",
            never_indexed: false,
        },
        FieldLine {
            name: b"x-large",
            value: &value,
            never_indexed: false,
        },
    ];
    let region = Backing::from(Vec::with_capacity(64 * 1024));
    let stream = client
        .connection
        .open(&mut client.outbound, sent.iter().copied(), true, region)
        .expect("the region and the queue have room");
    assert_eq!(stream, 1, "the first stream of a client (RFC 9113, section 5.1.1)");
    let output = client.sent();
    // After the client preface and its SETTINGS frame of 3 settings: each frame of the block.
    let mut at = PREFACE.len() + 9 + 18;
    let mut kinds = Vec::new();
    while let Some(&[l0, l1, l2, kind, flags]) = output.get(at..at + 5).and_then(|bytes| bytes.first_chunk()) {
        let length = u32::from_be_bytes([0, l0, l1, l2]);
        assert!(length <= 16_384, "a frame of {length} bytes");
        kinds.push((kind, flags));
        at += 9 + length as usize;
    }
    // HEADERS with END_STREAM, a CONTINUATION frame, and the last with END_HEADERS.
    assert_eq!(kinds, [(0x1, 0x1), (0x9, 0x0), (0x9, 0x4)]);
    let mut server = Peer::new(
        Role::Server,
        Limits {
            settings: Settings {
                max_header_list_size: 64 * 1024,
                ..SETTINGS
            },
            work: 256 * 1024,
            ..LIMITS
        },
    );
    server.receive(&output);
    let value = core::str::from_utf8(&value).expect("ASCII");
    assert_eq!(
        server.run(),
        (
            vec![
                Seen::Settings(SETTINGS),
                Seen::Headers(1, true, lines(&[(":method", "GET"), ("x-large", value)])),
            ],
            WAIT
        )
    );
}

/// A DATA frame goes out as a 9-byte header from the pool and the caller's region, with no copy
/// (RFC 9113, section 6.1).
#[test]
fn data_goes_out_with_no_copy() {
    let mut client = Peer::client();
    let stream = client.open(false);
    client.sent();
    let data = Lease::from(b"hello".to_vec());
    let sent = client.connection.data(&mut client.outbound, stream, &data, true);
    assert_eq!(sent, Ok(5));
    let header = client.outbound.submit().expect("the header");
    assert_eq!(header.region.bytes(), head(5, 0x0, 0x1, 1));
    client.outbound.ack(header.id, 9).expect("outstanding");
    let payload = client.outbound.submit().expect("the payload");
    assert_eq!(payload.region.as_ptr(), data.as_ptr());
}

/// A block that adds `x-a: v` to the dynamic table: a literal with incremental indexing and a
/// new name (RFC 7541, section 6.2.1).
const INSERT: &[u8] = b"\x40\x03x-a\x01v";

/// A block that reads the newest entry of the dynamic table: index 62 (RFC 7541, section 2.3.3).
const NEWEST: &[u8] = b"\xbe";

/// A block of `:method: GET`, `:scheme: http`, and `:path: /`, all in the static table, so it
/// changes no dynamic table (RFC 7541, Appendix A).
const STATIC: &[u8] = b"\x82\x86\x84";

/// A PRIORITY frame on `stream` that depends on stream 0 (RFC 9113, figure 5).
fn priority(stream: u32) -> Vec<u8> {
    frame(0x2, 0, stream, b"\x00\x00\x00\x00\x10")
}

/// Each transition of the stream states of RFC 9113, sections 5.1 and 5.1.1, that frames of the
/// peer cause, on a server and on a client. Each case gives the events, the output, and the end
/// that the rule of its name requires. On a closed stream, each frame gets the minimal
/// processing of section 5.1, which the lead decided for each closed stream (the rule of
/// nghttp2): no error.
#[test]
fn each_stream_state_transition_gives_the_rfc_result() {
    let protocol = || Err(ErrorCode::PROTOCOL_ERROR);
    let closed = ErrorCode::STREAM_CLOSED;
    let headers = |stream: u32, end_stream: bool| Seen::Headers(stream, end_stream, lines(&C31_LINES));
    // Each case: the rule, the role, the input, the events, and the RST_STREAM codes of the
    // output, or the code of the GOAWAY that ends the connection.
    type Case = (
        &'static str,
        Role,
        Vec<u8>,
        Vec<Seen>,
        Result<Vec<(u32, ErrorCode)>, ErrorCode>,
    );
    let cases: Vec<Case> = vec![
        ("5.1 idle: DATA", Role::Server, data(1, false, b"x"), vec![], protocol()),
        (
            "6.4 idle: RST_STREAM",
            Role::Server,
            rst(1, ErrorCode::CANCEL),
            vec![],
            protocol(),
        ),
        (
            "5.1 idle: WINDOW_UPDATE",
            Role::Server,
            window_update(1, 1),
            vec![],
            protocol(),
        ),
        (
            "5.1.1 a client stream is odd",
            Role::Server,
            request(2, true),
            vec![],
            protocol(),
        ),
        (
            "6.3 PRIORITY changes no state, so stream 1 can open after stream 9",
            Role::Server,
            [priority(9), request(1, true)].concat(),
            vec![headers(1, true)],
            Ok(vec![]),
        ),
        (
            "5.1 idle to open, and to half-closed (remote) at END_STREAM, where DATA is a STREAM_CLOSED stream error",
            Role::Server,
            [request(1, false), data(1, true, b"a"), data(1, false, b"b")].concat(),
            vec![
                headers(1, false),
                Seen::Data(1, b"a".to_vec(), true),
                Seen::StreamError(1, closed),
            ],
            Ok(vec![(1, closed)]),
        ),
        (
            "5.1 half-closed (remote): HEADERS is a STREAM_CLOSED stream error",
            Role::Server,
            [request(1, true), request(1, true)].concat(),
            vec![headers(1, true), Seen::StreamError(1, closed)],
            Ok(vec![(1, closed)]),
        ),
        (
            "5.1 half-closed (remote): WINDOW_UPDATE and PRIORITY are permitted",
            Role::Server,
            [request(1, true), window_update(1, 10), priority(1)].concat(),
            vec![headers(1, true), Seen::WindowUpdate(1, 10)],
            Ok(vec![]),
        ),
        (
            "5.1 open to closed at RST_STREAM, and later frames on the closed stream change nothing",
            Role::Server,
            [
                request(1, false),
                rst(1, ErrorCode::CANCEL),
                data(1, false, b"x"),
                window_update(1, 1),
                rst(1, ErrorCode::CANCEL),
                priority(1),
            ]
            .concat(),
            vec![headers(1, false), Seen::Reset(1, ErrorCode::CANCEL)],
            Ok(vec![]),
        ),
        (
            "5.1.1 a skipped stream is closed: its block decodes and is discarded",
            Role::Server,
            [
                frame(0x1, 0x5, 5, STATIC),
                frame(0x1, 0x5, 3, INSERT),
                frame(0x1, 0x5, 7, NEWEST),
            ]
            .concat(),
            vec![
                Seen::Headers(
                    5,
                    true,
                    lines(&[(":method", "GET"), (":scheme", "http"), (":path", "/")]),
                ),
                Seen::Headers(7, true, lines(&[("x-a", "v")])),
            ],
            Ok(vec![]),
        ),
        (
            "5.1 a client: HEADERS on an idle stream",
            Role::Client,
            request(1, true),
            vec![],
            protocol(),
        ),
        (
            "5.1 a client: HEADERS on a stream of the server, which push makes idle",
            Role::Client,
            request(2, true),
            vec![],
            protocol(),
        ),
    ];
    for (rule, role, input, events, output) in cases {
        let mut peer = match role {
            Role::Server => Peer::server(),
            Role::Client => Peer::client(),
        };
        peer.receive(&input);
        let (seen, progress) = peer.run();
        assert_eq!(seen, events, "{rule}");
        let sent = peer.sent();
        match output {
            Ok(resets) => {
                assert_eq!(progress, WAIT, "{rule}");
                let expected: Vec<u8> = resets.iter().flat_map(|&(stream, code)| rst(stream, code)).collect();
                assert_eq!(sent, expected, "{rule}");
            }
            Err(code) => {
                ended(progress, Kind::Malformed);
                assert_eq!(sent, goaway(0, code), "{rule}");
            }
        }
    }
}

/// The stream of a client goes from idle to half-closed (local) when its request has END_STREAM,
/// and to closed when the response ends (RFC 9113, sections 5.1 and 8.8.1). A frame on the closed
/// stream then changes nothing.
#[test]
fn a_client_stream_closes_after_the_request_and_the_response_end() {
    let mut client = Peer::client();
    let stream = client.open(true);
    assert_eq!(
        client.send(stream, b"x", false),
        Err(Kind::Misuse),
        "half-closed (local)"
    );
    // `:status: 200`, index 8 of the static table.
    client.receive(&[frame(0x1, 0x4, stream, b"\x88"), data(stream, true, b"ok")].concat());
    let status = lines(&[(":status", "200")]);
    assert_eq!(
        client.run(),
        (
            vec![
                Seen::Headers(stream, false, status),
                Seen::Data(stream, b"ok".to_vec(), true),
            ],
            WAIT
        )
    );
    client.sent();
    client.receive(&data(stream, false, b"late"));
    assert_eq!(client.run(), (vec![], WAIT));
    assert_eq!(client.sent(), b"");
}

/// A stream that the connection refuses still decodes its header block, so the HPACK state stays
/// in step and the next stream decodes (RFC 9113, sections 4.3 and 5.1.2). A refused block adds
/// an entry, and the next stream reads it. An engine that skips the decode of a refused block
/// fails here: the next block reads an entry that it does not have. The GOAWAY of a later error
/// names the last stream that went up, not the refused one (section 8.7).
#[test]
fn a_refused_stream_still_updates_hpack_state_and_the_next_stream_decodes() {
    let limits = Limits {
        settings: Settings {
            max_concurrent_streams: 1,
            ..SETTINGS
        },
        ..LIMITS
    };
    let mut server = Peer::server_with(limits);
    server.receive(&[frame(0x1, 0x4, 1, STATIC), frame(0x1, 0x5, 3, INSERT)].concat());
    let get = lines(&[(":method", "GET"), (":scheme", "http"), (":path", "/")]);
    assert_eq!(server.run(), (vec![Seen::Headers(1, false, get)], WAIT));
    // The peer cannot know the limit before it acknowledges the settings, so the code permits a
    // retry (section 8.7).
    assert_eq!(server.sent(), rst(3, ErrorCode::REFUSED_STREAM));
    server.receive(&[rst(1, ErrorCode::CANCEL), frame(0x1, 0x5, 5, NEWEST)].concat());
    assert_eq!(
        server.run(),
        (
            vec![
                Seen::Reset(1, ErrorCode::CANCEL),
                Seen::Headers(5, true, lines(&[("x-a", "v")])),
            ],
            WAIT
        )
    );
    // After the acknowledgement, the peer knows the limit: PROTOCOL_ERROR. The last stream of
    // the GOAWAY is 5, which went up, and not the refused stream 7.
    server.receive(&[SETTINGS_ACK, &frame(0x1, 0x5, 7, INSERT), &frame(0x6, 0, 1, &[0; 8])].concat());
    ended(server.run().1, Kind::Malformed);
    assert_eq!(
        server.sent(),
        [rst(7, ErrorCode::PROTOCOL_ERROR), goaway(5, ErrorCode::PROTOCOL_ERROR)].concat()
    );
    // A refused block past the work bound cannot keep the HPACK state, so the connection ends
    // with COMPRESSION_ERROR (section 4.3).
    let mut server = Peer::server_with(Limits { work: 1024, ..limits });
    server.receive(&[frame(0x1, 0x4, 1, STATIC), head(1025, 0x1, 0x5, 3)].concat());
    let (_, progress) = server.run();
    ended(progress, Kind::Overload);
    assert_eq!(server.sent(), goaway(1, ErrorCode::COMPRESSION_ERROR));
}

/// After the endpoint resets a stream, the peer can still send frames that it sent before it read
/// the reset. The connection processes them minimally and discards them (RFC 9113, section 5.1,
/// closed): a header block decodes, so the next stream reads its entry, and DATA counts toward
/// the connection window, so its credit comes back. A server cannot refuse a stream that went up
/// (section 8.7).
#[test]
fn frames_after_a_reset_keep_hpack_and_the_connection_window_in_step() {
    let mut server = Peer::server();
    server.receive(&request(1, false));
    assert_eq!(server.run().0.len(), 1, "a request");
    assert_eq!(
        server
            .connection
            .reset(&mut server.outbound, 1, ErrorCode::REFUSED_STREAM)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    server
        .connection
        .reset(&mut server.outbound, 1, ErrorCode::CANCEL)
        .expect("the queue has room");
    assert_eq!(server.sent(), rst(1, ErrorCode::CANCEL));
    // The whole connection window of 65,535 bytes on the reset stream, then its trailers.
    let chunk = vec![b'x'; 16_383];
    let mut input: Vec<u8> = (0..4).flat_map(|_| data(1, false, &chunk)).collect();
    input.extend(data(1, false, b"xxx"));
    input.extend(frame(0x1, 0x5, 1, INSERT));
    server.receive(&input);
    assert_eq!(server.run(), (vec![], WAIT));
    let returned: u32 = grants(&server.sent(), 0).iter().sum();
    assert!(returned > 0 && returned <= 65_535, "{returned} bytes returned");
    server.receive(&frame(0x1, 0x5, 3, NEWEST));
    assert_eq!(
        server.run(),
        (vec![Seen::Headers(3, true, lines(&[("x-a", "v")]))], WAIT)
    );
}

/// The limits of a server whose streams each admit `window` bytes.
fn windowed(window: u32) -> Limits {
    Limits {
        settings: Settings {
            initial_window_size: window,
            ..SETTINGS
        },
        ..LIMITS
    }
}

/// DATA past a window is a FLOW_CONTROL_ERROR: a stream error past the stream window, and a
/// connection error past the connection window, as the lead decided (the rule of nghttp2). The
/// whole payload counts, with the pad length and the padding (RFC 9113, section 6.1). Before the
/// peer acknowledges a smaller `SETTINGS_INITIAL_WINDOW_SIZE`, it can still use 65,535 (section
/// 6.9.3), and at the acknowledgement each window changes by the difference (section 6.9.2).
#[test]
fn data_past_a_window_is_a_flow_control_error() {
    let flow = ErrorCode::FLOW_CONTROL_ERROR;
    // 17 bytes of data, and 10 bytes of data with a pad length of 6: 17 bytes of payload.
    for past in [
        data(1, false, &[b'x'; 17]),
        frame(0x0, 0x8, 1, b"\x06xxxxxxxxxx\0\0\0\0\0\0"),
    ] {
        let mut server = Peer::acknowledged(windowed(16));
        server.receive(&[request(1, false), past].concat());
        let (events, progress) = server.run();
        assert_eq!(events[1..], [Seen::StreamError(1, flow)]);
        assert_eq!(progress, WAIT, "the connection goes on");
        assert_eq!(server.sent(), rst(1, flow));
    }
    // Four frames of 16,384 bytes are one byte past the connection window of 65,535.
    let mut server = Peer::acknowledged(windowed(1 << 20));
    let chunk = vec![b'x'; 16_384];
    let input: Vec<u8> = (0..4).flat_map(|_| data(1, false, &chunk)).collect();
    server.receive(&[request(1, false), input].concat());
    ended(server.run().1, Kind::Malformed);
    assert_eq!(server.sent(), goaway(1, flow));
    // Before the acknowledgement of a window of 16, a stream can take 1000 bytes. The
    // acknowledgement makes its window 65,535 - 1000 + 16 - 65,535 = -984, so one more byte is
    // past it.
    let mut server = Peer::server_with(windowed(16));
    server.receive(&[request(1, false), data(1, false, &[b'x'; 1000])].concat());
    assert_eq!(server.run().0.len(), 2, "the request and its data");
    server.receive(&[SETTINGS_ACK, &data(1, false, b"x")].concat());
    assert_eq!(server.run(), (vec![Seen::StreamError(1, flow)], WAIT));
}

/// A WINDOW_UPDATE goes to the peer only for bytes that the consumer released, so the peer can
/// never send more than the capacity that the consumer admitted (the design: transport windows
/// grant only capacity that the next owner can admit). A release while the peer has no credit
/// gives credit (RFC 9113, section 6.9.1), and the padding, which no consumer holds, comes back
/// too.
#[test]
fn a_window_grant_never_exceeds_the_capacity_that_the_consumer_admitted() {
    let mut server = Peer::acknowledged(windowed(1000));
    // A frame of 100 bytes in two regions: the consumer holds only the bytes that went up.
    let split = data(1, false, &[b'w'; 100]);
    server.receive(&[&request(1, false), &split[..59]].concat());
    assert_eq!(server.run().0[1..], [Seen::Data(1, vec![b'w'; 50], false)]);
    assert_eq!(server.release(1, 51), Err(Kind::Misuse), "50 bytes went up");
    server.receive(
        &[
            &split[59..],
            &data(1, false, &[b'x'; 500]),
            &data(1, false, &[b'y'; 400]),
        ]
        .concat(),
    );
    assert_eq!(server.run().0.len(), 3, "the rest of the data");
    assert_eq!(server.sent(), b"", "no credit before a release");
    // The peer has no credit, so the first release gives some, and no release gives more than its
    // bytes.
    let (mut released, mut granted) = (0, 0);
    for bytes in [50, 50, 900] {
        server.release(1, bytes).expect("the consumer holds the bytes");
        released += bytes;
        granted += grants(&server.sent(), 1).iter().sum::<u32>();
        assert!(granted > 0 && granted <= released, "{granted} for {released} bytes");
    }
    assert_eq!(server.release(1, 1), Err(Kind::Misuse), "the consumer holds no byte");
    // The peer's credit is 1000 - 1000 + the grants (RFC 9113, section 6.9.1). It can send that,
    // and no byte more.
    server.receive(&data(1, false, &vec![b'z'; granted as usize]));
    assert_eq!(server.run().1, WAIT);
    server.receive(&data(1, false, b"z"));
    assert_eq!(server.run().0, [Seen::StreamError(1, ErrorCode::FLOW_CONTROL_ERROR)]);
    // A frame of 1 byte of data and 999 bytes of padding and its pad length uses the window of a
    // new stream. The consumer holds 1 byte, so the 999 other bytes come back with no release.
    let mut server = Peer::acknowledged(windowed(1000));
    let padded = [&b"\xfex"[..], &[0; 254]].concat();
    let input = [
        request(1, false),
        frame(0x0, 0x8, 1, &padded),
        frame(0x0, 0x8, 1, &padded),
        frame(0x0, 0x8, 1, &padded),
        frame(0x0, 0x8, 1, &[&b"\xe6x"[..], &[0; 230]].concat()),
    ]
    .concat();
    server.receive(&input);
    assert_eq!(server.run().1, WAIT);
    let granted: u32 = grants(&server.sent(), 1).iter().sum();
    assert!(granted > 0 && granted <= 996, "{granted} bytes of padding");
}

/// A WINDOW_UPDATE that takes a window past 2^31 - 1 ends the stream with RST_STREAM
/// FLOW_CONTROL_ERROR, or the connection with GOAWAY FLOW_CONTROL_ERROR (RFC 9113, section
/// 6.9.1). A `SETTINGS_INITIAL_WINDOW_SIZE` that takes a window past it is a connection error
/// of the same code (section 6.9.2). A window of exactly 2^31 - 1 is valid.
#[test]
fn a_window_past_2_31_minus_1_gives_flow_control_error() {
    let flow = ErrorCode::FLOW_CONTROL_ERROR;
    let max = (1 << 31) - 1;
    let mut client = Peer::client();
    let stream = client.open(false);
    client.sent();
    client.receive(&[window_update(stream, max - 65_535), window_update(stream, 1)].concat());
    assert_eq!(
        client.run(),
        (
            vec![
                Seen::WindowUpdate(stream, max - 65_535),
                Seen::StreamError(stream, flow)
            ],
            WAIT
        )
    );
    assert_eq!(client.sent(), rst(stream, flow));
    client.receive(&window_update(0, max - 65_535 + 1));
    ended(client.run().1, Kind::Malformed);
    assert_eq!(client.sent(), goaway(0, flow));
    // A window of 65,535 + 1000, and then an initial window of 2^31 - 1.
    let mut client = Peer::client();
    let stream = client.open(false);
    client.sent();
    let settings = frame(0x4, 0, 0, &[&b"\x00\x04"[..], &max.to_be_bytes()].concat());
    client.receive(&[window_update(stream, 1000), settings].concat());
    let (events, progress) = client.run();
    assert_eq!(events, [Seen::WindowUpdate(stream, 1000)]);
    ended(progress, Kind::Malformed);
    assert_eq!(client.sent(), goaway(0, flow));
}

/// A sender sends DATA only within the stream window and the connection window, in frames of at
/// most the peer's `SETTINGS_MAX_FRAME_SIZE` (RFC 9113, sections 4.2 and 6.9.1). A smaller
/// `SETTINGS_INITIAL_WINDOW_SIZE` can make a window negative, and the sender then waits for a
/// WINDOW_UPDATE that makes it positive: the example of section 6.9.2.
#[test]
fn data_waits_for_both_windows() {
    let mut client = Peer::client();
    let stream = client.open(false);
    let body = vec![b'x'; 100_000];
    let mut sent = 0;
    while let Ok(len @ 1..) = client.send(stream, &body[sent..], false) {
        assert!(len <= 16_384, "a frame of {len} bytes");
        sent += len;
    }
    assert_eq!(sent, 65_535, "the initial windows");
    // Credit on the stream alone sends nothing: the connection window is empty.
    client.receive(&window_update(stream, 10_000));
    assert_eq!(client.run().1, WAIT);
    assert_eq!(client.send(stream, &body[sent..], false), Ok(0));
    client.receive(&window_update(0, 100_000));
    assert_eq!(client.run().1, WAIT);
    assert_eq!(client.send(stream, &body[sent..], false), Ok(10_000));
    // An initial window of 16,384 makes the stream window 0 + 16,384 - 65,535 = -49,151.
    client.receive(&frame(0x4, 0, 0, b"\x00\x04\x00\x00\x40\x00"));
    assert_eq!(client.run().1, WAIT);
    client.receive(&window_update(stream, 49_151));
    assert_eq!(client.run().1, WAIT);
    assert_eq!(client.send(stream, b"x", false), Ok(0), "a window of 0");
    client.receive(&window_update(stream, 1));
    assert_eq!(client.run().1, WAIT);
    assert_eq!(client.send(stream, b"xx", true), Ok(1));
    // An empty DATA frame with END_STREAM needs no credit (section 6.9.1).
    assert_eq!(client.send(stream, b"", true), Ok(0));
    let output = client.sent();
    assert!(output.ends_with(&data(stream, true, b"")), "the end of the stream");
}

/// A message is a header section, DATA, and an optional trailer section that ends the stream. A
/// response can start with interim (1xx) responses. A trailer section with no END_STREAM, DATA
/// before the header section, and an interim response with END_STREAM are malformed: stream
/// errors of type PROTOCOL_ERROR (RFC 9113, sections 8.1 and 8.1.1). A sender cannot make these
/// messages.
#[test]
fn trailers_end_the_body_and_a_message_out_of_order_is_malformed() {
    let protocol = ErrorCode::PROTOCOL_ERROR;
    // `x-t: 1`, a literal with no indexing and a new name (RFC 7541, section 6.2.2).
    let trailer = b"\x00\x03x-t\x011";
    let mut server = Peer::server();
    server.receive(
        &[
            request(1, false),
            data(1, false, b"x"),
            frame(0x1, 0x5, 1, trailer),
            request(3, false),
            frame(0x1, 0x4, 3, trailer),
        ]
        .concat(),
    );
    assert_eq!(
        server.run(),
        (
            vec![
                Seen::Headers(1, false, lines(&C31_LINES)),
                Seen::Data(1, b"x".to_vec(), false),
                Seen::Trailers(1, lines(&[("x-t", "1")])),
                Seen::Headers(3, false, lines(&C31_LINES)),
                Seen::StreamError(3, protocol),
            ],
            WAIT
        )
    );
    assert_eq!(server.sent(), rst(3, protocol));
    // The sender: an interim response cannot end the stream, DATA waits for the final response,
    // and a trailer section must end the stream.
    assert_eq!(server.section(1, ":status", "103", true), Err(Kind::Misuse));
    assert_eq!(server.section(1, ":status", "103", false), Ok(()));
    assert_eq!(server.send(1, b"x", false), Err(Kind::Misuse));
    assert_eq!(server.section(1, ":status", "200", false), Ok(()));
    assert_eq!(server.section(1, "x-t", "1", false), Err(Kind::Misuse));
    assert_eq!(server.section(1, "x-t", "1", true), Ok(()));
    // The client: `:status: 103` is a literal with no indexing of the name of index 8, and
    // `:status: 200` is index 8 (RFC 7541, Appendix A).
    let interim = b"\x08\x03103";
    let mut client = Peer::client();
    let (one, three, five) = (client.open(true), client.open(true), client.open(true));
    client.receive(
        &[
            frame(0x1, 0x4, one, interim),
            frame(0x1, 0x4, one, b"\x88"),
            data(one, false, b"x"),
            frame(0x1, 0x5, one, trailer),
            data(three, false, b"x"),
            frame(0x1, 0x5, five, interim),
        ]
        .concat(),
    );
    assert_eq!(
        client.run(),
        (
            vec![
                Seen::Headers(one, false, lines(&[(":status", "103")])),
                Seen::Headers(one, false, lines(&[(":status", "200")])),
                Seen::Data(one, b"x".to_vec(), false),
                Seen::Trailers(one, lines(&[("x-t", "1")])),
                Seen::StreamError(three, protocol),
                Seen::StreamError(five, protocol),
            ],
            WAIT
        )
    );
}

/// A GOAWAY of the peer ends each stream of the endpoint above its last stream, and no new stream
/// opens (RFC 9113, section 6.8). The streams at or below it complete, and then the connection
/// sends its own GOAWAY and ends with no error. A later GOAWAY cannot raise the last stream: a
/// PROTOCOL_ERROR, as the lead decided (the rule of nghttp2).
#[test]
fn a_goaway_of_the_peer_drains_the_streams_at_or_below_its_last_stream() {
    let no_error = ErrorCode::NO_ERROR;
    for raise in [false, true] {
        let mut client = Peer::client();
        let streams = [client.open(false), client.open(false), client.open(false)];
        assert_eq!(streams, [1, 3, 5]);
        client.sent();
        client.receive(&goaway(3, no_error));
        assert_eq!(client.run(), (vec![Seen::GoAway(3, no_error)], WAIT));
        assert_eq!(client.send(5, b"x", true), Err(Kind::Misuse), "stream 5 ended");
        let region = Backing::from(Vec::with_capacity(256));
        let refused = client
            .connection
            .open(&mut client.outbound, [].into_iter(), true, region);
        assert_eq!(refused.map_err(|error| error.kind()), Err(Kind::Overload));
        if raise {
            client.receive(&goaway(5, no_error));
            ended(client.run().1, Kind::Malformed);
            assert_eq!(client.sent(), goaway(0, ErrorCode::PROTOCOL_ERROR));
            continue;
        }
        for stream in [1, 3] {
            assert_eq!(client.send(stream, b"", true), Ok(0));
            client.receive(&frame(0x1, 0x5, stream, b"\x88"));
        }
        let (events, progress) = client.run();
        assert_eq!(events.len(), 2, "two responses");
        assert_eq!(progress, Progress::Terminal(Ok(())));
        assert!(
            client.sent().ends_with(&goaway(0, no_error)),
            "the GOAWAY of the client"
        );
    }
}

/// The shutdown of a server: a GOAWAY with the last stream 2^31 - 1 and a PING, and at the PING's
/// answer the GOAWAY with the last stream that went up (RFC 9113, section 6.8). A request in
/// flight before the answer is accepted, and a request after it is discarded with no reset. The
/// accepted streams complete, and then the connection ends with no error.
#[test]
fn a_server_shutdown_drains_accepted_streams_and_discards_later_ones() {
    let no_error = ErrorCode::NO_ERROR;
    let mut server = Peer::server();
    server.receive(&request(1, false));
    assert_eq!(server.run().0.len(), 1, "a request");
    server
        .connection
        .shutdown(&mut server.outbound)
        .expect("the queue has room");
    assert_eq!(
        server.sent(),
        [goaway((1 << 31) - 1, no_error), frame(0x6, 0, 0, b"shutdown")].concat()
    );
    server.receive(&[request(3, true), frame(0x6, 0x1, 0, b"shutdown"), request(5, true)].concat());
    assert_eq!(server.run(), (vec![Seen::Headers(3, true, lines(&C31_LINES))], WAIT));
    assert_eq!(server.sent(), goaway(3, no_error));
    assert_eq!(server.section(3, ":status", "200", true), Ok(()));
    assert_eq!(server.section(1, ":status", "200", true), Ok(()));
    server.receive(&data(1, true, b""));
    let (events, progress) = server.run();
    assert_eq!(events, [Seen::Data(1, Vec::new(), true)]);
    assert_eq!(progress, Progress::Terminal(Ok(())));
}
