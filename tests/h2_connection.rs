//! The contracts of the HTTP/2 frame and connection layer: the preface, SETTINGS and their
//! acknowledgement, PING, GOAWAY, header blocks across CONTINUATION frames, each connection error
//! with its RFC 9113 code, and frames that parse in place. Each expected byte and code comes from
//! RFC 9113 or RFC 7541, as each test states, not from the code under test.

use core::assert_matches;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h2::frame::{ErrorCode, PREFACE};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::{FieldLine, Lines};
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

/// The settings of each endpoint in the tests: a list limit, and the initial values.
const SETTINGS: Settings = Settings {
    max_header_list_size: 16 * 1024,
    ..Settings::INITIAL
};

const LIMITS: Limits = Limits {
    settings: SETTINGS,
    work: 64 * 1024,
    encoder_table_bytes: 4096,
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

/// What the layer above saw: each event, with its bytes copied.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Seen {
    Headers(u32, bool, Option<Vec<(Vec<u8>, Vec<u8>)>>),
    Data(u32, Vec<u8>, u32, bool),
    Reset(u32, ErrorCode),
    WindowUpdate(u32, u32),
    Settings(Settings),
    PingAck([u8; 8]),
    GoAway(u32, ErrorCode),
    StreamError(u32, ErrorCode),
}

fn seen(event: Event<'_>) -> Seen {
    match event {
        Event::Headers {
            stream,
            end_stream,
            lines,
        } => Seen::Headers(
            stream,
            end_stream,
            lines.map(|block| {
                block
                    .lines()
                    .map(|line| (line.name.to_vec(), line.value.to_vec()))
                    .collect()
            }),
        ),
        Event::Data {
            stream,
            data,
            flow,
            end_stream,
        } => Seen::Data(stream, data.bytes().to_vec(), flow, end_stream),
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
    // SETTINGS_MAX_HEADER_LIST_SIZE (0x6) 16384, then SETTINGS_ENABLE_PUSH (0x2) 0.
    let settings = frame(0x4, 0, 0, b"\x00\x06\x00\x00\x40\x00\x00\x02\x00\x00\x00\x00");
    assert_eq!(
        client.sent(),
        [&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], settings.as_slice()].concat()
    );
    let mut server = Peer::new(Role::Server, LIMITS);
    assert_eq!(server.sent(), frame(0x4, 0, 0, b"\x00\x06\x00\x00\x40\x00"));
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

/// The bytes of a DATA frame go up in order as each region arrives. The first event of a frame
/// counts its whole payload against flow control, its padding too (RFC 9113, section 6.1), and
/// the last event of the frame has its END_STREAM.
#[test]
fn data_goes_up_in_pieces_with_the_flow_of_the_whole_frame() {
    let mut server = Peer::server();
    // PADDED and END_STREAM: pad length 3, "abcdef", 3 bytes of padding. The payload is 10 bytes.
    let data = frame(0x0, 0x9, 1, b"\x03abcdef\x00\x00\x00");
    server.receive(&data[..12]);
    assert_eq!(server.run(), (vec![Seen::Data(1, b"ab".to_vec(), 10, false)], WAIT));
    server.receive(&data[12..18]);
    assert_eq!(server.run(), (vec![Seen::Data(1, b"cdef".to_vec(), 0, false)], WAIT));
    server.receive(&data[18..]);
    assert_eq!(server.run(), (vec![Seen::Data(1, Vec::new(), 0, true)], WAIT));
    // A DATA frame with only padding still counts its payload.
    server.receive(&frame(0x0, 0x8, 3, b"\x01\x00"));
    assert_eq!(server.run(), (vec![Seen::Data(3, Vec::new(), 2, false)], WAIT));
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
/// PROTOCOL_ERROR, and the connection goes on (RFC 9113, section 6.9).
#[test]
fn stream_and_control_frames_go_up_with_their_fields() {
    let mut server = Peer::server();
    let away = frame(0x7, 0, 0, b"\x00\x00\x00\x05\x00\x00\x00\x0bdebug data");
    server.receive(
        &[
            frame(0x3, 0, 1, b"\x00\x00\x00\x08"),
            frame(0x8, 0, 0, b"\x80\x00\x10\x00"),
            frame(0x8, 0, 3, b"\x00\x00\x00\x00"),
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
            WAIT
        )
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

/// The end of the input at a frame boundary ends the connection with no error, and the end inside
/// a frame or a header block ends it as partial.
#[test]
fn the_end_of_the_input_inside_a_frame_is_partial() {
    let headers = frame(0x1, 0x0, 1, &C31[..3]);
    for (input, partial) in [
        (Vec::new(), false),
        (frame(0x6, 0, 0, &[0; 8])[..12].to_vec(), true),
        (headers, true),
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
    client
        .connection
        .headers(&mut client.outbound, 1, sent.iter().copied(), true, region)
        .expect("the region and the queue have room");
    let output = client.sent();
    // After the client preface and its SETTINGS frame of 2 settings: each frame of the block.
    let mut at = PREFACE.len() + 9 + 12;
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
/// (RFC 9113, section 6.1). A payload larger than the peer's frame size refuses.
#[test]
fn data_goes_out_with_no_copy() {
    let mut server = Peer::server();
    server.sent();
    let data = Lease::from(b"hello".to_vec());
    server
        .connection
        .data(&mut server.outbound, 1, &data, true)
        .expect("the queue has room");
    let header = server.outbound.submit().expect("the header");
    assert_eq!(header.region.bytes(), head(5, 0x0, 0x1, 1));
    server.outbound.ack(header.id, 9).expect("outstanding");
    let payload = server.outbound.submit().expect("the payload");
    assert_eq!(payload.region.as_ptr(), data.as_ptr());
    server.outbound.ack(payload.id, 5).expect("outstanding");
    let large = Lease::from(vec![0; 16_385]);
    let refused = server.connection.data(&mut server.outbound, 1, &large, false);
    assert_eq!(refused.map_err(|error| error.kind()), Err(Kind::Misuse));
}
