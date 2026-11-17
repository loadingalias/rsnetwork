//! The HTTP/2 engine reads fuzzed frames as a server or a client. The first byte of the input
//! selects the role, the work limit, the table size, and the size of the regions of a cut input.
//! The rest is the input of the peer. For a server, the target puts the client preface before
//! it. A client opens streams 1 and 3 before it reads.
//!
//! Each stream admits 1024 bytes and a server takes 4 streams, so the input can pass a window and
//! the stream limit. The target is the consumer: it releases the data of a stream at the end of
//! its body, which comes at the same point in each cut.
//!
//! A cut input gives the events, the output, and the end of the whole input, so a frame that
//! crosses regions reads the same. Consecutive DATA events of one stream join, because a cut
//! gives more of them. No drive allocates more than the work limit, which bounds the one join of
//! a header block. Each charge returns when the connection drops. No frame follows a GOAWAY, and a
//! connection error ends with one. The stream checks:
//!
//! - Data and a trailer section go up only on a stream whose header section went up, and before
//!   the end of its body. No event follows the reset of a stream.
//! - No frame of the endpoint follows its RST_STREAM on a stream, and no RST_STREAM goes on an
//!   idle stream.
//! - The WINDOW_UPDATE frames of a stream, and of the connection, give back at most the DATA bytes
//!   that the input has for it, with their padding: no credit passes the admitted capacity.
//! - The last stream of the GOAWAY frames of the endpoint never increases.
//! - A server has at most 4 handlers in flight: a request starts one, and only the close of a
//!   stream that a reset ended ends it. The target closes the lowest such stream only when the
//!   connection waits for a free slot, so the connection waits at the same frame in each cut.

#![no_main]

use core::num::{NonZeroU64, NonZeroUsize};
use std::collections::{BTreeMap, BTreeSet};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h2::frame::{ErrorCode, HEAD, Head, PREFACE};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::{Block, FieldLine, Lines};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork_fuzz::allocated;

/// Work limits, table sizes, and region sizes that the control byte selects.
const WORK: [usize; 4] = [64, 1024, 16 * 1024, 64 * 1024];
const TABLES: [u32; 4] = [0, 256, 4096, 65_536];
const CUTS: [usize; 8] = [1, 2, 3, 7, 16, 64, 512, 4096];

/// Small turns, so that a turn stops at a limit inside the input.
const TURN: TurnLimits = TurnLimits { bytes: 512, frames: 4 };

/// The time of the host, which stays at the start of its clock. The settings timeout never ends
/// a run.
const NOW: Option<Instant> = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

const ENDPOINT: Endpoint = Endpoint {
    peer: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 1)), 443),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The streams that a client opens before it reads.
const CLIENT_STREAMS: [u32; 2] = [1, 3];

/// The frame types that the checks read (RFC 9113, section 6).
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, rest @ ..] = input else {
        return;
    };
    let pick = |shift: u8| usize::from((control >> shift) & 3);
    let role = if control & 1 == 0 { Role::Server } else { Role::Client };
    let limits = Limits {
        settings: Settings {
            header_table_size: TABLES[pick(3)],
            max_concurrent_streams: 4,
            initial_window_size: 1024,
            max_header_list_size: 4096,
            ..Settings::INITIAL
        },
        work: WORK[pick(1)],
        encoder_table_bytes: 4096,
        connection_window: 65_535,
    };
    let peer = match role {
        Role::Server => [PREFACE.as_slice(), rest].concat(),
        Role::Client => rest.to_vec(),
    };
    let whole = run(role, limits, &peer, peer.len().max(1));
    let cut = run(role, limits, &peer, CUTS[usize::from(control >> 5)]);
    assert_eq!(whole, cut, "a cut input gave another result");
});

/// One decoded field line: its name, its value, and its never-indexed mark.
type Line = (Vec<u8>, Vec<u8>, bool);

/// What the layer above saw, with the bytes of each event copied.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Headers(u32, bool, Option<Vec<Line>>),
    Trailers(u32, Option<Vec<Line>>),
    /// The joined bytes of consecutive DATA events of one stream, and the end.
    Data(u32, Vec<u8>, bool),
    Reset(u32, ErrorCode),
    WindowUpdate(u32, u32),
    Settings(Settings),
    PingAck([u8; 8]),
    GoAway(u32, ErrorCode),
    StreamError(u32, ErrorCode),
}

/// The result of one run.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    events: Vec<Seen>,
    sent: Vec<u8>,
    end: Option<Result<(), Kind>>,
}

/// The state of each stream as the consumer sees it.
#[derive(Default)]
struct Consumer {
    /// The streams that opened: the streams of a client, and each request of a server.
    opened: BTreeSet<u32>,
    /// The streams whose header section went up.
    headed: BTreeSet<u32>,
    /// The streams whose body ended.
    finished: BTreeSet<u32>,
    /// The streams that a reset ended.
    closed: BTreeSet<u32>,
    /// The data bytes of each stream that the consumer holds.
    held: BTreeMap<u32, u32>,
    /// The streams that a reset ended, which the consumer did not close.
    reset: BTreeSet<u32>,
    /// The handlers of a server that run: its requests, less the streams that it closed.
    running: u32,
}

impl Consumer {
    /// Checks that an event on `stream` comes while it is open. An event of its body comes after
    /// its header section and before the end of its body.
    fn live(&self, stream: u32, body: bool) {
        assert!(self.opened.contains(&stream), "an event on {stream} before it opened");
        assert!(!self.closed.contains(&stream), "an event after the reset of {stream}");
        if body {
            assert!(
                self.headed.contains(&stream),
                "a body on {stream} before its header section"
            );
            assert!(!self.finished.contains(&stream), "a body on {stream} after its end");
        }
    }
}

/// Drives one connection of `role` over `input`, cut into regions of `cut` bytes. The transport
/// accepts each output in full.
fn run(role: Role, limits: Limits, input: &[u8], cut: usize) -> Run {
    let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
    let available = budget.available();
    let mut result = Run {
        events: Vec::new(),
        sent: Vec::new(),
        end: None,
    };
    {
        let queue = NonZeroUsize::new(8).expect("not zero");
        let mut inbound = Inbound::new(queue, &budget).expect("the budget pays for the queue");
        let mut outbound = Outbound::new(queue, &budget).expect("the budget pays for the queue");
        let mut connection =
            Connection::new(role, limits, TURN, &mut outbound, &budget).expect("the budget pays for the connection");
        let mut lines = Lines::new(connection.header_limits(), &budget).expect("the budget pays for the lines");
        let mut consumer = Consumer::default();
        if role == Role::Client {
            let get = FieldLine {
                name: b":method",
                value: b"GET",
                never_indexed: false,
            };
            for expected in CLIENT_STREAMS {
                let region = Backing::from(Vec::with_capacity(64));
                let stream = connection
                    .open(&mut outbound, [get].into_iter(), true, region)
                    .expect("the client opens a stream");
                assert_eq!(stream, expected, "the streams of a client are odd and increase");
                consumer.opened.insert(stream);
            }
        }
        let mut chunks = input.chunks(cut);
        // The rounds in a row in which the connection waits for output that the transport took.
        let mut stalled = 0;
        loop {
            let (progress, ended) = drive(
                &mut connection,
                &mut inbound,
                &mut outbound,
                &mut lines,
                limits.work,
                &mut result,
                &mut consumer,
            );
            while let Some(output) = outbound.submit() {
                result.sent.extend_from_slice(output.region.bytes());
                outbound
                    .ack(output.id, output.region.initialized())
                    .expect("the output is outstanding");
            }
            // The consumer releases the data of a stream at the end of its body.
            if let Some(stream) = ended
                && let Some(bytes) = consumer.held.remove(&stream)
                && !matches!(progress, Progress::Terminal(_))
            {
                connection
                    .release(&mut outbound, stream, bytes)
                    .expect("the consumer releases the bytes that it holds");
            }
            stalled = if progress == Progress::Blocked(Blocked::Output) {
                stalled + 1
            } else {
                0
            };
            assert!(stalled < 2, "the connection waits for output that the transport took");
            match progress {
                Progress::Pending | Progress::Blocked(Blocked::Output) => {}
                Progress::Blocked(Blocked::Input) => match chunks.next() {
                    Some(chunk) => {
                        let received = Received {
                            region: Lease::from(chunk.to_vec()),
                            endpoint: ENDPOINT,
                            capacity: 1 << 20,
                        };
                        assert!(inbound.push(received).is_ok(), "the queue has room");
                    }
                    None if inbound.ended() => panic!("the connection waits after the end of its input"),
                    None => inbound.end(),
                },
                Progress::Blocked(Blocked::Capacity(units)) => panic!("the budget refused {units} units"),
                Progress::Blocked(Blocked::Streams) => {
                    let stream = consumer.reset.pop_first().expect("a reset holds the slot");
                    connection.close(stream).expect("the slot of the stream is held");
                    consumer.running -= 1;
                }
                Progress::Terminal(end) => {
                    result.end = Some(end.map_err(|error| error.kind()));
                    break;
                }
            }
        }
    }
    assert_eq!(budget.available(), available, "a charge did not return");
    check_output(role, input, &result);
    result
}

/// One drive. It checks the allocation bound and the stream order of the event, and records the
/// event. Gives the progress, and the stream whose body ended.
fn drive(
    connection: &mut Connection,
    inbound: &mut Inbound,
    outbound: &mut Outbound,
    lines: &mut Lines,
    work: usize,
    result: &mut Run,
    consumer: &mut Consumer,
) -> (Progress, Option<u32>) {
    let ((event, turn), bytes) = allocated(move || connection.drive(inbound, outbound, lines, NOW));
    assert!(
        bytes <= work,
        "a drive allocated {bytes} bytes, past the work limit {work}"
    );
    let Some(event) = event else {
        return (turn.progress, None);
    };
    let copy = |lines: Option<Block<'_>>| {
        lines.map(|block| {
            block
                .lines()
                .map(|line| (line.name.to_vec(), line.value.to_vec(), line.never_indexed))
                .collect()
        })
    };
    // The stream whose body the event ends, or that it resets.
    let (seen, ended) = match event {
        Event::Headers {
            stream,
            end_stream,
            lines,
        } => {
            // A client opened each of its streams, so a new stream is a request to a server.
            if consumer.opened.insert(stream) {
                consumer.running += 1;
                assert!(consumer.running <= 4, "{} handlers in flight", consumer.running);
            }
            consumer.live(stream, false);
            assert!(
                !consumer.finished.contains(&stream),
                "a header section after the end of {stream}"
            );
            consumer.headed.insert(stream);
            (
                Seen::Headers(stream, end_stream, copy(lines)),
                end_stream.then_some(stream),
            )
        }
        Event::Trailers { stream, lines } => {
            consumer.live(stream, true);
            (Seen::Trailers(stream, copy(lines)), Some(stream))
        }
        Event::Data {
            stream,
            data,
            end_stream,
        } => {
            consumer.live(stream, true);
            *consumer.held.entry(stream).or_default() += u32::try_from(data.initialized()).expect("a frame");
            let ended = end_stream.then_some(stream);
            if let Some(Seen::Data(last, bytes, end)) = result.events.last_mut()
                && *last == stream
                && !*end
            {
                bytes.extend_from_slice(data.bytes());
                *end = end_stream;
                if let Some(stream) = ended {
                    consumer.finished.insert(stream);
                }
                return (turn.progress, ended);
            }
            (Seen::Data(stream, data.bytes().to_vec(), end_stream), ended)
        }
        Event::Reset { stream, code } => {
            consumer.live(stream, false);
            consumer.closed.insert(stream);
            consumer.reset.insert(stream);
            (Seen::Reset(stream, code), Some(stream))
        }
        Event::StreamError { stream, code } => {
            consumer.live(stream, false);
            consumer.closed.insert(stream);
            consumer.reset.insert(stream);
            (Seen::StreamError(stream, code), Some(stream))
        }
        Event::WindowUpdate { stream, increment } => (Seen::WindowUpdate(stream, increment), None),
        Event::Settings(settings) => (Seen::Settings(settings), None),
        Event::PingAck(opaque) => (Seen::PingAck(opaque), None),
        Event::GoAway { last_stream, code } => (Seen::GoAway(last_stream, code), None),
    };
    if let Some(stream) = ended {
        consumer.finished.insert(stream);
    }
    result.events.push(seen);
    (turn.progress, ended)
}

/// Each frame at the start of `bytes` with its payload, up to the first frame that does not end
/// in it, and the bytes after them.
fn frames(mut bytes: &[u8]) -> (Vec<(Head, &[u8])>, &[u8]) {
    let mut frames = Vec::new();
    while let Some(&head) = bytes.first_chunk::<HEAD>() {
        let head = Head::parse(head);
        let Some(payload) = bytes.get(HEAD..HEAD + head.length as usize) else {
            break;
        };
        frames.push((head, payload));
        bytes = &bytes[HEAD + payload.len()..];
    }
    (frames, bytes)
}

/// The value of the first 4 bytes of `payload`, with no reserved bit.
fn word(payload: &[u8]) -> u32 {
    payload.first_chunk().copied().map_or(0, u32::from_be_bytes) & 0x7fff_ffff
}

/// Checks the frames of the output against the rules of the module documentation.
fn check_output(role: Role, input: &[u8], result: &Run) {
    let sent = match role {
        Role::Client => result.sent.get(PREFACE.len()..).expect("the client preface"),
        Role::Server => &result.sent[..],
    };
    let (sent, rest) = frames(sent);
    assert!(rest.is_empty(), "the output ends inside a frame");
    // The DATA bytes of each stream in the input, and each stream that can be open.
    let peer = match role {
        Role::Client => input,
        Role::Server => &input[PREFACE.len()..],
    };
    let mut flow: BTreeMap<u32, u64> = BTreeMap::new();
    let mut streams: BTreeSet<u32> = match role {
        Role::Client => CLIENT_STREAMS.into_iter().collect(),
        Role::Server => BTreeSet::new(),
    };
    // The connection counts a DATA frame at its header (RFC 9113, section 6.9.1), so a frame
    // that the input ends inside counts too.
    let mut rest = peer;
    while let Some(&head) = rest.first_chunk::<HEAD>() {
        let head = Head::parse(head);
        match head.kind.code() {
            DATA => *flow.entry(head.stream).or_default() += u64::from(head.length),
            HEADERS if role == Role::Server => {
                streams.insert(head.stream);
            }
            _ => {}
        }
        let Some(next) = rest.get(HEAD + head.length as usize..) else {
            break;
        };
        rest = next;
    }
    let mut granted: BTreeMap<u32, u64> = BTreeMap::new();
    let mut reset = BTreeSet::new();
    let (mut last, mut goaway) = (None, None::<u32>);
    for (head, payload) in sent {
        let kind = head.kind.code();
        assert_ne!(last, Some(GOAWAY), "a frame follows a GOAWAY");
        last = Some(kind);
        assert!(
            !reset.contains(&head.stream),
            "a frame follows the reset of {}",
            head.stream
        );
        match kind {
            RST_STREAM => {
                assert!(
                    streams.contains(&head.stream),
                    "a reset of the idle stream {}",
                    head.stream
                );
                reset.insert(head.stream);
            }
            WINDOW_UPDATE => *granted.entry(head.stream).or_default() += u64::from(word(payload)),
            GOAWAY => {
                let stream = word(payload);
                assert!(
                    goaway.is_none_or(|earlier| stream <= earlier),
                    "a GOAWAY raised its last stream"
                );
                goaway = Some(stream);
            }
            _ => {}
        }
    }
    let total: u64 = flow.values().sum();
    for (&stream, &bytes) in &granted {
        let arrived = if stream == 0 {
            total
        } else {
            flow.get(&stream).copied().unwrap_or(0)
        };
        assert!(
            bytes <= arrived,
            "{bytes} bytes of credit on stream {stream} for {arrived} bytes"
        );
    }
    match result.end {
        Some(Err(Kind::Malformed | Kind::Overload)) => assert_eq!(last, Some(GOAWAY), "no GOAWAY ends the connection"),
        Some(Err(Kind::Misuse)) => panic!("the connection broke its own contract"),
        _ => {}
    }
}
