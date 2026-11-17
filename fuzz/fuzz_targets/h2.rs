//! The HTTP/2 connection layer reads fuzzed frames as a server or a client. The first byte of the
//! input selects the role, the work limit, the table size, and the size of the regions of a cut
//! input. The rest is the input of the peer. For a server, the target puts the client preface
//! before it.
//!
//! A cut input gives the events, the output, and the end of the whole input, so a frame that
//! crosses regions reads the same. Consecutive DATA events of one stream join, because a cut
//! gives more of them. No drive allocates more than the work limit, which bounds the one join of
//! a header block. Each charge returns when the connection drops. No frame follows a GOAWAY, and a
//! connection error ends with one.

#![no_main]

use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h2::frame::{ErrorCode, HEAD, Head, PREFACE};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::Lines;
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

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, rest @ ..] = input else {
        return;
    };
    let pick = |shift: u8| usize::from((control >> shift) & 3);
    let role = if control & 1 == 0 { Role::Server } else { Role::Client };
    let limits = Limits {
        settings: Settings {
            header_table_size: TABLES[pick(3)],
            max_header_list_size: 4096,
            ..Settings::INITIAL
        },
        work: WORK[pick(1)],
        encoder_table_bytes: 4096,
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
    /// The joined bytes of consecutive DATA events of one stream, their flow, and the end.
    Data(u32, Vec<u8>, u64, bool),
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
        let mut chunks = input.chunks(cut);
        // The rounds in a row in which the connection waits for output that the transport took.
        let mut stalled = 0;
        loop {
            let progress = drive(
                &mut connection,
                &mut inbound,
                &mut outbound,
                &mut lines,
                limits.work,
                &mut result,
            );
            while let Some(output) = outbound.submit() {
                result.sent.extend_from_slice(output.region.bytes());
                outbound
                    .ack(output.id, output.region.initialized())
                    .expect("the output is outstanding");
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
                Progress::Terminal(end) => {
                    result.end = Some(end.map_err(|error| error.kind()));
                    break;
                }
            }
        }
    }
    assert_eq!(budget.available(), available, "a charge did not return");
    check_output(role, &result);
    result
}

/// One drive. It checks the allocation bound and records the event.
fn drive(
    connection: &mut Connection,
    inbound: &mut Inbound,
    outbound: &mut Outbound,
    lines: &mut Lines,
    work: usize,
    result: &mut Run,
) -> Progress {
    let ((event, turn), bytes) = allocated(move || connection.drive(inbound, outbound, lines, NOW));
    assert!(
        bytes <= work,
        "a drive allocated {bytes} bytes, past the work limit {work}"
    );
    let Some(event) = event else {
        return turn.progress;
    };
    let seen = match event {
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
                    .map(|line| (line.name.to_vec(), line.value.to_vec(), line.never_indexed))
                    .collect()
            }),
        ),
        Event::Data {
            stream,
            data,
            flow,
            end_stream,
        } => {
            if let Some(Seen::Data(last, bytes, total, end)) = result.events.last_mut()
                && *last == stream
                && !*end
            {
                bytes.extend_from_slice(data.bytes());
                *total += u64::from(flow);
                *end = end_stream;
                return turn.progress;
            }
            Seen::Data(stream, data.bytes().to_vec(), u64::from(flow), end_stream)
        }
        Event::Reset { stream, code } => Seen::Reset(stream, code),
        Event::WindowUpdate { stream, increment } => Seen::WindowUpdate(stream, increment),
        Event::Settings(settings) => Seen::Settings(settings),
        Event::PingAck(opaque) => Seen::PingAck(opaque),
        Event::GoAway { last_stream, code } => Seen::GoAway(last_stream, code),
        Event::StreamError { stream, code } => Seen::StreamError(stream, code),
    };
    result.events.push(seen);
    turn.progress
}

/// Checks the frames of the output: no frame follows a GOAWAY, and a connection error of the
/// peer ends with one.
fn check_output(role: Role, result: &Run) {
    let mut rest = match role {
        Role::Client => result.sent.get(PREFACE.len()..).expect("the client preface"),
        Role::Server => &result.sent[..],
    };
    let mut last = None;
    while let Some(&bytes) = rest.first_chunk::<HEAD>() {
        let head = Head::parse(bytes);
        assert_ne!(last, Some(0x7), "a frame follows a GOAWAY");
        last = Some(head.kind.code());
        rest = rest.get(HEAD + head.length as usize..).expect("a complete frame");
    }
    assert!(rest.is_empty(), "the output ends inside a frame");
    match result.end {
        Some(Err(Kind::Malformed | Kind::Overload)) => assert_eq!(last, Some(0x7), "no GOAWAY ends the connection"),
        Some(Err(Kind::Misuse)) => panic!("the connection broke its own contract"),
        _ => {}
    }
}
