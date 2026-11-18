//! The send scheduler of the HTTP/2 engine, under the frames of a hostile peer. The first byte of
//! the input selects the role, the size of each body, the size of the regions of the cut input,
//! the number of chunks of each body, and the end of each body. The rest is the input of the peer.
//! For a server, the target puts the client preface before it.
//!
//! The target is the application. A client opens streams 1 and 3 with a request and sends a body
//! on each. A server answers each request with a header section and a body. A body goes in one or
//! two chunks: the second after the `Sent` event of the first. It ends with END_STREAM on its last
//! chunk, or with a trailer section after the `Sent` event of its last chunk. At a reset, the
//! handler of the stream ends at once. The transport accepts each output in full after each
//! drive.
//!
//! After each drive, the target applies the frames that the connection read to a model of the
//! send windows: WINDOW_UPDATE, RST_STREAM, and GOAWAY, and the `SETTINGS_INITIAL_WINDOW_SIZE` of
//! each `Settings` event. The scheduler sends after the reader, so the target then checks each
//! DATA frame of the drive:
//!
//! - It has 1 to 16,384 bytes, and fits in its stream window and in the connection window.
//! - No END_STREAM, RST_STREAM, or GOAWAY of the endpoint, and no RST_STREAM of the peer, came
//!   before it on its stream. For a client, its stream is at or below the last stream of each
//!   GOAWAY of the peer.
//! - Its payload is the next bytes of the body of its stream, which the application gave, and
//!   END_STREAM is on the last byte of a body that ends with it.
//!
//! `Sent` comes only after each byte of its chunk went out. When the connection waits for input,
//! no stream has body bytes that both windows admit. When it waits for output, the output queue
//! is not empty. No drive allocates past the work limit, and each charge returns when the
//! connection drops.

#![no_main]

use core::num::{NonZeroU64, NonZeroUsize};
use std::collections::BTreeMap;

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h2::frame::{HEAD, Head, PREFACE};
use rsnetwork::h2::{Connection, Event, Limits, Role, Settings};
use rsnetwork::hpack::{FieldLine, Lines};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork_fuzz::allocated;

/// The body sizes that the control byte selects: the last one is past the initial window.
const BODIES: [usize; 4] = [1, 1000, 20_000, 70_000];
const CUTS: [usize; 8] = [1, 2, 3, 7, 16, 64, 512, 4096];

/// Small turns, so that a turn stops at a limit inside the input.
const TURN: TurnLimits = TurnLimits { bytes: 512, frames: 4 };

/// The work limit of a header block.
const WORK: usize = 16 * 1024;

/// The time of the host, which stays at the start of its clock.
const NOW: Option<Instant> = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

const ENDPOINT: Endpoint = Endpoint {
    peer: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 1)), 443),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The frame types and flags that the model reads (RFC 9113, section 6).
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const END_STREAM: u8 = 0x1;

/// The largest DATA frame of the scheduler.
const QUANTUM: usize = 16_384;

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, rest @ ..] = input else {
        return;
    };
    let role = if control & 1 == 0 { Role::Server } else { Role::Client };
    let plan = Plan {
        body: BODIES[usize::from((control >> 1) & 3)],
        halves: control & 0x40 != 0,
        trailers: control & 0x80 != 0,
    };
    let peer = match role {
        Role::Server => [PREFACE.as_slice(), rest].concat(),
        Role::Client => rest.to_vec(),
    };
    run(role, plan, &peer, CUTS[usize::from((control >> 3) & 7)]);
});

/// The body of each stream.
#[derive(Clone, Copy)]
struct Plan {
    body: usize,
    /// The body goes in two chunks, not one.
    halves: bool,
    /// A trailer section ends the body, not END_STREAM on its last chunk.
    trailers: bool,
}

impl Plan {
    /// The end of the chunk that starts at `start`.
    fn chunk_end(self, start: usize) -> usize {
        if self.halves && start < self.body / 2 {
            self.body / 2
        } else {
            self.body
        }
    }
}

/// The byte at `offset` of the body of `stream`.
fn byte(stream: u32, offset: usize) -> u8 {
    (offset.to_le_bytes()[0].wrapping_mul(31)) ^ stream.to_le_bytes()[0]
}

/// The body of one stream, as the application and the model see it.
#[derive(Default)]
struct Stream {
    /// The bytes that the application gave.
    given: usize,
    /// The bytes that went out.
    sent: usize,
    /// The WINDOW_UPDATE increments of the peer.
    updates: i64,
    /// An END_STREAM, a reset, or a GOAWAY ended the stream: no DATA comes after it.
    ended: bool,
}

/// The send windows of the connection, from the frames that it read and sent.
struct Model {
    plan: Plan,
    role: Role,
    /// The peer's `SETTINGS_INITIAL_WINDOW_SIZE` of its last `Settings` event. The connection
    /// applies it at the end of the frame, which can come in a later drive than the frame.
    initial: i64,
    /// The connection window: the initial window and the increments, less the DATA that went out.
    connection: i64,
    streams: BTreeMap<u32, Stream>,
    /// The endpoint sent a GOAWAY.
    away: bool,
    /// The input that the model read, and the output that it did not check.
    read: usize,
    output: Vec<u8>,
}

impl Model {
    /// Applies each complete frame of `input` after the frames that it read.
    fn read(&mut self, input: &[u8]) {
        while let Some(&head) = input.get(self.read..).and_then(|rest| rest.first_chunk::<HEAD>()) {
            let head = Head::parse(head);
            let start = self.read + HEAD;
            let Some(payload) = input.get(start..start + head.length as usize) else {
                return;
            };
            self.read = start + payload.len();
            match (head.kind.code(), payload.len()) {
                (WINDOW_UPDATE, 4) if head.stream == 0 => self.connection += i64::from(word(payload) & 0x7fff_ffff),
                (WINDOW_UPDATE, 4) => {
                    self.streams.entry(head.stream).or_default().updates += i64::from(word(payload) & 0x7fff_ffff);
                }
                (RST_STREAM, 4) => self.streams.entry(head.stream).or_default().ended = true,
                (GOAWAY, 8..) if self.role == Role::Client => {
                    let last = word(payload) & 0x7fff_ffff;
                    for (_, stream) in self.streams.range_mut(last + 1..) {
                        stream.ended = true;
                    }
                }
                _ => {}
            }
        }
    }

    /// Checks each complete frame of the output that it did not check.
    fn check(&mut self, sent: &[u8]) {
        self.output.extend_from_slice(sent);
        let mut at = 0;
        while let Some(&head) = self.output.get(at..).and_then(|rest| rest.first_chunk::<HEAD>()) {
            let head = Head::parse(head);
            let Some(payload) = self.output.get(at + HEAD..at + HEAD + head.length as usize) else {
                break;
            };
            at += HEAD + payload.len();
            let stream = self.streams.entry(head.stream).or_default();
            match head.kind.code() {
                DATA => {
                    let id = head.stream;
                    assert!(!self.away, "DATA on {id} after a GOAWAY");
                    assert!(!stream.ended, "DATA on {id} after its end");
                    let len = payload.len();
                    assert!((1..=QUANTUM).contains(&len), "DATA of {len} bytes on {id}");
                    let bytes = i64::try_from(len).expect("a frame");
                    assert!(bytes <= self.connection, "DATA past the connection window");
                    let window = self.initial + stream.updates - i64::try_from(stream.sent).expect("a body");
                    assert!(
                        bytes <= window,
                        "DATA of {len} bytes on {id} past its window of {window}"
                    );
                    assert!(
                        stream.sent + len <= stream.given,
                        "DATA that the application did not give"
                    );
                    for (offset, &got) in (stream.sent..).zip(payload) {
                        assert_eq!(got, byte(id, offset), "the body of {id} at {offset}");
                    }
                    self.connection -= bytes;
                    stream.sent += len;
                    let last = stream.sent == self.plan.body && !self.plan.trailers;
                    assert_eq!(head.flags & END_STREAM != 0, last, "END_STREAM of {id}");
                    stream.ended = last;
                }
                HEADERS if head.flags & END_STREAM != 0 => stream.ended = true,
                RST_STREAM => stream.ended = true,
                GOAWAY => self.away = true,
                _ => {}
            }
        }
        self.output.drain(..at);
    }

    /// Checks that no stream has body bytes that both windows admit.
    fn idle(&self) {
        if self.away || self.connection <= 0 {
            return;
        }
        for (id, stream) in &self.streams {
            let window = self.initial + stream.updates - i64::try_from(stream.sent).expect("a body");
            assert!(
                stream.ended || stream.sent == stream.given || window <= 0,
                "{} bytes of {id} wait with a window of {window}",
                stream.given - stream.sent
            );
        }
    }
}

/// The value of the first 4 bytes of `bytes`.
fn word(bytes: &[u8]) -> u32 {
    bytes.first_chunk().copied().map_or(0, u32::from_be_bytes)
}

/// What the application does after a drive.
enum Act {
    Respond(u32),
    Next(u32),
    Close(u32),
}

/// Gives the next chunk of the body of `stream`.
fn give(connection: &mut Connection, outbound: &mut Outbound, model: &mut Model, id: u32) {
    let stream = model.streams.entry(id).or_default();
    let (start, end) = (stream.given, model.plan.chunk_end(stream.given));
    let chunk: Vec<u8> = (start..end).map(|offset| byte(id, offset)).collect();
    let end_stream = end == model.plan.body && !model.plan.trailers;
    connection
        .data(outbound, id, Lease::from(chunk), end_stream)
        .expect("an open stream takes a chunk after its Sent event");
    stream.given = end;
}

/// Drives one connection of `role` over `input`, cut into regions of `cut` bytes.
fn run(role: Role, plan: Plan, input: &[u8], cut: usize) {
    let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
    let available = budget.available();
    {
        let limits = Limits {
            settings: Settings {
                max_concurrent_streams: 4,
                max_header_list_size: 4096,
                ..Settings::INITIAL
            },
            work: WORK,
            encoder_table_bytes: 4096,
            connection_window: 65_535,
        };
        let queue = NonZeroUsize::new(8).expect("not zero");
        let mut inbound = Inbound::new(queue, &budget).expect("the budget pays for the queue");
        let mut outbound = Outbound::new(queue, &budget).expect("the budget pays for the queue");
        let mut connection =
            Connection::new(role, limits, TURN, &mut outbound, &budget).expect("the budget pays for the connection");
        let mut lines = Lines::new(connection.header_limits(), &budget).expect("the budget pays for the lines");
        let mut model = Model {
            plan,
            role,
            initial: 65_535,
            connection: 65_535,
            streams: BTreeMap::new(),
            away: false,
            read: 0,
            output: Vec::new(),
        };
        let line = |name: &'static [u8], value: &'static [u8]| FieldLine {
            name,
            value,
            never_indexed: false,
        };
        let peer = match role {
            Role::Server => &input[PREFACE.len()..],
            Role::Client => {
                // The preface of the client is not a frame.
                let preface = outbound.submit().expect("the client preface");
                assert_eq!(preface.region.bytes(), PREFACE);
                outbound
                    .ack(preface.id, PREFACE.len())
                    .expect("the output is outstanding");
                for expected in [1, 3] {
                    let region = Backing::from(Vec::with_capacity(64));
                    let post = line(b":method", b"POST");
                    let stream = connection
                        .open(&mut outbound, [post].into_iter(), false, region)
                        .expect("the client opens a stream");
                    assert_eq!(stream, expected);
                    give(&mut connection, &mut outbound, &mut model, stream);
                }
                input
            }
        };
        let (mut chunks, mut pushed) = (input.chunks(cut), 0);
        loop {
            let (to, from, into, with) = (&mut connection, &mut inbound, &mut outbound, &mut lines);
            let ((event, turn), bytes) = allocated(move || to.drive(from, into, with, NOW));
            assert!(
                bytes <= WORK,
                "a drive allocated {bytes} bytes, past the work limit {WORK}"
            );
            let act = match event {
                Some(Event::Settings(settings)) => {
                    model.initial = i64::from(settings.initial_window_size);
                    None
                }
                Some(Event::Headers { stream, .. }) if role == Role::Server && !model.streams.contains_key(&stream) => {
                    Some(Act::Respond(stream))
                }
                Some(Event::Sent { stream }) => Some(Act::Next(stream)),
                Some(Event::Reset { stream, .. } | Event::StreamError { stream, .. }) => Some(Act::Close(stream)),
                _ => None,
            };
            let progress = turn.progress;
            if progress == Progress::Blocked(Blocked::Output) {
                assert!(
                    outbound.free() < outbound.limit(),
                    "the connection waits for an empty queue"
                );
            }
            let mut sent = Vec::new();
            while let Some(output) = outbound.submit() {
                sent.extend_from_slice(output.region.bytes());
                outbound
                    .ack(output.id, output.region.initialized())
                    .expect("the output is outstanding");
            }
            // The server reads the client preface, which is not a frame.
            let unread = inbound.front().map_or(0, |front| front.region.initialized());
            let consumed = (pushed - unread).saturating_sub(input.len() - peer.len());
            model.read(&peer[..consumed]);
            model.check(&sent);
            match act {
                Some(Act::Respond(stream)) => {
                    let region = Backing::from(Vec::with_capacity(64));
                    connection
                        .headers(
                            &mut outbound,
                            stream,
                            [line(b":status", b"200")].into_iter(),
                            false,
                            region,
                        )
                        .expect("a drained queue has room for a response");
                    give(&mut connection, &mut outbound, &mut model, stream);
                }
                Some(Act::Next(id)) => {
                    let stream = model.streams.entry(id).or_default();
                    assert_eq!(stream.sent, stream.given, "Sent on {id} before its chunk went out");
                    if stream.given < plan.body {
                        give(&mut connection, &mut outbound, &mut model, id);
                    } else {
                        assert!(plan.trailers, "Sent on {id} after the chunk that ends it");
                        let region = Backing::from(Vec::with_capacity(64));
                        connection
                            .headers(&mut outbound, id, [line(b"x-t", b"1")].into_iter(), true, region)
                            .expect("a drained queue has room for a trailer section");
                        stream.ended = true;
                    }
                }
                Some(Act::Close(stream)) => {
                    model.streams.entry(stream).or_default().ended = true;
                    connection.close(stream).expect("a reset holds the slot");
                }
                None => {}
            }
            match progress {
                Progress::Pending | Progress::Blocked(Blocked::Output) => {}
                Progress::Blocked(Blocked::Input) => {
                    model.idle();
                    match chunks.next() {
                        Some(chunk) => {
                            let received = Received {
                                region: Lease::from(chunk.to_vec()),
                                endpoint: ENDPOINT,
                                capacity: 1 << 20,
                            };
                            assert!(inbound.push(received).is_ok(), "the queue has room");
                            pushed += chunk.len();
                        }
                        None if inbound.ended() => panic!("the connection waits after the end of its input"),
                        None => inbound.end(),
                    }
                }
                Progress::Blocked(Blocked::Streams) => panic!("a slot waits, and each reset closed its stream"),
                Progress::Blocked(Blocked::Capacity(units)) => panic!("the budget refused {units} units"),
                Progress::Terminal(_) => break,
            }
        }
    }
    assert_eq!(budget.available(), available, "a charge did not return");
}
