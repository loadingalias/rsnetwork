//! The harness of the fuzz targets: a counting allocator, the limits of the engines, and a
//! transport that drives one H1 engine over cut input and short writes.
//!
//! The transport checks the bounds of the limits page on each drive: the engine keeps at most one
//! charged join, no drive allocates past the limit of one section, each charge returns when the
//! engine drops, and each round makes progress. A target compares the run of the whole input with
//! the run of a cut input, because two readers that cut a stream in two ways must read the same
//! messages.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use std::alloc::System;

use rsnetwork::body::Outcome;
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Error, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Limits};
use rsnetwork::host::Engine;
use rsnetwork::time::{ClockDomain, Instant, Suspend};

/// Counts the bytes that each thread allocates.
struct Counting;

thread_local! {
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

#[expect(
    unsafe_code,
    reason = "the allocator counts each allocation and forwards it to the system allocator"
)]
// SAFETY: each method forwards its arguments to the system allocator, which meets the contract.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.set(ALLOCATED.get().wrapping_add(layout.size()));
        // SAFETY: the caller meets the contract of `alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller meets the contract of `dealloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Runs `work`, and gives its result with the bytes that it allocated on this thread.
///
/// It first counts one known allocation. Thus a count of zero cannot come from a counter that
/// does not count.
pub fn allocated<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let control = ALLOCATED.get();
    drop(core::hint::black_box(Vec::<u8>::with_capacity(1)));
    assert_ne!(ALLOCATED.get(), control, "the counter sees no allocation");
    let before = ALLOCATED.get();
    let result = work();
    (result, ALLOCATED.get().wrapping_sub(before))
}

/// The head limits of the conformance suite, so that an input of a few kilobytes reaches each
/// limit.
pub const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

/// The body limits of the conformance suite.
pub const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1 << 10,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

/// Small turn limits, so that a body of a few chunks stops at a limit and continues.
pub const TURN: TurnLimits = TurnLimits {
    bytes: 256,
    frames: 4,
    visits: 64,
};

/// The largest section that an engine joins or copies: a head or a trailer section. The limits
/// page permits one charged join of it.
const SECTION: usize = if LIMITS.head_bytes > BODY.trailer_bytes {
    LIMITS.head_bytes
} else {
    BODY.trailer_bytes
};

/// The most bytes of the record that holds a joined section in its lease.
const RECORD: usize = 256;

/// The time of each drive. It stays at the start of the clock, so the head timer never expires
/// and the time cannot change a result.
const NOW: Option<Instant> = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The sizes of the regions or the writes of a run: all available bytes at once, or at most
/// this many bytes each time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    Whole,
    Each(NonZeroUsize),
}

impl Cut {
    /// The cut of a control byte of an input: zero is whole.
    pub fn from_byte(byte: u8) -> Self {
        NonZeroUsize::new(usize::from(byte)).map_or(Self::Whole, Self::Each)
    }

    /// The size of the next region or write, when `left` bytes are available.
    pub fn take(self, left: usize) -> usize {
        match self {
            Self::Whole => left,
            Self::Each(size) => size.get().min(left),
        }
    }
}

/// What the application sees.
#[derive(Debug)]
pub enum Moment<T> {
    /// A drive, with its event if it gave one. Also a write, when the application waits for space
    /// in the output queue.
    Event(Option<T>),
    /// A round in which the transport and the engine did nothing else.
    Quiet,
}

/// What the application did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    /// Nothing.
    Idle,
    /// It called the engine.
    Acted,
    /// It owes a call that the full output queue refused. It calls again after a write, before
    /// the next drive.
    Wait,
    /// The engine gave the connection to another protocol.
    Handoff,
}

/// The result of one run, apart from what the application saw.
#[derive(Debug, PartialEq, Eq)]
pub struct Run {
    /// Each byte that the transport accepted from the engine, in order.
    pub sent: Vec<u8>,
    /// The end of the engine.
    pub end: Result<(), Kind>,
    /// After a handoff, the bytes that belong to the new protocol: the queued bytes and the bytes
    /// that the transport did not receive yet.
    pub handoff: Option<Vec<u8>>,
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("not zero")
}

/// Drives the engine that `make` gives over `input`, until its terminal release, and checks the
/// bounds of each drive.
///
/// Each round, the transport receives one region of `regions` from the first `available` bytes
/// of `input`. Then it drives until the engine waits, and `answer` sees each drive. Then it makes
/// one write of `writes`. The output queue has two entries, so a pipelined exchange meets
/// backpressure. An application that waits for space in the queue makes its call before the
/// engine drives again, as it does with whole writes.
///
/// A round that does nothing else is quiet, and `answer` sees it. Only then does the application
/// make a call that waits for the peer, such as the next request of a client, which makes more
/// bytes available. When it does nothing, the peer sends the rest of `input`, and after the last
/// byte it closes its side. Thus no call races with bytes or with the close, whose order RFC 9112,
/// section 9.3.1, leaves open. After the close, a quiet round is a stall, because the next round
/// would do the same.
pub fn run<E: Engine>(
    input: &[u8],
    available: &Cell<usize>,
    regions: Cut,
    writes: Cut,
    make: impl FnOnce(&mut Outbound, &Budget) -> E,
    mut answer: impl FnMut(&mut E, &mut Outbound, Moment<E::Event>) -> Act,
) -> Run {
    let queues = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
    let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
    let mut inbound = Inbound::new(nonzero(16), &queues).expect("the budget admits the queue");
    let mut outbound = Outbound::new(nonzero(2), &queues).expect("the budget admits the queue");
    let mut engine = make(&mut outbound, &budget);
    let admitted = budget.available();
    let (mut read, mut sent, mut handoff, mut end) = (0, Vec::new(), None, None);
    let mut waiting = false;
    while end.is_none() || !outbound.outstanding().is_empty() {
        let mut progress = false;
        let ready = available.get().min(input.len());
        if read < ready {
            let size = regions.take(ready - read);
            let received = Received {
                region: Lease::from(input[read..read + size].to_vec()),
                endpoint: ENDPOINT,
                capacity: 1 << 16,
            };
            // A full queue gives the region back, and the transport gives it again later.
            if inbound.push(received).is_ok() {
                read += size;
                progress = true;
            }
        }
        if waiting {
            let act = answer(&mut engine, &mut outbound, Moment::Event(None));
            (waiting, progress) = (act == Act::Wait, progress || act == Act::Acted);
        }
        while end.is_none() && !waiting {
            let ((event, turn), bytes) = allocated(|| engine.drive(&mut inbound, &mut outbound, NOW));
            assert!(
                bytes <= SECTION + RECORD,
                "a drive allocated {bytes} bytes, past one section of {SECTION} bytes"
            );
            let charge = admitted
                .checked_sub(budget.available())
                .expect("a charge, not a refund");
            assert!(
                charge <= SECTION as u64,
                "the engine holds a charge of {charge} bytes, past one section of {SECTION} bytes"
            );
            let gave = event.is_some();
            let act = answer(&mut engine, &mut outbound, Moment::Event(event));
            if act == Act::Handoff {
                let mut rest = Vec::new();
                while let Some(received) = inbound.take_front() {
                    rest.extend_from_slice(received.region.bytes());
                }
                rest.extend_from_slice(&input[read..]);
                (read, handoff) = (input.len(), Some(rest));
                available.set(input.len());
            }
            let acted = matches!(act, Act::Acted | Act::Handoff);
            (waiting, progress) = (act == Act::Wait, progress || gave || acted);
            match turn.progress {
                Progress::Terminal(result) => {
                    end = Some(result.map_err(|error| error.kind()));
                    progress = true;
                }
                Progress::Pending => {}
                Progress::Blocked(_) if gave || acted => {}
                Progress::Blocked(_) => break,
            }
        }
        if let Some(output) = outbound.submit() {
            let size = writes.take(output.region.initialized());
            sent.extend_from_slice(&output.region.bytes()[..size]);
            outbound
                .ack(output.id, size)
                .expect("the transport accepted these bytes");
            progress = true;
        }
        if !progress && end.is_none() {
            let act = answer(&mut engine, &mut outbound, Moment::Quiet);
            waiting = act == Act::Wait;
            progress = act != Act::Idle;
        }
        if !progress && available.get() < input.len() {
            available.set(input.len());
            progress = true;
        }
        if !progress && read == input.len() && !inbound.ended() {
            inbound.end();
            progress = true;
        }
        assert!(progress, "the connection stalled after {read} input bytes");
    }
    drop(engine);
    assert_eq!(
        budget.available(),
        budget.bound(),
        "the engine kept a charge after its drop"
    );
    drop((inbound, outbound));
    assert_eq!(
        queues.available(),
        queues.bound(),
        "a queue kept a charge after its drop"
    );
    Run {
        sent,
        end: end.expect("the loop ends at the end of the engine"),
        handoff,
    }
}

/// What the application saw, in order. Each byte string shows its bytes as escaped ASCII, so a
/// failure shows them.
#[derive(PartialEq, Eq)]
pub enum Seen {
    /// A head, as the facts of the engine.
    Head(String),
    /// The body bytes since the last head, in one piece, however the engine gave them.
    Data(String),
    /// The end of a body.
    End(String),
    /// A call of the application that the engine refused.
    Refused(Kind),
    /// The handoff to another protocol.
    Handoff,
}

impl fmt::Debug for Seen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Head(text) => write!(f, "head {text}"),
            Self::Data(text) => write!(f, "data \"{text}\""),
            Self::End(text) => write!(f, "end {text}"),
            Self::Refused(kind) => write!(f, "refused {kind:?}"),
            Self::Handoff => f.write_str("handoff"),
        }
    }
}

/// Records body bytes after the bytes of the same body. Empty bytes add nothing.
pub fn data(seen: &mut Vec<Seen>, bytes: &[u8]) {
    let text = bytes.escape_ascii().to_string();
    match seen.last_mut() {
        _ if bytes.is_empty() => {}
        Some(Seen::Data(earlier)) => earlier.push_str(&text),
        _ => seen.push(Seen::Data(text)),
    }
}

/// The end of a body, with each trailer field line, and whether the body is complete.
pub fn end(outcome: &Outcome) -> (Seen, bool) {
    match outcome {
        Outcome::Complete(trailers) => {
            let mut text = String::from("complete");
            for field in trailers.iter().flat_map(|trailers| trailers.fields()) {
                text.push_str(&format!(
                    " {}: {}",
                    field.name().escape_ascii(),
                    field.value().escape_ascii()
                ));
            }
            (Seen::End(text), true)
        }
        other => (Seen::End(format!("{other:?}")), false),
    }
}

/// The result of a call of the application. A full output queue gives `None`, and the
/// application calls again after a write. Another refusal is part of what the application saw,
/// and the application does not call again.
pub fn call(seen: &mut Vec<Seen>, result: Result<(), Error>) -> Option<()> {
    match result {
        Ok(()) => Some(()),
        Err(error) if error.kind() == Kind::Overload => None,
        Err(error) => {
            seen.push(Seen::Refused(error.kind()));
            Some(())
        }
    }
}
