//! The stream layer of the connection engine: the streams of RFC 9000, sections 2 to 4, their
//! flow control and their limits, the send scheduler, and the unreliable datagrams of RFC 9221.
//!
//! The table holds each stream that is in use. A stream that the peer opened in passing, when it
//! opened a higher one, keeps no state until its first frame. A stream keeps its entry until the
//! application closes it and both directions ended, and only then does the peer get the credit
//! for a new stream. So a peer that opens and resets streams never has more streams in work than
//! the limit of the caller.
//!
//! Received data in order goes up at once, as a view of its received region. The receive credit
//! follows the consumer: the peer gets more credit only for the bytes that the consumer released,
//! at the stream and at the connection, so no second window exists. Data after a gap waits in the
//! [`reassembly`](super::reassembly) store.
//!
//! The application gives the data of a stream in regions, at most [`STREAM_REGIONS_MAX`] at a
//! time. The send scheduler takes the stream with the lowest urgency value first. Inside one
//! urgency, the streams that are not incremental go first, in the order of their identifiers, and
//! the incremental streams share: each fills the rest of one packet, and then the next one sends.
//! A stream with no send credit leaves the scheduler, so a slow consumer of the peer holds back
//! only its own stream.

use core::fmt;
use core::ops::Range;
use std::collections::VecDeque;

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Credit};

use super::frame::{Direction, Frame, STREAMS_MAX};
use super::packet::Side;
use super::params::Parameters;
use super::reassembly::{Reassembly, Refused, Reorder, grow};
use super::recovery::{DataRange, Output, Record};
use super::{ErrorCode, VARINT_MAX, varint_len};
use crate::drive::{Error, Kind};

/// The regions of one stream that wait to go out at one time. Give the next region after
/// [`Event::Sent`].
pub const STREAM_REGIONS_MAX: usize = 4;

/// No stream, no region, and the end of each list.
const NONE: u32 = u32::MAX;

/// The identifier of a stream (RFC 9000, section 2.1). Its two low bits give the end that opened
/// the stream, and whether the stream carries data in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// The stream with the identifier `id`, or `None` when `id` is above 2^62 - 1.
    pub const fn new(id: u64) -> Option<Self> {
        if id <= VARINT_MAX { Some(Self(id)) } else { None }
    }

    /// The identifier as a number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The end that opened the stream.
    pub const fn initiator(self) -> Side {
        if self.0 & 1 == 0 { Side::Client } else { Side::Server }
    }

    /// Whether the stream carries data in both directions, or only from its initiator.
    pub const fn direction(self) -> Direction {
        if self.0 & 2 == 0 {
            Direction::Bidirectional
        } else {
            Direction::Unidirectional
        }
    }

    /// The stream number `index` of `direction` that `initiator` opens.
    const fn of(initiator: Side, direction: Direction, index: u64) -> Self {
        Self((index << 2) | ((direction as u64) << 1) | matches!(initiator, Side::Server) as u64)
    }

    /// The number of the stream among the streams of its initiator and its direction.
    const fn index(self) -> u64 {
        self.0 >> 2
    }

    /// Whether `side` opened the stream.
    const fn opened_by(self, side: Side) -> bool {
        matches!(side, Side::Server) == (self.0 & 1 == 1)
    }
}

/// The send priority of a stream, in the terms of RFC 9218.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    /// The urgency: the stream with the lowest value sends first, and a stream with a higher
    /// value sends only when no stream with a lower one can.
    pub urgency: u8,
    /// Whether the stream shares the connection with the other incremental streams of its
    /// urgency, packet by packet. A stream that is not incremental sends before them, and before
    /// each stream of its urgency with a higher identifier.
    pub incremental: bool,
}

impl Priority {
    /// The priority of a new stream: the middle urgency, and incremental, so each stream gets its
    /// share.
    pub const DEFAULT: Self = Self {
        urgency: 127,
        incremental: true,
    };
}

impl Default for Priority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An event of a connection or of its streams.
#[derive(Clone)]
pub enum Event {
    /// The connection ended for the application, with this outcome: the peer closed it or reset it,
    /// or this end closed it for an error. Each later call of the application refuses. The host
    /// drives the connection until its terminal outcome, which follows three probe timeouts later
    /// (RFC 9000, section 10.2). A connection that ends before its handshake is confirmed, at a
    /// deadline, or by [`Connection::close`](super::Connection::close) gives only its terminal
    /// outcome.
    Closed(Result<(), Error>),
    /// This side flow needs fresh acknowledgement state. The next parent packet probes the path.
    /// Only authenticated side feedback acknowledges its data.
    SideProbe(super::SideFlow),
    /// The next bytes of a stream, in order: a view of the region that they arrived in, with no
    /// copy, or of a page of the engine for bytes that arrived out of order. The view keeps its
    /// whole region, so copy the bytes out, or hold the view only as long as the region can stay.
    /// Give the bytes back to flow control with
    /// [`Connection::release`](super::Connection::release).
    Stream {
        /// The stream.
        stream: StreamId,
        /// The bytes, which can be empty when `end` is set.
        data: Lease,
        /// The peer ended the stream, and these are its last bytes: the data is complete.
        end: bool,
    },
    /// RESET_STREAM: the peer ended its direction of a stream early. The bytes that did not go up
    /// are gone, and the data of the stream is not complete.
    Reset {
        /// The stream.
        stream: StreamId,
        /// The error code of the application protocol.
        code: u64,
    },
    /// STOP_SENDING: the peer reads no more of a stream. The connection reset the direction of
    /// this end with the same code, and dropped the regions that waited.
    Stopped {
        /// The stream.
        stream: StreamId,
        /// The error code of the application protocol.
        code: u64,
    },
    /// Each region that [`Connection::send`](super::Connection::send) gave to the stream is in a
    /// packet. Give the next regions.
    Sent {
        /// The stream.
        stream: StreamId,
    },
    /// The peer acknowledged the stream prefix through `offset` and its end when `end` is set.
    Acknowledged {
        /// The stream.
        stream: StreamId,
        /// The first byte after the acknowledged regions.
        offset: u64,
        /// The peer acknowledged all bytes and the FIN.
        end: bool,
    },
    /// The peer raised its stream limit after [`Connection::open`](super::Connection::open) gave
    /// no stream of this direction.
    Openable(Direction),
    /// An unreliable datagram of the peer (RFC 9221): a view of the region that it arrived in.
    Unreliable(Lease),
}

impl fmt::Debug for Event {
    /// The data is peer bytes, so only its length shows.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream { stream, data, end } => f
                .debug_struct("Stream")
                .field("stream", stream)
                .field("len", &data.initialized())
                .field("end", end)
                .finish(),
            Self::Reset { stream, code } => f
                .debug_struct("Reset")
                .field("stream", stream)
                .field("code", code)
                .finish(),
            Self::Stopped { stream, code } => f
                .debug_struct("Stopped")
                .field("stream", stream)
                .field("code", code)
                .finish(),
            Self::SideProbe(flow) => f.debug_tuple("SideProbe").field(flow).finish(),
            Self::Closed(outcome) => f.debug_tuple("Closed").field(outcome).finish(),
            Self::Sent { stream } => f.debug_struct("Sent").field("stream", stream).finish(),
            Self::Acknowledged { stream, offset, end } => f
                .debug_struct("Acknowledged")
                .field("stream", stream)
                .field("offset", offset)
                .field("end", end)
                .finish(),
            Self::Openable(direction) => f.debug_tuple("Openable").field(direction).finish(),
            Self::Unreliable(data) => f.debug_tuple("Unreliable").field(&data.initialized()).finish(),
        }
    }
}

/// Why the layer did not take a frame of the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stop {
    /// The frame, of this type, breaks a rule: the connection closes with the code.
    Violation(ErrorCode, u64),
    /// The engine has no room for the state or the data of the frame: its packet is not received.
    Refused(Refused),
}

impl From<Refused> for Stop {
    fn from(refused: Refused) -> Self {
        Self::Refused(refused)
    }
}

/// The limits of the caller that the layer keeps.
#[derive(Clone, Copy, Debug)]
pub(super) struct Config {
    /// The receive window of the connection.
    pub(super) data_bytes: u64,
    /// The receive window of each stream.
    pub(super) stream_bytes: u64,
    /// The streams that the peer has open at one time: bidirectional, and unidirectional.
    pub(super) streams: [u64; 2],
    pub(super) reassembly_bytes: u64,
    pub(super) send_bytes: u64,
    /// The bytes of unreliable datagrams that wait to go out, or `None` when they are off.
    pub(super) unreliable_bytes: Option<u64>,
}

/// The receive credit of the connection or of a stream, in absolute offsets.
#[derive(Clone, Copy, Debug)]
struct Window {
    /// The limit that the peer knows: the last one that went out.
    max: u64,
    /// The bytes that the peer used: the sum of the highest offsets, or the highest offset.
    used: u64,
    /// The bytes that the consumer released, or that the engine discarded.
    released: u64,
}

impl Window {
    const fn new(capacity: u64) -> Self {
        Self {
            max: capacity,
            used: 0,
            released: 0,
        }
    }

    /// The limit to send now, for a consumer that admits `capacity` bytes at one time: the
    /// released bytes plus the capacity, once the credit that it adds reaches the credit that the
    /// peer still has. This is the rule of nghttp2 and of the HTTP/2 engine, so no small update
    /// goes out.
    fn due(&self, capacity: u64) -> Option<u64> {
        let target = self.released.saturating_add(capacity).min(VARINT_MAX);
        let free = target.saturating_sub(self.max);
        (free > 0 && free >= self.max.saturating_sub(self.used)).then_some(target)
    }
}

/// The frames of the connection that wait to go out.
mod owed {
    pub(super) const MAX_DATA: u8 = 1;
    /// MAX_STREAMS of the bidirectional streams. The unidirectional ones have the next bit.
    pub(super) const MAX_STREAMS: u8 = 2;
    pub(super) const DATA_BLOCKED: u8 = 8;
    /// STREAMS_BLOCKED of the bidirectional streams. The unidirectional ones have the next bit.
    pub(super) const STREAMS_BLOCKED: u8 = 16;
}

/// The frames of one stream that wait to go out.
mod control {
    pub(super) const RESET: u8 = 1;
    pub(super) const STOP: u8 = 2;
    pub(super) const MAX_STREAM_DATA: u8 = 4;
    pub(super) const BLOCKED: u8 = 8;
    /// A STREAM frame with no data that ends the stream.
    pub(super) const FIN: u8 = 16;
}

/// The events of one stream that wait for the application.
mod notify {
    pub(super) const READABLE: u8 = 1;
    pub(super) const RESET: u8 = 2;
    pub(super) const STOPPED: u8 = 4;
    pub(super) const SENT: u8 = 8;
    pub(super) const ACKNOWLEDGED: u8 = 16;
}

/// The lists that a stream is in.
mod list {
    pub(super) const CONTROL: usize = 0;
    pub(super) const NOTIFY: usize = 1;
    /// The bit of the scheduler in [`Stream::linked`](super::Stream).
    pub(super) const READY: u8 = 4;
}

/// The receive direction of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receiving {
    Open,
    /// Each byte up to the final size went up, the last one with the end.
    Ended,
    /// The peer reset the stream with this code.
    Reset(u64),
    /// The application stopped the stream with this code: each later byte drops.
    Stopped(u64),
}

/// The send direction of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sending {
    Open,
    /// The application gave the end, and it is not in a packet yet.
    Finishing,
    /// The end is in a packet.
    FinSent,
    /// The peer acknowledged the end.
    Finished,
    /// The direction was reset with `code`: by the application, or for a STOP_SENDING frame of
    /// the peer. The peer acknowledges the reset before the stream leaves the table.
    Reset {
        code: u64,
        stopped: bool,
        acknowledged: bool,
    },
}

#[derive(Debug)]
struct Recv {
    window: Window,
    /// The offset of the next byte in order.
    next: u64,
    /// The bytes that went up to the consumer.
    up: u64,
    final_size: Option<u64>,
    state: Receiving,
    reorder: Reorder,
}

#[derive(Debug)]
struct Send {
    /// The bytes that are in packets: the offset of the next byte.
    offset: u64,
    /// The bytes of the regions that wait.
    queued: u64,
    /// The limit of the peer for the stream.
    max: u64,
    /// The limit that the last STREAM_DATA_BLOCKED frame named.
    blocked_at: Option<u64>,
    /// The first and the last region that wait, and the bytes of the first that are in packets.
    head: u32,
    tail: u32,
    /// The first region whose bytes still need an ACK.
    held: u32,
    head_at: usize,
    regions: usize,
    state: Sending,
    priority: Priority,
}

/// One stream of the table, or a free entry.
#[derive(Debug)]
struct Stream {
    id: StreamId,
    recv: Option<Recv>,
    send: Option<Send>,
    /// The entry holds a stream.
    live: bool,
    /// The application is done with the stream.
    closed: bool,
    /// The frames of [`control`] that wait.
    control: u8,
    /// The events of [`notify`] that wait.
    notify: u8,
    /// The lists that hold the stream: one bit for each of [`list`].
    linked: u8,
    /// The next stream in the control list and in the notify list, or the next free entry.
    next: [u32; 2],
    /// The stream before and the stream after in its list of the scheduler.
    ready: [u32; 2],
}

/// A region of a stream that waits to go out, or a free entry.
#[derive(Debug)]
struct Region {
    lease: Option<Lease>,
    offset: u64,
    remaining: u64,
    previous: u32,
    next: u32,
}

/// The streams of one urgency that can send: the ones that are not incremental, in the order of
/// their identifiers, and then the incremental ones, in the order of their turns. Each list has
/// its first and its last stream.
#[derive(Clone, Copy, Debug)]
struct Level {
    urgency: u8,
    lists: [[u32; 2]; 2],
}

/// The streams of one direction that the peer opens.
#[derive(Debug)]
struct Remote {
    /// The number of streams that the peer opened: one more than its highest stream.
    next: u64,
    /// The stream limit that the peer knows.
    limit: u64,
    /// The streams that left the table.
    closed: u64,
    /// The streams below `next` that the peer opened in passing, with no frame yet: sorted
    /// ranges of stream numbers.
    unused: Vec<Range<u64>>,
}

/// The streams of one direction that this end opens.
#[derive(Clone, Copy, Debug)]
struct Local {
    next: u64,
    /// The stream limit of the peer.
    limit: u64,
    /// The limit that the last STREAMS_BLOCKED frame named.
    blocked_at: Option<u64>,
    /// [`Streams::open`] gave no stream: the application waits for [`Event::Openable`].
    wanted: bool,
}

/// The stream layer of one connection.
#[derive(Debug)]
pub(super) struct Streams {
    side: Side,
    config: Config,
    /// The transport parameters of the peer arrived, so streams can open.
    active: bool,
    slots: Vec<Stream>,
    /// The first free entry of `slots`.
    free: u32,
    /// The identifier and the entry of each stream in use, sorted.
    index: VecDeque<(u64, u32)>,
    remote: [Remote; 2],
    local: [Local; 2],
    /// The initial send limit of a stream of the peer, of a bidirectional stream of this end,
    /// and of a unidirectional stream of this end.
    peer_stream_bytes: [u64; 3],
    window: Window,
    /// The limit of the peer for the connection, and the bytes that this end sent.
    send_max: u64,
    send_used: u64,
    /// The limit that the last DATA_BLOCKED frame named.
    blocked_at: Option<u64>,
    /// The frames of [`owed`] that wait.
    owed: u8,
    /// An [`Event::Openable`] waits, for each direction.
    openable: [bool; 2],
    regions: Vec<Region>,
    region_free: u32,
    retained_bytes: u64,
    /// The urgencies that had a stream, sorted.
    levels: Vec<Level>,
    /// The first and the last stream of the control list and of the notify list.
    fifo: [[u32; 2]; 2],
    /// The unreliable datagrams that wait to go out, and their bytes.
    unreliable: VecDeque<Lease>,
    unreliable_bytes: u64,
    pub(super) unreliable_dropped: u64,
    /// The largest DATAGRAM frame that the peer takes.
    peer_unreliable: Option<u64>,
    reassembly: Reassembly,
    /// The charge of each table of the layer.
    credit: Credit,
}

const NOT_OPEN: Error = Error::new(Kind::Misuse, "the QUIC stream is not open");
const NO_ROOM: Error = Error::new(Kind::Overload, "the budget refused the state of a QUIC stream");

/// The entry `slot` as a link of a list.
#[expect(
    clippy::cast_possible_truncation,
    reason = "`create` gives no entry at or above 2^32 - 1, so each entry fits"
)]
const fn link_of(slot: usize) -> u32 {
    slot as u32
}

/// The most bytes of a STREAM or DATAGRAM frame that fit in `space` bytes with their length
/// field, at most `want`.
pub(super) fn fit(space: usize, want: usize) -> usize {
    [1, 2, 4, 8]
        .into_iter()
        .map(|field| (field, want.min(space.saturating_sub(field))))
        .find(|&(field, len)| varint_len(len as u64).is_some_and(|needed| needed <= field))
        .map_or(0, |(_, len)| len)
}

impl Streams {
    pub(super) fn new(side: Side, config: Config, budget: &Budget) -> Self {
        let remote = |streams: u64| Remote {
            next: 0,
            limit: streams,
            closed: 0,
            unused: Vec::new(),
        };
        let local = Local {
            next: 0,
            limit: 0,
            blocked_at: None,
            wanted: false,
        };
        Self {
            side,
            config,
            active: false,
            slots: Vec::new(),
            free: NONE,
            index: VecDeque::new(),
            remote: [remote(config.streams[0]), remote(config.streams[1])],
            local: [local; 2],
            peer_stream_bytes: [0; 3],
            window: Window::new(config.data_bytes),
            send_max: 0,
            send_used: 0,
            blocked_at: None,
            owed: 0,
            openable: [false; 2],
            regions: Vec::new(),
            region_free: NONE,
            retained_bytes: 0,
            levels: Vec::new(),
            fifo: [[NONE; 2]; 2],
            unreliable: VecDeque::new(),
            unreliable_bytes: 0,
            unreliable_dropped: 0,
            peer_unreliable: None,
            reassembly: Reassembly::new(config.reassembly_bytes, budget),
            credit: budget.credit(0),
        }
    }

    /// Takes the limits of the peer from its transport parameters, when the handshake completes.
    pub(super) fn peer(&mut self, parameters: &Parameters) {
        self.active = true;
        self.send_max = parameters.data_bytes_initial;
        self.local[0].limit = parameters.streams_bidi_initial;
        self.local[1].limit = parameters.streams_uni_initial;
        self.peer_stream_bytes = [
            parameters.stream_bytes_bidi_local_initial,
            parameters.stream_bytes_bidi_remote_initial,
            parameters.stream_bytes_uni_initial,
        ];
        self.peer_unreliable = parameters.datagram_bytes_max;
    }

    /// The entry of stream `id`.
    fn find(&self, id: StreamId) -> Option<u32> {
        let at = self.index.binary_search_by_key(&id.0, |&(id, _)| id).ok()?;
        self.index.get(at).map(|&(_, slot)| slot)
    }

    /// The entry of the open stream `id` of the application.
    fn open_slot(&self, id: StreamId) -> Result<usize, Error> {
        if !self.active {
            return Err(Error::new(Kind::Misuse, "the QUIC handshake is not complete"));
        }
        self.find(id)
            .map(|slot| slot as usize)
            .filter(|&slot| !self.slots[slot].closed)
            .ok_or(NOT_OPEN)
    }

    /// Makes the entry of stream `id`. A refusal changes nothing.
    fn create(&mut self, id: StreamId) -> Result<u32, Refused> {
        let local = id.opened_by(self.side);
        let both = id.direction() == Direction::Bidirectional;
        let index = &mut self.index;
        grow(
            (index.len(), index.capacity(), size_of::<(u64, u32)>()),
            &mut self.credit,
            |more| index.try_reserve_exact(more).is_ok(),
        )?;
        if self.free == NONE {
            let slots = &mut self.slots;
            grow(
                (slots.len(), slots.capacity(), size_of::<Stream>()),
                &mut self.credit,
                |more| slots.try_reserve_exact(more).is_ok(),
            )?;
        }
        let recv = (both || !local).then(|| Recv {
            window: Window::new(self.config.stream_bytes),
            next: 0,
            up: 0,
            final_size: None,
            state: Receiving::Open,
            reorder: Reorder::default(),
        });
        let send = (both || local).then(|| Send {
            offset: 0,
            queued: 0,
            max: self.peer_stream_bytes[if !both {
                2
            } else if local {
                1
            } else {
                0
            }],
            blocked_at: None,
            head: NONE,
            tail: NONE,
            held: NONE,
            head_at: 0,
            regions: 0,
            state: Sending::Open,
            priority: Priority::DEFAULT,
        });
        let stream = Stream {
            id,
            recv,
            send,
            live: true,
            closed: false,
            control: 0,
            notify: 0,
            linked: 0,
            next: [NONE; 2],
            ready: [NONE; 2],
        };
        let slot = if let Some(free) = self.slots.get_mut(self.free as usize) {
            let slot = self.free;
            self.free = free.next[0];
            *free = stream;
            slot
        } else {
            self.slots.push(stream);
            u32::try_from(self.slots.len() - 1).map_err(|_| Refused::Bound)?
        };
        let at = self.index.partition_point(|&(other, _)| other < id.0);
        self.index.insert(at, (id.0, slot));
        Ok(slot)
    }

    /// The entry of the stream `id` that a frame of type `frame` of the peer names, which it
    /// makes for a stream that the frame opens. `None` for a stream that ended and left the table:
    /// the frame then changes nothing.
    fn named(&mut self, id: StreamId, frame: u64) -> Result<Option<usize>, Stop> {
        let direction = id.direction() as usize;
        if id.opened_by(self.side) {
            // The peer cannot name a stream of this end that this end did not open.
            if id.index() >= self.local[direction].next {
                return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, frame));
            }
            return Ok(self.find(id).map(|slot| slot as usize));
        }
        if id.index() >= self.remote[direction].limit {
            return Err(Stop::Violation(ErrorCode::STREAM_LIMIT_ERROR, frame));
        }
        if let Some(slot) = self.find(id) {
            return Ok(Some(slot as usize));
        }
        let (index, next) = (id.index(), self.remote[direction].next);
        let unused = &mut self.remote[direction].unused;
        let at = unused.partition_point(|range| range.end <= index);
        let passed = unused.get(at).filter(|range| range.start <= index).cloned();
        if index < next && passed.is_none() {
            return Ok(None);
        }
        // The stream opens, and it can leave one more range of streams that have no frame yet.
        grow(
            (unused.len(), unused.capacity(), size_of::<Range<u64>>()),
            &mut self.credit,
            |more| unused.try_reserve_exact(more).is_ok(),
        )?;
        let slot = self.create(id)?;
        let remote = &mut self.remote[direction];
        match passed {
            Some(range) => {
                let parts = [range.start..index, index + 1..range.end];
                remote
                    .unused
                    .splice(at..=at, parts.into_iter().filter(|part| !part.is_empty()));
            }
            // RFC 9000, section 3.2: a stream opens each stream below it of its type.
            None => {
                if index > next {
                    remote.unused.push(next..index);
                }
                remote.next = index + 1;
            }
        }
        Ok(Some(slot as usize))
    }

    /// Puts stream `slot` at the end of the list `list` when it is not in it.
    fn push(&mut self, which: usize, slot: usize) {
        let stream = &mut self.slots[slot];
        if stream.linked & (1 << which) != 0 {
            return;
        }
        stream.linked |= 1 << which;
        stream.next[which] = NONE;
        let slot = link_of(slot);
        match self.fifo[which][1] {
            NONE => self.fifo[which][0] = slot,
            tail => self.slots[tail as usize].next[which] = slot,
        }
        self.fifo[which][1] = slot;
    }

    /// Takes the first stream out of the list `which`.
    fn pop(&mut self, which: usize) {
        let head = self.fifo[which][0] as usize;
        let Some(stream) = self.slots.get_mut(head) else {
            return;
        };
        stream.linked &= !(1 << which);
        self.fifo[which][0] = stream.next[which];
        if self.fifo[which][0] == NONE {
            self.fifo[which][1] = NONE;
        }
    }

    /// A frame of stream `slot` waits to go out.
    fn owe(&mut self, slot: usize, frame: u8) {
        self.slots[slot].control |= frame;
        self.push(list::CONTROL, slot);
    }

    /// An event of stream `slot` waits, unless the application is done with the stream.
    fn tell(&mut self, slot: usize, event: u8) {
        if !self.slots[slot].closed {
            self.slots[slot].notify |= event;
            self.push(list::NOTIFY, slot);
        }
    }

    /// The place of `urgency` in the levels, which it makes for a new urgency.
    fn level(&mut self, urgency: u8) -> Result<usize, Refused> {
        match self.levels.binary_search_by_key(&urgency, |level| level.urgency) {
            Ok(at) => Ok(at),
            Err(at) => {
                let levels = &mut self.levels;
                grow(
                    (levels.len(), levels.capacity(), size_of::<Level>()),
                    &mut self.credit,
                    |more| levels.try_reserve_exact(more).is_ok(),
                )?;
                self.levels.insert(
                    at,
                    Level {
                        urgency,
                        lists: [[NONE; 2]; 2],
                    },
                );
                Ok(at)
            }
        }
    }

    /// The level and the list of the scheduler for stream `slot`.
    fn place(&self, slot: usize) -> Option<(usize, usize)> {
        let priority = self.slots[slot].send.as_ref()?.priority;
        let level = self
            .levels
            .binary_search_by_key(&priority.urgency, |level| level.urgency)
            .ok()?;
        Some((level, usize::from(priority.incremental)))
    }

    /// Puts stream `slot` into the scheduler: a stream that is not incremental at its place in
    /// the order of the identifiers, and an incremental one at the end of its list.
    fn link(&mut self, slot: usize) {
        if self.slots[slot].linked & list::READY != 0 {
            return;
        }
        let Some((level, class)) = self.place(slot) else {
            return;
        };
        let [head, tail] = self.levels[level].lists[class];
        let id = self.slots[slot].id;
        let mut before = tail;
        if class == 0 {
            while let Some(other) = self.slots.get(before as usize)
                && other.id > id
            {
                before = other.ready[0];
            }
        }
        let after = match self.slots.get(before as usize) {
            Some(other) => other.ready[1],
            None => head,
        };
        let stream = &mut self.slots[slot];
        stream.ready = [before, after];
        stream.linked |= list::READY;
        let slot = link_of(slot);
        match self.slots.get_mut(before as usize) {
            Some(other) => other.ready[1] = slot,
            None => self.levels[level].lists[class][0] = slot,
        }
        match self.slots.get_mut(after as usize) {
            Some(other) => other.ready[0] = slot,
            None => self.levels[level].lists[class][1] = slot,
        }
    }

    /// Takes stream `slot` out of the scheduler.
    fn unlink(&mut self, slot: usize) {
        if self.slots[slot].linked & list::READY == 0 {
            return;
        }
        let Some((level, class)) = self.place(slot) else {
            return;
        };
        let stream = &mut self.slots[slot];
        stream.linked &= !list::READY;
        let [before, after] = stream.ready;
        match self.slots.get_mut(before as usize) {
            Some(other) => other.ready[1] = after,
            None => self.levels[level].lists[class][0] = after,
        }
        match self.slots.get_mut(after as usize) {
            Some(other) => other.ready[0] = before,
            None => self.levels[level].lists[class][1] = before,
        }
    }

    /// The stream that sends next.
    fn first(&self) -> Option<usize> {
        self.levels
            .iter()
            .flat_map(|level| level.lists)
            .map(|[head, _]| head)
            .find(|&head| head != NONE)
            .map(|head| head as usize)
    }

    /// Drops the regions of stream `slot` that wait.
    fn drop_regions(&mut self, slot: usize) {
        self.unlink(slot);
        let Some(send) = &mut self.slots[slot].send else {
            return;
        };
        let mut region = core::mem::replace(&mut send.held, NONE);
        send.head = NONE;
        (send.tail, send.head_at, send.regions, send.queued) = (NONE, 0, 0, 0);
        while let Some(entry) = self.regions.get_mut(region as usize) {
            self.retained_bytes -= entry.lease.take().map_or(0, |lease| lease.initialized() as u64);
            let next = core::mem::replace(&mut entry.next, self.region_free);
            self.region_free = region;
            region = next;
        }
    }

    /// Frees the entry of stream `slot` when the application closed it, both directions ended for
    /// the peer too, and nothing of it waits. The peer then gets the credit for one more stream.
    fn settle(&mut self, slot: usize) {
        let stream = &self.slots[slot];
        let received = stream.recv.as_ref().is_none_or(|recv| match recv.state {
            Receiving::Open => false,
            // The final size closes the count of the stream for the window of the connection.
            Receiving::Stopped(_) => recv.final_size.is_some(),
            Receiving::Ended | Receiving::Reset(_) => true,
        });
        let sent = stream.send.as_ref().is_none_or(|send| {
            send.held == NONE
                && matches!(
                    send.state,
                    Sending::Finished | Sending::Reset { acknowledged: true, .. }
                )
        });
        if !(stream.live && stream.closed && received && sent && stream.linked == 0 && stream.control == 0) {
            return;
        }
        let id = stream.id;
        if let Some(recv) = &mut self.slots[slot].recv {
            self.reassembly.clear(&mut recv.reorder);
        }
        if let Ok(at) = self.index.binary_search_by_key(&id.0, |&(id, _)| id) {
            self.index.remove(at);
        }
        let stream = &mut self.slots[slot];
        (stream.live, stream.recv, stream.send) = (false, None, None);
        stream.next[0] = core::mem::replace(&mut self.free, link_of(slot));
        if !id.opened_by(self.side) {
            let direction = id.direction() as usize;
            self.remote[direction].closed += 1;
            self.streams_due(direction);
        }
    }

    /// Owes a MAX_STREAMS frame of `direction` when its credit is due.
    fn streams_due(&mut self, direction: usize) {
        let remote = &self.remote[direction];
        let window = Window {
            max: remote.limit,
            used: remote.next,
            released: remote.closed,
        };
        if window.due(self.config.streams[direction]).is_some() {
            self.owed |= owed::MAX_STREAMS << direction;
        }
    }

    /// Counts `bytes` bytes that the consumer of the connection released, or that the engine
    /// discarded, and owes a MAX_DATA frame when its credit is due.
    fn released(&mut self, bytes: u64) {
        self.window.released += bytes;
        if self.window.due(self.config.data_bytes).is_some() {
            self.owed |= owed::MAX_DATA;
        }
    }

    /// Checks a frame of type `frame` that moves the highest offset of stream `slot` to `end`,
    /// its final size with `last`, and gives the new bytes that it uses of the connection window
    /// (RFC 9000, sections 4.1 and 4.5).
    fn admit(&self, slot: usize, end: u64, last: bool, frame: u64) -> Result<u64, Stop> {
        let Some(recv) = &self.slots[slot].recv else {
            return Ok(0);
        };
        let final_size = match recv.final_size {
            Some(size) => end > size || (last && end != size),
            None => last && end < recv.window.used,
        };
        if final_size {
            return Err(Stop::Violation(ErrorCode::FINAL_SIZE_ERROR, frame));
        }
        let grown = end.saturating_sub(recv.window.used);
        if end > recv.window.max || grown > self.window.max.saturating_sub(self.window.used) {
            return Err(Stop::Violation(ErrorCode::FLOW_CONTROL_ERROR, frame));
        }
        Ok(grown)
    }

    /// A STREAM frame: the bytes at `range` of `payload` are the data of stream `id` at `offset`.
    pub(super) fn stream_in(
        &mut self,
        id: u64,
        (offset, fin): (u64, bool),
        range: Range<usize>,
        payload: &Lease,
    ) -> Result<Option<Event>, Stop> {
        const FRAME: u64 = 0x08;
        let id = StreamId(id);
        if id.direction() == Direction::Unidirectional && id.opened_by(self.side) {
            return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, FRAME));
        }
        let Some(slot) = self.named(id, FRAME)? else {
            return Ok(None);
        };
        let end = offset + range.len() as u64;
        let grown = self.admit(slot, end, fin, FRAME)?;
        let Some(recv) = &mut self.slots[slot].recv else {
            return Ok(None);
        };
        let open = recv.state == Receiving::Open;
        if open && offset > recv.next && !range.is_empty() {
            let data = payload.bytes().get(range.clone()).unwrap_or_default();
            self.reassembly.insert(&mut recv.reorder, offset, data)?;
        }
        recv.window.used += grown;
        self.window.used += grown;
        if fin {
            recv.final_size = Some(end);
        }
        if !open {
            // The bytes drop, so the peer gets their credit of the connection back.
            let stopped = matches!(recv.state, Receiving::Stopped(_));
            self.released(grown);
            if stopped {
                self.settle(slot);
            }
            return Ok(None);
        }
        let fresh = end.saturating_sub(recv.next);
        let ends = recv.final_size == Some(end.max(recv.next));
        if offset > recv.next || (fresh == 0 && !ends) {
            return Ok(None);
        }
        // The bytes are in order: the ones that did not go up before go up as a view.
        let start = range.end - usize::try_from(fresh).unwrap_or(usize::MAX).min(range.len());
        let Some(data) = payload.view(start..range.end) else {
            return Ok(None);
        };
        recv.next += fresh;
        recv.up += fresh;
        let waits = self.reassembly.ready(&mut recv.reorder, recv.next);
        if ends {
            recv.state = Receiving::Ended;
        }
        if waits {
            self.tell(slot, notify::READABLE);
        }
        Ok(Some(Event::Stream {
            stream: id,
            data,
            end: ends,
        }))
    }

    /// A RESET_STREAM frame.
    pub(super) fn reset_in(&mut self, id: u64, code: u64, final_size: u64) -> Result<(), Stop> {
        const FRAME: u64 = 0x04;
        let id = StreamId(id);
        if id.direction() == Direction::Unidirectional && id.opened_by(self.side) {
            return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, FRAME));
        }
        let Some(slot) = self.named(id, FRAME)? else {
            return Ok(());
        };
        let grown = self.admit(slot, final_size, true, FRAME)?;
        let Some(recv) = &mut self.slots[slot].recv else {
            return Ok(());
        };
        recv.window.used += grown;
        self.window.used += grown;
        recv.final_size = Some(final_size);
        match recv.state {
            // Each byte went up, or the stream was reset before: the frame changes nothing.
            Receiving::Ended | Receiving::Reset(_) => {}
            Receiving::Stopped(_) => {
                self.released(grown);
                self.settle(slot);
            }
            Receiving::Open => {
                // The bytes that did not go up are gone, and so are the gaps before them.
                let dropped = final_size - recv.next;
                recv.state = Receiving::Reset(code);
                self.reassembly.clear(&mut recv.reorder);
                self.slots[slot].notify &= !notify::READABLE;
                self.released(dropped);
                self.tell(slot, notify::RESET);
            }
        }
        Ok(())
    }

    /// A STOP_SENDING frame: this end resets its direction of the stream with the code of the
    /// peer (RFC 9000, section 3.5).
    pub(super) fn stop_in(&mut self, id: u64, code: u64) -> Result<(), Stop> {
        const FRAME: u64 = 0x05;
        let id = StreamId(id);
        if id.direction() == Direction::Unidirectional && !id.opened_by(self.side) {
            return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, FRAME));
        }
        let Some(slot) = self.named(id, FRAME)? else {
            return Ok(());
        };
        if self.abandon(slot, code, true) {
            self.tell(slot, notify::STOPPED);
        }
        Ok(())
    }

    /// Resets the send direction of stream `slot` with `code`, and gives whether it was not reset
    /// before.
    fn abandon(&mut self, slot: usize, code: u64, stopped: bool) -> bool {
        let Some(send) = &mut self.slots[slot].send else {
            return false;
        };
        if matches!(send.state, Sending::Reset { .. }) {
            return false;
        }
        send.state = Sending::Reset {
            code,
            stopped,
            acknowledged: false,
        };
        self.drop_regions(slot);
        let stream = &mut self.slots[slot];
        stream.control &= !(control::FIN | control::BLOCKED);
        stream.notify &= !(notify::SENT | notify::ACKNOWLEDGED);
        self.owe(slot, control::RESET);
        true
    }

    /// A MAX_DATA frame.
    pub(super) fn max_data_in(&mut self, max: u64) {
        self.send_max = self.send_max.max(max);
    }

    /// A MAX_STREAM_DATA frame.
    pub(super) fn max_stream_data_in(&mut self, id: u64, max: u64) -> Result<(), Stop> {
        const FRAME: u64 = 0x11;
        let id = StreamId(id);
        if id.direction() == Direction::Unidirectional && !id.opened_by(self.side) {
            return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, FRAME));
        }
        let Some(slot) = self.named(id, FRAME)? else {
            return Ok(());
        };
        if let Some(send) = &mut self.slots[slot].send
            && max > send.max
        {
            send.max = max;
            if send.queued > 0 {
                self.link(slot);
            }
        }
        Ok(())
    }

    /// A MAX_STREAMS frame.
    pub(super) fn max_streams_in(&mut self, direction: Direction, max: u64) {
        let local = &mut self.local[direction as usize];
        if max > local.limit {
            local.limit = max;
            self.openable[direction as usize] |= core::mem::take(&mut local.wanted);
        }
    }

    /// A STREAM_DATA_BLOCKED frame: it only names its stream, which it can open.
    pub(super) fn blocked_in(&mut self, id: u64) -> Result<(), Stop> {
        const FRAME: u64 = 0x15;
        let id = StreamId(id);
        if id.direction() == Direction::Unidirectional && id.opened_by(self.side) {
            return Err(Stop::Violation(ErrorCode::STREAM_STATE_ERROR, FRAME));
        }
        self.named(id, FRAME).map(drop)
    }

    /// A DATAGRAM frame of `frame_bytes` bytes, whose data is at `range` of `payload`.
    pub(super) fn unreliable_in(
        &self,
        frame_bytes: usize,
        range: Range<usize>,
        payload: &Lease,
    ) -> Result<Option<Event>, Stop> {
        // RFC 9221, section 3: a frame that this end did not offer to take, or a larger one.
        if self.config.unreliable_bytes.is_none() || frame_bytes as u64 > UNRELIABLE_FRAME_BYTES_MAX {
            return Err(Stop::Violation(ErrorCode::PROTOCOL_VIOLATION, 0x30));
        }
        Ok(payload.view(range).map(Event::Unreliable))
    }

    /// The next event that waits.
    pub(super) fn event(&mut self) -> Option<Event> {
        for (direction, name) in [Direction::Bidirectional, Direction::Unidirectional]
            .into_iter()
            .enumerate()
        {
            if core::mem::take(&mut self.openable[direction]) {
                return Some(Event::Openable(name));
            }
        }
        loop {
            let slot = self.fifo[list::NOTIFY][0] as usize;
            let stream = self.slots.get_mut(slot)?;
            let id = stream.id;
            if stream.notify & notify::READABLE != 0
                && let Some(recv) = &mut stream.recv
            {
                if let Some(data) = self.reassembly.take(&mut recv.reorder, recv.next) {
                    let len = data.initialized() as u64;
                    recv.next += len;
                    recv.up += len;
                    let end = recv.final_size == Some(recv.next);
                    if end {
                        recv.state = Receiving::Ended;
                    }
                    if !self.reassembly.ready(&mut recv.reorder, recv.next) {
                        stream.notify &= !notify::READABLE;
                    }
                    return Some(Event::Stream { stream: id, data, end });
                }
                stream.notify &= !notify::READABLE;
            }
            if stream.notify & notify::RESET != 0
                && let Some(Receiving::Reset(code)) = stream.recv.as_ref().map(|recv| recv.state)
            {
                stream.notify &= !notify::RESET;
                return Some(Event::Reset { stream: id, code });
            }
            if stream.notify & notify::STOPPED != 0
                && let Some(Sending::Reset { code, .. }) = stream.send.as_ref().map(|send| send.state)
            {
                stream.notify &= !notify::STOPPED;
                return Some(Event::Stopped { stream: id, code });
            }
            if stream.notify & notify::SENT != 0 {
                stream.notify &= !notify::SENT;
                return Some(Event::Sent { stream: id });
            }
            if stream.notify & notify::ACKNOWLEDGED != 0
                && let Some(send) = &stream.send
            {
                stream.notify &= !notify::ACKNOWLEDGED;
                let offset = self.regions.get(send.held as usize).map_or(send.offset, |r| r.offset);
                return Some(Event::Acknowledged {
                    stream: id,
                    offset,
                    end: send.held == NONE && send.state == Sending::Finished,
                });
            }
            stream.notify = 0;
            self.pop(list::NOTIFY);
            self.settle(slot);
        }
    }

    /// Opens the next stream of `direction` of this end, or gives `None` when the limit of the
    /// peer allows no new stream: [`Event::Openable`] then tells when it does.
    pub(super) fn open(&mut self, direction: Direction) -> Result<Option<StreamId>, Error> {
        if !self.active {
            return Err(Error::new(Kind::Misuse, "the QUIC handshake is not complete"));
        }
        let local = &mut self.local[direction as usize];
        if local.next >= local.limit {
            local.wanted = true;
            if local.blocked_at.replace(local.limit) != Some(local.limit) {
                self.owed |= owed::STREAMS_BLOCKED << direction as usize;
            }
            return Ok(None);
        }
        let id = StreamId::of(self.side, direction, local.next);
        self.create(id).map_err(|_| NO_ROOM)?;
        self.local[direction as usize].next += 1;
        Ok(Some(id))
    }

    /// Gives `data` to stream `id`, after the regions that wait, and its end with `end`.
    pub(super) fn send(&mut self, id: StreamId, data: Lease, end: bool) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        let Some(send) = &self.slots[slot].send else {
            return Err(Error::new(Kind::Misuse, "the QUIC stream only receives"));
        };
        let len = data.initialized();
        match send.state {
            Sending::Open => {}
            Sending::Reset { stopped: true, .. } => {
                return Err(Error::new(Kind::Cancelled, "the peer stopped the QUIC stream"));
            }
            _ => return Err(Error::new(Kind::Misuse, "the QUIC stream sent its end")),
        }
        if len == 0 && !end {
            return Err(Error::new(Kind::Misuse, "a region has bytes or ends the stream"));
        }
        if len > 0 && send.regions == STREAM_REGIONS_MAX {
            return Err(Error::new(
                Kind::Misuse,
                "the regions of the stream wait: give the next one after its Event::Sent",
            ));
        }
        if (send.offset + send.queued).saturating_add(len as u64) > VARINT_MAX {
            return Err(Error::new(Kind::Misuse, "a QUIC stream carries at most 2^62 - 1 bytes"));
        }
        if len as u64 > self.config.send_bytes - self.retained_bytes {
            return Err(Error::new(
                Kind::Overload,
                "the QUIC stream regions reached the send byte limit",
            ));
        }
        let offset = send.offset + send.queued;
        let previous = send.tail;
        let urgency = send.priority.urgency;
        if len > 0 {
            self.level(urgency).map_err(|_| NO_ROOM)?;
            if self.region_free == NONE {
                let regions = &mut self.regions;
                grow(
                    (regions.len(), regions.capacity(), size_of::<Region>()),
                    &mut self.credit,
                    |more| regions.try_reserve_exact(more).is_ok(),
                )
                .map_err(|_| NO_ROOM)?;
            }
            let region = Region {
                lease: Some(data),
                offset,
                remaining: len as u64,
                previous,
                next: NONE,
            };
            let at = if let Some(free) = self.regions.get_mut(self.region_free as usize) {
                let at = self.region_free;
                self.region_free = free.next;
                *free = region;
                at
            } else {
                self.regions.push(region);
                u32::try_from(self.regions.len() - 1).map_err(|_| NO_ROOM)?
            };
            let tail = self.slots[slot].send.as_ref().map_or(NONE, |send| send.tail);
            if let Some(tail) = self.regions.get_mut(tail as usize) {
                tail.next = at;
            }
            if let Some(send) = &mut self.slots[slot].send {
                if send.head == NONE {
                    send.head = at;
                }
                if send.held == NONE {
                    send.held = at;
                }
                self.retained_bytes += len as u64;
                send.tail = at;
                send.regions += 1;
                send.queued += len as u64;
            }
        }
        let Some(send) = &mut self.slots[slot].send else {
            return Ok(());
        };
        if end {
            send.state = Sending::Finishing;
        }
        if send.queued == 0 {
            // An end with no byte goes out as a frame of its own, which needs no credit.
            self.owe(slot, control::FIN);
        } else if send.offset < send.max {
            self.link(slot);
        } else if send.blocked_at.replace(send.max) != Some(send.max) {
            self.owe(slot, control::BLOCKED);
        }
        Ok(())
    }

    /// Resets the send direction of stream `id` with `code`: the regions that wait drop.
    pub(super) fn reset(&mut self, id: StreamId, code: u64) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        if code > VARINT_MAX {
            return Err(Error::new(Kind::Misuse, "an error code is at most 2^62 - 1"));
        }
        match self.slots[slot].send.as_ref().map(|send| send.state) {
            None => Err(Error::new(Kind::Misuse, "the QUIC stream only receives")),
            Some(Sending::Reset { .. }) => Err(Error::new(Kind::Misuse, "the QUIC stream was reset before")),
            Some(_) => {
                self.abandon(slot, code, false);
                Ok(())
            }
        }
    }

    /// Stops the receive direction of stream `id` with `code`: the bytes that did not go up drop,
    /// and so does each later byte.
    pub(super) fn stop(&mut self, id: StreamId, code: u64) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        if code > VARINT_MAX {
            return Err(Error::new(Kind::Misuse, "an error code is at most 2^62 - 1"));
        }
        let stream = &mut self.slots[slot];
        let Some(recv) = &mut stream.recv else {
            return Err(Error::new(Kind::Misuse, "the QUIC stream only sends"));
        };
        if recv.state != Receiving::Open {
            return Err(Error::new(Kind::Misuse, "the QUIC stream ended its data before"));
        }
        let dropped = recv.window.used - recv.next;
        recv.state = Receiving::Stopped(code);
        self.reassembly.clear(&mut recv.reorder);
        stream.notify &= !notify::READABLE;
        self.released(dropped);
        self.owe(slot, control::STOP);
        Ok(())
    }

    /// Counts `bytes` bytes of stream `id` that the consumer is done with, and owes the frames
    /// that give their credit back to the peer when it is due.
    pub(super) fn release(&mut self, id: StreamId, bytes: u64) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        let capacity = self.config.stream_bytes;
        let Some(recv) = &mut self.slots[slot].recv else {
            return Err(Error::new(Kind::Misuse, "the QUIC stream only sends"));
        };
        if bytes > recv.up - recv.window.released {
            return Err(Error::new(
                Kind::Misuse,
                "the consumer released more bytes than it holds",
            ));
        }
        recv.window.released += bytes;
        // A stream whose final size is known needs no credit.
        let due = recv.state == Receiving::Open && recv.final_size.is_none() && recv.window.due(capacity).is_some();
        self.released(bytes);
        if due {
            self.owe(slot, control::MAX_STREAM_DATA);
        }
        Ok(())
    }

    /// Ends the use of stream `id` by the application, after each of its directions ended, was
    /// reset, or was stopped. The bytes that the consumer still holds count as released.
    pub(super) fn close(&mut self, id: StreamId) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        let stream = &mut self.slots[slot];
        let receiving = stream.recv.as_ref().is_some_and(|recv| recv.state == Receiving::Open);
        let sending = stream.send.as_ref().is_some_and(|send| send.state == Sending::Open);
        if receiving || sending {
            return Err(Error::new(
                Kind::Misuse,
                "a direction of the QUIC stream is open: end, reset, or stop it first",
            ));
        }
        stream.closed = true;
        stream.notify = 0;
        let held = stream.recv.as_mut().map_or(0, |recv| {
            let held = recv.up - recv.window.released;
            recv.window.released = recv.up;
            held
        });
        self.released(held);
        self.settle(slot);
        Ok(())
    }

    /// Sets the send priority of stream `id`.
    pub(super) fn set_priority(&mut self, id: StreamId, priority: Priority) -> Result<(), Error> {
        let slot = self.open_slot(id)?;
        if self.slots[slot].send.is_none() {
            return Err(Error::new(Kind::Misuse, "the QUIC stream only receives"));
        }
        self.level(priority.urgency).map_err(|_| NO_ROOM)?;
        let linked = self.slots[slot].linked & list::READY != 0;
        self.unlink(slot);
        if let Some(send) = &mut self.slots[slot].send {
            send.priority = priority;
        }
        if linked {
            self.link(slot);
        }
        Ok(())
    }

    /// The largest unreliable datagram that goes out now, in a packet with `room` bytes for its
    /// frames, or `None` when the peer takes none or this end has them off.
    pub(super) fn unreliable_room(&self, room: usize) -> Option<usize> {
        let peer = usize::try_from(self.peer_unreliable?).unwrap_or(usize::MAX);
        self.config.unreliable_bytes?;
        Some(fit(room.min(peer).saturating_sub(1), usize::MAX))
    }

    /// Queues `data` as one unreliable datagram, for a packet with `room` bytes for its frames.
    pub(super) fn resize_unreliable(&mut self, room: usize) {
        let Some(max) = self.unreliable_room(room) else { return };
        self.unreliable.retain(|data| {
            if data.initialized() <= max {
                return true;
            }
            self.unreliable_bytes -= data.initialized() as u64;
            self.unreliable_dropped = self.unreliable_dropped.saturating_add(1);
            false
        });
    }

    pub(super) fn unreliable(&mut self, data: Lease, room: usize) -> Result<(), Error> {
        if !self.active {
            return Err(Error::new(Kind::Misuse, "the QUIC handshake is not complete"));
        }
        let (Some(bound), Some(largest)) = (self.config.unreliable_bytes, self.unreliable_room(room)) else {
            return Err(Error::new(
                Kind::Unsupported,
                "the peer or this end takes no unreliable datagram",
            ));
        };
        let len = data.initialized();
        if len > largest {
            return Err(Error::new(
                Kind::Overload,
                "the unreliable datagram is larger than the peer and the path take",
            ));
        }
        if self.unreliable_bytes + len as u64 > bound {
            return Err(Error::new(Kind::Overload, "the queue of unreliable datagrams is full"));
        }
        let queue = &mut self.unreliable;
        grow(
            (queue.len(), queue.capacity(), size_of::<Lease>()),
            &mut self.credit,
            |more| queue.try_reserve_exact(more).is_ok(),
        )
        .map_err(|_| NO_ROOM)?;
        self.unreliable_bytes += len as u64;
        self.unreliable.push_back(data);
        Ok(())
    }

    /// The original bytes of a lost STREAM frame. A reset releases its regions and cancels the resend.
    pub(super) fn retained(&self, id: StreamId, region: u32, offset: u64, len: usize) -> Option<&[u8]> {
        let send = self.slots[self.find(id)? as usize].send.as_ref()?;
        if matches!(send.state, Sending::Reset { .. }) {
            return None;
        }
        let entry = self.regions.get(region as usize)?;
        let start = usize::try_from(offset.checked_sub(entry.offset)?).ok()?;
        entry.lease.as_ref()?.bytes().get(start..start.checked_add(len)?)
    }

    /// Gives back a region as soon as its last outstanding byte receives an ACK.
    pub(super) fn acknowledged(&mut self, record: Record) {
        let (id, region, len, fin) = match record {
            Record::Range(DataRange::Stream {
                id, region, len, fin, ..
            }) => (id, region, len, fin),
            Record::Control(id, control::FIN) => (id, NONE, 0, true),
            Record::Control(id, control::RESET) => {
                if let Some(slot) = self.find(id) {
                    let stream = &mut self.slots[slot as usize];
                    if let Some(Sending::Reset { acknowledged, .. }) = stream.send.as_mut().map(|s| &mut s.state) {
                        *acknowledged = true;
                    }
                    self.settle(slot as usize);
                }
                return;
            }
            _ => return,
        };
        let Some(slot) = self.find(id).map(|slot| slot as usize) else {
            return;
        };
        let stream = &mut self.slots[slot];
        let Some(send) = &mut stream.send else { return };
        if matches!(send.state, Sending::Reset { .. }) {
            return;
        }
        if fin {
            send.state = Sending::Finished;
        }
        let mut progress = false;
        if let Some(entry) = self.regions.get_mut(region as usize) {
            entry.remaining -= len as u64;
            if entry.remaining == 0 {
                self.retained_bytes -= entry.lease.take().expect("a live region owns its bytes").initialized() as u64;
                let previous = entry.previous;
                let next = core::mem::replace(&mut entry.next, self.region_free);
                self.region_free = region;
                if let Some(before) = self.regions.get_mut(previous as usize) {
                    before.next = next;
                } else {
                    send.held = next;
                    progress = true;
                }
                if let Some(after) = self.regions.get_mut(next as usize) {
                    after.previous = previous;
                } else {
                    send.tail = previous;
                }
            }
        }
        if !stream.closed && (progress || (fin && send.held == NONE)) {
            self.tell(slot, notify::ACKNOWLEDGED);
        }
        self.settle(slot);
    }

    /// Rebuilds a lost control frame from the current limits and stream state.
    pub(super) fn lost_control(&mut self, record: Record) {
        match record {
            Record::Limit(bit) => self.owed |= bit,
            Record::Control(id, bit) => {
                if let Some(slot) = self.find(id) {
                    self.owe(slot as usize, bit);
                }
            }
            _ => {}
        }
    }

    /// Whether a parent control frame has priority over side data.
    pub(super) fn control_pending(&self) -> bool {
        self.owed != 0 || self.fifo[list::CONTROL][0] != NONE
    }

    pub(super) fn pending(&self) -> bool {
        self.control_pending()
            || !self.unreliable.is_empty()
            || (self.send_used < self.send_max && self.first().is_some())
    }

    /// Writes the frames that wait into the packet of `builder`, as many as fit: the limits of
    /// the connection, the frames of each stream, the unreliable datagrams, and then the data of
    /// the streams in the order of the scheduler. Gives whether it wrote a frame.
    pub(super) fn write(&mut self, builder: &mut Output<'_, '_>) -> bool {
        let before = builder.room();
        if self.write_limits(builder) && self.write_control(builder) {
            while let Some(data) = self.unreliable.front() {
                if builder.builder.frame(&Frame::Datagram { data: data.bytes() }).is_err() {
                    break;
                }
                self.unreliable_bytes -= data.initialized() as u64;
                self.unreliable.pop_front();
            }
            self.write_data(builder);
        }
        builder.room() < before
    }

    /// Writes the frames of the connection that wait. Gives `false` when the packet is full.
    fn write_limits(&mut self, builder: &mut Output<'_, '_>) -> bool {
        if self.owed & owed::MAX_DATA != 0 {
            let max = self.window.due(self.config.data_bytes).unwrap_or(self.window.max);
            if builder
                .track(&Frame::MaxData { max }, Record::Limit(owed::MAX_DATA))
                .is_err()
            {
                return false;
            }
            self.window.max = max;
            self.owed &= !owed::MAX_DATA;
        }
        if self.owed & owed::DATA_BLOCKED != 0 {
            if builder
                .track(
                    &Frame::DataBlocked { limit: self.send_max },
                    Record::Limit(owed::DATA_BLOCKED),
                )
                .is_err()
            {
                return false;
            }
            self.owed &= !owed::DATA_BLOCKED;
        }
        for (at, direction) in [Direction::Bidirectional, Direction::Unidirectional]
            .into_iter()
            .enumerate()
        {
            if self.owed & (owed::MAX_STREAMS << at) != 0 {
                let remote = &mut self.remote[at];
                let max = remote.closed.saturating_add(self.config.streams[at]).min(STREAMS_MAX);
                if builder
                    .track(
                        &Frame::MaxStreams { direction, max },
                        Record::Limit(owed::MAX_STREAMS << at),
                    )
                    .is_err()
                {
                    return false;
                }
                remote.limit = max;
                self.owed &= !(owed::MAX_STREAMS << at);
            }
            if self.owed & (owed::STREAMS_BLOCKED << at) != 0 {
                let limit = self.local[at].limit;
                if builder
                    .track(
                        &Frame::StreamsBlocked { direction, limit },
                        Record::Limit(owed::STREAMS_BLOCKED << at),
                    )
                    .is_err()
                {
                    return false;
                }
                self.owed &= !(owed::STREAMS_BLOCKED << at);
            }
        }
        true
    }

    /// Writes the frames of each stream of the control list. Gives `false` when the packet is
    /// full.
    fn write_control(&mut self, builder: &mut Output<'_, '_>) -> bool {
        loop {
            let slot = self.fifo[list::CONTROL][0] as usize;
            let capacity = self.config.stream_bytes;
            let Some(stream) = self.slots.get_mut(slot) else {
                return true;
            };
            let id = stream.id.0;
            if stream.control & control::RESET != 0
                && let Some(send) = &mut stream.send
                && let Sending::Reset {
                    code,
                    acknowledged: false,
                    ..
                } = &mut send.state
            {
                let frame = Frame::ResetStream {
                    stream: id,
                    code: *code,
                    final_size: send.offset,
                };
                if builder
                    .track(&frame, Record::Control(stream.id, control::RESET))
                    .is_err()
                {
                    return false;
                }
            }
            stream.control &= !control::RESET;
            if stream.control & control::STOP != 0
                && let Some(Receiving::Stopped(code)) = stream.recv.as_ref().map(|recv| recv.state)
                && builder
                    .track(
                        &Frame::StopSending { stream: id, code },
                        Record::Control(stream.id, control::STOP),
                    )
                    .is_err()
            {
                return false;
            }
            stream.control &= !control::STOP;
            if stream.control & control::MAX_STREAM_DATA != 0
                && let Some(recv) = &mut stream.recv
                && recv.state == Receiving::Open
                && recv.final_size.is_none()
            {
                let max = recv.window.due(capacity).unwrap_or(recv.window.max);
                if builder
                    .track(
                        &Frame::MaxStreamData { stream: id, max },
                        Record::Control(stream.id, control::MAX_STREAM_DATA),
                    )
                    .is_err()
                {
                    return false;
                }
                recv.window.max = max;
            }
            stream.control &= !control::MAX_STREAM_DATA;
            if stream.control & control::BLOCKED != 0
                && let Some(send) = &stream.send
                && matches!(send.state, Sending::Open | Sending::Finishing)
                && builder
                    .track(
                        &Frame::StreamDataBlocked {
                            stream: id,
                            limit: send.max,
                        },
                        Record::Control(stream.id, control::BLOCKED),
                    )
                    .is_err()
            {
                return false;
            }
            stream.control &= !control::BLOCKED;
            let mut sent = false;
            if stream.control & control::FIN != 0
                && let Some(send) = &mut stream.send
                && matches!(send.state, Sending::Finishing | Sending::FinSent)
                && send.queued == 0
            {
                let frame = Frame::Stream {
                    stream: id,
                    offset: send.offset,
                    data: &[],
                    fin: true,
                };
                if builder.track(&frame, Record::Control(stream.id, control::FIN)).is_err() {
                    return false;
                }
                sent = send.state == Sending::Finishing;
                send.state = Sending::FinSent;
            }
            stream.control &= !control::FIN;
            self.pop(list::CONTROL);
            if sent {
                self.tell(slot, notify::SENT);
            }
            self.settle(slot);
        }
    }

    /// Writes STREAM frames in the order of the scheduler, while the connection has send credit
    /// and the packet has room.
    fn write_data(&mut self, builder: &mut Output<'_, '_>) {
        while self.send_used < self.send_max
            && let Some(slot) = self.first()
        {
            let full = self.write_stream(slot, builder);
            if full {
                // The next incremental stream of the urgency fills the next packet.
                let shares = self.slots[slot]
                    .send
                    .as_ref()
                    .is_some_and(|send| send.priority.incremental);
                if shares && self.slots[slot].linked & list::READY != 0 {
                    self.unlink(slot);
                    self.link(slot);
                }
                return;
            }
        }
        if self.first().is_some() && self.blocked_at.replace(self.send_max) != Some(self.send_max) {
            self.owed |= owed::DATA_BLOCKED;
        }
    }

    /// Writes STREAM frames of stream `slot`, which is in the scheduler, until its regions or its
    /// credit end. Gives `true` when the packet has no room for its next byte.
    fn write_stream(&mut self, slot: usize, builder: &mut Output<'_, '_>) -> bool {
        loop {
            let stream = &mut self.slots[slot];
            let id = stream.id.0;
            let send = stream.send.as_mut().filter(|send| send.queued > 0);
            let region = send.as_ref().and_then(|send| self.regions.get_mut(send.head as usize));
            let (Some(send), Some(region)) = (send, region) else {
                self.unlink(slot);
                return false;
            };
            let bytes = region.lease.as_ref().map_or(&[][..], |lease| lease.bytes());
            let bytes = bytes.get(send.head_at..).unwrap_or_default();
            let credit = (send.max - send.offset).min(self.send_max - self.send_used);
            let offset_bytes = if send.offset == 0 {
                0
            } else {
                varint_len(send.offset).unwrap_or(8)
            };
            let head = 1 + varint_len(id).unwrap_or(8) + offset_bytes;
            let want = bytes.len().min(usize::try_from(credit).unwrap_or(usize::MAX));
            let len = fit(builder.room().saturating_sub(head), want);
            let fin = send.state == Sending::Finishing && len as u64 == send.queued;
            let frame = Frame::Stream {
                stream: id,
                offset: send.offset,
                data: &bytes[..len],
                fin,
            };
            let record = Record::Range(DataRange::Stream {
                id: stream.id,
                region: send.head,
                offset: send.offset,
                len,
                fin,
            });
            if len == 0 || builder.track(&frame, record).is_err() {
                return true;
            }
            send.offset += len as u64;
            send.queued -= len as u64;
            send.head_at += len;
            self.send_used += len as u64;
            if fin {
                send.state = Sending::FinSent;
            }
            if len == bytes.len() {
                send.head = region.next;
                send.head_at = 0;
                send.regions -= 1;
            }
            let (sent, blocked) = (send.queued == 0, send.offset == send.max);
            if sent || blocked {
                let tell = blocked && !sent && send.blocked_at.replace(send.max) != Some(send.max);
                self.unlink(slot);
                if sent {
                    self.tell(slot, notify::SENT);
                    self.settle(slot);
                } else if tell {
                    self.owe(slot, control::BLOCKED);
                }
                return false;
            }
            if self.send_used == self.send_max {
                return false;
            }
        }
    }
}

/// The largest DATAGRAM frame that this end takes when unreliable datagrams are on: the value
/// that RFC 9221, section 3, recommends.
pub(super) const UNRELIABLE_FRAME_BYTES_MAX: u64 = 65_535;
