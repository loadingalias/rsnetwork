//! Packet delivery and loss on the paths of a QUIC connection (RFC 9000, section 13, and
//! RFC 9002). Each path has its window, pacer, and round-trip estimate. The paths share one store
//! of sent packets, and each packet counts only for the path that sent it (RFC 9000, section 9.4):
//! its acknowledgement, its congestion mark, and its loss change no other path.

use core::alloc::Layout;
use core::ops::Range;
use core::time::Duration;
use std::collections::VecDeque;

use rstypes::capacity::{Budget, Credit};
use rstypes::time::Instant;

use super::congestion::{CongestionControl, Controller};
use super::connection::DATAGRAM_MIN;
use super::frame::{Ack, EcnCounts, Frame};
use super::packet::{BuildError, Builder};
use super::path::{Mtu, Path, Probe, Validation};
use super::reassembly::grow;
use super::stream::StreamId;
use super::{ConnectionId, VARINT_MAX, Writer, varint_len};
use crate::drive::{Ecn, Error, Kind, TurnLimits, Work};

pub(super) const NO_ROOM: Error = Error::new(Kind::Overload, "the budget refused QUIC recovery state");
const PATHS_SPENT: Error = Error::new(Kind::Overload, "the QUIC connection used each of its path tags");
const GRANULARITY: Duration = Duration::from_millis(1);
const INITIAL_RTT: Duration = Duration::from_millis(333);
const PACKET_THRESHOLD: u64 = 3;
/// The marked datagrams that test the ECN of a path (RFC 9000, section 13.4.2.1).
const TRIAL_DATAGRAMS: u8 = 10;

/// The delivery state of the current path. Byte counts include QUIC headers and packet protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryStats {
    /// Flights that waited for more receive credit under the amplification limit: in the handshake of
    /// a server, or on a path whose peer address is not validated.
    pub amplification_blocked_round_trips: u64,
    /// The bytes in outstanding packets that elicit an ACK or contain padding.
    pub bytes_in_flight: u64,
    /// The congestion window in bytes.
    pub congestion_window: u64,
    /// The latest unadjusted round-trip sample.
    pub latest_rtt: Option<Duration>,
    /// The smoothed round-trip estimate after the first sample.
    pub smoothed_rtt: Option<Duration>,
    /// The packets declared lost across all packet number spaces.
    pub packets_lost: u64,
    /// The probe packets sent after a probe timeout.
    pub probes_sent: u64,
    /// The state of ECN validation on this path.
    pub ecn: EcnState,
    /// The marks that the peer reported in validated feedback across all flows.
    pub ecn_counts: EcnCounts,
}

/// Whether the peer has confirmed the ECN marks sent on this path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcnState {
    /// The sender can mark up to ten datagrams to test the path.
    Testing,
    /// The trial ended. Datagrams leave unmarked until the peer confirms a trial mark.
    Unknown,
    /// The peer reported valid counts for marked traffic.
    Capable,
    /// Validation failed. The sender uses Not-ECT.
    Failed,
}

/// One path of a connection: its addresses and its delivery state.
pub(super) struct PathState {
    pub(super) addresses: Path,
    /// The connection ID of the peer in the packets to this path.
    pub(super) remote_cid: ConnectionId,
    /// The datagram size of the path, and the search above it.
    pub(super) mtu: Mtu,
    /// The tag of the packets that this path sent.
    id: u32,
    /// Remaining send credit before the validation of the peer address. A validated path has no cap.
    pub(super) amplification_credit: Option<u64>,
    pub(super) amplification_blocked: bool,
    pub(super) amplification_rounds: u64,
    pub(super) controller: Controller,
    /// The virtual end of the last paced transmission, in clock nanoseconds.
    departure: u64,
    pub(super) pacing_wait: Option<Instant>,
    ecn: EcnState,
    trial_datagrams: u8,
    first_mark: Option<Instant>,
    ecn_counts: EcnCounts,
    collapsed: Option<u64>,
    reset_rtt: bool,
    pub(super) ack_delay_max: Duration,
    flight: u64,
    minimum: Option<Duration>,
    latest: Duration,
    smoothed: Duration,
    variation: Duration,
    lost: u64,
    pub(super) probes: u64,
    pub(super) backoff: u32,
}

impl PathState {
    /// A path that starts at 1,200 bytes and searches up to `top` bytes.
    pub(super) fn new(addresses: Path, remote_cid: ConnectionId, top: usize, algorithm: CongestionControl) -> Self {
        Self {
            addresses,
            remote_cid,
            mtu: Mtu::new(top),
            id: 0,
            amplification_credit: None,
            amplification_blocked: false,
            amplification_rounds: 0,
            controller: Controller::new(DATAGRAM_MIN as u64, algorithm),
            departure: 0,
            pacing_wait: None,
            ecn: EcnState::Testing,
            trial_datagrams: 0,
            first_mark: None,
            ecn_counts: EcnCounts::default(),
            collapsed: None,
            reset_rtt: false,
            ack_delay_max: Duration::from_millis(25),
            flight: 0,
            minimum: None,
            latest: INITIAL_RTT,
            smoothed: INITIAL_RTT,
            variation: INITIAL_RTT / 2,
            lost: 0,
            probes: 0,
            backoff: 0,
        }
    }

    /// The path that follows this one at `addresses`. A path that differs only in the port of the
    /// peer keeps the window, the round-trip estimate, and the datagram size. Each other path
    /// starts from the initial values (RFC 9000, section 9.4).
    pub(super) fn next(
        &self,
        addresses: Path,
        remote_cid: ConnectionId,
        top: usize,
        algorithm: CongestionControl,
    ) -> Self {
        let fresh = Self {
            ack_delay_max: self.ack_delay_max,
            ..Self::new(addresses, remote_cid, top, algorithm)
        };
        if addresses.local != self.addresses.local || addresses.peer.ip() != self.addresses.peer.ip() {
            return fresh;
        }
        Self {
            mtu: self.mtu.carried(),
            controller: self.controller.clone(),
            minimum: self.minimum,
            latest: self.latest,
            smoothed: self.smoothed,
            variation: self.variation,
            ..fresh
        }
    }

    /// Whether `bytes` more bytes can go to the path: before the validation of its peer address,
    /// at most three times the bytes that came from it (RFC 9000, sections 8.1 and 9.3.1).
    pub(super) fn allows(&self, bytes: u64) -> bool {
        self.amplification_credit.is_none_or(|credit| bytes <= credit)
    }

    /// Counts `bytes` that go to the path. Each sender on the path calls it, so the connection
    /// and its side flows share one limit.
    pub(super) fn charge(&mut self, bytes: u64) {
        if let Some(credit) = &mut self.amplification_credit {
            *credit = credit.saturating_sub(bytes);
            self.amplification_blocked = false;
        }
    }

    pub(super) fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            amplification_blocked_round_trips: self.amplification_rounds,
            bytes_in_flight: self.flight,
            congestion_window: self.controller.window,
            latest_rtt: self.minimum.map(|_| self.latest),
            smoothed_rtt: self.minimum.map(|_| self.smoothed),
            packets_lost: self.lost,
            probes_sent: self.probes,
            ecn: self.ecn,
            ecn_counts: self.ecn_counts,
        }
    }

    pub(super) fn room(&self) -> u64 {
        self.controller.window.saturating_sub(self.flight)
    }

    fn interval_ns(&self, bytes: u64) -> u64 {
        u64::try_from((self.smoothed.as_nanos() * u128::from(bytes)).div_ceil(u128::from(self.controller.window)))
            .unwrap_or(u64::MAX)
    }

    /// Allow one millisecond of batching at the pacing rate, so a batch for segmentation offload
    /// grows with the rate of the path, as a TSO burst of TCP does. A refused sender waits for the
    /// departure itself, so its next batch holds that millisecond again. Before the first RTT, the
    /// initial flight can leave together (RFC 9002, section 7.7).
    pub(super) fn paced(&mut self, bytes: u64, now: Instant) -> Result<bool, Error> {
        if self.pacing_wait.is_some_and(|at| at.as_nanos() <= now.as_nanos()) {
            self.pacing_wait = None;
        }
        if bytes > self.room() {
            return Ok(false);
        }
        let allowance = if self.minimum.is_some() {
            1_000_000
        } else {
            let initial = (10 * self.controller.datagram).min((2 * self.controller.datagram).max(14_720));
            self.interval_ns(initial.saturating_sub(bytes))
        };
        let wait = self.departure.saturating_sub(now.as_nanos());
        if wait <= allowance || self.smoothed.is_zero() {
            return Ok(true);
        }
        let at = now
            .checked_add(Duration::from_nanos(wait))
            .map_err(|_| super::connection::CLOCK)?;
        if self
            .pacing_wait
            .is_none_or(|previous| previous.as_nanos() > at.as_nanos())
        {
            self.pacing_wait = Some(at);
        }
        Ok(false)
    }

    fn sent(&mut self, bytes: u64, now: Instant) {
        self.flight += bytes;
        if bytes != 0 {
            self.departure = now
                .as_nanos()
                .max(self.departure)
                .saturating_add(self.interval_ns(bytes));
        }
    }

    /// The mark of the next datagrams, and how many of them can take it: during the test of the
    /// path, only the trial datagrams that remain.
    pub(super) fn mark(&mut self, now: Instant) -> (Ecn, usize) {
        if self.ecn == EcnState::Testing
            && self.first_mark.is_some_and(|first| {
                u128::from(now.as_nanos().saturating_sub(first.as_nanos()))
                    >= 3 * self.pto(self.ack_delay_max).as_nanos()
            })
        {
            self.ecn = EcnState::Unknown;
        }
        match self.ecn {
            EcnState::Capable => (Ecn::Ect0, usize::MAX),
            EcnState::Testing => (Ecn::Ect0, usize::from(TRIAL_DATAGRAMS - self.trial_datagrams)),
            _ => (Ecn::NotEct, usize::MAX),
        }
    }

    /// Counts `datagrams` that left with `mark`, at most the trial datagrams that remain.
    pub(super) fn marked(&mut self, mark: Ecn, datagrams: usize, now: Instant) {
        if mark == Ecn::Ect0 && self.ecn == EcnState::Testing {
            self.first_mark.get_or_insert(now);
            let left = TRIAL_DATAGRAMS - self.trial_datagrams;
            self.trial_datagrams += u8::try_from(datagrams).unwrap_or(left).min(left);
            if self.trial_datagrams == TRIAL_DATAGRAMS {
                self.ecn = EcnState::Unknown;
            }
        }
    }

    pub(super) fn acknowledged(&mut self, ack: Acked, now: Instant, grow: bool) {
        if grow && ack.bytes > 0 {
            self.controller.acknowledged(ack.bytes, now, self.smoothed);
        }
        if let Some(round) = ack.round {
            self.controller.round_sample(round, self.latest);
        }
    }

    pub(super) fn pto(&self, ack_delay: Duration) -> Duration {
        self.smoothed + (4 * self.variation).max(GRANULARITY) + ack_delay
    }

    fn sample(&mut self, latest: Duration, delay: Duration, now: Instant) {
        self.latest = latest;
        let reset = core::mem::take(&mut self.reset_rtt);
        let Some(previous) = self.minimum.filter(|_| !reset) else {
            self.departure = now.as_nanos();
            self.minimum = Some(latest);
            self.smoothed = latest;
            self.variation = latest / 2;
            return;
        };
        let minimum = previous.min(latest);
        self.minimum = Some(minimum);
        let adjusted = latest
            .checked_sub(delay)
            .filter(|rtt| *rtt >= minimum)
            .unwrap_or(latest);
        self.variation = (3 * self.variation + self.smoothed.abs_diff(adjusted)) / 4;
        self.smoothed = (7 * self.smoothed + adjusted) / 8;
    }

    fn loss_delay(&self) -> Duration {
        (self.latest.max(self.smoothed) * 9 / 8).max(GRANULARITY)
    }
}

/// Received packet numbers in ascending, disjoint ranges. Only gaps consume additional entries.
pub(super) struct Received {
    ranges: VecDeque<Range<u64>>,
    largest_at: Option<Instant>,
    window: u64,
    credit: Credit,
    pub(super) due: bool,
    ecn: EcnCounts,
}

impl Received {
    pub(super) fn new(window: u64, budget: &Budget) -> Self {
        Self {
            ranges: VecDeque::new(),
            largest_at: None,
            window,
            credit: budget.credit(0),
            due: false,
            ecn: EcnCounts::default(),
        }
    }

    pub(super) fn largest(&self) -> Option<u64> {
        self.ranges.back().map(|last| last.end - 1)
    }

    pub(super) fn seen(&self, number: u64) -> bool {
        let Some(last) = self.ranges.back() else { return false };
        if number >= last.end {
            return false;
        }
        number < last.end.saturating_sub(self.window)
            || self
                .ranges
                .get(self.ranges.partition_point(|r| r.end <= number))
                .is_some_and(|r| r.start <= number)
    }

    /// Commits a packet only after the engine accepts all its frames.
    pub(super) fn accept(&mut self, number: u64, now: Instant, eliciting: bool, mark: Ecn) -> Result<(), Error> {
        if self.largest().is_none_or(|largest| number > largest) {
            let floor = (number + 1).saturating_sub(self.window);
            while self.ranges.front().is_some_and(|r| r.end <= floor) {
                self.ranges.pop_front();
            }
            if let Some(first) = self.ranges.front_mut() {
                first.start = first.start.max(floor);
            }
            self.largest_at = Some(now);
        }
        let at = self.ranges.partition_point(|r| r.end < number);
        let end = number + 1;
        if self.ranges.get(at).is_some_and(|r| r.end == number) {
            self.ranges[at].end = end;
            if self.ranges.get(at + 1).is_some_and(|r| r.start == end) {
                self.ranges[at].end = self.ranges.remove(at + 1).expect("the next range exists").end;
            }
        } else if self.ranges.get(at).is_some_and(|r| r.start == end) {
            self.ranges[at].start = number;
        } else {
            let ranges = &mut self.ranges;
            grow(
                (ranges.len(), ranges.capacity(), size_of::<Range<u64>>()),
                &mut self.credit,
                |n| ranges.try_reserve_exact(n).is_ok(),
            )
            .map_err(|_| NO_ROOM)?;
            ranges.insert(at, number..end);
        }
        match mark {
            Ecn::Ect0 => self.ecn.ect0 += 1,
            Ecn::Ect1 => self.ecn.ect1 += 1,
            Ecn::Ce => self.ecn.ce += 1,
            Ecn::NotEct => {}
        }
        self.due |= eliciting;
        Ok(())
    }

    /// Writes the newest ranges that fit. The delay uses the default exponent of three.
    pub(super) fn write(&mut self, builder: &mut Builder<'_>, now: Instant) -> Result<(), Error> {
        if !self.due {
            return Ok(());
        }
        let at = self.largest_at.expect("an ACK has a received packet");
        let elapsed = now.duration_since(at).map_err(|_| super::connection::CLOCK)?;
        let delay = u64::try_from(elapsed.as_micros() / 8)
            .unwrap_or(VARINT_MAX)
            .min(VARINT_MAX);
        self.due = !builder.write_ack(|out| self.encode(out, delay));
        Ok(())
    }

    fn encode(&self, out: &mut [u8], delay: u64) -> Option<usize> {
        let mut ranges = self.ranges.iter().rev();
        let first = ranges.next()?;
        let marked = self.ecn != EcnCounts::default();
        let tail = if marked {
            varint_len(self.ecn.ect0)? + varint_len(self.ecn.ect1)? + varint_len(self.ecn.ce)?
        } else {
            0
        };
        let limit = out.len().checked_sub(tail)?;
        let mut writer = Writer::new(&mut out[..limit]);
        writer.u8(if marked { 0x03 } else { 0x02 })?;
        writer.varint(first.end - 1)?;
        writer.varint(delay)?;
        let count_at = writer.len();
        let width = varint_len(ranges.len() as u64)?;
        writer.varint_in(0, width)?;
        writer.varint(first.end - first.start - 1)?;
        let (mut count, mut written, mut low) = (0, writer.len(), first.start);
        for range in ranges {
            if writer.varint(low - range.end - 1).is_none() || writer.varint(range.end - range.start - 1).is_none() {
                break;
            }
            written = writer.len();
            low = range.start;
            count += 1;
        }
        Writer::new(&mut out[count_at..]).varint_in(count, width)?;
        if marked {
            let mut tail = Writer::new(&mut out[written..]);
            tail.varint(self.ecn.ect0)?;
            tail.varint(self.ecn.ect1)?;
            tail.varint(self.ecn.ce)?;
            written += tail.len();
        }
        Some(written)
    }
}

/// The information that must survive the loss of a packet. Stream and CRYPTO bytes keep their original owners.
#[derive(Clone, Copy, Debug)]
pub(super) enum DataRange {
    Crypto {
        offset: u64,
        len: usize,
    },
    Stream {
        id: StreamId,
        region: u32,
        offset: u64,
        len: usize,
        fin: bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Record {
    IssueId(u64),
    RetireId(u64),
    NewToken,
    Range(DataRange),
    Limit(u8),
    Control(StreamId, u8),
    HandshakeDone,
    /// A probe of the datagram size, which is alone in its packet. The recovery layer takes it.
    Mtu(usize),
    /// A PATH_CHALLENGE frame. The recovery layer takes it.
    Challenge,
}

/// A packet normally carries one stream range. Only a packet with more records needs a second allocation.
#[derive(Default)]
pub(super) struct Records {
    first: Option<Record>,
    rest: Vec<Record>,
    charge: Option<Credit>,
}

impl Records {
    pub(super) fn iter(&self) -> impl Iterator<Item = Record> + '_ {
        self.first.into_iter().chain(self.rest.iter().copied())
    }

    /// Whether the packet is a probe of the datagram size. Its loss is no sign of congestion
    /// (RFC 9000, section 14.4).
    fn probe(&self) -> bool {
        matches!(self.first, Some(Record::Mtu(_)))
    }

    fn push(&mut self, record: Record, budget: &Budget) -> Result<(), Error> {
        if self.first.is_none() {
            self.first = Some(record);
        } else {
            let rest = &mut self.rest;
            let charge = self.charge.get_or_insert_with(|| budget.credit(0));
            grow((rest.len(), rest.capacity(), size_of::<Record>()), charge, |n| {
                rest.try_reserve_exact(n).is_ok()
            })
            .map_err(|_| NO_ROOM)?;
            rest.push(record);
        }
        Ok(())
    }
}

/// Writes a frame and keeps its delivery record only if it fits.
pub(super) struct Output<'a, 'b> {
    pub(super) builder: Builder<'b>,
    pub(super) records: Records,
    budget: &'a Budget,
    pub(super) refused: bool,
}

impl<'a, 'b> Output<'a, 'b> {
    pub(super) fn new(builder: Builder<'b>, budget: &'a Budget) -> Self {
        Self {
            builder,
            budget,
            records: Records::default(),
            refused: false,
        }
    }

    pub(super) fn room(&self) -> usize {
        self.builder.room()
    }

    pub(super) fn track(&mut self, frame: &Frame<'_>, record: Record) -> Result<(), BuildError> {
        self.builder.frame(frame)?;
        if !self.refused && self.records.push(record, self.budget).is_err() {
            self.refused = true;
        }
        Ok(())
    }
}

pub(super) struct Sent {
    pub(super) number: u64,
    pub(super) time: Instant,
    pub(super) bytes: u64,
    pub(super) eliciting: bool,
    pub(super) records: Records,
    pub(super) mark: Ecn,
}

/// Slots in send order. Removal unlinks two neighbors. The next insertion reuses the free slot.
struct Slot {
    packet: Option<Sent>,
    /// The number of the last packet of the slot. Bare ACKs that leave back to back share one
    /// slot, from the number of the packet through this one.
    through: u64,
    previous: usize,
    next: usize,
    path_previous: usize,
    path_next: usize,
    gap: Gap,
    sampled: bool,
    round: u64,
    /// The tag of the path that sent the packet.
    path: u32,
}

const NONE: usize = usize::MAX;
/// The live slots of bare ACKs that a loss run goes past on each side when a packet settles. Past
/// them, the run waits for those slots to settle, which a PING brings (RFC 9000, section 13.2.4).
const BARE_PAST_MAX: usize = 16;

/// Geometric blocks keep existing slots in place during growth. The directory has at most one
/// entry per bit of a slot index. A new block initializes only the slot being inserted.
#[derive(Default)]
struct Slots {
    blocks: Vec<Vec<Slot>>,
    len: usize,
}

impl Slots {
    const FIRST: usize = 4;

    fn address(at: usize) -> (usize, usize) {
        let key = at + Self::FIRST;
        let shift = key.ilog2();
        ((shift - Self::FIRST.ilog2()) as usize, key - (1 << shift))
    }

    fn get(&self, at: usize) -> Option<&Slot> {
        if at >= self.len {
            return None;
        }
        let (block, index) = Self::address(at);
        Some(&self.blocks[block][index])
    }

    fn get_mut(&mut self, at: usize) -> Option<&mut Slot> {
        if at >= self.len {
            return None;
        }
        let (block, index) = Self::address(at);
        Some(&mut self.blocks[block][index])
    }

    fn push(&mut self, slot: Slot, credit: &mut Credit) -> Result<usize, Error> {
        let at = self.len;
        let (block, index) = Self::address(at);
        if index == 0 {
            let blocks = &mut self.blocks;
            grow((blocks.len(), blocks.capacity(), size_of::<Vec<Slot>>()), credit, |n| {
                blocks.try_reserve_exact(n).is_ok()
            })
            .map_err(|_| NO_ROOM)?;
            let count = Self::FIRST << block;
            let bytes = Layout::array::<Slot>(count).map_err(|_| NO_ROOM)?.size() as u64;
            credit.charge(bytes).map_err(|_| NO_ROOM)?;
            let mut entries = Vec::new();
            if entries.try_reserve_exact(count).is_err() {
                credit.refund(bytes).expect("the new block owns its charge");
                return Err(NO_ROOM);
            }
            blocks.push(entries);
        }
        self.blocks[block].push(slot);
        self.len += 1;
        Ok(at)
    }
}

/// Settled packets between two live packets in path send order. An ACK splits a loss run.
/// Only the two ends can still join a run as its neighboring packets settle.
#[derive(Clone, Copy, Default)]
struct Gap {
    prefix_end: Option<u64>,
    suffix_start: Option<u64>,
    broken: bool,
}

impl Gap {
    const BARRIER: Self = Self {
        prefix_end: None,
        suffix_start: None,
        broken: true,
    };

    /// No settled packet in the gap is a loss of a run or a delivery.
    const fn is_empty(self) -> bool {
        self.prefix_end.is_none() && self.suffix_start.is_none() && !self.broken
    }

    fn join(self, right: Self) -> Self {
        Self {
            prefix_end: if self.broken {
                self.prefix_end
            } else {
                right.prefix_end.or(self.prefix_end)
            },
            suffix_start: if right.broken {
                right.suffix_start
            } else {
                self.suffix_start.or(right.suffix_start)
            },
            broken: self.broken || right.broken,
        }
    }
}

/// All number spaces and side flows allocate slots here. Each slot also links its neighbors in
/// send order.
struct Store {
    slots: Slots,
    free: usize,
    last: usize,
    tail: Gap,
    credit: Credit,
}

impl Store {
    fn new(budget: &Budget) -> Self {
        Self {
            slots: Slots::default(),
            free: NONE,
            last: NONE,
            tail: Gap::default(),
            credit: budget.credit(0),
        }
    }

    /// Slot `at`, when it holds live bare ACKs of the path `path`. A loss run goes past them
    /// until an ACK covers one of them.
    fn bare(&self, at: usize, path: u32) -> Option<&Slot> {
        self.slots
            .get(at)
            .filter(|slot| slot.path == path && slot.packet.as_ref().is_some_and(|packet| packet.bytes == 0))
    }

    /// The start of the loss run that ends at the right of `gap`, past the live bare ACKs of
    /// `path` from the slot `left` back.
    fn run_start(&self, mut gap: Gap, mut left: usize, path: u32) -> Option<u64> {
        let mut start = gap.suffix_start;
        for _ in 0..BARE_PAST_MAX {
            let Some(slot) = self.bare(left, path).filter(|_| !gap.broken) else {
                break;
            };
            gap = slot.gap;
            start = gap.suffix_start.or(start);
            left = slot.path_previous;
        }
        start
    }

    /// The end of the loss run that starts at the left of `gap`, past the live bare ACKs of `path`
    /// from the slot `right` on.
    fn run_end(&self, mut gap: Gap, mut right: usize, path: u32) -> Option<u64> {
        let mut end = gap.prefix_end;
        for _ in 0..BARE_PAST_MAX {
            let Some(slot) = self.bare(right, path).filter(|_| !gap.broken) else {
                break;
            };
            right = slot.path_next;
            gap = self.slots.get(right).map_or(self.tail, |next| next.gap);
            end = gap.prefix_end.or(end);
        }
        end
    }
}

/// The paths of a connection, and the packets that it sent on them.
pub(super) struct Paths {
    store: Store,
    /// The path that carries the connection.
    pub(super) active: PathState,
    /// The validation of the active path, with the path that the connection came from.
    pub(super) validation: Option<Validation>,
    /// The validation of the path to or from the preferred address of the server, before the
    /// connection moves to it.
    pub(super) probe: Option<Probe>,
    /// The send credit of one address with no validation that does not carry the connection. It
    /// is the newest such address that a datagram came from, or that the connection left. Each
    /// address has one credit, here or in its [`PathState`], so no datagram pays for two sends.
    off_path: Option<(Path, u64)>,
    /// The tag of the next path.
    next: u32,
}

impl Paths {
    pub(super) fn new(active: PathState, budget: &Budget) -> Self {
        Self {
            store: Store::new(budget),
            active,
            validation: None,
            probe: None,
            off_path: None,
            next: 1,
        }
    }

    /// Makes `next` the active path, and gives the path before it. No packet that went out
    /// before counts for `next`. Refuses with [`Kind::Overload`] after 2^32 - 2 changes, so no
    /// tag comes again. A side flow can keep a packet of a tag until the flow ends.
    pub(super) fn switch(&mut self, mut next: PathState) -> Result<PathState, Error> {
        next.id = self.next;
        self.next = self.next.checked_add(1).ok_or(PATHS_SPENT)?;
        Ok(self.activate(next))
    }

    /// Makes `next` the active path: a new path, or the fallback path of a validation that
    /// ended. Gives the path before it. A loss run does not continue from one path to the next.
    /// The credit of a path with no validation stays with its address.
    pub(super) fn activate(&mut self, next: PathState) -> PathState {
        self.store.tail = self.store.tail.join(Gap::BARRIER);
        let old = core::mem::replace(&mut self.active, next);
        if let Some(credit) = old.amplification_credit {
            self.off_path = Some((old.addresses, credit));
        }
        old
    }

    /// Counts a datagram of `bytes` bytes that came on `path`. A path with no validation gets
    /// three times these bytes as send credit (RFC 9000, sections 8.1 and 9.3.1). The caller
    /// counts each datagram one time.
    pub(super) fn received(&mut self, path: Path, bytes: u64) {
        let credit = bytes.saturating_mul(3);
        if path == self.active.addresses {
            if let Some(balance) = &mut self.active.amplification_credit {
                *balance = balance.saturating_add(credit);
                if *balance >= DATAGRAM_MIN as u64 {
                    self.active.amplification_blocked = false;
                }
            }
        } else if self
            .validation
            .as_ref()
            .is_none_or(|validation| validation.fallback.addresses != path)
        {
            match &mut self.off_path {
                Some((known, balance)) if *known == path => *balance = balance.saturating_add(credit),
                other => *other = Some((path, credit)),
            }
        }
    }

    /// Takes the credit of `path`, which becomes the active path of a server.
    pub(super) fn take_credit(&mut self, path: Path) -> u64 {
        self.off_path
            .take_if(|(known, _)| *known == path)
            .map_or(0, |(_, credit)| credit)
    }

    /// The bytes of one datagram that the credit of `path` allows: at most 1,200. `path` has no
    /// validation, and does not carry the connection. A path with no credit gets no datagram.
    pub(super) fn off_path_room(&self, path: Path) -> usize {
        let credit = self.off_path.filter(|(known, _)| *known == path);
        credit.map_or(0, |(_, credit)| {
            DATAGRAM_MIN.min(usize::try_from(credit).unwrap_or(usize::MAX))
        })
    }

    /// Takes the `bytes` of a datagram that went to `path` from the credit of `path`.
    pub(super) fn off_path_sent(&mut self, path: Path, bytes: u64) {
        if let Some((_, credit)) = self.off_path.as_mut().filter(|(known, _)| *known == path) {
            *credit = credit.saturating_sub(bytes);
        }
    }

    /// The time threshold of a packet that the path with the tag `sender` sent. It is the
    /// threshold of that path, or of the active path when the connection no longer has that path.
    fn loss_delay(&self, sender: u32) -> Duration {
        self.validation
            .as_ref()
            .map(|validation| &validation.fallback)
            .filter(|fallback| fallback.id == sender)
            .unwrap_or(&self.active)
            .loss_delay()
    }

    /// The path with the tag `sender`, while the connection has it: the active path, or the
    /// fallback path.
    fn owner(&mut self, sender: u32) -> Option<&mut PathState> {
        if self.active.id == sender {
            return Some(&mut self.active);
        }
        let fallback = self.validation.as_mut().map(|validation| &mut validation.fallback);
        fallback.filter(|fallback| fallback.id == sender)
    }
}

#[derive(Clone, Copy)]
enum Settlement {
    Delivered,
    Lost,
    Discarded,
}

/// What an ACK frame newly acknowledged of the packets that the active path sent.
#[derive(Default)]
pub(super) struct Acked {
    /// One of them was ack-eliciting.
    pub(super) eliciting: bool,
    bytes: u64,
    round: Option<u64>,
}

pub(super) struct History {
    first: usize,
    last: usize,
    pub(super) bytes: u64,
    elicitors: usize,
    last_sent: Option<Instant>,
    pub(super) largest: Option<u64>,
    pub(super) loss_time: Option<Instant>,
    pub(super) ect_sent: u64,
    feedback: EcnCounts,
    /// A live packet near the largest acknowledged number, where the walk of the next ACK
    /// starts, or `NONE`.
    near: usize,
    /// The ACK frame and the loss scan that a limit of a turn stopped.
    walk: Option<Walk>,
    scan: Option<Scan>,
}

/// The walk of an ACK frame that a limit of a turn stopped: where it goes on, and what it found.
#[derive(Clone, Copy)]
struct Walk {
    /// The range of the frame, counted from the largest, and the packet where the walk goes on.
    range: usize,
    at: usize,
    /// The walk reached the newest packet at or below the largest number of the frame.
    located: bool,
    /// The frame raised the largest acknowledged number.
    advances: bool,
    eliciting: bool,
    grow_by: u64,
    marked: u64,
    elsewhere: u64,
    sample: Option<Instant>,
    round: Option<u64>,
}

/// A loss scan that a limit of a turn stopped: the packet where it goes on, the earliest time
/// threshold of the packets before it that wait, and whether each datagram that the active path
/// lost in it is above the base size.
#[derive(Clone, Copy)]
struct Scan {
    at: usize,
    waiting: Option<Instant>,
    large: Option<bool>,
}

impl History {
    pub(super) fn new() -> Self {
        Self {
            first: NONE,
            last: NONE,
            bytes: 0,
            elicitors: 0,
            last_sent: None,
            largest: None,
            loss_time: None,
            ect_sent: 0,
            feedback: EcnCounts::default(),
            near: NONE,
            walk: None,
            scan: None,
        }
    }

    pub(super) fn pto_start(&self) -> Option<Instant> {
        self.last_sent.filter(|_| self.elicitors > 0)
    }

    pub(super) fn insert(&mut self, paths: &mut Paths, packet: Sent) -> Result<(), Error> {
        let (number, bytes, eliciting, time) = (packet.number, packet.bytes, packet.eliciting, packet.time);
        let (store, path) = (&mut paths.store, &mut paths.active);
        let slot = Slot {
            packet: Some(packet),
            through: number,
            previous: self.last,
            next: NONE,
            path_previous: store.last,
            path_next: NONE,
            gap: store.tail,
            sampled: path.minimum.is_some(),
            round: path.controller.round(),
            path: path.id,
        };
        let at = if let Some(free) = store.slots.get_mut(store.free) {
            let at = core::mem::replace(&mut store.free, free.next);
            *free = slot;
            at
        } else {
            store.slots.push(slot, &mut store.credit)?
        };
        store.tail = Gap::default();
        if let Some(last) = store.slots.get_mut(store.last) {
            last.path_next = at;
        }
        store.last = at;
        self.bytes += bytes;
        if eliciting {
            self.elicitors += 1;
            self.last_sent = Some(time);
        }
        if let Some(last) = store.slots.get_mut(self.last) {
            last.next = at;
        } else {
            self.first = at;
        }
        self.last = at;
        path.sent(bytes, time);
        Ok(())
    }

    /// Adds the bare ACK `number`, which left at `now` with `mark`, to the slot of the bare ACKs
    /// before it, and gives whether it could: the slot is the last packet of the path, no packet
    /// settled after it, and the space has no live ack-eliciting packet, so the slot gives no
    /// round-trip sample.
    pub(super) fn extend(&mut self, paths: &mut Paths, number: u64, now: Instant, mark: Ecn) -> bool {
        let store = &mut paths.store;
        if self.elicitors > 0 || self.last != store.last || !store.tail.is_empty() {
            return false;
        }
        let Some(slot) = store.slots.get_mut(self.last) else {
            return false;
        };
        let Some(packet) = slot
            .packet
            .as_mut()
            .filter(|packet| packet.bytes == 0 && packet.mark == mark)
        else {
            return false;
        };
        slot.through = number;
        packet.time = now;
        true
    }

    /// Whether the oldest packet of the space waited one probe timeout for an ACK, and no
    /// ack-eliciting packet of the space can bring one. Only an ACK settles a bare ACK, so the
    /// next packet then elicits one (RFC 9000, section 13.2.4).
    pub(super) fn stale(&self, paths: &Paths, now: Instant) -> bool {
        let pto = paths.active.pto(paths.active.ack_delay_max);
        self.elicitors == 0
            && paths
                .store
                .slots
                .get(self.first)
                .and_then(|slot| slot.packet.as_ref())
                .is_some_and(|packet| now.duration_since(packet.time).is_ok_and(|age| age >= pto))
    }

    /// Takes a packet out of the store. Only the path that sent it counts its bytes and its loss.
    fn remove(&mut self, paths: &mut Paths, at: usize, reason: Settlement) -> Sent {
        let Paths {
            store,
            active: path,
            validation,
            ..
        } = paths;
        let slot = store.slots.get_mut(at).expect("the packet has a slot");
        let packet = slot.packet.take().expect("only a live packet leaves the list");
        let (previous, next) = (slot.previous, core::mem::replace(&mut slot.next, store.free));
        let (left, right, gap, sampled) = (slot.path_previous, slot.path_next, slot.gap, slot.sampled);
        let sender = slot.path;
        store.free = at;
        // A walk goes to older packets, and a scan to newer ones.
        if self.near == at {
            self.near = previous;
        }
        if let Some(walk) = self.walk.as_mut().filter(|walk| walk.at == at) {
            walk.at = previous;
        }
        if let Some(scan) = self.scan.as_mut().filter(|scan| scan.at == at) {
            scan.at = next;
        }
        if let Some(before) = store.slots.get_mut(previous) {
            before.next = next;
        } else {
            self.first = next;
        }
        if let Some(after) = store.slots.get_mut(next) {
            after.previous = previous;
        } else {
            self.last = previous;
        }
        if let Some(before) = store.slots.get_mut(left) {
            before.path_next = right;
        }
        let mut middle = Gap::BARRIER;
        let mut span = None;
        if sender == path.id && matches!(reason, Settlement::Lost) {
            let time = (sampled && packet.eliciting && !packet.records.probe()).then(|| packet.time.as_nanos());
            middle = Gap {
                prefix_end: time,
                suffix_start: time,
                broken: false,
            };
            let after = store.slots.get(right).map_or(store.tail, |after| after.gap);
            let first = store.run_start(gap, left, path.id).or(time);
            if let (Some(first), Some(last)) = (first, store.run_end(after, right, path.id).or(time)) {
                span = Some((first, last));
            }
        }
        let after = if let Some(after) = store.slots.get_mut(right) {
            after.path_previous = left;
            &mut after.gap
        } else {
            store.last = left;
            &mut store.tail
        };
        *after = gap.join(middle).join(*after);
        self.bytes -= packet.bytes;
        self.elicitors -= usize::from(packet.eliciting);
        if sender == path.id {
            path.flight -= packet.bytes;
        } else if let Some(validation) = validation
            && validation.fallback.id == sender
        {
            validation.fallback.flight -= packet.bytes;
        }
        if let Some((first, last)) = span
            && path.collapsed.is_none_or(|previous| first > previous)
            && u128::from(last.saturating_sub(first)) > 3 * path.pto(path.ack_delay_max).as_nanos()
        {
            path.controller.persistent();
            path.collapsed = Some(last);
            path.reset_rtt = true;
        }
        packet
    }

    pub(super) fn discard(&mut self, paths: &mut Paths) {
        while self.first != NONE {
            self.remove(paths, self.first, Settlement::Discarded);
        }
        (self.walk, self.scan) = (None, None);
    }

    /// Checks the ECN counts of an ACK frame for the active path `path`. `marked` of its marked
    /// packets are newly acknowledged, and `elsewhere` marked packets of other paths. Gives
    /// whether a congestion mark reduced the window.
    fn validate_ecn(
        &mut self,
        path: &mut PathState,
        counts: Option<EcnCounts>,
        (marked, elsewhere): (u64, u64),
        sent: Option<Instant>,
        now: Instant,
    ) -> bool {
        if path.ecn == EcnState::Failed {
            return false;
        }
        let Some(counts) = counts else {
            if marked > 0 {
                path.ecn = EcnState::Failed;
            }
            return false;
        };
        let Some(ect) = counts.ect0.checked_sub(self.feedback.ect0) else {
            path.ecn = EcnState::Failed;
            return false;
        };
        let Some(ce) = counts.ce.checked_sub(self.feedback.ce) else {
            path.ecn = EcnState::Failed;
            return false;
        };
        if counts.ect1 != 0 || counts.ect0 + counts.ce > self.ect_sent || ect + ce < marked {
            path.ecn = EcnState::Failed;
            return false;
        }
        self.feedback = counts;
        if marked > 0 {
            path.ecn = EcnState::Capable;
        }
        // The counts are for the packet number space. A mark that a packet of another path can
        // explain is no feedback for this path (RFC 9000, section 9.4).
        let here = ce.saturating_sub(elsewhere);
        let ect = ect.saturating_sub(elsewhere - (ce - here));
        path.ecn_counts.ect0 = path.ecn_counts.ect0.saturating_add(ect);
        path.ecn_counts.ce = path.ecn_counts.ce.saturating_add(here);
        here > 0 && sent.is_some_and(|sent| path.controller.congestion(sent, now))
    }

    /// Walks the ranges and the live packets together, once, from the newest packet at or below
    /// the largest number of the frame: the packets that left after it cost no work, and a gap in
    /// packet numbers costs none either. A packet of another path gives the active path no
    /// round-trip sample, no growth, no congestion mark, and no sign that the path delivers.
    /// Gives `None` when a limit of the turn stopped the walk: give the same frame in the next
    /// turn, and the walk goes on.
    pub(super) fn ack(
        &mut self,
        ack: &Ack<'_>,
        paths: &mut Paths,
        now: Instant,
        delay: Duration,
        (work, limits): (&mut Work, &TurnLimits),
        mut delivered: impl FnMut(Record),
    ) -> Result<Option<Acked>, Error> {
        let mut walk = if let Some(walk) = self.walk.take() {
            walk
        } else {
            let advances = self.largest.is_none_or(|old| ack.largest > old);
            self.largest = Some(self.largest.map_or(ack.largest, |old| old.max(ack.largest)));
            if paths
                .store
                .slots
                .get(self.first)
                .and_then(|slot| slot.packet.as_ref())
                .is_none_or(|first| first.number > ack.largest)
            {
                return Ok(Some(Acked::default()));
            }
            Walk {
                range: 0,
                at: if self.near == NONE { self.first } else { self.near },
                located: false,
                advances,
                eliciting: false,
                grow_by: 0,
                marked: 0,
                elsewhere: 0,
                sample: None,
                round: None,
            }
        };
        while !walk.located
            && let Some(slot) = paths.store.slots.get(walk.at)
        {
            if !work.visit(limits) {
                self.walk = Some(walk);
                return Ok(None);
            }
            let newer = paths.store.slots.get(slot.next).and_then(|next| next.packet.as_ref());
            if slot.packet.as_ref().is_some_and(|packet| packet.number > ack.largest) {
                walk.at = slot.previous;
            } else if newer.is_some_and(|next| next.number <= ack.largest) {
                walk.at = slot.next;
            } else {
                walk.located = true;
            }
        }
        for (index, range) in ack.ranges().enumerate().skip(walk.range) {
            walk.range = index;
            while let Some(slot) = paths.store.slots.get(walk.at) {
                if !work.visit(limits) {
                    self.walk = Some(walk);
                    return Ok(None);
                }
                let packet = slot.packet.as_ref().expect("the send list links live packets");
                if slot.through < *range.start() {
                    break;
                }
                let previous = slot.previous;
                // A slot of bare ACKs is delivered when the range covers one of them.
                if packet.number <= *range.end() {
                    let (sent_round, sender, through) = (slot.round, slot.path, slot.through);
                    let current = sender == paths.active.id;
                    let packet = self.remove(paths, walk.at, Settlement::Delivered);
                    let path = &mut paths.active;
                    let marks = u64::from(packet.mark == Ecn::Ect0) * (through - packet.number + 1);
                    if current {
                        walk.eliciting |= packet.eliciting;
                        walk.marked += marks;
                        if path.controller.can_grow(packet.time) {
                            walk.grow_by += packet.bytes;
                        }
                        if (packet.number..=through).contains(&ack.largest) {
                            walk.sample = Some(packet.time);
                            walk.round = Some(sent_round);
                        }
                        if packet.bytes > DATAGRAM_MIN as u64 {
                            path.mtu.large_acknowledged();
                        }
                    } else {
                        walk.elsewhere += marks;
                    }
                    for record in packet.records.iter() {
                        match record {
                            // A probe settles on the path that sent it, also after the connection
                            // left that path, so the search of that path can go on.
                            Record::Mtu(size) => {
                                if let Some(owner) = paths.owner(sender) {
                                    owner.mtu.probe_acknowledged(size);
                                }
                            }
                            Record::Challenge => {}
                            record => delivered(record),
                        }
                    }
                }
                walk.at = previous;
            }
            if walk.at == NONE {
                break;
            }
        }
        self.near = walk.at;
        let Walk {
            advances,
            eliciting,
            mut grow_by,
            marked,
            elsewhere,
            sample,
            round,
            ..
        } = walk;
        let path = &mut paths.active;
        if eliciting && let Some(sent) = sample {
            path.sample(
                now.duration_since(sent).map_err(|_| super::connection::CLOCK)?,
                delay,
                now,
            );
        }
        if advances && self.validate_ecn(path, ack.ecn, (marked, elsewhere), sample, now) {
            grow_by = 0;
        }
        Ok(Some(Acked {
            eliciting,
            bytes: grow_by,
            round: round.filter(|_| eliciting),
        }))
    }

    /// Stops at the first packet of the active path below both loss thresholds. Each later packet
    /// is newer. A packet of another path waits for the time threshold of its own path. An
    /// acknowledgement that came on a faster path is no sign of its loss. Only a packet of the
    /// active path is a sign of congestion on it. A limit of the turn can stop the scan: the loss
    /// timer of the space is then due at once, and the next scan goes on from there.
    pub(super) fn detect(
        &mut self,
        paths: &mut Paths,
        now: Instant,
        (work, limits): (&mut Work, &TurnLimits),
        mut lost: impl FnMut(Record) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let previous_collapse = paths.active.collapsed;
        let mut congestion = false;
        let Scan {
            mut at,
            mut waiting,
            mut large,
        } = self.scan.take().unwrap_or(Scan {
            at: self.first,
            waiting: None,
            large: None,
        });
        while let Some(slot) = paths.store.slots.get(at)
            && let Some(packet) = slot.packet.as_ref()
        {
            if !work.visit(limits) {
                self.scan = Some(Scan { at, waiting, large });
                self.loss_time = Some(now);
                return Ok(congestion || previous_collapse != paths.active.collapsed);
            }
            let (next, sender, through) = (slot.next, slot.path, slot.through);
            let Some(largest) = self.largest.filter(|largest| *largest >= through) else {
                break;
            };
            let current = sender == paths.active.id;
            let due = packet
                .time
                .checked_add(paths.loss_delay(sender))
                .map_err(|_| super::connection::CLOCK)?;
            let reordered = current && largest - through >= PACKET_THRESHOLD;
            if !reordered && now.as_nanos() < due.as_nanos() {
                if waiting.is_none_or(|first| due.as_nanos() < first.as_nanos()) {
                    waiting = Some(due);
                }
                // Each later packet is newer. Only a packet of the fallback path has another
                // delay, and each of them went out before the active path sent.
                if current {
                    break;
                }
                at = next;
                continue;
            }
            if current && packet.bytes > 0 && !packet.records.probe() {
                congestion |= paths.active.controller.congestion(packet.time, now);
                paths.active.lost = paths.active.lost.saturating_add(1);
                large = Some(large.unwrap_or(true) && packet.bytes > DATAGRAM_MIN as u64);
            }
            let packet = self.remove(paths, at, Settlement::Lost);
            at = next;
            for record in packet.records.iter() {
                match record {
                    Record::Mtu(size) => {
                        if let Some(owner) = paths.owner(sender) {
                            owner.mtu.probe_lost(size);
                        }
                    }
                    Record::Challenge if current => {
                        if let Some(validation) = &mut paths.validation {
                            validation.send = true;
                        }
                    }
                    Record::Challenge => {}
                    record => lost(record)?,
                }
            }
        }
        self.loss_time = waiting;
        if let Some(large) = large {
            paths.active.mtu.lost(large);
        }
        Ok(congestion || previous_collapse != paths.active.collapsed)
    }
}

#[cfg(test)]
mod tests;
