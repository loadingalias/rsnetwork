//! Packet delivery and loss on one QUIC path (RFC 9000, section 13, and RFC 9002).

use core::alloc::Layout;
use core::ops::Range;
use core::time::Duration;
use std::collections::VecDeque;

use rstypes::capacity::{Budget, Credit};
use rstypes::time::Instant;

use super::congestion::{CongestionControl, Controller};
use super::frame::{Ack, EcnCounts, Frame};
use super::packet::{BuildError, Builder};
use super::reassembly::grow;
use super::stream::StreamId;
use super::{VARINT_MAX, Writer, varint_len};
use crate::drive::{Ecn, Error, Kind};

pub(super) const NO_ROOM: Error = Error::new(Kind::Overload, "the budget refused QUIC recovery state");
const GRANULARITY: Duration = Duration::from_millis(1);
const INITIAL_RTT: Duration = Duration::from_millis(333);
const PACKET_THRESHOLD: u64 = 3;

/// The delivery state of the current path. Byte counts include QUIC headers and packet protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryStats {
    /// Handshake flights that waited for more receive credit under the server amplification limit.
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

pub(super) struct Path {
    /// Remaining send credit before client address validation. A validated path has no cap.
    pub(super) amplification_credit: Option<u64>,
    pub(super) amplification_blocked: bool,
    pub(super) amplification_rounds: u64,
    pub(super) controller: Controller,
    store: Store,
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

impl Path {
    pub(super) fn new(datagram: usize, algorithm: CongestionControl, budget: &Budget) -> Self {
        Self {
            amplification_credit: None,
            amplification_blocked: false,
            amplification_rounds: 0,
            controller: Controller::new(datagram as u64, algorithm),
            store: Store::new(budget),
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

    /// Allow one millisecond of batching, up to the initial window. Before the first RTT,
    /// the initial flight can leave together (RFC 9002, section 7.7).
    pub(super) fn paced(&mut self, bytes: u64, now: Instant) -> Result<bool, Error> {
        if self.pacing_wait.is_some_and(|at| at.as_nanos() <= now.as_nanos()) {
            self.pacing_wait = None;
        }
        if bytes > self.room() {
            return Ok(false);
        }
        let initial = (10 * self.controller.datagram).min((2 * self.controller.datagram).max(14_720));
        let allowance = self.interval_ns(initial.saturating_sub(bytes));
        let allowance = if self.minimum.is_some() {
            allowance.min(1_000_000)
        } else {
            allowance
        };
        let wait = self.departure.saturating_sub(now.as_nanos()).saturating_sub(allowance);
        if wait == 0 || self.smoothed.is_zero() {
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

    pub(super) fn mark(&mut self, now: Instant) -> Ecn {
        if self.ecn == EcnState::Testing
            && self.first_mark.is_some_and(|first| {
                u128::from(now.as_nanos().saturating_sub(first.as_nanos()))
                    >= 3 * self.pto(self.ack_delay_max).as_nanos()
            })
        {
            self.ecn = EcnState::Unknown;
        }
        match self.ecn {
            EcnState::Capable => Ecn::Ect0,
            EcnState::Testing => Ecn::Ect0,
            _ => Ecn::NotEct,
        }
    }

    pub(super) fn marked(&mut self, mark: Ecn, now: Instant) {
        if mark == Ecn::Ect0 && self.ecn == EcnState::Testing {
            self.first_mark.get_or_insert(now);
            self.trial_datagrams += 1;
            if self.trial_datagrams == 10 {
                self.ecn = EcnState::Unknown;
            }
        }
    }

    pub(super) fn untracked(&mut self) {
        self.store.tail = self.store.tail.join(Gap::BARRIER);
    }

    /// The peer can negotiate a smaller maximum datagram. Preserve the number of packets in the window.
    pub(super) fn datagram_limit(&mut self, bytes: usize) {
        self.controller.datagram_limit(bytes as u64);
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
    previous: usize,
    next: usize,
    path_previous: usize,
    path_next: usize,
    gap: Gap,
    sampled: bool,
    round: u64,
}

const NONE: usize = usize::MAX;

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

/// All number spaces and side flows allocate slots here. Each slot also links its path neighbors.
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
}

#[derive(Clone, Copy)]
enum Settlement {
    Delivered,
    Lost,
    Discarded,
}

#[derive(Default)]
pub(super) struct Acked {
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
        }
    }

    pub(super) fn pto_start(&self) -> Option<Instant> {
        self.last_sent.filter(|_| self.elicitors > 0)
    }

    pub(super) fn insert(&mut self, path: &mut Path, packet: Sent) -> Result<(), Error> {
        let (bytes, eliciting, time) = (packet.bytes, packet.eliciting, packet.time);
        let store = &mut path.store;
        let slot = Slot {
            packet: Some(packet),
            previous: self.last,
            next: NONE,
            path_previous: store.last,
            path_next: NONE,
            gap: store.tail,
            sampled: path.minimum.is_some(),
            round: path.controller.round(),
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

    fn remove(&mut self, path: &mut Path, at: usize, reason: Settlement) -> Sent {
        let store = &mut path.store;
        let slot = store.slots.get_mut(at).expect("the packet has a slot");
        let packet = slot.packet.take().expect("only a live packet leaves the list");
        let (previous, next) = (slot.previous, core::mem::replace(&mut slot.next, store.free));
        let (left, right, gap, sampled) = (slot.path_previous, slot.path_next, slot.gap, slot.sampled);
        store.free = at;
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
        let after = if let Some(after) = store.slots.get_mut(right) {
            after.path_previous = left;
            &mut after.gap
        } else {
            store.last = left;
            &mut store.tail
        };
        let mut middle = Gap::BARRIER;
        let mut span = None;
        if matches!(reason, Settlement::Lost) {
            let time = (sampled && packet.eliciting).then(|| packet.time.as_nanos());
            middle = Gap {
                prefix_end: time,
                suffix_start: time,
                broken: false,
            };
            if let (Some(first), Some(last)) = (gap.suffix_start.or(time), after.prefix_end.or(time)) {
                span = Some((first, last));
            }
        }
        *after = gap.join(middle).join(*after);
        self.bytes -= packet.bytes;
        path.flight -= packet.bytes;
        self.elicitors -= usize::from(packet.eliciting);
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

    pub(super) fn discard(&mut self, path: &mut Path) {
        while self.first != NONE {
            self.remove(path, self.first, Settlement::Discarded);
        }
    }

    fn validate_ecn(
        &mut self,
        path: &mut Path,
        counts: Option<EcnCounts>,
        marked: u64,
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
        path.ecn_counts.ect0 = path.ecn_counts.ect0.saturating_add(ect);
        path.ecn_counts.ce = path.ecn_counts.ce.saturating_add(ce);
        ce > 0 && sent.is_some_and(|sent| path.controller.congestion(sent, now))
    }

    /// Walks the ranges and the live packets together, once. A gap in packet numbers costs no work.
    pub(super) fn ack(
        &mut self,
        ack: &Ack<'_>,
        path: &mut Path,
        now: Instant,
        delay: Duration,
        mut delivered: impl FnMut(Record),
    ) -> Result<Acked, Error> {
        let advances = self.largest.is_none_or(|old| ack.largest > old);
        self.largest = Some(self.largest.map_or(ack.largest, |old| old.max(ack.largest)));
        if path
            .store
            .slots
            .get(self.first)
            .and_then(|slot| slot.packet.as_ref())
            .is_none_or(|first| first.number > ack.largest)
        {
            return Ok(Acked::default());
        }
        let mut at = self.last;
        let mut eliciting = false;
        let mut grow_by = 0;
        let mut marked = 0;
        let mut sample = None;
        let mut round = None;
        for range in ack.ranges() {
            while let Some(slot) = path.store.slots.get(at) {
                let packet = slot.packet.as_ref().expect("the send list links live packets");
                if packet.number < *range.start() {
                    break;
                }
                let previous = slot.previous;
                if packet.number <= *range.end() {
                    let sent_round = slot.round;
                    let packet = self.remove(path, at, Settlement::Delivered);
                    marked += u64::from(packet.mark == Ecn::Ect0);
                    if path.controller.can_grow(packet.time) {
                        grow_by += packet.bytes;
                    }
                    if packet.number == ack.largest {
                        sample = Some(packet.time);
                        round = Some(sent_round);
                    }
                    eliciting |= packet.eliciting;
                    packet.records.iter().for_each(&mut delivered);
                }
                at = previous;
            }
            if at == NONE {
                break;
            }
        }
        if eliciting && let Some(sent) = sample {
            path.sample(
                now.duration_since(sent).map_err(|_| super::connection::CLOCK)?,
                delay,
                now,
            );
        }
        if advances && self.validate_ecn(path, ack.ecn, marked, sample, now) {
            grow_by = 0;
        }
        Ok(Acked {
            eliciting,
            bytes: grow_by,
            round: round.filter(|_| eliciting),
        })
    }

    /// Stops at the first packet below both loss thresholds. Each later packet is newer.
    pub(super) fn detect(
        &mut self,
        path: &mut Path,
        now: Instant,
        mut lost: impl FnMut(Record) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        self.loss_time = None;
        let delay = path.loss_delay();
        let previous_collapse = path.collapsed;
        let mut congestion = false;
        while let Some(packet) = path.store.slots.get(self.first).and_then(|slot| slot.packet.as_ref()) {
            // A bare ACK below no acknowledged number has no remaining RTT or loss evidence.
            if packet.bytes == 0 && self.largest.is_none_or(|largest| largest < packet.number) {
                self.remove(path, self.first, Settlement::Discarded);
                continue;
            }
            let Some(largest) = self.largest.filter(|largest| *largest >= packet.number) else {
                break;
            };
            let due = packet.time.checked_add(delay).map_err(|_| super::connection::CLOCK)?;
            if largest - packet.number < PACKET_THRESHOLD && now.as_nanos() < due.as_nanos() {
                self.loss_time = Some(due);
                break;
            }
            if packet.bytes > 0 {
                congestion |= path.controller.congestion(packet.time, now);
                path.lost = path.lost.saturating_add(1);
            }
            let packet = self.remove(path, self.first, Settlement::Lost);
            packet.records.iter().try_for_each(&mut lost)?;
        }
        Ok(congestion || previous_collapse != path.collapsed)
    }
}

#[cfg(test)]
mod tests;
