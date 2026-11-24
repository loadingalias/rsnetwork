//! Packet delivery and loss on one QUIC path (RFC 9000, section 13, and RFC 9002).

use core::alloc::Layout;
use core::ops::Range;
use core::time::Duration;
use std::collections::VecDeque;

use rstypes::capacity::{Budget, Credit};
use rstypes::time::Instant;

use super::frame::{Ack, Frame};
use super::packet::{BuildError, Builder};
use super::reassembly::grow;
use super::stream::StreamId;
use super::{VARINT_MAX, Writer, varint_len};
use crate::drive::{Error, Kind};

pub(super) const NO_ROOM: Error = Error::new(Kind::Overload, "the budget refused QUIC recovery state");
const GRANULARITY: Duration = Duration::from_millis(1);
const INITIAL_RTT: Duration = Duration::from_millis(333);
const PACKET_THRESHOLD: u64 = 3;

/// The delivery state of the current path. Byte counts include QUIC headers and packet protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryStats {
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
}

/// The congestion controller of one path. Each packet number space uses the same window.
trait Controller {
    fn window(&self) -> u64;
    fn datagram_limit(&mut self, bytes: u64);
    fn can_grow(&self, sent: Instant) -> bool;
    fn lost(&mut self, sent: Instant, now: Instant) -> bool;
    fn acknowledged(&mut self, bytes: u64);
}

struct NewReno {
    datagram: u64,
    window: u64,
    threshold: u64,
    recovery: Option<Instant>,
    /// Bytes acknowledged in congestion avoidance toward the next one-datagram increase.
    increase: u64,
}

impl NewReno {
    fn new(datagram: u64) -> Self {
        Self {
            datagram,
            window: (10 * datagram).min((2 * datagram).max(14_720)),
            threshold: u64::MAX,
            recovery: None,
            increase: 0,
        }
    }
}

impl Controller for NewReno {
    fn window(&self) -> u64 {
        self.window
    }

    fn datagram_limit(&mut self, bytes: u64) {
        if bytes < self.datagram {
            let scale = |n| {
                u64::try_from(u128::from(n) * u128::from(bytes) / u128::from(self.datagram))
                    .expect("the datagram limit only decreases")
            };
            self.window = scale(self.window).max(2 * bytes);
            if self.threshold != u64::MAX {
                self.threshold = scale(self.threshold);
            }
            self.increase = scale(self.increase);
            self.datagram = bytes;
        }
    }

    fn can_grow(&self, sent: Instant) -> bool {
        self.recovery.is_none_or(|start| sent.as_nanos() > start.as_nanos())
    }

    fn lost(&mut self, sent: Instant, now: Instant) -> bool {
        if !self.can_grow(sent) {
            return false;
        }
        self.recovery = Some(now);
        self.threshold = (self.window / 2).max(2 * self.datagram);
        self.window = self.threshold;
        self.increase = 0;
        true
    }

    fn acknowledged(&mut self, bytes: u64) {
        if self.window < self.threshold {
            self.window = self.window.saturating_add(bytes);
        } else {
            self.increase = self.increase.saturating_add(bytes);
            if self.increase >= self.window {
                self.increase -= self.window;
                self.window = self.window.saturating_add(self.datagram);
            }
        }
    }
}

pub(super) struct Path {
    controller: NewReno,
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
    pub(super) fn new(datagram: usize) -> Self {
        Self {
            controller: NewReno::new(datagram as u64),
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
            bytes_in_flight: self.flight,
            congestion_window: self.controller.window(),
            latest_rtt: self.minimum.map(|_| self.latest),
            smoothed_rtt: self.minimum.map(|_| self.smoothed),
            packets_lost: self.lost,
            probes_sent: self.probes,
        }
    }

    pub(super) fn room(&self) -> u64 {
        self.controller.window().saturating_sub(self.flight)
    }

    pub(super) fn sent(&mut self, bytes: u64) {
        self.flight += bytes;
    }

    /// The peer can negotiate a smaller maximum datagram. Preserve the number of packets in the window.
    pub(super) fn datagram_limit(&mut self, bytes: usize) {
        self.controller.datagram_limit(bytes as u64);
    }

    pub(super) fn acknowledged(&mut self, bytes: u64) {
        self.controller.acknowledged(bytes);
    }

    pub(super) fn discard(&mut self, bytes: u64) {
        self.flight -= bytes;
        self.backoff = 0;
    }

    pub(super) fn pto(&self, ack_delay: Duration) -> Duration {
        self.smoothed + (4 * self.variation).max(GRANULARITY) + ack_delay
    }

    fn sample(&mut self, latest: Duration, delay: Duration) {
        self.latest = latest;
        let Some(previous) = self.minimum else {
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
}

impl Received {
    pub(super) fn new(window: u64, budget: &Budget) -> Self {
        Self {
            ranges: VecDeque::new(),
            largest_at: None,
            window,
            credit: budget.credit(0),
            due: false,
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
    pub(super) fn accept(&mut self, number: u64, now: Instant, eliciting: bool) -> Result<(), Error> {
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
        let mut writer = Writer::new(out);
        writer.u8(0x02)?;
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
}

/// Slots in send order. Removal unlinks two neighbors. The next insertion reuses the free slot.
struct Slot {
    packet: Option<Sent>,
    previous: usize,
    next: usize,
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

pub(super) struct History {
    slots: Slots,
    first: usize,
    last: usize,
    free: usize,
    credit: Credit,
    pub(super) bytes: u64,
    elicitors: usize,
    last_sent: Option<Instant>,
    pub(super) largest: Option<u64>,
    pub(super) loss_time: Option<Instant>,
}

impl History {
    pub(super) fn new(budget: &Budget) -> Self {
        Self {
            slots: Slots::default(),
            first: NONE,
            last: NONE,
            free: NONE,
            credit: budget.credit(0),
            bytes: 0,
            elicitors: 0,
            last_sent: None,
            largest: None,
            loss_time: None,
        }
    }

    pub(super) fn pto_start(&self) -> Option<Instant> {
        self.last_sent.filter(|_| self.elicitors > 0)
    }

    pub(super) fn insert(&mut self, packet: Sent) -> Result<(), Error> {
        let (bytes, eliciting, time) = (packet.bytes, packet.eliciting, packet.time);
        let slot = Slot {
            packet: Some(packet),
            previous: self.last,
            next: NONE,
        };
        let at = if let Some(free) = self.slots.get_mut(self.free) {
            let at = core::mem::replace(&mut self.free, free.next);
            *free = slot;
            at
        } else {
            self.slots.push(slot, &mut self.credit)?
        };
        self.bytes += bytes;
        if eliciting {
            self.elicitors += 1;
            self.last_sent = Some(time);
        }
        if let Some(last) = self.slots.get_mut(self.last) {
            last.next = at;
        } else {
            self.first = at;
        }
        self.last = at;
        Ok(())
    }

    fn remove(&mut self, at: usize) -> Sent {
        let slot = self.slots.get_mut(at).expect("the packet has a slot");
        let packet = slot.packet.take().expect("only a live packet leaves the list");
        let (previous, next) = (slot.previous, core::mem::replace(&mut slot.next, self.free));
        self.free = at;
        if let Some(before) = self.slots.get_mut(previous) {
            before.next = next;
        } else {
            self.first = next;
        }
        if let Some(after) = self.slots.get_mut(next) {
            after.previous = previous;
        } else {
            self.last = previous;
        }
        self.bytes -= packet.bytes;
        self.elicitors -= usize::from(packet.eliciting);
        packet
    }

    /// Walks the ranges and the live packets together, once. A gap in packet numbers costs no work.
    pub(super) fn ack(
        &mut self,
        ack: &Ack<'_>,
        path: &mut Path,
        now: Instant,
        delay: Duration,
        mut delivered: impl FnMut(Record),
    ) -> Result<(bool, u64), Error> {
        self.largest = Some(self.largest.map_or(ack.largest, |old| old.max(ack.largest)));
        if self
            .slots
            .get(self.first)
            .and_then(|slot| slot.packet.as_ref())
            .is_none_or(|first| first.number > ack.largest)
        {
            return Ok((false, 0));
        }
        let mut at = self.last;
        let mut eliciting = false;
        let mut grow_by = 0;
        let mut sample = None;
        for range in ack.ranges() {
            while let Some(slot) = self.slots.get(at) {
                let packet = slot.packet.as_ref().expect("the send list links live packets");
                if packet.number < *range.start() {
                    break;
                }
                let previous = slot.previous;
                if packet.number <= *range.end() {
                    let packet = self.remove(at);
                    path.flight -= packet.bytes;
                    if path.controller.can_grow(packet.time) {
                        grow_by += packet.bytes;
                    }
                    if packet.number == ack.largest {
                        sample = Some(packet.time);
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
            path.sample(now.duration_since(sent).map_err(|_| super::connection::CLOCK)?, delay);
        }
        Ok((eliciting, grow_by))
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
        let mut congestion = false;
        while let Some(packet) = self.slots.get(self.first).and_then(|slot| slot.packet.as_ref()) {
            // A bare ACK older than every live elicitor can no longer supply an RTT sample.
            if packet.bytes == 0 {
                self.remove(self.first);
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
            let packet = self.remove(self.first);
            path.flight -= packet.bytes;
            path.lost = path.lost.saturating_add(1);
            congestion |= path.controller.lost(packet.time, now);
            packet.records.iter().try_for_each(&mut lost)?;
        }
        Ok(congestion)
    }
}

#[cfg(test)]
mod tests;
