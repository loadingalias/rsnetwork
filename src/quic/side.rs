//! Admission and recovery for side datagrams. The extension owns its wire format and payloads.

use core::time::Duration;

use rstypes::capacity::{Budget, Credit};
use rstypes::time::Instant;

use super::VARINT_MAX;
use super::frame::Ack;
use super::reassembly::grow;
use super::recovery::{History, NO_ROOM, Paths, Records, Sent};
use crate::drive::{Ecn, Error, Kind, TurnLimits, Work};

/// The limits of the work of a call of the side flow API, which is no drive turn: the walk of
/// an acknowledgement costs one visit for each packet that it settles or passes.
const CALL: TurnLimits = TurnLimits {
    bytes: u64::MAX,
    frames: usize::MAX,
    visits: usize::MAX,
};

/// A side-flow packet number space on the connection that opened it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SideFlow(u64);

/// One side datagram admitted to the parent path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideDatagram {
    /// The packet number in this side flow.
    pub number: u64,
    /// The ECN codepoint for the host to apply.
    pub ecn: Ecn,
}

struct Space {
    id: SideFlow,
    next: u64,
    history: History,
    waiting: bool,
}

pub(super) struct Flows {
    spaces: Vec<Space>,
    credit: Credit,
    limit: u16,
    next: u64,
    deadline: Option<Instant>,
    oldest: Option<(Instant, SideFlow)>,
    last_probe: Option<Instant>,
    pub(super) notify_probe: Option<SideFlow>,
    waiting: usize,
    sweep: Option<Sweep>,
}

/// A timer sweep that a limit of a turn stopped: the next flow, and the earliest loss time and
/// the oldest probe start of the flows before it.
#[derive(Clone, Copy, Default)]
struct Sweep {
    next: usize,
    deadline: Option<Instant>,
    oldest: Option<(Instant, SideFlow)>,
}

impl Flows {
    pub(super) fn new(budget: &Budget, limit: u16) -> Self {
        Self {
            spaces: Vec::new(),
            credit: budget.credit(0),
            limit,
            next: 0,
            deadline: None,
            oldest: None,
            last_probe: None,
            notify_probe: None,
            waiting: 0,
            sweep: None,
        }
    }

    pub(super) fn open(&mut self) -> Result<SideFlow, Error> {
        if self.spaces.len() >= usize::from(self.limit) || self.next > VARINT_MAX {
            return Err(Error::new(Kind::Overload, "the QUIC side flows reached their limit"));
        }
        let spaces = &mut self.spaces;
        grow(
            (spaces.len(), spaces.capacity(), size_of::<Space>()),
            &mut self.credit,
            |n| spaces.try_reserve_exact(n).is_ok(),
        )
        .map_err(|_| NO_ROOM)?;
        let id = SideFlow(self.next);
        self.next += 1;
        spaces.push(Space {
            id,
            next: 0,
            history: History::new(),
            waiting: false,
        });
        Ok(id)
    }

    fn index(&self, id: SideFlow) -> Result<usize, Error> {
        self.spaces
            .binary_search_by_key(&id, |space| space.id)
            .map_err(|_| Error::new(Kind::Misuse, "the QUIC side flow is not open"))
    }

    pub(super) fn close(&mut self, id: SideFlow, paths: &mut Paths) -> Result<(), Error> {
        let index = self.index(id)?;
        let mut space = self.spaces.remove(index);
        self.sweep = None;
        self.waiting -= usize::from(space.waiting);
        space.history.discard(paths);
        if self.notify_probe == Some(id) {
            self.notify_probe = None;
        }
        self.refresh();
        Ok(())
    }

    /// Admits one side datagram to the active path, under its window, its pacer, and its
    /// amplification limit, which the connection shares with its side flows.
    pub(super) fn admit(
        &mut self,
        id: SideFlow,
        paths: &mut Paths,
        bytes: u64,
        now: Instant,
        control_pending: bool,
    ) -> Result<Option<SideDatagram>, Error> {
        let index = self.index(id)?;
        let space = &mut self.spaces[index];
        if space.next > VARINT_MAX {
            return Err(Error::new(
                Kind::Overload,
                "the QUIC side flow reached its packet number limit",
            ));
        }
        let path = &mut paths.active;
        if control_pending || !path.allows(bytes) || !path.paced(bytes, now)? {
            if !core::mem::replace(&mut space.waiting, true) {
                self.waiting += 1;
            }
            return Ok(None);
        }
        let number = space.next;
        let (ecn, _) = path.mark(now);
        space.history.insert(
            paths,
            Sent {
                number,
                time: now,
                bytes,
                eliciting: true,
                records: Records::default(),
                mark: ecn,
            },
        )?;
        space.history.ect_sent += u64::from(ecn == Ecn::Ect0);
        paths.active.charge(bytes);
        paths.active.marked(ecn, 1, now);
        space.next += 1;
        self.waiting -= usize::from(core::mem::take(&mut space.waiting));
        if self.oldest.is_none_or(|(_, oldest)| oldest == id) {
            self.refresh_oldest();
        }
        Ok(Some(SideDatagram { number, ecn }))
    }

    pub(super) fn waiting(&self) -> bool {
        self.waiting != 0
    }

    pub(super) fn acknowledge(
        &mut self,
        id: SideFlow,
        paths: &mut Paths,
        ack: &Ack<'_>,
        delay: Duration,
        now: Instant,
        limited: bool,
    ) -> Result<(), Error> {
        let index = self.index(id)?;
        let space = &mut self.spaces[index];
        if ack.largest >= space.next || !ack.valid() {
            self.close(id, paths)?;
            return Err(Error::new(
                Kind::Malformed,
                "the QUIC side acknowledgement has invalid packet numbers or counts",
            ));
        }
        paths.active.controller.limited(now, limited);
        let work = &mut Work::default();
        let acked = space
            .history
            .ack(ack, paths, now, delay, (work, &CALL), |_| {})?
            .expect("a call has no visit limit");
        let delivered = acked.eliciting;
        let congestion = space.history.detect(paths, now, (work, &CALL), |_| Ok(()))?;
        paths.active.acknowledged(acked, now, limited && !congestion);
        if let Some(at) = space.history.loss_time
            && self.deadline.is_none_or(|old| old.as_nanos() > at.as_nanos())
        {
            self.deadline = Some(at);
        }
        if delivered {
            if self.notify_probe == Some(id) {
                self.notify_probe = None;
            }
            paths.active.backoff = 0;
        }
        if self.oldest.is_some_and(|(_, oldest)| oldest == id) {
            self.refresh_oldest();
        }
        Ok(())
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub(super) fn probe(&mut self, id: SideFlow, now: Instant) {
        self.last_probe = Some(now);
        self.notify_probe = Some(id);
    }

    pub(super) fn probe_start(&self) -> Option<(Instant, SideFlow)> {
        let (sent, id) = self.oldest?;
        let base = self
            .last_probe
            .filter(|probe| probe.as_nanos() > sent.as_nanos())
            .unwrap_or(sent);
        Some((base, id))
    }

    fn refresh_oldest(&mut self) {
        self.oldest = self
            .spaces
            .iter()
            .filter_map(|s| s.history.pto_start().map(|at| (at, s.id)))
            .min_by_key(|(at, _)| at.as_nanos());
    }

    fn refresh(&mut self) {
        self.refresh_oldest();
        self.deadline = self
            .spaces
            .iter()
            .filter_map(|space| space.history.loss_time)
            .min_by_key(|at| at.as_nanos());
    }

    /// Runs the loss scan of each flow that is due, and finds the next deadline and the oldest
    /// probe start on the way. A limit of the turn can stop the sweep: the deadline is then due at
    /// once, and the next sweep goes on from that flow.
    pub(super) fn timers(
        &mut self,
        paths: &mut Paths,
        now: Instant,
        (work, limits): (&mut Work, &TurnLimits),
    ) -> Result<(), Error> {
        if !self.deadline.is_some_and(|at| at.as_nanos() <= now.as_nanos()) {
            return Ok(());
        }
        let mut sweep = self.sweep.take().unwrap_or_default();
        let due = |history: &History| history.loss_time.is_some_and(|at| at.as_nanos() <= now.as_nanos());
        while let Some(space) = self.spaces.get_mut(sweep.next) {
            // A scan that a limit stopped is due at once, so the sweep stops at its flow.
            let stopped = !work.visit(limits) || {
                if due(&space.history) {
                    space.history.detect(paths, now, (work, limits), |_| Ok(()))?;
                }
                due(&space.history)
            };
            if stopped {
                self.sweep = Some(sweep);
                self.deadline = Some(now);
                return Ok(());
            }
            sweep.deadline = super::connection::earlier(sweep.deadline, space.history.loss_time);
            if let Some(at) = space.history.pto_start()
                && sweep.oldest.is_none_or(|(first, _)| at.as_nanos() < first.as_nanos())
            {
                sweep.oldest = Some((at, space.id));
            }
            sweep.next += 1;
        }
        (self.deadline, self.oldest) = (sweep.deadline, sweep.oldest);
        Ok(())
    }
}
