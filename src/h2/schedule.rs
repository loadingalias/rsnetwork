//! The order in which the send scheduler visits the streams whose chunk can go out (RFC 9218,
//! section 10).
//!
//! A higher urgency goes first. Of one urgency, the streams share a round-robin of turns, and each
//! turn sends one DATA frame. An incremental stream has a turn of its own. The streams that are
//! not incremental share one turn, the turn of their group, and the group sends from its first
//! stream, in the order of the stream identifiers, until that stream leaves. So an incremental
//! response and a series of responses that the client uses whole share the connection, and
//! neither starves.
//!
//! The turns of all urgencies are one ring buffer, in runs from urgency 0 to 7, and the groups
//! are a second one. Each stream is in at most one of them, so each buffer holds at most the
//! streams of the table.

use std::collections::VecDeque;

use crate::drive::{Error, Kind};
use crate::priority::Priority;

/// The turn of the group of an urgency. No stream has the identifier 0.
const GROUP: u32 = 0;

/// The urgencies of RFC 9218: 0 to 7.
const URGENCIES: usize = 8;

/// The streams whose chunk can go out, in the order of their next visit.
#[derive(Debug)]
pub(super) struct Schedule {
    /// The turns, in runs from urgency 0 to 7: an incremental stream, or [`GROUP`].
    turns: VecDeque<u32>,
    /// The streams that are not incremental, in runs from urgency 0 to 7, each run in the order
    /// of the stream identifiers.
    groups: VecDeque<u32>,
    /// The entries of each run: of `turns`, and of `groups`.
    runs: [(usize, usize); URGENCIES],
}

impl Schedule {
    /// A schedule for at most `limit` streams. The caller charged two buffers of `limit`
    /// identifiers.
    pub(super) fn new(limit: usize) -> Result<Self, Error> {
        let (mut turns, mut groups) = (VecDeque::new(), VecDeque::new());
        turns
            .try_reserve_exact(limit)
            .and_then(|()| groups.try_reserve_exact(limit))
            .map_err(|_| Error::new(Kind::Overload, "the memory for the stream table is not available"))?;
        Ok(Self {
            turns,
            groups,
            runs: [(0, 0); URGENCIES],
        })
    }

    /// Whether no stream waits.
    pub(super) fn is_empty(&self) -> bool {
        self.turns.is_empty()
    }

    /// The start of the runs of `urgency` in `turns` and in `groups`.
    fn start(&self, urgency: usize) -> (usize, usize) {
        self.runs[..urgency]
            .iter()
            .fold((0, 0), |(turns, groups), &(own, grouped)| {
                (turns + own, groups + grouped)
            })
    }

    /// Adds stream `id` of `priority`, which is not in the schedule: at the end of the turns of
    /// its urgency, or at its place in its group.
    pub(super) fn join(&mut self, id: u32, priority: Priority) {
        let urgency = usize::from(priority.urgency.get());
        let (turns, groups) = self.start(urgency);
        let (own, grouped) = self.runs[urgency];
        if priority.incremental {
            self.turns.insert(turns + own, id);
            self.runs[urgency].0 += 1;
            return;
        }
        // A new stream has the highest identifier, so it usually goes at the end of its group.
        let end = groups + grouped;
        let place = if grouped == 0 || self.groups[end - 1] < id {
            end
        } else {
            groups + self.groups.range(groups..end).take_while(|&&other| other < id).count()
        };
        self.groups.insert(place, id);
        self.runs[urgency].1 += 1;
        if grouped == 0 {
            self.turns.insert(turns + own, GROUP);
            self.runs[urgency].0 += 1;
        }
    }

    /// Removes stream `id` of `priority`, which is in the schedule. A group with no stream left
    /// loses its turn.
    pub(super) fn leave(&mut self, id: u32, priority: Priority) {
        let urgency = usize::from(priority.urgency.get());
        let (turns, groups) = self.start(urgency);
        let (own, grouped) = self.runs[urgency];
        let (queue, start, len, member) = if priority.incremental {
            (&mut self.turns, turns, own, id)
        } else {
            (&mut self.groups, groups, grouped, id)
        };
        let at = queue.range(start..start + len).position(|&other| other == member);
        let at = at.expect("each stream of the schedule is in the run of its priority");
        queue.remove(start + at);
        if priority.incremental {
            self.runs[urgency].0 -= 1;
            return;
        }
        self.runs[urgency].1 -= 1;
        if grouped == 1 {
            self.remove_turn(urgency, turns, GROUP);
        }
    }

    /// Removes the turn `member` from the run of `urgency`, which starts at `turns`.
    fn remove_turn(&mut self, urgency: usize, turns: usize, member: u32) {
        let own = self.runs[urgency].0;
        let at = self.turns.range(turns..turns + own).position(|&other| other == member);
        self.turns
            .remove(turns + at.expect("each group with a stream has its turn"));
        self.runs[urgency].0 -= 1;
    }

    /// The stream that sends next: of the first turn of the highest urgency, the stream of its
    /// own, or the first stream of its group.
    pub(super) fn front(&self) -> Option<u32> {
        let urgency = self.runs.iter().position(|&(own, _)| own > 0)?;
        let (turns, groups) = self.start(urgency);
        match self.turns[turns] {
            GROUP => Some(self.groups[groups]),
            id => Some(id),
        }
    }

    /// Ends the turn of the front, which sent one frame: it goes to the end of the turns of its
    /// urgency. `stays` tells whether its stream can send again. A stream that cannot leaves, and
    /// so does the turn of a group with no stream left.
    pub(super) fn advance(&mut self, stays: bool) {
        let Some(urgency) = self.runs.iter().position(|&(own, _)| own > 0) else {
            return;
        };
        let (turns, groups) = self.start(urgency);
        let member = self.turns.remove(turns).expect("the front has a turn");
        self.runs[urgency].0 -= 1;
        if member == GROUP && !stays {
            self.groups.remove(groups);
            self.runs[urgency].1 -= 1;
        }
        if (member == GROUP && self.runs[urgency].1 > 0) || (member != GROUP && stays) {
            let own = self.runs[urgency].0;
            self.turns.insert(turns + own, member);
            self.runs[urgency].0 += 1;
        }
    }
}
