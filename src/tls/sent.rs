//! The plaintext that the transport accepted: the record layer marks each plaintext region that it
//! seals, and maps the ciphertext that the transport accepts back to whole records of them.

use std::collections::VecDeque;

use core::num::NonZeroUsize;

use rstypes::capacity::{Budget, Permit};

use super::record::{HEADER, TAG};
use crate::drive::{Accepted, Error, reserve};

/// The ciphertext bytes that one data record adds to its content: its header, its content type,
/// and its tag. The record layer adds no padding.
const OVERHEAD: u64 = (HEADER + 1 + TAG) as u64;

/// A run of the records of one plaintext region in one output: its records are the ciphertext
/// from `start` to `end`, in the order of the output.
#[derive(Clone, Copy, Debug)]
struct Mark {
    start: u64,
    end: u64,
    /// The plaintext bytes of the run.
    len: u64,
    /// The plaintext bytes of each record of the run but the last.
    record: u64,
    /// The run holds body bytes.
    payload: bool,
}

/// The sealed plaintext regions whose records the transport has not accepted, and the plaintext
/// of the regions that it accepted.
#[derive(Debug)]
pub(super) struct Sent {
    marks: VecDeque<Mark>,
    /// The most marks: the limit of the plaintext queue. When the marks are full, the record
    /// layer seals no more until the transport accepts ciphertext.
    max: usize,
    _charge: Permit,
    /// The plaintext of the regions whose records the transport accepted.
    done: Accepted,
}

impl Sent {
    /// Makes room for `max` marks, charged to `budget`.
    pub(super) fn new(max: NonZeroUsize, budget: &Budget) -> Result<Self, Error> {
        let (marks, charge) = reserve(max, budget)?;
        Ok(Self {
            marks,
            max: max.get(),
            _charge: charge,
            done: Accepted::default(),
        })
    }

    /// The marks that are free. With none, the record layer waits for the transport before it
    /// seals another region.
    pub(super) fn free(&self) -> usize {
        self.max - self.marks.len()
    }

    /// Marks a run of `len` plaintext bytes in records of `record` bytes, but the last, whose
    /// ciphertext goes from `start` to `end`. The caller checked that a mark is free.
    pub(super) fn push(&mut self, start: u64, end: u64, len: usize, record: usize, payload: bool) {
        assert!(
            self.free() > 0,
            "the record layer seals a region only when a mark is free"
        );
        self.marks.push_back(Mark {
            start,
            end,
            len: len as u64,
            record: record as u64,
            payload,
        });
    }

    /// Drops the marks of the regions whose records the transport accepted, when it accepted
    /// `accepted` bytes of the ciphertext.
    pub(super) fn settle(&mut self, accepted: u64) {
        while let Some(mark) = self.marks.front()
            && mark.end <= accepted
        {
            self.done.add(mark.len, mark.payload);
            self.marks.pop_front();
        }
    }

    /// The plaintext whose records the transport accepted, when it accepted `accepted` bytes of
    /// the ciphertext. A record counts when each of its bytes went. In the region in which this
    /// end changed its key, the records count when the region is complete.
    pub(super) fn sent(&self, accepted: u64) -> Accepted {
        let mut sent = self.done;
        for mark in &self.marks {
            if mark.end <= accepted {
                sent.add(mark.len, mark.payload);
                continue;
            }
            let records = mark.len.div_ceil(mark.record.max(1));
            // Each record but the last holds `record` bytes. A KeyUpdate inside the run makes it
            // longer, and then no part of it counts.
            if accepted > mark.start && mark.end - mark.start == mark.len + records * OVERHEAD {
                let whole = (accepted - mark.start) / (mark.record + OVERHEAD);
                sent.add(whole * mark.record, mark.payload);
            }
            break;
        }
        sent
    }
}
