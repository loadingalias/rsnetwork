//! The plaintext that the transport accepted: the record layer marks each plaintext region that it
//! seals, and maps the ciphertext that the transport accepts back to whole records of them.

use std::collections::VecDeque;

use core::num::NonZeroUsize;

use rstypes::capacity::{Budget, Permit};

use super::record::{CONTENT_MAX, HEADER, TAG};
use crate::drive::{Accepted, Error, reserve};

/// The ciphertext bytes that one data record adds to its content: its header, its content type,
/// and its tag. The record layer adds no padding.
const OVERHEAD: u64 = (HEADER + 1 + TAG) as u64;

/// One plaintext region that the record layer sealed: its records are the ciphertext from `start`
/// to `end`, in the order of the output.
#[derive(Clone, Copy, Debug)]
struct Mark {
    start: u64,
    end: u64,
    /// The plaintext bytes of the region.
    len: u64,
    /// The region holds body bytes.
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

    /// Whether the record layer must wait for the transport before it seals another region.
    pub(super) fn full(&self) -> bool {
        self.marks.len() >= self.max
    }

    /// Marks a region of `len` plaintext bytes, whose records are the ciphertext from `start` to
    /// `end`. The caller checked that the marks are not full.
    pub(super) fn push(&mut self, start: u64, end: u64, len: usize, payload: bool) {
        assert!(!self.full(), "the record layer seals a region only when a mark is free");
        self.marks.push_back(Mark {
            start,
            end,
            len: len as u64,
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
            let records = mark.len.div_ceil(CONTENT_MAX as u64);
            // Each record but the last holds `CONTENT_MAX` bytes. A KeyUpdate inside the region
            // makes it longer, and then no part of it counts.
            if accepted > mark.start && mark.end - mark.start == mark.len + records * OVERHEAD {
                let whole = (accepted - mark.start) / (CONTENT_MAX as u64 + OVERHEAD);
                sent.add(whole * CONTENT_MAX as u64, mark.payload);
            }
            break;
        }
        sent
    }
}
