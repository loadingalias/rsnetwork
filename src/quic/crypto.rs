//! The CRYPTO stream of one encryption level (RFC 9000, section 19.6, and RFC 9001, section 4):
//! the received handshake bytes, in order for rustls, and the messages of rustls to send.
//!
//! A CRYPTO frame arrives in a decrypted packet in the received region. Its bytes are copied once
//! into the buffer of their level, because rustls reads one ordered byte stream and the frames of
//! a flight can arrive in any order and across packets. The buffer holds the bytes from the first
//! byte that rustls did not consume, up to [`CRYPTO_BUFFER_BYTES_MAX`] after it, and each growth
//! is charged before it is allocated.

use core::mem::size_of;
use core::ops::Range;
use std::collections::VecDeque;

use rstypes::capacity::{Budget, Credit};
use rustls::TlsInputBuffer;

use super::ErrorCode;

/// The CRYPTO bytes that one level buffers past the first byte that rustls did not consume: the
/// largest handshake message that rustls reads, 2^16 - 1 bytes, with its 4-byte header. So no
/// message that rustls accepts, such as a Certificate with a post-quantum chain, is refused.
pub const CRYPTO_BUFFER_BYTES_MAX: usize = 4 + 0xffff;
/// The ranges of received bytes, with gaps between them, that one level keeps. A peer that
/// sends more pieces out of order closes its connection.
const RANGES_MAX: usize = 64;
/// The smallest growth of a receive buffer.
const GROWTH_MIN: usize = 4096;

/// Why CRYPTO data refused: the connection closes with `code`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// The data passed the bound, or its pieces passed [`RANGES_MAX`]: `CRYPTO_BUFFER_EXCEEDED`.
    Bound,
    /// The budget refused the memory: `CRYPTO_BUFFER_EXCEEDED` too, because this end cannot
    /// buffer the data.
    Budget,
}

impl Refused {
    pub(super) const fn code(self) -> ErrorCode {
        ErrorCode::CRYPTO_BUFFER_EXCEEDED
    }
}

/// The received CRYPTO bytes of one level.
#[derive(Debug)]
pub(super) struct Receive {
    /// The stream offset of `bytes[0]`.
    base: u64,
    /// The bytes from `base`. Each range of `ranges` holds data, and each gap holds zeros.
    bytes: Vec<u8>,
    /// The stream offset of the first byte that rustls did not consume.
    consumed: u64,
    /// The stream offsets of the received data past `consumed`, sorted and apart.
    ranges: Vec<Range<u64>>,
    credit: Credit,
}

impl Receive {
    pub(super) fn new(budget: &Budget) -> Self {
        Self {
            base: 0,
            bytes: Vec::new(),
            consumed: 0,
            ranges: Vec::new(),
            credit: budget.credit(0),
        }
    }

    /// Takes the data of a CRYPTO frame at `offset`. Data that rustls consumed is ignored.
    pub(super) fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), Refused> {
        let end = offset.checked_add(data.len() as u64).ok_or(Refused::Bound)?;
        if end <= self.consumed {
            return Ok(());
        }
        let skip = self.consumed.saturating_sub(offset);
        let (offset, data) = (
            offset + skip,
            &data[usize::try_from(skip).map_err(|_| Refused::Bound)?..],
        );
        if end - self.consumed > CRYPTO_BUFFER_BYTES_MAX as u64 {
            return Err(Refused::Bound);
        }
        self.room(end)?;
        let at = usize::try_from(offset - self.base).map_err(|_| Refused::Bound)?;
        self.bytes[at..at + data.len()].copy_from_slice(data);
        self.mark(offset..end)
    }

    /// Makes `bytes` reach the stream offset `end`: it moves the consumed bytes out, and grows
    /// the buffer under its charge.
    fn room(&mut self, end: u64) -> Result<(), Refused> {
        let consumed = usize::try_from(self.consumed - self.base).map_err(|_| Refused::Bound)?;
        let needed = usize::try_from(end - self.base).map_err(|_| Refused::Bound)?;
        if needed <= self.bytes.len() {
            return Ok(());
        }
        if consumed > 0 {
            self.bytes.drain(..consumed);
            self.base = self.consumed;
        }
        let needed = usize::try_from(end - self.base).map_err(|_| Refused::Bound)?;
        if needed > self.bytes.capacity() {
            let target = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .clamp(GROWTH_MIN, CRYPTO_BUFFER_BYTES_MAX)
                .max(needed);
            let growth = target - self.bytes.capacity();
            self.credit.charge(growth as u64).map_err(|_| Refused::Budget)?;
            if self.bytes.try_reserve_exact(target - self.bytes.len()).is_err() {
                let refunded = self.credit.refund(growth as u64);
                assert!(refunded.is_ok(), "a credit refunds what it charged");
                return Err(Refused::Budget);
            }
        }
        self.bytes.resize(needed, 0);
        Ok(())
    }

    /// Adds `range` to the received ranges, and joins the ranges that touch it.
    fn mark(&mut self, range: Range<u64>) -> Result<(), Refused> {
        if self.ranges.capacity() == 0 {
            let bytes = (RANGES_MAX + 1) * size_of::<Range<u64>>();
            self.credit.charge(bytes as u64).map_err(|_| Refused::Budget)?;
            if self.ranges.try_reserve_exact(RANGES_MAX + 1).is_err() {
                let refunded = self.credit.refund(bytes as u64);
                assert!(refunded.is_ok(), "a credit refunds what it charged");
                return Err(Refused::Budget);
            }
        }
        let at = self.ranges.partition_point(|r| r.end < range.start);
        let mut joined = range;
        let mut last = at;
        while let Some(next) = self.ranges.get(last)
            && next.start <= joined.end
        {
            joined = joined.start.min(next.start)..joined.end.max(next.end);
            last += 1;
        }
        self.ranges.splice(at..last, [joined]);
        if self.ranges.len() > RANGES_MAX {
            return Err(Refused::Bound);
        }
        Ok(())
    }

    /// The stream offset of the first byte that rustls did not consume.
    pub(super) const fn consumed(&self) -> u64 {
        self.consumed
    }

    /// The bytes after `consumed` that arrived with no gap.
    pub(super) fn ordered(&self) -> usize {
        match self.ranges.first() {
            Some(first) if first.start <= self.consumed => {
                usize::try_from(first.end - self.consumed).expect("the buffered bytes fit their bound")
            }
            _ => 0,
        }
    }
}

impl TlsInputBuffer for Receive {
    fn slice_mut(&mut self) -> &mut [u8] {
        let start = usize::try_from(self.consumed - self.base).expect("the consumed bytes are in the buffer");
        let end = start + self.ordered();
        &mut self.bytes[start..end]
    }

    fn discard(&mut self, len: usize) {
        let len = len.min(self.ordered());
        self.consumed += len as u64;
        if let Some(first) = self.ranges.first_mut() {
            first.start = first.start.max(self.consumed);
            if first.is_empty() {
                self.ranges.remove(0);
            }
        }
    }

    // QUIC carries no TLS alert and no end of input: a CONNECTION_CLOSE frame ends a connection.
    fn received_close_notify(&mut self) {}

    fn has_seen_eof(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct Message {
    start: u64,
    bytes: Vec<u8>,
    remaining: usize,
}

/// The memory of the entry of one message in its list. A message adds one entry at most.
pub(super) const ENTRY_BYTES: u64 = size_of::<Message>() as u64;

/// The CRYPTO messages of one level until their acknowledgement or the discard of its keys.
///
/// The list takes no charge of its own: the connection charges [`bytes`](Self::bytes) to the
/// output of its rustls calls. A message comes from a call, so its charge is the one that the
/// call reserved, and no new charge can fail after rustls wrote the message.
#[derive(Debug)]
pub(super) struct Send {
    messages: VecDeque<Message>,
    /// The stream offset of the next byte to send.
    next: u64,
    /// The stream offset after the last message.
    end: u64,
    /// The capacity of the bytes of the messages that wait.
    held: u64,
}

impl Send {
    pub(super) const fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            next: 0,
            end: 0,
            held: 0,
        }
    }

    /// Queues `message` after the others. Refuses when the allocator gives no entry: the message
    /// then drops.
    pub(super) fn push(&mut self, message: Vec<u8>) -> Result<(), Refused> {
        if message.is_empty() {
            return Ok(());
        }
        let start = self.end;
        let remaining = message.len();
        let end = start
            .checked_add(remaining as u64)
            .filter(|end| *end <= super::VARINT_MAX)
            .ok_or(Refused::Bound)?;
        // The list grows by one entry, so the entries of one call stay within its reservation.
        self.messages.try_reserve_exact(1).map_err(|_| Refused::Budget)?;
        self.held += message.capacity() as u64;
        self.messages.push_back(Message {
            start,
            bytes: message,
            remaining,
        });
        self.end = end;
        Ok(())
    }

    /// The memory of the messages that wait and of their list.
    pub(super) fn bytes(&self) -> u64 {
        self.messages.capacity() as u64 * ENTRY_BYTES + self.held
    }

    /// Whether bytes wait to be sent.
    pub(super) const fn pending(&self) -> bool {
        self.next < self.end
    }

    /// Resends the ClientHello after a Retry, before any server packet acknowledged it.
    pub(super) fn rewind(&mut self) {
        self.next = 0;
    }

    /// Borrows up to `room` bytes of one CRYPTO message with its stream offset.
    pub(super) fn next(&self, room: usize) -> Option<(u64, &[u8])> {
        self.retained(self.next, room).map(|bytes| (self.next, bytes))
    }

    pub(super) fn retained(&self, offset: u64, room: usize) -> Option<&[u8]> {
        let at = self
            .messages
            .partition_point(|message| message.start <= offset)
            .checked_sub(1)?;
        let message = &self.messages[at];
        let bytes = message.bytes.get(usize::try_from(offset - message.start).ok()?..)?;
        let len = room.min(bytes.len());
        (len > 0).then(|| &bytes[..len])
    }

    /// Takes the acknowledgement of `len` bytes at `offset`, and gives the bytes of the message
    /// that it completed, which leave [`bytes`](Self::bytes).
    pub(super) fn acknowledged(&mut self, offset: u64, len: usize) -> u64 {
        let at = self.messages.partition_point(|message| message.start <= offset) - 1;
        let message = &mut self.messages[at];
        message.remaining -= len;
        if message.remaining > 0 {
            return 0;
        }
        let bytes = core::mem::take(&mut message.bytes).capacity() as u64;
        self.held -= bytes;
        while self.messages.front().is_some_and(|m| m.remaining == 0) {
            self.messages.pop_front();
        }
        bytes
    }

    /// Marks `len` more bytes as sent.
    pub(super) fn sent(&mut self, len: usize) {
        self.next = (self.next + len as u64).min(self.end);
    }
}
