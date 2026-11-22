//! The encoder: one header block at a time, into the free capacity of a region of the caller.

use core::fmt;

use rstypes::buffer::{BufferMut, WriteLoan};
use rstypes::capacity::{Budget, Permit};

use super::table::{OVERHEAD, STATIC, Table};
use super::{EncodeError, FieldLine, huffman, integer, sensitive};
use crate::drive::{Error, Kind};

/// The maximum size of a dynamic table when an HTTP/2 connection starts: the initial value of
/// `SETTINGS_HEADER_TABLE_SIZE` (RFC 9113, section 6.5.2).
const INITIAL: usize = 4096;

/// The HPACK encoder of one connection: the one owner of its dynamic table.
///
/// [`new`](Self::new) charges and allocates its dynamic table. [`encode`](Self::encode) never
/// allocates: it writes into the free capacity of the caller's region.
pub struct Encoder {
    table: Table,
    /// The smallest maximum size since the last block, when the maximum size changed. The next
    /// block signals it, and then the maximum size (RFC 7541, section 4.2).
    low: Option<usize>,
    _charge: Permit,
}

impl Encoder {
    /// Makes an encoder whose dynamic table holds at most `table_bytes`. It charges the table to
    /// `budget` before it allocates, and refuses with [`Kind::Overload`], with no allocation,
    /// when the budget cannot pay.
    ///
    /// The peer's limit starts at 4096, the initial `SETTINGS_HEADER_TABLE_SIZE` of HTTP/2. The
    /// maximum size of the table is the smaller of the two limits. When it is not 4096, the
    /// first block signals it.
    pub fn new(table_bytes: usize, budget: &Budget) -> Result<Self, Error> {
        let memory = Table::memory(table_bytes).ok_or(Error::new(Kind::Overload, "the encoder is too large"))?;
        let charge = budget
            .reserve(memory as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the encoder"))?;
        let mut table = Table::new(table_bytes).ok_or(Error::new(
            Kind::Overload,
            "the memory for the encoder is not available",
        ))?;
        let max = table_bytes.min(INITIAL);
        table.set_max(max);
        Ok(Self {
            table,
            low: (max != INITIAL).then_some(max),
            _charge: charge,
        })
    }

    /// Sets the limit of the peer's decoder: the `SETTINGS_HEADER_TABLE_SIZE` that the peer
    /// sent. The maximum size of the table becomes the smaller of `limit` and the limit of the
    /// encoder, and the next block signals a change.
    pub fn set_peer_limit(&mut self, limit: usize) {
        let max = limit.min(self.table.limit());
        if max != self.table.max() {
            self.table.set_max(max);
            self.low = Some(self.low.map_or(max, |low| low.min(max)));
        }
    }

    /// The longest block that [`encode`](Self::encode) can give for `lines` now: the free bytes
    /// that it needs in its output region.
    pub(crate) fn needed<'a>(&self, lines: impl Iterator<Item = FieldLine<'a>>) -> usize {
        let max = self.table.max();
        let updates = self
            .low
            .map_or(0, |low| integer::len(low as u64, 5) + integer::len(max as u64, 5));
        // The largest index in the block: the dynamic table holds at most `max / 32` entries.
        let index = (STATIC.len() + max / OVERHEAD) as u64;
        lines.fold(updates, |needed, line| {
            needed
                .saturating_add(integer::len(index, 4))
                .saturating_add(string_len(line.name))
                .saturating_add(string_len(line.value))
        })
    }

    /// Encodes `lines` as one header block, in their order, after the filled bytes of `out`.
    /// Each name goes in lowercase, as HTTP/2 requires (RFC 9113, section 8.2.1).
    ///
    /// A line is indexed when an entry has its name and value. Otherwise, it is a literal with
    /// the index of its name when an entry has the name, and it goes into the dynamic table when
    /// it fits. A string is a Huffman string when that is shorter. A line that the caller marks
    /// [`never_indexed`](FieldLine::never_indexed), or that the sensitive-field rule selects, is
    /// a literal that is never indexed: it never goes into the table and is never sent as an
    /// index.
    ///
    /// Refuses, and writes and changes nothing, if `out` has fewer free bytes than the longest
    /// block that `lines` can give.
    pub fn encode<'a, B: BufferMut>(
        &mut self,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        out: &mut WriteLoan<B>,
    ) -> Result<(), EncodeError> {
        let max = self.table.max();
        let needed = self.needed(lines.clone());
        let available = out.capacity() - out.filled().len();
        if needed > available {
            return Err(EncodeError::Full { needed, available });
        }
        let mut put = |bytes: &[u8]| {
            out.fill_from(bytes);
        };
        if let Some(low) = self.low.take() {
            integer::encode(low as u64, 5, 0x20, &mut put);
            if low != max {
                integer::encode(max as u64, 5, 0x20, &mut put);
            }
        }
        for line in lines {
            let never_indexed = line.never_indexed || sensitive(line.name, line.value);
            let (exact, named) = self.table.find(line.name, line.value);
            if let Some(index) = exact.filter(|_| !never_indexed) {
                integer::encode(index as u64, 7, 0x80, &mut put);
                continue;
            }
            let size = line
                .name
                .len()
                .saturating_add(line.value.len())
                .saturating_add(OVERHEAD);
            let insert = !never_indexed && size <= self.table.max();
            let (prefix, flags) = match (insert, never_indexed) {
                (true, _) => (6, 0x40),
                (false, true) => (4, 0x10),
                (false, false) => (4, 0x00),
            };
            match named {
                Some(index) => integer::encode(index as u64, prefix, flags, &mut put),
                None => {
                    put(&[flags]);
                    name(line.name, &mut put);
                }
            }
            string(line.value, &mut put);
            if insert {
                self.table.insert_folded(line.name, line.value);
            }
        }
        Ok(())
    }
}

/// The longest string literal of `bytes`: its length and its bytes, with no Huffman coding.
fn string_len(bytes: &[u8]) -> usize {
    integer::len(bytes.len() as u64, 7).saturating_add(bytes.len())
}

/// Writes `bytes` as a string literal (RFC 7541, section 5.2): a Huffman string when it is
/// shorter.
fn string(bytes: &[u8], put: &mut impl FnMut(&[u8])) {
    let huffman = huffman::encoded_len(bytes.iter().copied());
    if huffman < bytes.len() {
        integer::encode(huffman as u64, 7, 0x80, &mut *put);
        huffman::encode(bytes.iter().copied(), put);
    } else {
        integer::encode(bytes.len() as u64, 7, 0x00, &mut *put);
        put(bytes);
    }
}

/// Writes the name `bytes` in lowercase as a string literal, as [`string`] does.
fn name(bytes: &[u8], put: &mut impl FnMut(&[u8])) {
    let folded = || bytes.iter().map(u8::to_ascii_lowercase);
    let huffman = huffman::encoded_len(folded());
    if huffman < bytes.len() {
        integer::encode(huffman as u64, 7, 0x80, &mut *put);
        huffman::encode(folded(), put);
    } else {
        integer::encode(bytes.len() as u64, 7, 0x00, &mut *put);
        let mut piece = [0_u8; 64];
        for chunk in bytes.chunks(piece.len()) {
            let piece = &mut piece[..chunk.len()];
            piece.copy_from_slice(chunk);
            piece.make_ascii_lowercase();
            put(piece);
        }
    }
}

impl fmt::Debug for Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("limit", &self.table.limit())
            .field("max", &self.table.max())
            .field("entries", &self.table.len())
            .finish_non_exhaustive()
    }
}
