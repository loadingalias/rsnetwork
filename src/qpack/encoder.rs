//! The encoder: one field section at a time into the free capacity of a region of the caller,
//! and its insertions into a region of the encoder stream.

use core::fmt;
use std::collections::VecDeque;

use rstypes::buffer::{BufferMut, WriteLoan};
use rstypes::capacity::{Budget, Permit};

use super::table::{Dynamic, STATIC, find_static};
use super::{EncodeError, EncoderLimits, FieldLine, Full, Prefix, Settings, Stash, StreamError, free, put};
use crate::drive::{Error, Kind};
use crate::hpack::table::{OVERHEAD, Table};
use crate::hpack::{huffman, integer, sensitive};

/// The QPACK encoder of one connection: the one owner of its dynamic table.
///
/// [`new`](Self::new) charges and allocates all of its memory: the dynamic table and the list of
/// field sections that wait for their acknowledgement. No other call allocates.
pub struct Encoder {
    table: Dynamic,
    limits: EncoderLimits,
    /// The Known Received Count: the insertions that the decoder acknowledged (RFC 9204, section
    /// 2.1.4).
    known: u64,
    peer: Option<Settings>,
    /// The capacity that the next Set Dynamic Table Capacity sets, until it goes out.
    capacity: Option<usize>,
    /// Each field section with references to the dynamic table that waits for its
    /// acknowledgement, oldest first. It holds at most `sections`.
    sections: VecDeque<Section>,
    stash: Stash,
    scan: Option<FeedbackScan>,
    /// An instruction on the decoder stream failed.
    failed: bool,
    _charge: Permit,
}

/// A field section that waits for its acknowledgement.
#[derive(Clone, Copy)]
struct Section {
    stream: u64,
    /// Its Required Insert Count.
    required: u64,
    /// The smallest absolute index that it references. The entries from it on cannot be evicted.
    oldest: u64,
}

/// The unvisited prefix of the section FIFO. Visited survivors rotate to the back.
struct FeedbackScan {
    action: Feedback,
    left: usize,
    rotated: bool,
}
#[derive(Clone, Copy)]
enum Feedback {
    Acknowledge(u64),
    Cancel(u64),
    Restore,
}

/// The state of one encode.
struct Encode {
    /// The end of the encoder-stream bytes that the caller can send.
    instruction_end: usize,
    /// The Base of the section: the Insert Count before its insertions.
    base: u64,
    /// The references can name only entries with an absolute index below it.
    below: u64,
    /// The entries from this absolute index on cannot be evicted.
    pinned: u64,
    /// One more than the largest absolute index that the section references.
    required: u64,
    /// The smallest absolute index that the section references.
    oldest: u64,
}

impl Encoder {
    /// Makes an encoder for `limits`. It charges its dynamic table of `table_bytes` and a list of
    /// `sections` sections to `budget` before it allocates. It refuses with [`Kind::Overload`],
    /// with no allocation, when the budget cannot pay.
    ///
    /// Until [`set_peer`](Self::set_peer), the capacity of the peer is zero, so the encoder uses
    /// only the static table and literals (RFC 9204, section 3.2.3).
    pub fn new(limits: EncoderLimits, budget: &Budget) -> Result<Self, Error> {
        let memory = Table::memory(limits.table_bytes)
            .and_then(|table| limits.sections.checked_mul(size_of::<Section>())?.checked_add(table))
            .ok_or(Error::new(Kind::Overload, "the encoder is too large"))?;
        let charge = budget
            .reserve(memory as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the encoder"))?;
        let unavailable = Error::new(Kind::Overload, "the memory for the encoder is not available");
        let table = Dynamic::new(limits.table_bytes).ok_or(unavailable)?;
        let mut sections = VecDeque::new();
        sections.try_reserve_exact(limits.sections).map_err(|_| unavailable)?;
        Ok(Self {
            table,
            limits,
            known: 0,
            peer: None,
            capacity: None,
            sections,
            stash: Stash::default(),
            scan: None,
            failed: false,
            _charge: charge,
        })
    }

    /// Sets the settings that the peer's decoder sent. The capacity of the table becomes the
    /// smaller of the two limits, and the next encode sets it on the encoder stream.
    ///
    /// It refuses with [`EncodeError::Settings`], and changes nothing, after earlier settings.
    pub fn set_peer(&mut self, peer: Settings) -> Result<(), EncodeError> {
        if self.peer.is_some() {
            return Err(EncodeError::Settings);
        }
        self.peer = Some(peer);
        let capacity =
            usize::try_from(peer.table_bytes).map_or(self.limits.table_bytes, |peer| peer.min(self.limits.table_bytes));
        // A capacity below the size of the smallest entry holds no entry.
        self.capacity = (capacity >= OVERHEAD).then_some(capacity);
        Ok(())
    }

    /// The longest lines of a section that [`encode`](Self::encode) can give for `lines`: the
    /// free bytes that it needs in its region.
    pub(crate) fn needed<'a>(&self, lines: impl Iterator<Item = FieldLine<'a>>) -> usize {
        // The largest index: the static table, or the entries of the largest table.
        let index = (STATIC.len() + self.table.ring.limit() / OVERHEAD) as u64;
        lines.fold(0, |needed: usize, line| {
            needed
                .saturating_add(integer::len(index.max(line.name.len() as u64), 3))
                .saturating_add(line.name.len())
                .saturating_add(integer::len(line.value.len() as u64, 7))
                .saturating_add(line.value.len())
        })
    }

    /// Encodes `lines` as the field section of `stream`, in their order. It writes the lines
    /// after the filled bytes of `section`, and its insertions into `instructions`, the next
    /// bytes of the encoder stream. It gives the prefix of the section, which comes before the
    /// lines.
    ///
    /// A line is an index when a table entry has its name and value. Otherwise, it goes into the
    /// dynamic table when the table and `instructions` have room for it, and then it is an index
    /// when the section can name the new entry. Else it is a literal, with the index of its
    /// name when an entry has the name. A string is a Huffman string when that is shorter. A
    /// line that the caller marks [`never_indexed`](FieldLine::never_indexed), or that the
    /// sensitive-field rule selects, is a literal that is never indexed: it never goes into the
    /// table.
    ///
    /// A section names entries that the decoder did not acknowledge only while the peer permits
    /// one more blocked stream (RFC 9204, section 2.1.2). An insertion evicts only entries that
    /// the decoder acknowledged and that no section that waits references (section 2.1.1). An
    /// instruction goes into `instructions` only whole, so a section always encodes, also with
    /// no room on the encoder stream (section 2.1.3).
    ///
    /// Refuses with [`EncodeError::Full`], and writes and changes nothing, if `section` has fewer
    /// free bytes than the longest lines that `lines` can give.
    pub fn encode<'a, B: BufferMut, C: BufferMut>(
        &mut self,
        stream: u64,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        section: &mut WriteLoan<B>,
        instructions: &mut WriteLoan<C>,
    ) -> Result<Prefix, EncodeError> {
        self.encode_with_credit(stream, lines, section, instructions, usize::MAX)
    }

    pub(crate) fn encode_with_credit<'a, B: BufferMut, C: BufferMut>(
        &mut self,
        stream: u64,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        section: &mut WriteLoan<B>,
        instructions: &mut WriteLoan<C>,
        credit: usize,
    ) -> Result<Prefix, EncodeError> {
        let needed = self.needed(lines.clone());
        let available = free(section);
        if needed > available {
            return Err(EncodeError::Full(Full { needed, available }));
        }
        let room = free(instructions).min(credit);
        let instruction_end = instructions.filled().len() + room;
        if let Some(capacity) = self.capacity
            && integer::len(capacity as u64, 5) <= room
        {
            put(instructions, capacity as u64, 5, 0x20);
            self.table.ring.set_max(capacity);
            self.capacity = None;
        }
        let peer = self.peer.unwrap_or_default();
        let entries = peer.table_bytes / OVERHEAD as u64;
        let known = self.known;
        let waits = |section: &&Section| section.required > known;
        // A stream that waits already blocks no more streams.
        let blocking = self
            .sections
            .iter()
            .filter(waits)
            .any(|section| section.stream == stream)
            || (self.sections.iter().filter(waits).count() as u64) < peer.blocked_streams;
        let below = if entries == 0 || self.sections.len() >= self.limits.sections || self.scan.is_some() {
            0
        } else if blocking {
            u64::MAX
        } else {
            known
        };
        let mut encode = Encode {
            instruction_end,
            base: self.table.inserted,
            below,
            pinned: self.sections.iter().map(|section| section.oldest).fold(known, u64::min),
            required: 0,
            oldest: u64::MAX,
        };
        for line in lines {
            self.line(line, &mut encode, section, instructions);
        }
        let mut prefix = Prefix { bytes: [0; 22], len: 0 };
        let mut write = |bytes: &[u8]| {
            prefix.bytes[prefix.len..prefix.len + bytes.len()].copy_from_slice(bytes);
            prefix.len += bytes.len();
        };
        let Encode { base, required, .. } = encode;
        if required == 0 {
            write(&[0, 0]);
        } else {
            // A reference needs a capacity of at least one entry, so `entries` is not zero.
            integer::encode(required % (2 * entries) + 1, 8, 0x00, &mut write);
            if base >= required {
                integer::encode(base - required, 7, 0x00, &mut write);
            } else {
                integer::encode(required - base - 1, 7, 0x80, &mut write);
            }
            // The list has the capacity of `sections`, and `below` was zero when it was full.
            self.sections.push_back(Section {
                stream,
                required,
                oldest: encode.oldest,
            });
        }
        Ok(prefix)
    }

    /// Encodes one line of a section (RFC 9204, section 4.5).
    fn line<B: BufferMut, C: BufferMut>(
        &mut self,
        line: FieldLine<'_>,
        encode: &mut Encode,
        section: &mut WriteLoan<B>,
        instructions: &mut WriteLoan<C>,
    ) {
        let never_indexed = line.never_indexed || sensitive(line.name, line.value);
        let (exact_static, named_static) = find_static(line.name, line.value);
        if let Some(index) = exact_static.filter(|_| !never_indexed) {
            put(section, index as u64, 6, 0xc0);
            return;
        }
        let (exact, mut named) = self.table.find(line.name, line.value, encode.below);
        let mut reference = exact.filter(|&index| !never_indexed && index < encode.below);
        if !never_indexed && exact.is_none() && self.insert(line, named_static, encode, instructions) {
            let index = self.table.inserted - 1;
            if index < encode.below {
                reference = Some(index);
            } else {
                // The insertion can evict the entry of the name.
                named = self.table.find(line.name, line.value, encode.below).1;
            }
        }
        if let Some(index) = reference {
            if index < encode.base {
                put(section, encode.base - 1 - index, 6, 0x80);
            } else {
                put(section, index - encode.base, 4, 0x10);
            }
            encode.refer(index);
            return;
        }
        let flag = |set: u8| if never_indexed { set } else { 0 };
        match (named_static, named) {
            (Some(index), _) => put(section, index as u64, 4, 0x50 | flag(0x20)),
            (None, Some(index)) => {
                if index < encode.base {
                    put(section, encode.base - 1 - index, 4, 0x40 | flag(0x20));
                } else {
                    put(section, index - encode.base, 3, flag(0x08));
                }
                encode.refer(index);
            }
            (None, None) => string(section, line.name, 3, 0x20 | flag(0x10)),
        }
        string(section, line.value, 7, 0x00);
    }

    /// Inserts `line` into the dynamic table (RFC 9204, section 4.3) when the table has room
    /// for it after the eviction of only entries below `pinned`, and `out` has room for the whole
    /// instruction. Gives whether it inserted.
    fn insert<C: BufferMut>(
        &mut self,
        line: FieldLine<'_>,
        named_static: Option<usize>,
        encode: &Encode,
        out: &mut WriteLoan<C>,
    ) -> bool {
        let size = line
            .name
            .len()
            .saturating_add(line.value.len())
            .saturating_add(OVERHEAD);
        let capacity = self.table.ring.max();
        if size > capacity {
            return false;
        }
        // The oldest entries go first, and each of them must be evictable.
        let mut room = capacity - self.table.ring.size();
        let mut position = self.table.ring.len();
        while room < size {
            let Some(next) = position.checked_sub(1) else {
                return false;
            };
            position = next;
            let Some((name, value)) = self.table.ring.get(position) else {
                return false;
            };
            if self.table.inserted - 1 - position as u64 >= encode.pinned {
                return false;
            }
            room += name.len() + value.len() + OVERHEAD;
        }
        // The decoder reads a name reference before the insertion evicts its entry.
        let named = named_static
            .is_none()
            .then(|| self.table.find(line.name, line.value, u64::MAX).1)
            .flatten();
        let relative = |index: u64| self.table.inserted - 1 - index;
        let len = match (named_static, named) {
            (Some(index), _) => integer::len(index as u64, 6),
            (None, Some(index)) => integer::len(relative(index), 6),
            (None, None) => string_len(line.name, 5),
        } + string_len(line.value, 7);
        if len > encode.instruction_end - out.filled().len() {
            return false;
        }
        match (named_static, named) {
            (Some(index), _) => put(out, index as u64, 6, 0xc0),
            (None, Some(index)) => put(out, relative(index), 6, 0x80),
            (None, None) => string(out, line.name, 5, 0x40),
        }
        string(out, line.value, 7, 0x00);
        self.table.insert(line.name, line.value);
        true
    }

    /// Reads the next bytes of the decoder stream (RFC 9204, section 4.4). An instruction can end
    /// in a later call. Each instruction costs at most one pass over the sections that wait.
    ///
    /// An instruction that breaks RFC 9204 gives [`StreamError::Decoder`], and the encoder
    /// refuses each later call.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut rest = bytes;
        loop {
            let used = self.receive_part(rest, usize::MAX, usize::MAX)?;
            rest = &rest[used..];
            if rest.is_empty() && self.scan.is_none() {
                return Ok(());
            }
        }
    }

    #[cfg(feature = "tls")]
    pub(crate) fn feedback_pending(&self) -> bool {
        self.scan.is_some()
    }

    /// Advances a bounded number of instructions and section visits. An unfinished scan also accepts empty input.
    pub(crate) fn receive_part(
        &mut self,
        bytes: &[u8],
        mut instructions: usize,
        mut visits: usize,
    ) -> Result<usize, StreamError> {
        if self.failed {
            return Err(StreamError::Decoder);
        }
        let mut rest = bytes;
        let result = (|| {
            loop {
                if let Some(scan) = &mut self.scan {
                    while scan.left > 0 && visits > 0 {
                        let section = self.sections.pop_front().expect("the scan owns its unvisited prefix");
                        visits -= 1;
                        scan.left -= 1;
                        match scan.action {
                            Feedback::Acknowledge(id) if section.stream == id => {
                                self.known = self.known.max(section.required);
                                // An acknowledgement of the front entry leaves the FIFO in order.
                                if !scan.rotated {
                                    scan.left = 0;
                                }
                                scan.action = Feedback::Restore;
                            }
                            Feedback::Cancel(id) if section.stream == id => {}
                            _ => {
                                self.sections.push_back(section);
                                scan.rotated = true;
                            }
                        }
                    }
                    if scan.left != 0 {
                        break;
                    }
                    if matches!(scan.action, Feedback::Acknowledge(_)) {
                        return Err(());
                    }
                    self.scan = None;
                }
                if instructions == 0 || rest.is_empty() {
                    break;
                }
                let first = self.stash.first(rest).expect("the input has at least one byte");
                let prefix = if first >= 0x80 { 7 } else { 6 };
                let Some((value, first)) = self.stash.integer(&mut rest, prefix)? else {
                    break;
                };
                instructions -= 1;
                let action = match first {
                    0x80.. => Feedback::Acknowledge(value),
                    0x40.. => Feedback::Cancel(value),
                    _ => {
                        self.known = self
                            .known
                            .checked_add(value)
                            .filter(|&known| value > 0 && known <= self.table.inserted)
                            .ok_or(())?;
                        continue;
                    }
                };
                self.scan = Some(FeedbackScan {
                    action,
                    left: self.sections.len(),
                    rotated: false,
                });
            }
            Ok(bytes.len() - rest.len())
        })();
        result.map_err(|()| {
            self.failed = true;
            StreamError::Decoder
        })
    }
}

impl Encode {
    /// Records a reference of the section to the entry with absolute index `index`.
    fn refer(&mut self, index: u64) {
        self.required = self.required.max(index + 1);
        self.oldest = self.oldest.min(index);
        self.pinned = self.pinned.min(index);
    }
}

/// The length of the string literal of `bytes` with a length prefix of `prefix` bits.
fn string_len(bytes: &[u8], prefix: u32) -> usize {
    let len = huffman::encoded_len(bytes.iter().copied()).min(bytes.len());
    integer::len(len as u64, prefix) + len
}

/// Writes `bytes` as a string literal (RFC 9204, section 4.1.2) with a length prefix of `prefix`
/// bits after the `flags` bits: a Huffman string when it is shorter.
fn string<B: BufferMut>(out: &mut WriteLoan<B>, bytes: &[u8], prefix: u32, flags: u8) {
    let huffman = huffman::encoded_len(bytes.iter().copied());
    if huffman < bytes.len() {
        put(out, huffman as u64, prefix, flags | 1 << prefix);
        huffman::encode(bytes.iter().copied(), |piece| {
            out.fill_from(piece);
        });
    } else {
        put(out, bytes.len() as u64, prefix, flags);
        out.fill_from(bytes);
    }
}

impl fmt::Debug for Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encoder")
            .field("limits", &self.limits)
            .field("peer", &self.peer)
            .field("inserted", &self.table.inserted)
            .field("known", &self.known)
            .field("entries", &self.table.ring.len())
            .field("sections", &self.sections.len())
            .finish_non_exhaustive()
    }
}
