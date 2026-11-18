//! The decoder: the encoder stream into the dynamic table, and one field section at a time into
//! the lines that the caller lends.

use core::fmt;

use rstypes::buffer::{BufferMut, WriteLoan};
use rstypes::capacity::{Budget, Permit};

use super::table::{Dynamic, STATIC};
use super::{Block, DecodeError, Full, Limits, Stash, StreamError, free, put};
use crate::drive::{Error, Kind};
use crate::hpack;
use crate::hpack::decoder::{Buffer, Part, Representation, Span, string};
use crate::hpack::huffman::Partial;
use crate::hpack::integer;
use crate::hpack::table::{Bytes, OVERHEAD, Table};

/// The QPACK decoder of one connection: the one owner of its dynamic table.
///
/// [`new`](Self::new) charges and allocates all of its memory: the dynamic table, the space for
/// the entry that an instruction inserts, and the list of blocked streams. No other call
/// allocates.
pub struct Decoder {
    table: Dynamic,
    limits: Limits,
    /// The Known Received Count that the decoder stream gave the encoder so far.
    known: u64,
    /// Each blocked stream, with the Required Insert Count of its field section. It holds at
    /// most `blocked_streams`.
    blocked: Vec<(u64, u64)>,
    reader: Reader,
    /// An instruction on the encoder stream failed, so the table is not known.
    failed: bool,
    _charge: Permit,
}

/// The space for the decoded lines of one field section, which the caller lends to
/// [`Decoder::decode`].
///
/// [`new`](Self::new) charges and allocates it for the limits of a decoder. Between two
/// sections, a connection needs only its decoder, so a host can take lines from a pool for each
/// section.
#[derive(Debug)]
pub struct Lines(hpack::Lines);

/// The reader of the encoder stream: where it is in an instruction that the end of a read cut.
struct Reader {
    step: Step,
    stash: Stash,
    huffman: Partial,
    /// The name and then the value of the entry that the instruction inserts. It holds at most
    /// the largest capacity, so a write into it never allocates.
    entry: Vec<u8>,
}

/// The next part of an instruction on the encoder stream (RFC 9204, section 4.3).
#[derive(Clone, Copy)]
enum Step {
    /// The first byte and the integer of an instruction.
    Start,
    /// The length of the value of an insertion, after a name of `name` bytes.
    Length { name: usize },
    /// `left` more bytes of the name of an insertion, when `name` is `None`, or of its value
    /// after a name of `name` bytes.
    String {
        left: usize,
        huffman: bool,
        name: Option<usize>,
    },
}

impl Decoder {
    /// Makes a decoder for `limits`. It charges its dynamic table of `table_bytes`, the space for
    /// one entry of `table_bytes`, and a list of `blocked_streams` streams to `budget` before it
    /// allocates. It refuses with [`Kind::Overload`], with no allocation, when the budget cannot
    /// pay.
    pub fn new(limits: Limits, budget: &Budget) -> Result<Self, Error> {
        let memory = Table::memory(limits.table_bytes)
            .and_then(|table| table.checked_add(limits.table_bytes))
            .and_then(|memory| {
                limits
                    .blocked_streams
                    .checked_mul(size_of::<(u64, u64)>())?
                    .checked_add(memory)
            })
            .ok_or(Error::new(Kind::Overload, "the decoder is too large"))?;
        let charge = budget
            .reserve(memory as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the decoder"))?;
        let unavailable = Error::new(Kind::Overload, "the memory for the decoder is not available");
        let table = Dynamic::new(limits.table_bytes).ok_or(unavailable)?;
        let mut entry = Vec::new();
        entry.try_reserve_exact(limits.table_bytes).map_err(|_| unavailable)?;
        let mut blocked = Vec::new();
        blocked
            .try_reserve_exact(limits.blocked_streams)
            .map_err(|_| unavailable)?;
        Ok(Self {
            table,
            limits,
            known: 0,
            blocked,
            reader: Reader {
                step: Step::Start,
                stash: Stash::default(),
                huffman: Partial::default(),
                entry,
            },
            failed: false,
            _charge: charge,
        })
    }

    /// Reads the next bytes of the encoder stream, and gives the number of bytes that it read.
    ///
    /// An instruction can end in a later call: the decoder keeps its state. A call stops at the
    /// first step after its work reaches `work`, and then it read fewer bytes than `bytes`: give
    /// the rest in the next call. One step copies at most two entries of the table. After the
    /// call, [`unblocked`](Self::unblocked) gives each stream whose field section can now decode.
    ///
    /// It writes an Insert Count Increment for the new entries into `out` when `out` has room for
    /// it. Otherwise, a later call that has room writes it.
    ///
    /// An instruction that breaks RFC 9204 gives [`StreamError::Encoder`]. The state of the
    /// table is then not known, and the decoder refuses each later call.
    pub fn receive<B: BufferMut>(&mut self, bytes: &[u8], out: &mut WriteLoan<B>) -> Result<usize, StreamError> {
        if self.failed {
            return Err(StreamError::Encoder);
        }
        let mut rest = bytes;
        let mut work = 0_usize;
        while !rest.is_empty() && (work == 0 || work < self.limits.work) {
            match self.step(&mut rest, &mut work) {
                Ok(()) => {}
                Err(()) => {
                    self.failed = true;
                    return Err(StreamError::Encoder);
                }
            }
        }
        self.increment(out);
        Ok(bytes.len() - rest.len())
    }

    /// Reads one step of an instruction from `rest`, and adds its work to `work`.
    fn step(&mut self, rest: &mut &[u8], work: &mut usize) -> Result<(), ()> {
        let before = rest.len();
        let reader = &mut self.reader;
        match reader.step {
            Step::Start => {
                let Some(first) = reader.stash.first(rest) else {
                    return Ok(());
                };
                let prefix = match first {
                    0x80.. => 6,
                    _ => 5,
                };
                let Some((value, first)) = reader.stash.integer(rest, prefix)? else {
                    return Ok(());
                };
                reader.entry.clear();
                // The room for the name and the value of an entry in the capacity.
                let room = self.table.ring.max().checked_sub(OVERHEAD);
                match first {
                    0x80.. => {
                        // Insert with Name Reference (RFC 9204, section 4.3.2).
                        let name = if first & 0x40 != 0 {
                            let (name, _) = STATIC.get(usize::try_from(value).map_err(|_| ())?).ok_or(())?;
                            Bytes(name, &[])
                        } else {
                            self.table
                                .ring
                                .get(usize::try_from(value).map_err(|_| ())?)
                                .ok_or(())?
                                .0
                        };
                        if name.len() > room.ok_or(())? {
                            return Err(());
                        }
                        reader.entry.extend_from_slice(name.0);
                        reader.entry.extend_from_slice(name.1);
                        *work += name.len();
                        reader.step = Step::Length { name: name.len() };
                    }
                    0x40.. => {
                        // Insert with Literal Name (RFC 9204, section 4.3.3).
                        room.ok_or(())?;
                        let left = usize::try_from(value).map_err(|_| ())?;
                        reader.start(left, first & 0x20 != 0, None);
                    }
                    0x20.. => {
                        // Set Dynamic Table Capacity (RFC 9204, section 4.3.1).
                        let capacity = usize::try_from(value)
                            .ok()
                            .filter(|&capacity| capacity <= self.limits.table_bytes)
                            .ok_or(())?;
                        self.table.ring.set_max(capacity);
                    }
                    _ => {
                        // Duplicate (RFC 9204, section 4.3.4). The copy keeps the entry when the
                        // insertion evicts it.
                        let (name, entry_value) =
                            self.table.ring.get(usize::try_from(value).map_err(|_| ())?).ok_or(())?;
                        for part in [name.0, name.1, entry_value.0, entry_value.1] {
                            reader.entry.extend_from_slice(part);
                        }
                        let len = reader.entry.len();
                        *work += 2 * len;
                        self.table
                            .insert(&reader.entry[..name.len()], &reader.entry[name.len()..]);
                    }
                }
            }
            Step::Length { name } => {
                let Some((value, first)) = reader.stash.integer(rest, 7)? else {
                    return Ok(());
                };
                reader.start(usize::try_from(value).map_err(|_| ())?, first & 0x80 != 0, Some(name));
            }
            Step::String { left, huffman, name } => {
                // A piece costs its bytes and its decoded bytes: at most three times its bytes.
                let take = left
                    .min(rest.len())
                    .min((self.limits.work.saturating_sub(*work) / 3).max(1));
                let (piece, after) = rest.split_at(take);
                *rest = after;
                let room = self.table.ring.max().checked_sub(OVERHEAD).ok_or(())?;
                let start = reader.entry.len();
                if huffman {
                    let decoded = reader.huffman.decode(piece, &mut reader.entry, room).map_err(|_| ())?;
                    if start + decoded > room {
                        return Err(());
                    }
                } else if start + take > room {
                    return Err(());
                } else {
                    reader.entry.extend_from_slice(piece);
                }
                *work += reader.entry.len() - start;
                reader.step = Step::String {
                    left: left - take,
                    huffman,
                    name,
                };
            }
        }
        *work += before - rest.len();
        // A string that is complete ends its part of the instruction.
        if let Step::String { left: 0, huffman, name } = reader.step {
            if huffman {
                reader.huffman.finish().map_err(|_| ())?;
            }
            match name {
                None => {
                    reader.step = Step::Length {
                        name: reader.entry.len(),
                    }
                }
                Some(name) => {
                    // The checks of each piece keep the entry in the capacity.
                    self.table.insert(&reader.entry[..name], &reader.entry[name..]);
                    *work += reader.entry.len();
                    reader.step = Step::Start;
                }
            }
        }
        Ok(())
    }

    /// Decodes one complete field section of `stream`, the payload of a HEADERS frame, into
    /// `lines`.
    ///
    /// Gives the lines of the section, or an error. The block borrows `lines`. A section whose
    /// lines are larger than `list_bytes` gives [`DecodeError::TooLarge`]. A section that names
    /// entries that did not arrive gives [`DecodeError::Blocked`], and the stream waits.
    ///
    /// After a section with references to the dynamic table, the decoder writes its Section
    /// Acknowledgment into `out` (RFC 9204, section 4.4.1). A section that needs one refuses
    /// with [`DecodeError::Full`] when `out` has no room for it.
    pub fn decode<'l, B: BufferMut>(
        &mut self,
        stream: u64,
        section: &[u8],
        lines: &'l mut Lines,
        out: &mut WriteLoan<B>,
    ) -> Result<Block<'l>, DecodeError> {
        if self.failed {
            return Err(DecodeError::Malformed);
        }
        let lines = &mut lines.0;
        if lines.room < self.limits.list_bytes || lines.count < self.limits.list_bytes / OVERHEAD {
            return Err(DecodeError::Misuse);
        }
        let mut rest = section;
        let (required, base) = self.prefix(&mut rest).ok_or(DecodeError::Malformed)?;
        if required > self.table.inserted {
            if self.blocked.iter().any(|&(blocked, _)| blocked == stream) {
                return Err(DecodeError::Blocked);
            }
            if self.blocked.len() >= self.limits.blocked_streams {
                return Err(DecodeError::TooManyBlocked);
            }
            // The list has the capacity of the limit, so this push does not allocate.
            self.blocked.push((stream, required));
            return Err(DecodeError::Blocked);
        }
        let needed = if required > 0 { integer::len(stream, 7) } else { 0 };
        let available = free(out);
        if needed > available {
            return Err(DecodeError::Full(Full { needed, available }));
        }
        self.blocked.retain(|&(blocked, _)| blocked != stream);
        let result = self.lines(rest, required, base, lines);
        if result == Err(DecodeError::Malformed) {
            return Err(DecodeError::Malformed);
        }
        if required > 0 {
            put(out, stream, 7, 0x80);
            self.known = self.known.max(required);
        }
        self.increment(out);
        result.map(|()| lines.block())
    }

    /// Reads the prefix of a field section (RFC 9204, section 4.5.1), and gives its Required
    /// Insert Count and its Base. Gives `None` for a prefix that a conformant encoder cannot
    /// make.
    fn prefix(&self, rest: &mut &[u8]) -> Option<(u64, u64)> {
        let (encoded, used) = integer::decode(rest, 8)?;
        *rest = &rest[used..];
        let negative = rest.first()? & 0x80 != 0;
        let (delta, used) = integer::decode(rest, 7)?;
        *rest = &rest[used..];
        // The algorithm of RFC 9204, section 4.5.1.1.
        let required = if encoded == 0 {
            0
        } else {
            let entries = (self.limits.table_bytes / OVERHEAD) as u64;
            let range = 2 * entries;
            if encoded > range {
                return None;
            }
            let most = self.table.inserted.checked_add(entries)?;
            let mut required = (most / range * range).checked_add(encoded - 1)?;
            if required > most {
                if required <= range {
                    return None;
                }
                required -= range;
            }
            if required == 0 {
                return None;
            }
            required
        };
        // A Base below zero is invalid (RFC 9204, section 4.5.1.2).
        let base = if negative {
            required.checked_sub(delta)?.checked_sub(1)?
        } else {
            required.checked_add(delta)?
        };
        Some((required, base))
    }

    /// Decodes the lines of a section after its prefix into `lines`.
    fn lines(&self, mut rest: &[u8], required: u64, base: u64, lines: &mut hpack::Lines) -> Result<(), DecodeError> {
        let mut buffer = Buffer {
            out: &mut lines.out,
            room: lines.room,
            lines: &mut lines.spans,
            work: 0,
            // A section copies at most `room` bytes, so its work needs no other limit.
            limit: usize::MAX,
        };
        buffer.out.clear();
        buffer.lines.clear();
        // The size of the decoded list, while it is at most `list_bytes`.
        let mut list = 0_usize;
        let mut too_large = false;
        // One more than the largest absolute index of a reference.
        let mut needed = 0;
        while !rest.is_empty() {
            let (line, index) = self.representation(&mut rest, required, base)?;
            if let Some(index) = index {
                needed = needed.max(index + 1);
            }
            // After the list is too large, a line needs no bytes. The decoder still checks its
            // Huffman strings.
            let at = buffer.out.len();
            let room = if too_large { 0 } else { buffer.room - at };
            let (name, value, fits) = buffer.stage(&line, room).map_err(|_| DecodeError::Malformed)?;
            if too_large {
                continue;
            }
            let size = name.saturating_add(value).saturating_add(OVERHEAD);
            match list
                .checked_add(size)
                .filter(|&sum| fits && sum <= self.limits.list_bytes)
            {
                Some(sum) => {
                    list = sum;
                    buffer.lines.push(Span {
                        start: at,
                        name,
                        value,
                        never_indexed: line.never_indexed,
                    });
                }
                None => {
                    too_large = true;
                    buffer.out.clear();
                    buffer.lines.clear();
                }
            }
        }
        // The Required Insert Count is one more than the largest reference (RFC 9204, section
        // 2.1.2). A larger count is an error too, selected on 2026-11-18 (section 2.2.1 permits
        // it): a conformant encoder never sends one.
        if needed != required {
            return Err(DecodeError::Malformed);
        }
        if too_large { Err(DecodeError::TooLarge) } else { Ok(()) }
    }

    /// Reads one field line representation (RFC 9204, section 4.5) from the start of `rest`, and
    /// gives the absolute index of its reference to the dynamic table.
    fn representation<'r, 'b: 'r>(
        &'r self,
        rest: &mut &'b [u8],
        required: u64,
        base: u64,
    ) -> Result<(Representation<'r>, Option<u64>), DecodeError> {
        let byte = rest.first().copied().ok_or(DecodeError::Malformed)?;
        // The prefix of the index, the flag of the static table, and the never-indexed flag.
        let (prefix, table, never_indexed) = match byte {
            0x80.. => (6, byte & 0x40, false),
            0x40.. => (4, byte & 0x10, byte & 0x20 != 0),
            0x20.. => (3, 0, byte & 0x10 != 0),
            0x10.. => (4, 0, false),
            _ => (3, 0, byte & 0x08 != 0),
        };
        if (0x20..0x40).contains(&byte) {
            // Literal Field Line with Literal Name (RFC 9204, section 4.5.6).
            let name = string(rest, 3).ok_or(DecodeError::Malformed)?;
            let value = string(rest, 7).ok_or(DecodeError::Malformed)?;
            return Ok((
                Representation {
                    name,
                    value,
                    insert: false,
                    never_indexed,
                },
                None,
            ));
        }
        let (index, used) = integer::decode(rest, prefix).ok_or(DecodeError::Malformed)?;
        *rest = &rest[used..];
        let (name, value, reference) = if table != 0 {
            let &(name, value) = usize::try_from(index)
                .ok()
                .and_then(|index| STATIC.get(index))
                .ok_or(DecodeError::Malformed)?;
            (Bytes(name, &[]), Bytes(value, &[]), None)
        } else {
            // A relative index counts down from the Base, and a post-Base index counts up from it.
            let absolute = if byte >= 0x40 {
                base.checked_sub(index).and_then(|index| index.checked_sub(1))
            } else {
                base.checked_add(index)
            }
            .filter(|&absolute| absolute < required)
            .ok_or(DecodeError::Malformed)?;
            let (name, value) = self.table.get(absolute).ok_or(DecodeError::Malformed)?;
            (name, value, Some(absolute))
        };
        let value = if (0x40..0x80).contains(&byte) || byte < 0x10 {
            string(rest, 7).ok_or(DecodeError::Malformed)?
        } else {
            Part::Plain(value)
        };
        Ok((
            Representation {
                name: Part::Plain(name),
                value,
                insert: false,
                never_indexed,
            },
            reference,
        ))
    }

    /// Gives one stream whose field section can now decode, and forgets that it waits. Call it
    /// after [`receive`](Self::receive) until it gives `None`, and decode the section of each
    /// stream.
    pub fn unblocked(&mut self) -> Option<u64> {
        let at = self
            .blocked
            .iter()
            .position(|&(_, required)| required <= self.table.inserted)?;
        Some(self.blocked.swap_remove(at).0)
    }

    /// Ends the field sections of `stream`: the stream was reset, or the caller stopped reading
    /// it before each of its sections decoded (RFC 9204, section 2.2.2.2).
    ///
    /// It writes the Stream Cancellation into `out`, so the encoder stops waiting for the
    /// acknowledgements of the stream. A decoder whose `table_bytes` is zero writes none: the
    /// encoder has no references to keep. It refuses with [`Full`], and changes nothing, when
    /// `out` has no room for the instruction.
    pub fn cancel<B: BufferMut>(&mut self, stream: u64, out: &mut WriteLoan<B>) -> Result<(), Full> {
        if self.limits.table_bytes == 0 {
            return Ok(());
        }
        let needed = integer::len(stream, 6);
        let available = free(out);
        if needed > available {
            return Err(Full { needed, available });
        }
        self.blocked.retain(|&(blocked, _)| blocked != stream);
        put(out, stream, 6, 0x40);
        self.increment(out);
        Ok(())
    }

    /// Writes an Insert Count Increment for the entries that the encoder does not know of yet
    /// (RFC 9204, section 4.4.3), when `out` has room for it.
    fn increment<B: BufferMut>(&mut self, out: &mut WriteLoan<B>) {
        let increment = self.table.inserted - self.known;
        if increment > 0 && integer::len(increment, 6) <= free(out) {
            put(out, increment, 6, 0x00);
            self.known = self.table.inserted;
        }
    }
}

impl Reader {
    /// Starts a string of `left` bytes, the name when `name` is `None`.
    fn start(&mut self, left: usize, huffman: bool, name: Option<usize>) {
        self.huffman = Partial::default();
        self.step = Step::String { left, huffman, name };
    }
}

impl Lines {
    /// Makes the lines for a decoder with `limits`: a buffer of `list_bytes`, and the positions of
    /// at most `list_bytes / 32` lines. It charges them to `budget` before it allocates, and
    /// refuses with [`Kind::Overload`], with no allocation, when the budget cannot pay.
    pub fn new(limits: Limits, budget: &Budget) -> Result<Self, Error> {
        hpack::Lines::with_room(limits.list_bytes, limits.list_bytes / OVERHEAD, budget).map(Self)
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("inserted", &self.table.inserted)
            .field("entries", &self.table.ring.len())
            .field("blocked", &self.blocked.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
