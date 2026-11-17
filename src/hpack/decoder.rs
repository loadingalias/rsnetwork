//! The decoder: one header block at a time, into the lines that the caller lends for the call.

use core::fmt;

use rstypes::capacity::{Budget, Permit};

use super::table::{Bytes, OVERHEAD, STATIC, Table};
use super::{DecodeError, FieldLine, Limits, huffman, integer};
use crate::drive::{Error, Kind};

/// The HPACK decoder of one connection: the one owner of its dynamic table.
///
/// [`new`](Self::new) charges and allocates its dynamic table, which is all of its memory.
/// [`decode`](Self::decode) never allocates: it writes into the [`Lines`] that the caller lends
/// for the call.
pub struct Decoder {
    table: Table,
    limits: Limits,
    /// The largest maximum size that a size update can set: at most the memory of the table.
    limit: usize,
    /// The next block must start with a size update, because the limit fell below the maximum
    /// size of the table.
    update: bool,
    /// The error that ended the decoder.
    failed: Option<DecodeError>,
    _charge: Permit,
}

/// The space for the decoded lines of one header block, which the caller lends to
/// [`Decoder::decode`].
///
/// [`new`](Self::new) charges and allocates it for the limits of a decoder. Between two blocks, a
/// connection needs only its decoder. Thus a host can take lines from a pool for each block, and
/// give them back while the connection is idle.
pub struct Lines {
    /// The bytes of the lines, or the bytes of one line on its way to the table.
    out: Vec<u8>,
    /// The capacity of `out` that the charge pays for.
    room: usize,
    spans: Vec<Span>,
    /// The capacity of `spans` that the charge pays for.
    count: usize,
    _charge: Permit,
}

/// The lines of the block that a decode writes, and the work of the block.
struct Buffer<'l> {
    out: &'l mut Vec<u8>,
    room: usize,
    lines: &'l mut Vec<Span>,
    /// The work of the block so far, and its limit.
    work: usize,
    limit: usize,
}

/// Where one decoded line is in the buffer.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    name: usize,
    value: usize,
    never_indexed: bool,
}

/// The source of the bytes of a name or a value.
#[derive(Clone, Copy)]
enum Part<'a> {
    /// Bytes in the block, the static table, or the dynamic table.
    Plain(Bytes<'a>),
    /// A Huffman string in the block.
    Huffman(&'a [u8]),
}

/// One line of a block, as its representation gives it (RFC 7541, section 6).
struct Representation<'a> {
    name: Part<'a>,
    value: Part<'a>,
    /// The line goes into the dynamic table.
    insert: bool,
    never_indexed: bool,
}

impl Decoder {
    /// Makes a decoder for `limits`. It charges its dynamic table of `table_bytes`, and the
    /// positions of at most `table_bytes / 32` entries, to `budget` before it allocates. It
    /// refuses with [`Kind::Overload`], with no allocation, when the budget cannot pay. The
    /// maximum size of the table starts at `table_bytes`.
    pub fn new(limits: Limits, budget: &Budget) -> Result<Self, Error> {
        let memory = Table::memory(limits.table_bytes).ok_or(Error::new(Kind::Overload, "the decoder is too large"))?;
        let charge = budget
            .reserve(memory as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the decoder"))?;
        let table = Table::new(limits.table_bytes).ok_or(Error::new(
            Kind::Overload,
            "the memory for the decoder is not available",
        ))?;
        Ok(Self {
            table,
            limits,
            limit: limits.table_bytes,
            update: false,
            failed: None,
            _charge: charge,
        })
    }

    /// Sets the largest maximum size that a size update can set, at most the `table_bytes` of
    /// [`new`](Self::new). HTTP/2 calls it when the peer acknowledges a new
    /// `SETTINGS_HEADER_TABLE_SIZE` (RFC 9113, section 4.3.1).
    ///
    /// When the maximum size of the table is above the new limit, the next block must start with
    /// a size update to at most the limit. A block that does not is [`DecodeError::Malformed`].
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit.min(self.table.limit());
        self.update = self.table.max() > self.limit;
    }

    /// Decodes one complete header block, the bytes of a HEADERS frame and its CONTINUATION
    /// frames, into `lines`.
    ///
    /// Gives the lines of the block, or an error. The block borrows `lines`. A block whose lines
    /// are larger than `list_bytes` still changes the table as the encoder expects, and then gives
    /// [`DecodeError::TooLarge`], so the next block decodes. After [`DecodeError::Malformed`] or
    /// [`DecodeError::Overload`], the state of the table is not known, and the decoder gives the
    /// same error for each later block. Lines that are smaller than the limits of the decoder
    /// need give [`DecodeError::Misuse`], and the decoder does not change.
    pub fn decode<'l>(&mut self, block: &[u8], lines: &'l mut Lines) -> Result<Block<'l>, DecodeError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if lines.room < self.limits.list_bytes.max(self.limits.table_bytes)
            || lines.count < self.limits.list_bytes / OVERHEAD
        {
            return Err(DecodeError::Misuse);
        }
        let mut buffer = Buffer {
            out: &mut lines.out,
            room: lines.room,
            lines: &mut lines.spans,
            work: 0,
            limit: self.limits.work,
        };
        let result = if self.update && block.first().is_none_or(|&byte| byte & 0xe0 != 0x20) {
            Err(DecodeError::Malformed)
        } else {
            run(&mut self.table, &mut buffer, self.limits.list_bytes, self.limit, block)
        };
        // A block that decodes started with its size update. After any other result, the decoder
        // failed.
        self.update = false;
        match result {
            Ok(()) => {
                let lines: &'l Lines = lines;
                Ok(Block {
                    bytes: &lines.out,
                    lines: &lines.spans,
                })
            }
            Err(DecodeError::TooLarge) => Err(DecodeError::TooLarge),
            Err(error) => {
                self.failed = Some(error);
                Err(error)
            }
        }
    }
}

/// Decodes `block` with `table` into `buffer`, within a list of `list_bytes` and size updates to at
/// most `limit`.
fn run(
    table: &mut Table,
    buffer: &mut Buffer,
    list_bytes: usize,
    limit: usize,
    block: &[u8],
) -> Result<(), DecodeError> {
    buffer.out.clear();
    buffer.lines.clear();
    buffer.work = 0;
    buffer.charge(block.len())?;
    // The size of the decoded list (RFC 7541, section 4.1), while it is at most `list_bytes`.
    let mut list = 0_usize;
    let mut too_large = false;
    let mut rest = block;
    let mut first = true;
    while let Some(&byte) = rest.first() {
        if byte & 0xe0 == 0x20 {
            // A dynamic table size update (RFC 7541, section 6.3) comes only at the start of a
            // block. The check of the limit comes before the table changes.
            let (max, used) = integer::decode(rest, 5).ok_or(DecodeError::Malformed)?;
            let max = usize::try_from(max)
                .ok()
                .filter(|&max| first && max <= limit)
                .ok_or(DecodeError::Malformed)?;
            table.set_max(max);
            rest = &rest[used..];
            continue;
        }
        first = false;
        let line = representation(table, &mut rest)?;
        // After the list is too large, a line that does not go into the table needs no bytes.
        // The decoder still checks its Huffman strings.
        let room = if too_large && !line.insert {
            0
        } else {
            buffer.room - buffer.out.len()
        };
        let (mut at, (name, value, mut fits)) = (buffer.out.len(), buffer.stage(&line, room)?);
        if !too_large {
            let size = name.saturating_add(value).saturating_add(OVERHEAD);
            match list.checked_add(size).filter(|&sum| fits && sum <= list_bytes) {
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
                    // No line goes out now. A line that does not fit in the free bytes is too
                    // large too, because `room` is at least `list_bytes`. The line for the table
                    // goes to the start of the buffer again.
                    too_large = true;
                    buffer.out.clear();
                    buffer.lines.clear();
                    at = 0;
                    if line.insert {
                        (_, _, fits) = buffer.stage(&line, buffer.room)?;
                    }
                }
            }
        }
        if line.insert {
            if fits {
                buffer.charge(name + value)?;
                let bytes = &buffer.out[at..at + name + value];
                table.insert(&bytes[..name], &bytes[name..]);
            } else {
                // The line is larger than the buffer, so it is larger than the table, and its
                // insertion empties the table (RFC 7541, section 4.4).
                table.clear();
            }
        }
        if too_large {
            buffer.out.clear();
        }
    }
    if too_large { Err(DecodeError::TooLarge) } else { Ok(()) }
}

/// Reads the representation of one line from the start of `rest`.
fn representation<'r, 'b: 'r>(table: &'r Table, rest: &mut &'b [u8]) -> Result<Representation<'r>, DecodeError> {
    let byte = rest.first().copied().ok_or(DecodeError::Malformed)?;
    let (prefix, insert, never_indexed) = match byte {
        0x80.. => {
            let (index, used) = integer::decode(rest, 7).ok_or(DecodeError::Malformed)?;
            *rest = &rest[used..];
            let (name, value) = entry(table, index)?;
            return Ok(Representation {
                name: Part::Plain(name),
                value: Part::Plain(value),
                insert: false,
                never_indexed: false,
            });
        }
        0x40.. => (6, true, false),
        0x10.. => (4, false, true),
        _ => (4, false, false),
    };
    let (index, used) = integer::decode(rest, prefix).ok_or(DecodeError::Malformed)?;
    *rest = &rest[used..];
    let name = if index == 0 {
        string(rest)?
    } else {
        Part::Plain(entry(table, index)?.0)
    };
    Ok(Representation {
        name,
        value: string(rest)?,
        insert,
        never_indexed,
    })
}

/// The name and the value at `index` in the static table and then in the dynamic table (RFC
/// 7541, section 2.3.3). Index 0 and an index past the tables are malformed.
fn entry(table: &Table, index: u64) -> Result<(Bytes<'_>, Bytes<'_>), DecodeError> {
    let index = usize::try_from(index).map_err(|_| DecodeError::Malformed)?;
    match index.checked_sub(1) {
        Some(position) if position < STATIC.len() => {
            let (name, value) = STATIC[position];
            Ok((Bytes(name, &[]), Bytes(value, &[])))
        }
        Some(position) => table.get(position - STATIC.len()).ok_or(DecodeError::Malformed),
        None => Err(DecodeError::Malformed),
    }
}

/// Reads one string literal (RFC 7541, section 5.2) from the start of `rest`. A length past the
/// end of the block is malformed, before any copy.
fn string<'a>(rest: &mut &'a [u8]) -> Result<Part<'a>, DecodeError> {
    let huffman = rest.first().is_some_and(|&byte| byte & 0x80 != 0);
    let (len, used) = integer::decode(rest, 7).ok_or(DecodeError::Malformed)?;
    let len = usize::try_from(len).map_err(|_| DecodeError::Malformed)?;
    let bytes = rest
        .get(used..)
        .and_then(|after| after.get(..len))
        .ok_or(DecodeError::Malformed)?;
    *rest = &rest[used + len..];
    Ok(if huffman {
        Part::Huffman(bytes)
    } else {
        Part::Plain(Bytes(bytes, &[]))
    })
}

impl Lines {
    /// Makes the lines for a decoder with `limits`: a buffer of `list_bytes` or `table_bytes`,
    /// whichever is larger, and the positions of at most `list_bytes / 32` lines. It charges them
    /// to `budget` before it allocates, and refuses with [`Kind::Overload`], with no allocation,
    /// when the budget cannot pay.
    pub fn new(limits: Limits, budget: &Budget) -> Result<Self, Error> {
        let room = limits.list_bytes.max(limits.table_bytes);
        let count = limits.list_bytes / OVERHEAD;
        let memory = count
            .checked_mul(size_of::<Span>())
            .and_then(|spans| spans.checked_add(room))
            .ok_or(Error::new(Kind::Overload, "the lines are too large"))?;
        let charge = budget
            .reserve(memory as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the lines"))?;
        let unavailable = Error::new(Kind::Overload, "the memory for the lines is not available");
        let mut out = Vec::new();
        out.try_reserve_exact(room).map_err(|_| unavailable)?;
        let mut spans = Vec::new();
        spans.try_reserve_exact(count).map_err(|_| unavailable)?;
        Ok(Self {
            out,
            room,
            spans,
            count,
            _charge: charge,
        })
    }
}

impl fmt::Debug for Lines {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lines")
            .field("room", &self.room)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl Buffer<'_> {
    /// Copies the name and then the value of `line` to the end of `out`, in at most `room`
    /// bytes. Gives their lengths, and whether both fit. A part that does not fit leaves no byte.
    fn stage(&mut self, line: &Representation<'_>, room: usize) -> Result<(usize, usize, bool), DecodeError> {
        let end = self.out.len() + room;
        let (name, name_fits) = self.copy(line.name, end)?;
        let (value, value_fits) = self.copy(line.value, end)?;
        Ok((name, value, name_fits && value_fits))
    }

    /// Copies `part` to the end of `out` while `out` holds at most `end` bytes. Gives the length
    /// of the part, and whether it fits.
    fn copy(&mut self, part: Part<'_>, end: usize) -> Result<(usize, bool), DecodeError> {
        let start = self.out.len();
        let room = end.saturating_sub(start);
        match part {
            Part::Plain(bytes) => {
                if bytes.len() > room {
                    return Ok((bytes.len(), false));
                }
                self.charge(bytes.len())?;
                self.out.extend_from_slice(bytes.0);
                self.out.extend_from_slice(bytes.1);
                Ok((bytes.len(), true))
            }
            Part::Huffman(code) => {
                // The decoded bytes stop at the work limit, so no copy passes it.
                let limit = start + room.min(self.limit - self.work);
                let len = huffman::decode(code, self.out, limit).map_err(|_| DecodeError::Malformed)?;
                self.work += self.out.len() - start;
                if len > room {
                    self.out.truncate(start);
                    return Ok((len, false));
                }
                if self.out.len() - start < len {
                    return Err(DecodeError::Overload);
                }
                Ok((len, true))
            }
        }
    }

    /// Charges `bytes` of work, or refuses before the work.
    fn charge(&mut self, bytes: usize) -> Result<(), DecodeError> {
        self.work = self
            .work
            .checked_add(bytes)
            .filter(|&work| work <= self.limit)
            .ok_or(DecodeError::Overload)?;
        Ok(())
    }
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("limits", &self.limits)
            .field("limit", &self.limit)
            .field("entries", &self.table.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// The decoded field lines of one header block, in their order. They borrow the [`Lines`] that
/// the decode wrote.
#[derive(Clone, Copy)]
pub struct Block<'a> {
    bytes: &'a [u8],
    lines: &'a [Span],
}

impl<'a> Block<'a> {
    /// The number of lines.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the block has no line.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The lines, in their order.
    pub fn lines(&self) -> impl ExactSizeIterator<Item = FieldLine<'a>> + Clone + 'a {
        let bytes = self.bytes;
        self.lines.iter().map(move |span| {
            let value = span.start + span.name;
            FieldLine {
                name: &bytes[span.start..value],
                value: &bytes[value..value + span.value],
                never_indexed: span.never_indexed,
            }
        })
    }
}

impl fmt::Debug for Block<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("lines", &self.lines.len())
            .finish_non_exhaustive()
    }
}
