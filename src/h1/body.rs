//! The H1 body reader and body writer that the server and the client engines share.

use core::alloc::Layout;
use core::fmt;
use core::num::{NonZeroU32, NonZeroUsize};

use rstypes::buffer::{Backing, Buffer as _, Lease, Pool, WriteLoan};
use rstypes::capacity::Budget;

use super::head::{BodyLimits, Limits, ParseError};
use super::join::{Join, Step, join};
use super::write::{begin_chunk, last_chunk};
use super::{ChunkDecoder, ChunkStep, Framing, WriteError};
use crate::body::Trailers;
use crate::drive::{Error, Inbound, Kind, Outbound, Work};
use crate::value::Field;

/// The size of a slot of the chunk-size line pool: 14 hexadecimal digits and CR LF.
const LINE: usize = 16;

/// What a read of a body found.
pub(super) enum Read {
    /// Body bytes: a view of a received region.
    Data(Lease),
    /// The end of the body, with its trailer section if it has trailers.
    End(Option<Trailers>),
    /// Nothing until more bytes arrive.
    Wait,
    /// The read consumed framing: read again.
    Again,
    /// The drain passed its limit: close the connection.
    Overdrawn,
    /// The input ended before the end of the body.
    Truncated,
    /// A trailer section continues in the next region, and the budget cannot pay for its join of
    /// this many bytes now.
    Capacity(u64),
}

/// Reads one body from the received regions, with no copy.
pub(super) struct BodyReader {
    state: State,
    /// The body bytes that the engine can still read and discard. `None` while the application
    /// reads the body.
    drain: Option<u64>,
    /// The largest trailer section, which is the limit of its join.
    trailer_bytes: usize,
    /// The join of a trailer section that continues in the next region.
    join: Option<Join>,
}

impl fmt::Debug for BodyReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyReader")
            .field("state", &self.state)
            .field("drain", &self.drain)
            .finish_non_exhaustive()
    }
}

/// The place of the reader in the body.
#[derive(Debug)]
enum State {
    /// This many more bytes.
    Length(u64),
    /// A chunked body.
    Chunked(ChunkDecoder),
    /// Each byte until the input ends.
    Close,
    /// After the end of the body.
    Done,
}

impl BodyReader {
    /// Makes a reader of a body with `framing`, within `body`. Its trailer field lines have the
    /// field limits of `fields`.
    pub(super) fn new(framing: Framing, body: BodyLimits, fields: Limits) -> Self {
        Self {
            state: match framing {
                Framing::Length(length) => State::Length(length),
                Framing::Chunked => State::Chunked(ChunkDecoder::new(body, fields)),
                Framing::Close => State::Close,
            },
            drain: None,
            trailer_bytes: body.trailer_bytes,
            join: None,
        }
    }

    /// The bytes that remain of a Content-Length body.
    pub(super) fn left(&self) -> Option<u64> {
        match self.state {
            State::Length(left) => Some(left),
            State::Chunked(_) | State::Close | State::Done => None,
        }
    }

    /// Reads and discards the rest of the body, up to `limit` bytes. A close-delimited body has
    /// no end before the close, so its drain is at once over its limit.
    pub(super) fn drain(&mut self, limit: u64) {
        self.drain = Some(limit);
    }

    /// Whether the reader discards the rest of the body.
    pub(super) fn draining(&self) -> bool {
        self.drain.is_some()
    }

    /// Reads the next part of the body at the front of `inbound`. A trailer section that
    /// continues in the next region joins into one region, charged to `budget`.
    ///
    /// It counts the bytes that it reads and the chunks that it decodes in `work`.
    pub(super) fn read(&mut self, inbound: &mut Inbound, budget: &Budget, work: &mut Work) -> Result<Read, ParseError> {
        if matches!(self.state, State::Done) {
            return Ok(Read::Wait);
        }
        if self.join.is_some() {
            return self.trailers(inbound, budget);
        }
        if matches!(self.state, State::Close) && self.draining() {
            return Ok(Read::Overdrawn);
        }
        let Some(front) = inbound.front() else {
            return Ok(match self.state {
                State::Close if inbound.ended() => {
                    self.state = State::Done;
                    Read::End(None)
                }
                State::Length(0) => {
                    self.state = State::Done;
                    Read::End(None)
                }
                _ if inbound.ended() => Read::Truncated,
                _ => Read::Wait,
            });
        };
        let region = front.region.clone();
        let available = region.initialized();
        match &mut self.state {
            State::Length(0) => {
                self.state = State::Done;
                Ok(Read::End(None))
            }
            State::Length(left) => {
                let len = usize::try_from(*left).map_or(available, |left| left.min(available));
                *left -= len as u64;
                work.add(len, 0);
                self.take(inbound, &region, 0, len)
            }
            State::Close => {
                work.add(available, 0);
                self.take(inbound, &region, 0, available)
            }
            State::Chunked(decoder) => match decoder.decode(region.bytes())? {
                // The trailer section continues in the next region.
                ChunkStep::More => self.trailers(inbound, budget),
                ChunkStep::Data { framing, data } => {
                    work.add(framing + data, usize::from(data > 0));
                    self.take(inbound, &region, framing, data)
                }
                ChunkStep::End { len, trailers } => {
                    let lines = (!trailers.is_empty())
                        .then(|| region.view(trailers))
                        .flatten()
                        .map(|lines| Trailers { lines });
                    work.add(len, 0);
                    inbound.consume(len).map_err(|_| ParseError::Framing)?;
                    self.state = State::Done;
                    Ok(Read::End(lines))
                }
            },
            State::Done => Ok(Read::Wait),
        }
    }

    /// Joins the trailer section at the front of `inbound`, which continues in the next region.
    fn trailers(&mut self, inbound: &mut Inbound, budget: &Budget) -> Result<Read, ParseError> {
        let State::Chunked(decoder) = &mut self.state else {
            return Ok(Read::Wait);
        };
        let mut lines = 0..0;
        let step = join(&mut self.join, budget, self.trailer_bytes, inbound, |bytes| {
            match decoder.decode(bytes)? {
                ChunkStep::End { len, trailers } => {
                    lines = trailers;
                    Ok(Some(len))
                }
                ChunkStep::More => Ok(None),
                // The decoder is in the trailer section, which has no data.
                ChunkStep::Data { .. } => Err(ParseError::Framing),
            }
        })?;
        Ok(match step {
            Step::Complete(region) => {
                self.state = State::Done;
                let trailers = (!lines.is_empty()).then(|| region.view(lines)).flatten();
                Read::End(trailers.map(|lines| Trailers { lines }))
            }
            Step::Wait if inbound.ended() => Read::Truncated,
            Step::Wait => Read::Wait,
            Step::Capacity(units) => Read::Capacity(units),
        })
    }

    /// Consumes `framing` bytes and then `len` body bytes of `region`, the front region of
    /// `inbound`, and gives the body bytes. A drain charges them to its limit instead.
    fn take(&mut self, inbound: &mut Inbound, region: &Lease, framing: usize, len: usize) -> Result<Read, ParseError> {
        let data = region
            .view(framing..framing + len)
            .filter(|data| data.initialized() > 0);
        inbound.consume(framing + len).map_err(|_| ParseError::Framing)?;
        if let Some(drain) = &mut self.drain {
            match drain.checked_sub(len as u64) {
                Some(left) => *drain = left,
                None => return Ok(Read::Overdrawn),
            }
        }
        Ok(data.map_or(Read::Again, Read::Data))
    }
}

/// Writes one body into the output queue, with no copy of its bytes and no allocation.
///
/// The size line of each chunk comes from a pool that the writer makes at construction, with one
/// slot of 16 bytes for each entry of the output queue. The CR LF after each chunk and the last
/// chunk with no trailers are static regions.
pub(super) struct BodyWriter {
    pool: Pool,
    /// The open body, if one is open.
    open: Option<Open>,
}

/// The framing of an open body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Open {
    /// This many more bytes.
    Length(u64),
    Chunked,
    Close,
}

impl BodyWriter {
    /// Makes the writer and its pool: one slot for each entry of `outbound`, charged to `budget`.
    pub(super) fn new(outbound: &Outbound, budget: &Budget) -> Result<Self, Error> {
        let slots = u32::try_from(outbound.limit())
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| misuse("the output queue has too many entries for a pool"))?;
        let pool = Pool::new(budget, slots, Layout::new::<[u8; LINE]>())
            .map_err(|_| Error::new(Kind::Overload, "the budget or the memory refused the chunk-line pool"))?;
        Ok(Self { pool, open: None })
    }

    /// Opens a body with `framing`. `Length(0)` is a body with no byte.
    pub(super) fn open(&mut self, framing: Framing) {
        self.open = Some(match framing {
            Framing::Length(length) => Open::Length(length),
            Framing::Chunked => Open::Chunked,
            Framing::Close => Open::Close,
        });
    }

    /// Closes the open body with no end, after a cancellation.
    pub(super) fn cancel(&mut self) {
        self.open = None;
    }

    /// Queues `data` as the next bytes of the body. A chunked body sends it as one chunk.
    pub(super) fn send(&mut self, outbound: &mut Outbound, data: &Lease) -> Result<(), Error> {
        let len = data.initialized();
        match self.open {
            None => Err(misuse("no body is open")),
            Some(_) if len == 0 => Ok(()),
            Some(Open::Length(left)) => {
                if len as u64 > left {
                    return Err(misuse("the data passes the end of the body"));
                }
                outbound.push(data.clone()).map_err(|_| full())?;
                self.open = Some(Open::Length(left - len as u64));
                Ok(())
            }
            Some(Open::Close) => outbound.push(data.clone()).map_err(|_| full()),
            Some(Open::Chunked) => {
                if outbound.free() < 3 {
                    return Err(full());
                }
                let size = NonZeroUsize::new(len).ok_or_else(|| misuse("an empty chunk"))?;
                let mut line = WriteLoan::new(self.pool.acquire().map_err(|_| full())?);
                begin_chunk(&mut line, size).map_err(|_| misuse("the chunk is too large for a size line"))?;
                for region in [Lease::from(line.into_inner()), data.clone(), Lease::from(&b"\r\n"[..])] {
                    outbound.push(region).map_err(|_| full())?;
                }
                Ok(())
            }
        }
    }

    /// Ends the open body. A chunked body gets its last chunk. Refuses when a Content-Length
    /// body has fewer bytes than its length.
    pub(super) fn finish(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        match self.open {
            None => return Err(misuse("no body is open")),
            Some(Open::Length(0) | Open::Close) => {}
            Some(Open::Length(_)) => return Err(misuse("the body is shorter than its Content-Length")),
            Some(Open::Chunked) => outbound.push(Lease::from(&b"0\r\n\r\n"[..])).map_err(|_| full())?,
        }
        self.open = None;
        Ok(())
    }

    /// Ends the open chunked body with a trailer section, which it writes into `region`.
    pub(super) fn finish_with_trailers(
        &mut self,
        outbound: &mut Outbound,
        trailers: &[Field<'_>],
        region: Backing,
    ) -> Result<(), Error> {
        if self.open != Some(Open::Chunked) {
            return Err(misuse("only a chunked body has trailers"));
        }
        if outbound.free() == 0 {
            return Err(full());
        }
        let mut out = WriteLoan::new(region);
        last_chunk(&mut out, trailers).map_err(write_error)?;
        outbound.push(Lease::from(out.into_inner())).map_err(|_| full())?;
        self.open = None;
        Ok(())
    }
}

impl fmt::Debug for BodyWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyWriter")
            .field("open", &self.open)
            .finish_non_exhaustive()
    }
}

/// The refusal of a full output queue or pool.
pub(super) fn full() -> Error {
    Error::new(Kind::Overload, "the output queue or the chunk-line pool is full")
}

/// A refusal of a call that the state of the engine does not permit.
pub(super) fn misuse(reason: &'static str) -> Error {
    Error::new(Kind::Misuse, reason)
}

/// The error of a refused head write.
pub(super) fn write_error(error: WriteError) -> Error {
    match error {
        WriteError::Full { .. } => Error::new(Kind::Overload, "the head region has too little free capacity"),
        WriteError::Status => misuse("the status does not permit the framing"),
        WriteError::FramingField => misuse("a field is a framing field, which the framing argument writes"),
        WriteError::Framing => misuse("the framing does not fit the message"),
    }
}
