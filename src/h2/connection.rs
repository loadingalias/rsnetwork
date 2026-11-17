//! The HTTP/2 engine of one connection: its frame and connection layer, on which the stream layer
//! of `stream` acts.

use core::alloc::Layout;
use core::fmt;
use core::num::NonZeroU32;
use core::time::Duration;

use rstypes::buffer::{Backing, Buffer as _, BufferMut as _, Lease, Pool, WriteLoan};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::{Deadline, Instant};

use super::frame::{
    self, ACK, ENABLE_PUSH, END_HEADERS, END_STREAM, Entries, ErrorCode, Fixed, Frame, FrameError, HEAD, Head,
    INITIAL_WINDOW_SIZE, Kind, MAX_STREAM, PREFACE, flag,
};
use super::stream::{self, Drain, Flow, INITIAL_WINDOW, Section, Streams};
use super::{Limits, Role, SETTINGS_TIMEOUT, Settings};
use crate::drive::{Blocked, Error, Inbound, Kind as ErrorKind, Outbound, Progress, Turn, TurnLimits, Work};
use crate::hpack::{self, Block, DecodeError, Decoder, Encoder, FieldLine, Lines};

/// The size of a slot of the frame pool. The largest frame from the pool is the SETTINGS frame of
/// the preface: 9 bytes and six settings of 6 bytes.
const SLOT: usize = 64;

/// A SETTINGS frame with the flag ACK.
const SETTINGS_ACK: &[u8] = &[0, 0, 0, 0x4, 0x1, 0, 0, 0, 0];

/// DATA frames fill at most the limit of the output queue divided by this value: one half. The
/// other half stays free between drives for the calls of the application (header sections, the
/// grants of `release`, resets, and pings) and for the answers of the next drive: the reserved
/// progress of the design. Without it, each drive fills the room that the transport freed, and
/// each call refuses while a body waits.
const DATA_SHARE: usize = 2;

/// The initial `SETTINGS_HEADER_TABLE_SIZE`. The peer's encoder can use it until the peer
/// acknowledges the settings of the preface (RFC 9113, section 4.3.1).
const INITIAL_TABLE: usize = 4096;

/// The opaque data of the PING of a server's shutdown. Its acknowledgement tells that the peer
/// read the first GOAWAY, so the server sends the GOAWAY with its last stream (RFC 9113, section
/// 6.8).
pub const SHUTDOWN_PING: [u8; 8] = *b"shutdown";

/// One HTTP/2 connection, with no I/O: its frames, its streams, and its flow control.
///
/// [`new`](Self::new) queues the connection preface. In each drive, the connection reads the
/// frames in the host's [`Inbound`] queue and gives one [`Event`]. It checks each frame (RFC 9113,
/// sections 4 to 6), applies and acknowledges the peer's SETTINGS frames, answers each PING,
/// joins and decodes each header block, and applies the rules of each stream state (section 5.1)
/// and of flow control at the stream and the connection level (sections 5.2 and 6.9). Then it
/// sends the chunks that [`data`](Self::data) gave, one DATA frame for each stream in turn.
///
/// A frame that breaks RFC 9113 is a connection error: the connection queues a GOAWAY with the
/// code of the error and the last stream that it gave up, and the turn is terminal when the GOAWAY
/// is in the queue. A stream error resets only its stream, with RST_STREAM. A frame of a type that
/// RFC 9113 does not define is discarded, also its payload with no copy, unless it interrupts a
/// header block.
///
/// The connection keeps at most one answer that the output queue has no room for: a SETTINGS
/// acknowledgement, a PING answer, a RST_STREAM, a WINDOW_UPDATE, or a GOAWAY. It reads no frame
/// while it keeps one, so a peer that does not read cannot make it keep more. Each frame that it
/// writes from its own memory comes from a pool that [`new`](Self::new) makes: one slot of 64
/// bytes for each entry of the output queue, and one more, charged to the caller's budget.
pub struct Connection {
    role: Role,
    /// The settings that the endpoint sent.
    local: Settings,
    /// The peer acknowledged them.
    acknowledged: bool,
    /// The settings of the peer, which the endpoint applies.
    peer: Settings,
    /// The peer sent the SETTINGS frame of its preface.
    preface: bool,
    decoder: Decoder,
    encoder: Encoder,
    /// The limits of the decoder.
    header: hpack::Limits,
    turn: TurnLimits,
    pool: Pool,
    budget: Budget,
    read: Read,
    /// The bytes of a frame header or of fixed fields that cross two regions.
    carry: Carry,
    /// The header block that the connection reads.
    block: Option<Assembly>,
    /// The answer that waits for room in the output queue.
    owed: Option<Owed>,
    /// The streams and the flow-control windows.
    streams: Streams,
    /// The largest `SETTINGS_INITIAL_WINDOW_SIZE` of the peer in the SETTINGS frame that the
    /// connection reads, with the value before the frame.
    window_peak: u32,
    settings_timeout: Option<Duration>,
    /// The deadline of the acknowledgement of the endpoint's settings.
    deadline: Option<Deadline>,
    /// The end of the connection.
    end: Option<Result<(), Error>>,
}

/// An event of the connection.
pub enum Event<'l> {
    /// A header section on a stream: a HEADERS frame and its CONTINUATION frames, decoded. For a
    /// server, it is a request on a new stream. For a client, it is a response: an interim (1xx)
    /// response, with more to come, or the final response.
    Headers {
        /// The stream.
        stream: u32,
        /// The flag END_STREAM of the HEADERS frame: the message has no body.
        end_stream: bool,
        /// The decoded lines, which borrow the [`Lines`] of the drive. `None` when they are larger
        /// than `SETTINGS_MAX_HEADER_LIST_SIZE`: the decode kept the HPACK state in step, so the
        /// connection continues. Refuse the stream.
        lines: Option<Block<'l>>,
    },
    /// The trailer section of a stream (RFC 9113, section 8.1). It ends the body.
    Trailers {
        /// The stream.
        stream: u32,
        /// The decoded lines, as in [`Event::Headers`]. `None` when they are larger than
        /// `SETTINGS_MAX_HEADER_LIST_SIZE`: the message is not complete.
        lines: Option<Block<'l>>,
    },
    /// Bytes of a DATA frame: a view of a received region, with no copy. A frame can give more
    /// than one event, one for each region that holds its bytes. Give the bytes back to flow
    /// control with [`Connection::release`] when the consumer is done with them.
    Data {
        /// The stream.
        stream: u32,
        /// The bytes, which can be empty.
        data: Lease,
        /// The frame had the flag END_STREAM, and this is its last event: the body is complete.
        end_stream: bool,
    },
    /// RST_STREAM: the peer ended a stream. The stream keeps its slot until
    /// [`Connection::close`], when its handler ends.
    Reset {
        /// The stream.
        stream: u32,
        /// Why the stream ends.
        code: ErrorCode,
    },
    /// The chunk that [`Connection::data`] gave to the stream is all in the output queue. Give
    /// the next chunk of the body, or the trailer section.
    Sent {
        /// The stream.
        stream: u32,
    },
    /// The peer's SETTINGS frame, applied. The connection queued its acknowledgement.
    Settings(Settings),
    /// The answer to a PING of the endpoint, with its opaque data.
    PingAck([u8; 8]),
    /// GOAWAY: the peer processes no stream of the endpoint after `last_stream`. The additional
    /// debug data of the frame is discarded.
    GoAway {
        /// The last stream of the endpoint that the peer processed or can process.
        last_stream: u32,
        /// Why the peer ends the connection.
        code: ErrorCode,
    },
    /// A frame of the peer on a stream is a stream error (RFC 9113, section 5.4.2), for example
    /// DATA past the stream window. The connection reset the stream with RST_STREAM of the code,
    /// and the stream ended. Its body is malformed. The stream keeps its slot until
    /// [`Connection::close`], when its handler ends.
    StreamError {
        /// The stream.
        stream: u32,
        /// The code of the error.
        code: ErrorCode,
    },
}

impl fmt::Debug for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Headers {
                stream,
                end_stream,
                lines,
            } => f
                .debug_struct("Headers")
                .field("stream", stream)
                .field("end_stream", end_stream)
                .field("lines", lines)
                .finish(),
            Self::Trailers { stream, lines } => f
                .debug_struct("Trailers")
                .field("stream", stream)
                .field("lines", lines)
                .finish(),
            Self::Data {
                stream,
                data,
                end_stream,
            } => f
                .debug_struct("Data")
                .field("stream", stream)
                .field("len", &data.initialized())
                .field("end_stream", end_stream)
                .finish(),
            Self::Reset { stream, code } => f
                .debug_struct("Reset")
                .field("stream", stream)
                .field("code", code)
                .finish(),
            Self::Sent { stream } => f.debug_struct("Sent").field("stream", stream).finish(),
            Self::Settings(settings) => f.debug_tuple("Settings").field(settings).finish(),
            Self::PingAck(_) => f.write_str("PingAck"),
            Self::GoAway { last_stream, code } => f
                .debug_struct("GoAway")
                .field("last_stream", last_stream)
                .field("code", code)
                .finish(),
            Self::StreamError { stream, code } => f
                .debug_struct("StreamError")
                .field("stream", stream)
                .field("code", code)
                .finish(),
        }
    }
}

/// The place of the connection in its input.
#[derive(Clone, Copy, Debug)]
enum Read {
    /// The server reads the client preface: this many of its bytes matched.
    Preface(usize),
    /// Before a frame header.
    Head,
    /// The fixed fields of a frame: this many bytes.
    Fixed(Head, usize),
    /// The variable part of a frame: this many more bytes.
    Body(Head, Fixed, u32),
    /// The padding of a frame: this many more bytes.
    Padding(Head, Fixed, u32),
}

/// The bytes of a frame header or of fixed fields that the connection gathers across regions.
#[derive(Clone, Copy, Debug, Default)]
struct Carry {
    bytes: [u8; HEAD],
    len: usize,
}

/// A header block that the connection reads.
#[derive(Debug)]
struct Assembly {
    stream: u32,
    end_stream: bool,
    /// The bytes of the fragments, and 9 bytes for each CONTINUATION frame: the size that the
    /// block bound `work` limits. Thus empty CONTINUATION frames cannot continue a block forever.
    size: usize,
    /// The fragments, when the block does not decode in place.
    join: Option<Join>,
}

/// The joined fragments of a header block, and the charge that pays for them.
struct Join {
    bytes: Vec<u8>,
    _permit: Permit,
}

impl fmt::Debug for Join {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Join")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// An answer that waits for room in the output queue.
#[derive(Clone, Copy)]
enum Owed {
    SettingsAck,
    PingAck([u8; 8]),
    /// A RST_STREAM on a stream, with its code.
    Reset(u32, ErrorCode),
    /// A WINDOW_UPDATE on a stream, with its increment.
    Window(u32, u32),
    /// A GOAWAY with its code and its last stream.
    GoAway(ErrorCode, u32),
}

impl fmt::Debug for Owed {
    /// Shows no PING data, which is peer bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SettingsAck => f.write_str("SettingsAck"),
            Self::PingAck(_) => f.write_str("PingAck"),
            Self::Reset(stream, code) => f.debug_tuple("Reset").field(stream).field(code).finish(),
            Self::Window(stream, increment) => f.debug_tuple("Window").field(stream).field(increment).finish(),
            Self::GoAway(code, last_stream) => f.debug_tuple("GoAway").field(code).field(last_stream).finish(),
        }
    }
}

/// A connection error: its RFC 9113 code, the kind of the local error, and a fixed reason.
#[derive(Clone, Copy, Debug)]
pub(super) struct Fault {
    code: ErrorCode,
    kind: ErrorKind,
    reason: &'static str,
}

impl Fault {
    /// A connection error that the peer caused.
    pub(super) const fn peer(code: ErrorCode, reason: &'static str) -> Self {
        Self {
            code,
            kind: ErrorKind::Malformed,
            reason,
        }
    }

    /// The connection error of a frame that a check of the codec refused.
    const fn frame(code: ErrorCode) -> Self {
        Self::peer(
            code,
            match code {
                ErrorCode::FRAME_SIZE_ERROR => "a frame has a size that its type or SETTINGS_MAX_FRAME_SIZE forbids",
                ErrorCode::FLOW_CONTROL_ERROR => "a setting is past the largest flow-control window",
                _ => "a frame breaks a rule of RFC 9113",
            },
        )
    }
}

/// What a step of the reader found.
enum Next<'l> {
    Event(Event<'l>),
    Wait(Blocked),
    /// The turn reached a limit, and work remains.
    Limit,
}

impl Connection {
    /// Makes the connection of `role` within `limits` and drives within `turn`, and queues its
    /// preface in `outbound`: for a client the 24 bytes of [`PREFACE`] and a SETTINGS frame, and
    /// for a server a SETTINGS frame. The frame has each setting that is not its initial value,
    /// in the order of the identifiers, and then for a client `SETTINGS_ENABLE_PUSH` 0. When
    /// `limits.connection_window` is above 65,535, a WINDOW_UPDATE on stream 0 follows, which
    /// raises the connection window to it.
    ///
    /// It charges its HPACK tables, its stream table, and its frame pool to `budget`, which also
    /// pays for the join of each header block later. The decoder table holds at least 4096 bytes,
    /// because the peer's encoder can use 4096 until the peer acknowledges the settings. Refuses
    /// with [`Kind::Misuse`](crate::drive::Kind::Misuse) when a limit is past its range or the
    /// output queue has fewer than 3 entries, and with
    /// [`Kind::Overload`](crate::drive::Kind::Overload) when the budget, the memory, or the free
    /// room of the queue refuses. A refusal keeps no memory and no charge.
    pub fn new(
        role: Role,
        limits: Limits,
        turn: TurnLimits,
        outbound: &mut Outbound,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let local = limits.settings;
        let misuse = |reason| Err(Error::new(ErrorKind::Misuse, reason));
        if local.initial_window_size > MAX_STREAM {
            return misuse("SETTINGS_INITIAL_WINDOW_SIZE is past 2^31 - 1");
        }
        if !(frame::MIN_FRAME_SIZE..=(1 << 24) - 1).contains(&local.max_frame_size) {
            return misuse("SETTINGS_MAX_FRAME_SIZE is outside 2^14 to 2^24 - 1");
        }
        if !(INITIAL_WINDOW..=MAX_STREAM).contains(&limits.connection_window) {
            return misuse("the connection window is outside 65,535 to 2^31 - 1");
        }
        if outbound.limit() < 3 {
            return misuse("the output queue has fewer than 3 entries");
        }
        if outbound.free() < 3 {
            return Err(Error::new(
                ErrorKind::Overload,
                "the output queue has no room for the preface",
            ));
        }
        let size = |value: u32| usize::try_from(value).unwrap_or(usize::MAX);
        let header = hpack::Limits {
            table_bytes: size(local.header_table_size).max(INITIAL_TABLE),
            list_bytes: size(local.max_header_list_size),
            work: limits.work,
        };
        let slots = u32::try_from(outbound.limit())
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .and_then(NonZeroU32::new)
            .ok_or(Error::new(
                ErrorKind::Misuse,
                "the output queue has too many entries for a pool",
            ))?;
        let pool = Pool::new(budget, slots, Layout::new::<[u8; SLOT]>())
            .map_err(|_| Error::new(ErrorKind::Overload, "the budget or the memory refused the frame pool"))?;
        let mut connection = Self {
            role,
            local,
            acknowledged: false,
            peer: Settings::INITIAL,
            preface: false,
            decoder: Decoder::new(header, budget)?,
            encoder: Encoder::new(limits.encoder_table_bytes, budget)?,
            header,
            turn,
            pool,
            budget: budget.clone(),
            read: match role {
                Role::Client => Read::Head,
                Role::Server => Read::Preface(0),
            },
            carry: Carry::default(),
            block: None,
            owed: None,
            streams: Streams::new(role, &local, limits.connection_window, budget)?,
            window_peak: INITIAL_WINDOW,
            settings_timeout: Some(SETTINGS_TIMEOUT),
            deadline: None,
            end: None,
        };
        // The settings that differ from their initial values, and then the push setting.
        let mut settings = [0; 36];
        let mut len = 0;
        let push = (role == Role::Client).then_some((ENABLE_PUSH, 0));
        for (id, value) in local
            .entries()
            .into_iter()
            .zip(Settings::INITIAL.entries())
            .filter(|((_, value), (_, initial))| value != initial)
            .map(|(entry, _)| entry)
            .chain(push)
        {
            settings[len..len + 2].copy_from_slice(&id.to_be_bytes());
            settings[len + 2..len + 6].copy_from_slice(&value.to_be_bytes());
            len += 6;
        }
        let settings =
            Entries::new(&settings[..len]).ok_or(Error::new(ErrorKind::Misuse, "a setting is not 6 bytes"))?;
        let frame = connection
            .pooled(&Frame::Settings { ack: false, settings })
            .ok_or(Error::new(ErrorKind::Overload, "the frame pool is empty"))?;
        let grant = match connection.streams.initial_grant() {
            Some(increment) => Some(
                connection
                    .pooled(&Frame::WindowUpdate { stream: 0, increment })
                    .ok_or(Error::new(ErrorKind::Overload, "the frame pool is empty"))?,
            ),
            None => None,
        };
        if role == Role::Client {
            push_region(outbound, Lease::from(PREFACE.as_slice()))?;
        }
        push_region(outbound, frame)?;
        if let Some(grant) = grant {
            push_region(outbound, grant)?;
        }
        Ok(connection)
    }

    /// Sets the settings timeout: the most time from the first drive to the acknowledgement of the
    /// endpoint's settings. At the deadline, the connection ends with `SETTINGS_TIMEOUT`. `None`
    /// turns it off. The default is [`SETTINGS_TIMEOUT`].
    pub fn settings_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.settings_timeout = timeout;
        self
    }

    /// The settings of the peer that the connection applies: their initial values until the
    /// peer's SETTINGS frame.
    pub fn peer_settings(&self) -> Settings {
        self.peer
    }

    /// The limits of the HPACK decoder. Make the [`Lines`] of each drive with them.
    pub fn header_limits(&self) -> hpack::Limits {
        self.header
    }

    /// Reads the frames in `inbound`, and gives the next event and the [`Turn`].
    ///
    /// The decoded lines of a header block go into `lines`, which the event borrows. A host can
    /// take them from a pool for each drive. Drive again after each event, and after more bytes
    /// arrive. When the turn is terminal, send the rest of `outbound`, and then close the
    /// connection.
    pub fn drive<'l>(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        lines: &'l mut Lines,
        now: Option<Instant>,
    ) -> (Option<Event<'l>>, Turn) {
        self.expire(now);
        let (mut event, mut progress) = (None, Progress::Blocked(Blocked::Output));
        if self.flush(outbound) && self.end.is_none() {
            if self.streams.drained() {
                self.finish();
            } else {
                match self.step(inbound, outbound, lines) {
                    Ok(Next::Event(next)) => (event, progress) = (Some(next), Progress::Pending),
                    Ok(Next::Wait(blocked)) => progress = Progress::Blocked(blocked),
                    Ok(Next::Limit) => progress = Progress::Pending,
                    Err(fault) => self.fail(fault),
                }
                // The scheduler sends after the reader, so the answers of the reader go first.
                // No frame follows the GOAWAY of a connection error.
                if self.end.is_none() {
                    match self.send(outbound) {
                        Ok(true) if matches!(progress, Progress::Blocked(_)) => {
                            progress = Progress::Blocked(Blocked::Output);
                        }
                        Ok(_) => {}
                        Err(fault) => self.fail(fault),
                    }
                }
                if event.is_none()
                    && self.end.is_none()
                    && let Some(stream) = self.streams.take_sent()
                {
                    (event, progress) = (Some(Event::Sent { stream }), Progress::Pending);
                }
            }
        }
        if event.is_none()
            && let Some(end) = self.end
        {
            // The GOAWAY of a connection error goes out before the end.
            progress = if self.flush(outbound) {
                Progress::Terminal(end)
            } else {
                Progress::Blocked(Blocked::Output)
            };
        }
        if !self.acknowledged
            && self.deadline.is_none()
            && let (Some(timeout), Some(now)) = (self.settings_timeout, now)
        {
            self.deadline = now.checked_add(timeout).ok().map(Deadline::at);
        }
        let deadline = self.deadline.filter(|_| self.end.is_none());
        (event, Turn { progress, deadline })
    }

    /// Sends a PING with `opaque`. Its answer comes as [`Event::PingAck`]. During the shutdown of
    /// a server, the connection takes the answer to a PING with [`SHUTDOWN_PING`] as its own.
    pub fn ping(&mut self, outbound: &mut Outbound, opaque: [u8; 8]) -> Result<(), Error> {
        self.writable(outbound)?;
        let frame = self.pooled(&Frame::Ping { ack: false, opaque }).ok_or_else(full)?;
        push_region(outbound, frame)
    }

    /// Opens a stream of a client with a request: a header block, as [`headers`](Self::headers)
    /// sends it, on the next free odd stream. Gives the stream.
    ///
    /// Refuses, and writes and changes nothing, for a server, when the stream table or the peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` has no free stream, after a GOAWAY went or came, when no
    /// stream identifier is free, and in each case where `headers` refuses.
    pub fn open<'a>(
        &mut self,
        outbound: &mut Outbound,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        end_stream: bool,
        region: Backing,
    ) -> Result<u32, Error> {
        self.writable(outbound)?;
        let stream = self.streams.next(self.peer.max_concurrent_streams)?;
        self.block(outbound, stream, lines, end_stream, region)?;
        self.streams.opened(stream, end_stream);
        Ok(stream)
    }

    /// Sends a header section on an open `stream`: a HEADERS frame, and CONTINUATION frames when
    /// the block is larger than the peer's `SETTINGS_MAX_FRAME_SIZE`. `end_stream` sets the flag
    /// END_STREAM. A server sends its response with it: interim (1xx) responses, and then the
    /// final response. After the final response or the request, a header section is the trailer
    /// section, which ends the stream.
    ///
    /// The frames go into the free capacity of `region`, after the bytes that it holds, and go out
    /// as views of it, with no copy: the HPACK block after a frame header, and the header of each
    /// CONTINUATION frame after the block. Thus the region needs room for the longest block of
    /// `lines` and for 9 bytes for each frame. Refuses, and writes and changes nothing, when the
    /// region or the output queue has too little room, when the stream is not open or sent its
    /// end, when an interim response has `end_stream`, and when a trailer section does not.
    pub fn headers<'a>(
        &mut self,
        outbound: &mut Outbound,
        stream: u32,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        end_stream: bool,
        region: Backing,
    ) -> Result<(), Error> {
        self.writable(outbound)?;
        let interim = stream::interim(lines.clone().next());
        self.streams.sendable(stream, interim, end_stream)?;
        self.block(outbound, stream, lines, end_stream, region)?;
        self.streams.sent(stream, interim, end_stream);
        Ok(())
    }

    /// Writes a header block on `stream` into `region`, and queues its frames.
    fn block<'a>(
        &mut self,
        outbound: &mut Outbound,
        stream: u32,
        lines: impl Iterator<Item = FieldLine<'a>> + Clone,
        end_stream: bool,
        region: Backing,
    ) -> Result<(), Error> {
        let max = self.peer.max_frame_size as usize;
        let needed = self.encoder.needed(lines.clone());
        let frames = needed.div_ceil(max).max(1);
        let start = region.initialized();
        let room = needed.saturating_add(frames.saturating_mul(HEAD));
        if region.capacity() - start < room {
            return Err(Error::new(
                ErrorKind::Overload,
                "the header region has too little free capacity",
            ));
        }
        if outbound.free() < frames.saturating_mul(2) - 1 {
            return Err(full());
        }
        let mut out = WriteLoan::new(region);
        out.fill_from(&[0; HEAD]);
        self.encoder
            .encode(lines, &mut out)
            .map_err(|_| Error::new(ErrorKind::Overload, "the header region has too little free capacity"))?;
        let mut region = out.into_inner();
        let block = region.initialized() - start - HEAD;
        let first = block.min(max);
        let flags = flag(end_stream, END_STREAM) | flag(first == block, END_HEADERS);
        let head = |length: usize, kind, flags| Head {
            length: narrow(length),
            kind,
            flags,
            stream,
        };
        region.bytes_mut()[start..start + HEAD].copy_from_slice(&head(first, Kind::Headers, flags).encode());
        // The header of each CONTINUATION frame goes after the block.
        let mut out = WriteLoan::new(region);
        let mut at = first;
        while at < block {
            let len = (block - at).min(max);
            let flags = flag(at + len == block, END_HEADERS);
            out.fill_from(&head(len, Kind::Continuation, flags).encode());
            at += len;
        }
        let lease = Lease::from(out.into_inner());
        let view = |range: core::ops::Range<usize>| lease.view(range).ok_or_else(full);
        let fragments = start + HEAD;
        push_region(outbound, view(start..fragments + first)?)?;
        let (mut at, mut tail) = (first, fragments + block);
        while at < block {
            let len = (block - at).min(max);
            push_region(outbound, view(tail..tail + HEAD)?)?;
            push_region(outbound, view(fragments + at..fragments + at + len)?)?;
            at += len;
            tail += HEAD;
        }
        Ok(())
    }

    /// Gives `data`, the next chunk of the body of `stream`, to the send scheduler, with no copy.
    /// `end_stream` ends the body with the last byte of the chunk. In each drive, the scheduler
    /// sends one DATA frame of at most 16,384 bytes for each stream in turn, within the two send
    /// windows, as views of `data`. When the chunk is all in the output queue, the drive gives
    /// [`Event::Sent`]: give the next chunk then. A stream holds one chunk at a time, so a
    /// stream that waits for credit holds back only itself.
    ///
    /// An empty `data` with `end_stream` needs no credit, so its DATA frame goes into the output
    /// queue at once. Refuses, and changes nothing, after the end of the connection, when the
    /// stream is not open, sent its end, or sent no header section, from an earlier `data` to its
    /// `Event::Sent`, and for an empty `data` with no `end_stream`
    /// ([`Kind::Misuse`](crate::drive::Kind::Misuse)). The empty frame also refuses when the
    /// output queue or the pool is full ([`Kind::Overload`](crate::drive::Kind::Overload)).
    pub fn data(&mut self, outbound: &mut Outbound, stream: u32, data: Lease, end_stream: bool) -> Result<(), Error> {
        if self.end.is_some() {
            return Err(Error::new(ErrorKind::Misuse, "the connection ended"));
        }
        if self.streams.sendable_data(stream, data.initialized(), end_stream)? {
            self.streams.chunk(stream, data, end_stream);
            return Ok(());
        }
        // The empty frame goes after the answer that waits, so the frames stay in their order.
        self.writable(outbound)?;
        if outbound.free() == 0 {
            return Err(full());
        }
        let head = Head {
            length: 0,
            kind: Kind::Data,
            flags: END_STREAM,
            stream,
        };
        let mut slot = WriteLoan::new(self.pool.acquire().map_err(|_| full())?);
        slot.fill_from(&head.encode());
        push_region(outbound, Lease::from(slot.into_inner()))?;
        self.streams.sent(stream, false, true);
        Ok(())
    }

    /// Writes the DATA frames of the send scheduler into `outbound` while they fill at most its
    /// share of [`DATA_SHARE`]. Each frame takes two entries: a 9-byte header from the pool and a
    /// view of a chunk. Gives whether a frame waits for room.
    fn send(&mut self, outbound: &mut Outbound) -> Result<bool, Fault> {
        while outbound.free() >= 2 + outbound.limit() / DATA_SHARE {
            let Ok(slot) = self.pool.acquire() else {
                return Ok(self.streams.ready());
            };
            let Some((stream, part, end_stream)) = self.streams.next_frame() else {
                return Ok(false);
            };
            let head = Head {
                length: narrow(part.initialized()),
                kind: Kind::Data,
                flags: flag(end_stream, END_STREAM),
                stream,
            };
            let mut slot = WriteLoan::new(slot);
            slot.fill_from(&head.encode());
            // The loop checked the room of both regions.
            for region in [Lease::from(slot.into_inner()), part] {
                outbound.push(region).map_err(|_| internal())?;
            }
        }
        Ok(self.streams.ready())
    }

    /// Resets an open `stream` with RST_STREAM of `code`, and ends it (RFC 9113, section 6.4).
    /// The connection discards each later frame of the peer on it, and keeps the HPACK state and
    /// the connection window in step.
    ///
    /// Refuses, and queues nothing, when the output queue or the pool has no room, when the
    /// stream is not open, and for a server with `REFUSED_STREAM`: each stream that a server
    /// knows went up to it, so it is not "unprocessed" (section 8.7).
    pub fn reset(&mut self, outbound: &mut Outbound, stream: u32, code: ErrorCode) -> Result<(), Error> {
        self.writable(outbound)?;
        self.streams.resettable(stream, code)?;
        if outbound.free() == 0 {
            return Err(full());
        }
        let frame = self.pooled(&Frame::RstStream { stream, code }).ok_or_else(full)?;
        push_region(outbound, frame)?;
        self.streams.close(stream);
        Ok(())
    }

    /// Closes `stream`, which a reset ended, when its handler ends: after [`Event::Reset`] or
    /// [`Event::StreamError`]. Until then, the stream keeps its slot in the stream table, so a
    /// peer that opens and resets streams at line rate starts at most `max_concurrent_streams`
    /// handlers (CVE-2023-44487). It sends nothing.
    ///
    /// Refuses, and changes nothing, when no reset holds the slot of the stream: the stream is
    /// open, or it was closed.
    pub fn close(&mut self, stream: u32) -> Result<(), Error> {
        self.streams.free(stream)
    }

    /// Releases `bytes` data bytes of `stream` that the consumer is done with: the bytes of
    /// [`Event::Data`] that it copied out or dropped. The connection gives their credit back to
    /// the peer at the stream and the connection level, with a WINDOW_UPDATE when the free
    /// credit reaches the credit that the peer still has. No other credit goes to the peer, so
    /// the peer can send at most the windows that the limits admit.
    ///
    /// Release the bytes of a stream that ended too. Refuses, and changes nothing, when the
    /// consumer of the stream or of the connection holds fewer bytes, and when the output queue or
    /// the pool has no room for the frames.
    pub fn release(&mut self, outbound: &mut Outbound, stream: u32, bytes: u32) -> Result<(), Error> {
        self.writable(outbound)?;
        let mut slots = [0, 1].map(|frames| {
            if outbound.free() > frames {
                self.pool.acquire().ok()
            } else {
                None
            }
        });
        let room = slots.iter().flatten().count();
        let grants = self.streams.release(stream, bytes, room)?;
        for ((stream, increment), slot) in grants
            .into_iter()
            .flatten()
            .zip(slots.iter_mut().filter_map(Option::take))
        {
            let mut out = WriteLoan::new(slot);
            Frame::WindowUpdate { stream, increment }
                .write(&mut out)
                .map_err(|_| full())?;
            push_region(outbound, Lease::from(out.into_inner()))?;
        }
        Ok(())
    }

    /// Starts the shutdown of the connection (RFC 9113, section 6.8): no new stream opens, each
    /// open stream completes, and then the connection ends with no error.
    ///
    /// A client sends GOAWAY with `NO_ERROR` and the last stream 0. A server first sends GOAWAY
    /// with `NO_ERROR` and the last stream 2^31 - 1, and a PING with [`SHUTDOWN_PING`]. At its
    /// answer, the server sends GOAWAY with the last stream that went up, and discards each later
    /// stream. Thus no request in flight is lost. Refuses, and queues nothing, when the output
    /// queue or the pool has no room. A second call changes nothing.
    pub fn shutdown(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        self.writable(outbound)?;
        if self.streams.drain != Drain::Open {
            return Ok(());
        }
        let (last_stream, drain) = match self.role {
            Role::Client => (self.streams.last_stream, Drain::Sent(self.streams.last_stream)),
            Role::Server => (MAX_STREAM, Drain::Notice),
        };
        let frames = 1 + usize::from(drain == Drain::Notice);
        if outbound.free() < frames {
            return Err(full());
        }
        let goaway = Frame::GoAway {
            last_stream,
            code: ErrorCode::NO_ERROR,
            debug: &[],
        };
        let goaway = self.pooled(&goaway).ok_or_else(full)?;
        let ping = match drain {
            Drain::Notice => Some(
                self.pooled(&Frame::Ping {
                    ack: false,
                    opaque: SHUTDOWN_PING,
                })
                .ok_or_else(full)?,
            ),
            _ => None,
        };
        push_region(outbound, goaway)?;
        if let Some(ping) = ping {
            push_region(outbound, ping)?;
        }
        self.streams.drain = drain;
        Ok(())
    }

    /// Refuses a write after the end of the connection, and sends the answer that waits first, so
    /// that the order of the frames stays.
    fn writable(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        if self.end.is_some() {
            return Err(Error::new(ErrorKind::Misuse, "the connection ended"));
        }
        if self.flush(outbound) { Ok(()) } else { Err(full()) }
    }

    /// Writes `frame` into a slot of the pool. Gives `None` when the pool is empty.
    fn pooled(&mut self, frame: &Frame<'_>) -> Option<Lease> {
        let mut out = WriteLoan::new(self.pool.acquire().ok()?);
        frame.write(&mut out).ok()?;
        Some(Lease::from(out.into_inner()))
    }

    /// Queues the answer that waits, and then the free credit of the connection when it is due.
    /// Gives whether no answer waits.
    fn flush(&mut self, outbound: &mut Outbound) -> bool {
        if let Some(owed) = self.owed {
            if outbound.free() == 0 {
                return false;
            }
            let region = match owed {
                Owed::SettingsAck => Some(Lease::from(SETTINGS_ACK)),
                Owed::PingAck(opaque) => self.pooled(&Frame::Ping { ack: true, opaque }),
                Owed::Reset(stream, code) => self.pooled(&Frame::RstStream { stream, code }),
                Owed::Window(stream, increment) => self.pooled(&Frame::WindowUpdate { stream, increment }),
                Owed::GoAway(code, last_stream) => self.pooled(&Frame::GoAway {
                    last_stream,
                    code,
                    debug: &[],
                }),
            };
            let Some(region) = region else { return false };
            if outbound.push(region).is_err() {
                return false;
            }
            // The peer's table limit holds from the acknowledgement on, and each later block of the
            // encoder goes after it.
            if matches!(owed, Owed::SettingsAck) {
                self.encoder.set_peer_limit(self.peer.header_table_size as usize);
            }
            self.owed = None;
        }
        // No frame follows the GOAWAY of a connection error. A grant that finds no room waits for
        // a later flush.
        if self.end.is_none()
            && outbound.free() > 0
            && let Some(increment) = self.streams.connection_due()
            && let Some(region) = self.pooled(&Frame::WindowUpdate { stream: 0, increment })
            && outbound.push(region).is_ok()
        {
            self.streams.connection_granted(increment);
        }
        true
    }

    /// Ends the connection with `fault`: a GOAWAY with its code waits for the output queue.
    fn fail(&mut self, fault: Fault) {
        self.owed = Some(Owed::GoAway(fault.code, self.streams.last_stream));
        self.end = Some(Err(Error::new(fault.kind, fault.reason)));
    }

    /// Ends a connection that has no open stream after a GOAWAY: the endpoint sends its own
    /// GOAWAY first, if it did not yet (RFC 9113, section 6.8).
    fn finish(&mut self) {
        if !matches!(self.streams.drain, Drain::Sent(_)) {
            let last_stream = self.streams.last_stream;
            self.owed = Some(Owed::GoAway(ErrorCode::NO_ERROR, last_stream));
            self.streams.drain = Drain::Sent(last_stream);
        }
        self.end = Some(Ok(()));
    }

    /// Ends the connection at `now` when the peer did not acknowledge the settings by their
    /// deadline. The timeout needs the time of the host.
    fn expire(&mut self, now: Option<Instant>) {
        if self.acknowledged || self.end.is_some() || self.settings_timeout.is_none() {
            return;
        }
        let Some(now) = now else {
            self.end = Some(Err(Error::new(
                ErrorKind::Unsupported,
                "the settings timeout needs the time of the host",
            )));
            return;
        };
        match self.deadline.map(|deadline| deadline.is_reached(now)) {
            None | Some(Ok(false)) => {}
            Some(Ok(true)) => self.fail(Fault {
                code: ErrorCode::SETTINGS_TIMEOUT,
                kind: ErrorKind::Deadline,
                reason: "the peer did not acknowledge the settings before their deadline",
            }),
            Some(Err(_)) => {
                self.end = Some(Err(Error::new(
                    ErrorKind::Misuse,
                    "the time of the host is on another clock than the deadline",
                )));
            }
        }
    }

    /// Reads frames from `inbound` until an event, a wait, or a limit of the turn.
    fn step<'l>(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        lines: &'l mut Lines,
    ) -> Result<Next<'l>, Fault> {
        let mut work = Work::default();
        loop {
            if !self.flush(outbound) {
                return Ok(Next::Wait(Blocked::Output));
            }
            match self.read {
                Read::Preface(matched) => {
                    let Some(front) = inbound.front() else {
                        return Ok(self.wait(inbound, matched == 0));
                    };
                    let bytes = front.region.bytes();
                    let take = (PREFACE.len() - matched).min(bytes.len());
                    if bytes[..take] != PREFACE[matched..matched + take] {
                        return Err(Fault::peer(ErrorCode::PROTOCOL_ERROR, "the client preface is wrong"));
                    }
                    consume(inbound, take, &mut work)?;
                    self.read = match matched + take {
                        24 => Read::Head,
                        matched => Read::Preface(matched),
                    };
                }
                Read::Head => {
                    if !self.gather(HEAD, inbound, &mut work)? {
                        let boundary = self.carry.len == 0 && self.block.is_none();
                        return Ok(self.wait(inbound, boundary));
                    }
                    let head = Head::parse(self.carry.bytes);
                    let fixed = self.begin(&head)?;
                    if head.kind == Kind::Headers && self.streams.waits(head.stream) {
                        // The header stays in the carry, and a later drive reads it again.
                        return Ok(Next::Wait(Blocked::Streams));
                    }
                    self.carry.len = 0;
                    work.add(0, 1);
                    self.read = Read::Fixed(head, fixed);
                }
                Read::Fixed(head, len) => {
                    if !self.gather(len, inbound, &mut work)? {
                        return Ok(self.wait(inbound, false));
                    }
                    let fixed = Fixed::parse(&head, &self.carry.bytes[..len]);
                    self.carry.len = 0;
                    match fixed {
                        Ok(fixed) => {
                            let variable = head.length - narrow(len) - u32::from(fixed.padding());
                            if let Some(event) = self.fixed(&head, fixed, variable)? {
                                return Ok(Next::Event(event));
                            }
                        }
                        // A WINDOW_UPDATE of 0 on a stream.
                        Err(FrameError::Stream(code)) => {
                            self.read = Read::Head;
                            if self.streams.zero_window(head.stream)? {
                                return Ok(Next::Event(self.reset_by_error(head.stream, code)));
                            }
                        }
                        Err(error) => return Err(fault(error)),
                    }
                }
                Read::Body(head, fixed @ Fixed::Data { .. }, 0) => {
                    self.read = Read::Padding(head, fixed, u32::from(fixed.padding()));
                }
                Read::Body(head, fixed @ Fixed::Data { .. }, left) => {
                    let Some(front) = inbound.front() else {
                        return Ok(self.wait(inbound, false));
                    };
                    let len = (left as usize).min(front.region.initialized());
                    let data = front.region.view(..len).ok_or(internal())?;
                    consume(inbound, len, &mut work)?;
                    let left = left - narrow(len);
                    // The padding after the last bytes of the data can be in the same region.
                    let mut padding = if left == 0 { u32::from(fixed.padding()) } else { 0 };
                    let complete = left == 0 && skip(inbound, &mut padding, &mut work)?;
                    self.read = match (left, complete) {
                        (0, true) => Read::Head,
                        (0, false) => Read::Padding(head, fixed, padding),
                        (left, _) => Read::Body(head, fixed, left),
                    };
                    if let Some(event) = self.delivered(head.stream, data, complete && head.flags & END_STREAM != 0) {
                        return Ok(Next::Event(event));
                    }
                }
                Read::Body(head, fixed @ (Fixed::Headers { .. } | Fixed::Continuation), left) => {
                    let padding = u32::from(fixed.padding());
                    let rest = left as usize + padding as usize;
                    let available = inbound.front().map_or(0, |front| front.region.initialized());
                    let assembly = self.block.as_mut().ok_or(internal())?;
                    if assembly.join.is_none() && head.flags & END_HEADERS != 0 && available >= rest {
                        // The rest of the frame is in the front region, and no fragment before it
                        // has a byte: the block decodes in place.
                        let (stream, end_stream) = (assembly.stream, assembly.end_stream);
                        self.block = None;
                        self.read = Read::Head;
                        let bytes = inbound.front().map_or(&[][..], |front| front.region.bytes());
                        let decoded = self.decoder.decode(&bytes[..left as usize], lines);
                        consume(inbound, rest, &mut work)?;
                        return self.decoded(stream, end_stream, decoded);
                    }
                    if left == 0 {
                        self.read = Read::Padding(head, fixed, padding);
                        continue;
                    }
                    let Some(front) = inbound.front() else {
                        return Ok(self.wait(inbound, false));
                    };
                    if assembly.join.is_none() {
                        // A last fragment joins only its own bytes. A block that continues
                        // reserves the bound of a block, which no later fragment passes.
                        let units = if head.flags & END_HEADERS != 0 {
                            left as usize
                        } else {
                            self.header.work
                        };
                        let Ok(permit) = self.budget.reserve(units as u64) else {
                            return Ok(Next::Wait(Blocked::Capacity(units as u64)));
                        };
                        let mut bytes = Vec::new();
                        if bytes.try_reserve_exact(units).is_err() {
                            return Ok(Next::Wait(Blocked::Capacity(units as u64)));
                        }
                        assembly.join = Some(Join { bytes, _permit: permit });
                    }
                    let join = assembly.join.as_mut().ok_or(internal())?;
                    let len = (left as usize).min(front.region.initialized());
                    join.bytes.extend_from_slice(&front.region.bytes()[..len]);
                    consume(inbound, len, &mut work)?;
                    self.read = match left - narrow(len) {
                        0 => Read::Padding(head, fixed, padding),
                        left => Read::Body(head, fixed, left),
                    };
                }
                Read::Body(head, Fixed::Settings, left) => {
                    if left == 0 {
                        self.read = Read::Head;
                        self.streams.settings(self.window_peak, self.peer.initial_window_size)?;
                        self.owed = Some(Owed::SettingsAck);
                        return Ok(Next::Event(Event::Settings(self.peer)));
                    }
                    if !self.gather(6, inbound, &mut work)? {
                        return Ok(self.wait(inbound, false));
                    }
                    let [i0, i1, v0, v1, v2, v3, ..] = self.carry.bytes;
                    self.carry.len = 0;
                    let (id, value) = frame::setting_of([i0, i1, v0, v1, v2, v3]);
                    frame::check_setting(id, value).map_err(fault)?;
                    if self.role == Role::Client && id == ENABLE_PUSH && value == 1 {
                        return Err(Fault::peer(ErrorCode::PROTOCOL_ERROR, "the server enabled push"));
                    }
                    self.peer.apply(id, value);
                    if id == INITIAL_WINDOW_SIZE {
                        self.window_peak = self.window_peak.max(value);
                    }
                    self.read = Read::Body(head, Fixed::Settings, left - 6);
                }
                Read::Body(head, fixed, left) => {
                    // The debug data of a GOAWAY, the payload of an unknown type, and a DATA
                    // payload that the stream layer discards: discarded, with no copy.
                    let mut left = left;
                    if !skip(inbound, &mut left, &mut work)? {
                        self.read = Read::Body(head, fixed, left);
                        return Ok(self.wait(inbound, false));
                    }
                    self.read = Read::Head;
                    if let Fixed::GoAway { last_stream, code } = fixed {
                        self.streams.goaway(last_stream)?;
                        return Ok(Next::Event(Event::GoAway { last_stream, code }));
                    }
                }
                Read::Padding(head, fixed, padding) => {
                    let mut padding = padding;
                    if !skip(inbound, &mut padding, &mut work)? {
                        self.read = Read::Padding(head, fixed, padding);
                        return Ok(self.wait(inbound, false));
                    }
                    self.read = Read::Head;
                    match fixed {
                        Fixed::Data { .. } if head.flags & END_STREAM != 0 => {
                            let empty = Lease::from(<&[u8]>::default());
                            if let Some(event) = self.delivered(head.stream, empty, true) {
                                return Ok(Next::Event(event));
                            }
                        }
                        Fixed::Headers { .. } | Fixed::Continuation if head.flags & END_HEADERS != 0 => {
                            let assembly = self.block.take().ok_or(internal())?;
                            let bytes = assembly.join.as_ref().map_or(&[][..], |join| &join.bytes[..]);
                            let decoded = self.decoder.decode(bytes, lines);
                            return self.decoded(assembly.stream, assembly.end_stream, decoded);
                        }
                        _ => {}
                    }
                }
            }
            if work.reached(&self.turn) {
                return Ok(Next::Limit);
            }
        }
    }

    /// Checks a frame header before its payload: the order of the frames, and the checks of the
    /// codec. Gives the length of its fixed fields.
    fn begin(&self, head: &Head) -> Result<usize, Fault> {
        if let Some(assembly) = &self.block
            && (head.kind != Kind::Continuation || head.stream != assembly.stream)
        {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "a frame interrupted a header block",
            ));
        }
        if !self.preface && (head.kind != Kind::Settings || head.flags & ACK != 0) {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "the preface of the peer does not start with a SETTINGS frame",
            ));
        }
        let fixed = head.check(self.local.max_frame_size).map_err(fault)?;
        match head.kind {
            Kind::PushPromise => Err(Fault::peer(ErrorCode::PROTOCOL_ERROR, "push is disabled")),
            Kind::Continuation if self.block.is_none() => Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "a CONTINUATION frame does not follow a header block",
            )),
            _ => Ok(fixed),
        }
    }

    /// Acts on the fixed fields of a frame, and sets the place of its variable part of `variable`
    /// bytes. Gives the event of a frame that has no variable part.
    fn fixed(&mut self, head: &Head, fixed: Fixed, variable: u32) -> Result<Option<Event<'static>>, Fault> {
        self.read = Read::Body(*head, fixed, variable);
        let event = match fixed {
            Fixed::Data { .. } => {
                let end_stream = head.flags & END_STREAM != 0;
                let (flow, grant) = self.streams.data(head.stream, head.length, variable, end_stream)?;
                if let Some(increment) = grant {
                    self.owed = Some(Owed::Window(head.stream, increment));
                }
                match flow {
                    Flow::Deliver => None,
                    Flow::Discard | Flow::Reset(_) => {
                        // The rest of the frame, with its padding, is discarded with no copy.
                        let rest = variable + u32::from(fixed.padding());
                        self.read = Read::Body(*head, Fixed::Unknown, rest);
                        match flow {
                            Flow::Reset(code) => Some(self.reset_by_error(head.stream, code)),
                            _ => None,
                        }
                    }
                }
            }
            Fixed::Headers { .. } | Fixed::Continuation => {
                // A CONTINUATION frame follows a HEADERS frame of its block (`begin`).
                let size = self
                    .block
                    .as_ref()
                    .map_or(0, |block| block.size.saturating_add(HEAD))
                    .saturating_add(variable as usize);
                if size > self.header.work {
                    return Err(Fault {
                        code: ErrorCode::COMPRESSION_ERROR,
                        kind: ErrorKind::Overload,
                        reason: "a header block is larger than its bound",
                    });
                }
                match &mut self.block {
                    Some(block) => block.size = size,
                    None => {
                        self.block = Some(Assembly {
                            stream: head.stream,
                            end_stream: head.flags & END_STREAM != 0,
                            size,
                            join: None,
                        });
                    }
                }
                None
            }
            Fixed::Settings if head.flags & ACK != 0 => {
                if self.acknowledged {
                    return Err(Fault::peer(
                        ErrorCode::PROTOCOL_ERROR,
                        "a SETTINGS acknowledgement has no SETTINGS frame",
                    ));
                }
                self.acknowledged = true;
                self.deadline = None;
                self.decoder.set_limit(self.local.header_table_size as usize);
                self.streams.acknowledged();
                self.read = Read::Head;
                None
            }
            Fixed::Settings => {
                self.preface = true;
                self.window_peak = self.peer.initial_window_size;
                None
            }
            Fixed::Ping(opaque) => {
                self.read = Read::Head;
                if head.flags & ACK == 0 {
                    self.owed = Some(Owed::PingAck(opaque));
                    None
                } else if self.streams.drain == Drain::Notice && opaque == SHUTDOWN_PING {
                    // The peer read the first GOAWAY of the shutdown, so each stream that it
                    // opens later is above the last stream.
                    let last_stream = self.streams.last_stream;
                    self.owed = Some(Owed::GoAway(ErrorCode::NO_ERROR, last_stream));
                    self.streams.drain = Drain::Sent(last_stream);
                    None
                } else {
                    Some(Event::PingAck(opaque))
                }
            }
            Fixed::RstStream(code) => {
                self.read = Read::Head;
                self.streams.reset(head.stream)?.then_some(Event::Reset {
                    stream: head.stream,
                    code,
                })
            }
            Fixed::WindowUpdate(increment) => {
                self.read = Read::Head;
                self.streams
                    .window(head.stream, increment)?
                    .map(|code| self.reset_by_error(head.stream, code))
            }
            Fixed::Priority(_) => {
                self.read = Read::Head;
                None
            }
            Fixed::GoAway { .. } | Fixed::Unknown | Fixed::PushPromise { .. } => None,
        };
        Ok(event)
    }

    /// The event of a decoded header block, or `Next::Limit` when no event goes up: one header
    /// block decodes in each drive.
    fn decoded<'l>(
        &mut self,
        stream: u32,
        end_stream: bool,
        decoded: Result<Block<'l>, DecodeError>,
    ) -> Result<Next<'l>, Fault> {
        let lines = match decoded {
            Ok(block) => Some(block),
            Err(DecodeError::TooLarge) => None,
            Err(DecodeError::Malformed) => {
                return Err(Fault::peer(
                    ErrorCode::COMPRESSION_ERROR,
                    "a header block breaks RFC 7541",
                ));
            }
            Err(DecodeError::Overload) => {
                return Err(Fault {
                    code: ErrorCode::COMPRESSION_ERROR,
                    kind: ErrorKind::Overload,
                    reason: "a header block needs more work than its limit",
                });
            }
            Err(DecodeError::Misuse) => {
                return Err(Fault {
                    code: ErrorCode::INTERNAL_ERROR,
                    kind: ErrorKind::Misuse,
                    reason: "the lines of the drive are smaller than the header limits need",
                });
            }
        };
        let first = lines.as_ref().and_then(|block| block.lines().next());
        Ok(
            match self.streams.headers(stream, end_stream, first, self.acknowledged)? {
                Section::Head => Next::Event(Event::Headers {
                    stream,
                    end_stream,
                    lines,
                }),
                Section::Trailers => Next::Event(Event::Trailers { stream, lines }),
                Section::Discard => Next::Limit,
                Section::Refuse(code) => {
                    self.owed = Some(Owed::Reset(stream, code));
                    Next::Limit
                }
                Section::Reset(code) => Next::Event(self.reset_by_error(stream, code)),
            },
        )
    }

    /// The event of DATA bytes that the peer sent on `stream`, or `None` when the stream no
    /// longer receives: the application reset it inside the frame.
    fn delivered(&mut self, stream: u32, data: Lease, end_stream: bool) -> Option<Event<'static>> {
        if !self.streams.receive(stream, narrow(data.initialized())) {
            return None;
        }
        if end_stream {
            self.streams.end(stream);
        }
        Some(Event::Data {
            stream,
            data,
            end_stream,
        })
    }

    /// Queues the RST_STREAM of a stream error of `code` on `stream`, which the stream layer
    /// ended, and gives its event.
    fn reset_by_error(&mut self, stream: u32, code: ErrorCode) -> Event<'static> {
        self.owed = Some(Owed::Reset(stream, code));
        Event::StreamError { stream, code }
    }

    /// Copies bytes from the front of `inbound` into the carry until it holds `len` bytes, and
    /// gives whether it holds them.
    fn gather(&mut self, len: usize, inbound: &mut Inbound, work: &mut Work) -> Result<bool, Fault> {
        while self.carry.len < len {
            let Some(front) = inbound.front() else { return Ok(false) };
            let bytes = front.region.bytes();
            let take = (len - self.carry.len).min(bytes.len());
            self.carry.bytes[self.carry.len..self.carry.len + take].copy_from_slice(&bytes[..take]);
            self.carry.len += take;
            consume(inbound, take, work)?;
        }
        Ok(true)
    }

    /// The result of a read that needs more input: a wait, or the end when the transport gives no
    /// more bytes. The end at a frame boundary (`boundary`) ends the connection with no error.
    fn wait(&mut self, inbound: &Inbound, boundary: bool) -> Next<'static> {
        if inbound.ended() && inbound.front().is_none() {
            self.end = Some(match (boundary, self.streams.active()) {
                (true, false) => Ok(()),
                (true, true) => Err(Error::new(ErrorKind::Partial, "the connection ended with open streams")),
                (false, _) => Err(Error::new(ErrorKind::Partial, "the connection ended inside a frame")),
            });
        }
        Next::Wait(Blocked::Input)
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.role)
            .field("local", &self.local)
            .field("acknowledged", &self.acknowledged)
            .field("peer", &self.peer)
            .field("read", &self.read)
            .field("block", &self.block)
            .field("owed", &self.owed)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// The connection error of a frame that a check of the codec refused.
const fn fault(error: FrameError) -> Fault {
    match error {
        FrameError::Connection(code) | FrameError::Stream(code) => Fault::frame(code),
    }
}

/// Consumes `len` bytes of the front region and counts them.
fn consume(inbound: &mut Inbound, len: usize, work: &mut Work) -> Result<(), Fault> {
    inbound.consume(len).map_err(|_| internal())?;
    work.add(len, 0);
    Ok(())
}

/// Consumes up to `left` bytes from the front regions, and gives whether no byte is left.
fn skip(inbound: &mut Inbound, left: &mut u32, work: &mut Work) -> Result<bool, Fault> {
    while *left > 0 {
        let Some(front) = inbound.front() else { return Ok(false) };
        let len = (*left as usize).min(front.region.initialized());
        consume(inbound, len, work)?;
        *left -= narrow(len);
    }
    Ok(true)
}

/// A length that a `u32` value bounds, as a `u32`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each caller gives a length that is at most a u32 value: a frame length or a part of one"
)]
const fn narrow(len: usize) -> u32 {
    len as u32
}

/// Pushes `region` into the output queue, which has room.
fn push_region(outbound: &mut Outbound, region: Lease) -> Result<(), Error> {
    outbound.push(region).map_err(|_| full())
}

/// The refusal of a full output queue or pool.
fn full() -> Error {
    Error::new(ErrorKind::Overload, "the output queue or the frame pool is full")
}

/// A state that the reader cannot reach.
const fn internal() -> Fault {
    Fault {
        code: ErrorCode::INTERNAL_ERROR,
        kind: ErrorKind::Misuse,
        reason: "the connection reached a state that it cannot reach",
    }
}
