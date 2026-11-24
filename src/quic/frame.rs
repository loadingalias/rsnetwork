//! The frame codec of version 1 (RFC 9000, section 19) and the DATAGRAM frame (RFC 9221): a parser
//! that gives each frame as views of the payload of its packet, the permitted frames of each kind
//! of packet, and a writer.

use core::fmt;
use core::ops::RangeInclusive;

use super::packet::Kind;
use super::{ConnectionId, ErrorCode, Reader, VARINT_MAX, Writer};

/// The largest stream count of MAX_STREAMS and STREAMS_BLOCKED: 2^60 (RFC 9000, section 19.11).
pub const STREAMS_MAX: u64 = 1 << 60;

/// The direction of the streams of MAX_STREAMS and STREAMS_BLOCKED.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Streams that carry data in both directions.
    Bidirectional,
    /// Streams that carry data from their initiator only.
    Unidirectional,
}

/// The ECN counts of an ACK frame (RFC 9000, section 19.3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EcnCounts {
    /// The packets with the ECT(0) codepoint.
    pub ect0: u64,
    /// The packets with the ECT(1) codepoint.
    pub ect1: u64,
    /// The packets with the ECN-CE codepoint.
    pub ce: u64,
}

/// An ACK frame (RFC 9000, section 19.3). The parser checked each range.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ack<'a> {
    /// The largest packet number that the frame acknowledges.
    pub largest: u64,
    /// The ACK delay, in units of the `ack_delay_exponent` of the peer.
    pub delay: u64,
    /// The packets below `largest` in the first range.
    pub first: u64,
    /// The number of ranges after the first.
    count: u64,
    /// The packet numbers below the first range that the encoded gaps and ranges span.
    span: u64,
    /// The encoded gaps and lengths of those ranges.
    ranges: &'a [u8],
    /// The ECN counts of an ACK frame of type 0x03.
    pub ecn: Option<EcnCounts>,
}

impl Ack<'_> {
    pub(super) fn valid(&self) -> bool {
        self.largest <= VARINT_MAX
            && self.delay <= VARINT_MAX
            && self.largest.checked_sub(self.first).is_some_and(|low| low >= self.span)
            && self.ecn.is_none_or(|c| c.ect0.max(c.ect1).max(c.ce) <= VARINT_MAX)
    }

    /// Each acknowledged range of packet numbers, from the largest down.
    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        let mut reader = Reader::new(self.ranges);
        let mut low = self.largest.saturating_sub(self.first);
        let valid = self.valid();
        let first = valid.then_some(low..=self.largest).into_iter();
        first.chain((0..if valid { self.count } else { 0 }).map_while(move |_| {
            let (gap, length) = (reader.varint()?, reader.varint()?);
            let high = low.checked_sub(gap)?.checked_sub(2)?;
            low = high.checked_sub(length)?;
            Some(low..=high)
        }))
    }
}

impl fmt::Debug for Ack<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ack")
            .field("largest", &self.largest)
            .field("delay", &self.delay)
            .field("first", &self.first)
            .field("count", &self.count)
            .field("ecn", &self.ecn)
            .finish()
    }
}

/// A frame of version 1. Each view is in the payload that the frame came from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// PADDING frames in a row.
    Padding {
        /// The bytes of zero.
        len: usize,
    },
    /// A PING frame.
    Ping,
    /// An ACK frame.
    Ack(Ack<'a>),
    /// A RESET_STREAM frame.
    ResetStream {
        /// The stream.
        stream: u64,
        /// The application error code.
        code: u64,
        /// The final size of the stream.
        final_size: u64,
    },
    /// A STOP_SENDING frame.
    StopSending {
        /// The stream.
        stream: u64,
        /// The application error code.
        code: u64,
    },
    /// A CRYPTO frame.
    Crypto {
        /// The offset of the data in the cryptographic stream of its packet number space.
        offset: u64,
        /// The data.
        data: &'a [u8],
    },
    /// A NEW_TOKEN frame, with a token that is not empty.
    NewToken {
        /// The address token.
        token: &'a [u8],
    },
    /// A STREAM frame.
    Stream {
        /// The stream.
        stream: u64,
        /// The offset of the data in the stream.
        offset: u64,
        /// The data.
        data: &'a [u8],
        /// The data ends the stream.
        fin: bool,
    },
    /// A MAX_DATA frame.
    MaxData {
        /// The most data that the connection can carry.
        max: u64,
    },
    /// A MAX_STREAM_DATA frame.
    MaxStreamData {
        /// The stream.
        stream: u64,
        /// The most data that the stream can carry.
        max: u64,
    },
    /// A MAX_STREAMS frame.
    MaxStreams {
        /// The direction of the streams.
        direction: Direction,
        /// The most streams of that direction that the peer can open, at most 2^60.
        max: u64,
    },
    /// A DATA_BLOCKED frame.
    DataBlocked {
        /// The limit of the connection at which the sender is blocked.
        limit: u64,
    },
    /// A STREAM_DATA_BLOCKED frame.
    StreamDataBlocked {
        /// The stream.
        stream: u64,
        /// The limit of the stream at which the sender is blocked.
        limit: u64,
    },
    /// A STREAMS_BLOCKED frame.
    StreamsBlocked {
        /// The direction of the streams.
        direction: Direction,
        /// The stream limit at which the sender is blocked, at most 2^60.
        limit: u64,
    },
    /// A NEW_CONNECTION_ID frame.
    NewConnectionId {
        /// The sequence number of the connection ID.
        sequence: u64,
        /// The connection IDs below this sequence number to retire.
        retire_prior_to: u64,
        /// The connection ID: 1 to 20 bytes.
        id: ConnectionId,
        /// The stateless reset token of the connection ID.
        reset_token: [u8; 16],
    },
    /// A RETIRE_CONNECTION_ID frame.
    RetireConnectionId {
        /// The sequence number of the connection ID to retire.
        sequence: u64,
    },
    /// A PATH_CHALLENGE frame.
    PathChallenge {
        /// The data that the answer echoes.
        data: [u8; 8],
    },
    /// A PATH_RESPONSE frame.
    PathResponse {
        /// The data of the challenge.
        data: [u8; 8],
    },
    /// A CONNECTION_CLOSE frame: of the transport (0x1c), with the type of the frame that caused
    /// the close, or of the application (0x1d).
    ConnectionClose {
        /// The error code: of the transport, or of the application.
        code: u64,
        /// The type of the frame that caused a close of the transport, or `None` for a close of the
        /// application.
        frame_type: Option<u64>,
        /// The reason phrase, peer bytes.
        reason: &'a [u8],
    },
    /// A HANDSHAKE_DONE frame.
    HandshakeDone,
    /// A DATAGRAM frame (RFC 9221).
    Datagram {
        /// The data.
        data: &'a [u8],
    },
}

/// A frame that is not valid: close the connection with `code`, and name `frame_type`, the type of
/// the frame, in the CONNECTION_CLOSE frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameError {
    /// The transport error code of the close.
    pub code: ErrorCode,
    /// The type of the frame.
    pub frame_type: u64,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the QUIC frame of type {:#x} is not valid", self.frame_type)
    }
}

impl core::error::Error for FrameError {}

/// Why a frame could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output has no room for it.
    Full,
    /// A value does not fit its field: above 2^62 - 1, or a stream count above 2^60.
    Value,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "the output has no room for the QUIC frame",
            Self::Value => "a value does not fit its field of the QUIC frame",
        })
    }
}

impl core::error::Error for WriteError {}

impl<'a> Frame<'a> {
    /// Parses the frame at the start of `bytes`, a payload of a packet, and gives it with the
    /// bytes that it took. A frame of a type that the codec does not know, or with a field that is
    /// not valid, refuses with `FRAME_ENCODING_ERROR`, and a type in a longer encoding than its
    /// shortest with `PROTOCOL_VIOLATION` (RFC 9000, section 12.4).
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), FrameError> {
        let mut reader = Reader::new(bytes);
        let Some((kind, len)) = reader.varint_with_len() else {
            return Err(encoding(0));
        };
        let error = encoding(kind);
        if super::varint_len(kind) != Some(len) {
            return Err(FrameError {
                code: ErrorCode::PROTOCOL_VIOLATION,
                frame_type: kind,
            });
        }
        let frame = Self::fields(kind, &mut reader).ok_or(error)?;
        Ok((frame, reader.at()))
    }

    /// The fields of a frame of type `kind`, after its type.
    fn fields(kind: u64, reader: &mut Reader<'a>) -> Option<Self> {
        let frame = match kind {
            0x00 => {
                let zeros = reader.rest().iter().take_while(|&&byte| byte == 0).count();
                reader.take(zeros)?;
                Self::Padding { len: zeros + 1 }
            }
            0x01 => Self::Ping,
            0x02 | 0x03 => Self::Ack(ack(reader, kind == 0x03)?),
            0x04 => Self::ResetStream {
                stream: reader.varint()?,
                code: reader.varint()?,
                final_size: reader.varint()?,
            },
            0x05 => Self::StopSending {
                stream: reader.varint()?,
                code: reader.varint()?,
            },
            0x06 => {
                let offset = reader.varint()?;
                let data = sized(reader)?;
                offset.checked_add(data.len() as u64).filter(|&end| end <= VARINT_MAX)?;
                Self::Crypto { offset, data }
            }
            0x07 => Self::NewToken {
                token: Some(sized(reader)?).filter(|token| !token.is_empty())?,
            },
            0x08..=0x0f => {
                let stream = reader.varint()?;
                let offset = if kind & 0x04 == 0 { 0 } else { reader.varint()? };
                let data = if kind & 0x02 == 0 {
                    reader.take(reader.rest().len())?
                } else {
                    sized(reader)?
                };
                offset.checked_add(data.len() as u64).filter(|&end| end <= VARINT_MAX)?;
                Self::Stream {
                    stream,
                    offset,
                    data,
                    fin: kind & 0x01 != 0,
                }
            }
            0x10 => Self::MaxData { max: reader.varint()? },
            0x11 => Self::MaxStreamData {
                stream: reader.varint()?,
                max: reader.varint()?,
            },
            0x12 | 0x13 => Self::MaxStreams {
                direction: direction(kind),
                max: Some(reader.varint()?).filter(|&max| max <= STREAMS_MAX)?,
            },
            0x14 => Self::DataBlocked {
                limit: reader.varint()?,
            },
            0x15 => Self::StreamDataBlocked {
                stream: reader.varint()?,
                limit: reader.varint()?,
            },
            0x16 | 0x17 => Self::StreamsBlocked {
                direction: direction(kind),
                limit: Some(reader.varint()?).filter(|&limit| limit <= STREAMS_MAX)?,
            },
            0x18 => {
                let sequence = reader.varint()?;
                let retire_prior_to = Some(reader.varint()?).filter(|&prior| prior <= sequence)?;
                let len = usize::from(reader.u8()?);
                let id = ConnectionId::new(reader.take(len)?).filter(|_| (1..=ConnectionId::MAX).contains(&len))?;
                Self::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token: reader.array()?,
                }
            }
            0x19 => Self::RetireConnectionId {
                sequence: reader.varint()?,
            },
            0x1a => Self::PathChallenge { data: reader.array()? },
            0x1b => Self::PathResponse { data: reader.array()? },
            0x1c | 0x1d => {
                let code = reader.varint()?;
                let frame_type = if kind == 0x1c { Some(reader.varint()?) } else { None };
                Self::ConnectionClose {
                    code,
                    frame_type,
                    reason: sized(reader)?,
                }
            }
            0x1e => Self::HandshakeDone,
            0x30 => Self::Datagram {
                data: reader.take(reader.rest().len())?,
            },
            0x31 => Self::Datagram { data: sized(reader)? },
            _ => return None,
        };
        Some(frame)
    }

    /// Whether a packet of `kind` can carry the frame (RFC 9000, section 12.4, table 3, and RFC
    /// 9221, section 4). A frame that its packet cannot carry ends the connection with
    /// `PROTOCOL_VIOLATION`.
    pub const fn permitted(&self, kind: Kind) -> bool {
        let early = matches!(kind, Kind::ZeroRtt);
        let data = matches!(kind, Kind::ZeroRtt | Kind::OneRtt);
        match self {
            Self::Padding { .. }
            | Self::Ping
            | Self::ConnectionClose {
                frame_type: Some(_), ..
            } => true,
            Self::Ack(_) | Self::Crypto { .. } => !early,
            Self::NewToken { .. }
            | Self::RetireConnectionId { .. }
            | Self::PathResponse { .. }
            | Self::HandshakeDone => {
                matches!(kind, Kind::OneRtt)
            }
            Self::ResetStream { .. }
            | Self::StopSending { .. }
            | Self::Stream { .. }
            | Self::MaxData { .. }
            | Self::MaxStreamData { .. }
            | Self::MaxStreams { .. }
            | Self::DataBlocked { .. }
            | Self::StreamDataBlocked { .. }
            | Self::StreamsBlocked { .. }
            | Self::NewConnectionId { .. }
            | Self::PathChallenge { .. }
            | Self::ConnectionClose { frame_type: None, .. }
            | Self::Datagram { .. } => data,
        }
    }

    /// Writes the frame at the start of `out`, and gives its bytes. A STREAM, CRYPTO, or DATAGRAM
    /// frame has its length, so another frame can follow it. Refuses, and gives no length, when
    /// `out` has no room or a value does not fit its field.
    pub fn write(&self, out: &mut [u8]) -> Result<usize, WriteError> {
        self.check()?;
        let mut writer = Writer::new(out);
        self.encode(&mut writer).ok_or(WriteError::Full)?;
        Ok(writer.len())
    }

    /// Refuses a value that does not fit its field.
    fn check(&self) -> Result<(), WriteError> {
        if self.largest() > VARINT_MAX {
            return Err(WriteError::Value);
        }
        let fits = match *self {
            Self::Ack(ack) => ack.valid(),
            Self::Crypto { offset, data } | Self::Stream { offset, data, .. } => offset
                .checked_add(data.len() as u64)
                .is_some_and(|end| end <= VARINT_MAX),
            Self::MaxStreams { max: count, .. } | Self::StreamsBlocked { limit: count, .. } => count <= STREAMS_MAX,
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                ..
            } => retire_prior_to <= sequence && !id.as_bytes().is_empty(),
            Self::NewToken { token } => !token.is_empty(),
            Self::Padding { len } => len > 0,
            _ => true,
        };
        if fits { Ok(()) } else { Err(WriteError::Value) }
    }

    /// The largest value of the variable-length fields of the frame.
    fn largest(&self) -> u64 {
        match *self {
            Self::Ack(ack) => {
                let ecn = ack.ecn.map_or(0, |ecn| ecn.ect0.max(ecn.ect1).max(ecn.ce));
                ack.largest.max(ack.delay).max(ack.count).max(ack.first).max(ecn)
            }
            Self::ResetStream {
                stream,
                code,
                final_size,
            } => stream.max(code).max(final_size),
            Self::StopSending {
                stream: first,
                code: second,
            }
            | Self::MaxStreamData {
                stream: first,
                max: second,
            }
            | Self::StreamDataBlocked {
                stream: first,
                limit: second,
            }
            | Self::Stream {
                stream: first,
                offset: second,
                ..
            }
            | Self::NewConnectionId {
                sequence: first,
                retire_prior_to: second,
                ..
            } => first.max(second),
            Self::Crypto { offset: value, .. }
            | Self::MaxData { max: value }
            | Self::MaxStreams { max: value, .. }
            | Self::DataBlocked { limit: value }
            | Self::StreamsBlocked { limit: value, .. }
            | Self::RetireConnectionId { sequence: value } => value,
            Self::ConnectionClose { code, frame_type, .. } => code.max(frame_type.unwrap_or(0)),
            Self::Padding { .. }
            | Self::Ping
            | Self::NewToken { .. }
            | Self::PathChallenge { .. }
            | Self::PathResponse { .. }
            | Self::HandshakeDone
            | Self::Datagram { .. } => 0,
        }
    }

    /// Writes the frame, whose values fit their fields. `None` when the output has no room.
    fn encode(&self, writer: &mut Writer<'_>) -> Option<()> {
        match *self {
            Self::Padding { len } => (0..len).try_for_each(|_| writer.u8(0)),
            Self::Ping => writer.u8(0x01),
            Self::Ack(ack) => {
                writer.u8(if ack.ecn.is_some() { 0x03 } else { 0x02 })?;
                [ack.largest, ack.delay, ack.count, ack.first]
                    .into_iter()
                    .try_for_each(|value| writer.varint(value))?;
                writer.bytes(ack.ranges)?;
                ack.ecn.map_or(Some(()), |ecn| {
                    [ecn.ect0, ecn.ect1, ecn.ce]
                        .into_iter()
                        .try_for_each(|count| writer.varint(count))
                })
            }
            Self::ResetStream {
                stream,
                code,
                final_size,
            } => {
                writer.u8(0x04)?;
                [stream, code, final_size]
                    .into_iter()
                    .try_for_each(|value| writer.varint(value))
            }
            Self::StopSending { stream, code } => {
                writer.u8(0x05)?;
                [stream, code].into_iter().try_for_each(|value| writer.varint(value))
            }
            Self::Crypto { offset, data } => {
                writer.u8(0x06)?;
                writer.varint(offset)?;
                sized_out(writer, data)
            }
            Self::NewToken { token } => {
                writer.u8(0x07)?;
                sized_out(writer, token)
            }
            Self::Stream {
                stream,
                offset,
                data,
                fin,
            } => {
                let off = if offset == 0 { 0 } else { 0x04 };
                writer.u8(0x08 | off | 0x02 | u8::from(fin))?;
                writer.varint(stream)?;
                if offset != 0 {
                    writer.varint(offset)?;
                }
                sized_out(writer, data)
            }
            Self::MaxData { max } => one(writer, 0x10, max),
            Self::MaxStreamData { stream, max } => two(writer, 0x11, stream, max),
            Self::MaxStreams { direction, max } => one(writer, 0x12 | bit(direction), max),
            Self::DataBlocked { limit } => one(writer, 0x14, limit),
            Self::StreamDataBlocked { stream, limit } => two(writer, 0x15, stream, limit),
            Self::StreamsBlocked { direction, limit } => one(writer, 0x16 | bit(direction), limit),
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => {
                two(writer, 0x18, sequence, retire_prior_to)?;
                writer.u8(u8::try_from(id.as_bytes().len()).ok()?)?;
                writer.bytes(id.as_bytes())?;
                writer.bytes(&reset_token)
            }
            Self::RetireConnectionId { sequence } => one(writer, 0x19, sequence),
            Self::PathChallenge { data } => {
                writer.u8(0x1a)?;
                writer.bytes(&data)
            }
            Self::PathResponse { data } => {
                writer.u8(0x1b)?;
                writer.bytes(&data)
            }
            Self::ConnectionClose {
                code,
                frame_type,
                reason,
            } => {
                writer.u8(if frame_type.is_some() { 0x1c } else { 0x1d })?;
                writer.varint(code)?;
                if let Some(frame_type) = frame_type {
                    writer.varint(frame_type)?;
                }
                sized_out(writer, reason)
            }
            Self::HandshakeDone => writer.u8(0x1e),
            Self::Datagram { data } => {
                writer.u8(0x31)?;
                sized_out(writer, data)
            }
        }
    }
}

impl fmt::Debug for Frame<'_> {
    /// The data, the tokens, and the reasons are peer bytes, so only their lengths show.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto { offset, data } => f
                .debug_struct("Crypto")
                .field("offset", offset)
                .field("len", &data.len())
                .finish(),
            Self::NewToken { token } => f.debug_struct("NewToken").field("len", &token.len()).finish(),
            Self::Stream {
                stream,
                offset,
                data,
                fin,
            } => f
                .debug_struct("Stream")
                .field("stream", stream)
                .field("offset", offset)
                .field("len", &data.len())
                .field("fin", fin)
                .finish(),
            Self::ConnectionClose {
                code,
                frame_type,
                reason,
            } => f
                .debug_struct("ConnectionClose")
                .field("code", code)
                .field("frame_type", frame_type)
                .field("reason_len", &reason.len())
                .finish(),
            Self::Datagram { data } => f.debug_struct("Datagram").field("len", &data.len()).finish(),
            Self::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                ..
            } => f
                .debug_struct("NewConnectionId")
                .field("sequence", sequence)
                .field("retire_prior_to", retire_prior_to)
                .field("id", id)
                .finish_non_exhaustive(),
            Self::Padding { len } => f.debug_struct("Padding").field("len", len).finish(),
            Self::Ping => f.write_str("Ping"),
            Self::Ack(ack) => ack.fmt(f),
            Self::ResetStream {
                stream,
                code,
                final_size,
            } => f
                .debug_struct("ResetStream")
                .field("stream", stream)
                .field("code", code)
                .field("final_size", final_size)
                .finish(),
            Self::StopSending { stream, code } => f
                .debug_struct("StopSending")
                .field("stream", stream)
                .field("code", code)
                .finish(),
            Self::MaxData { max } => f.debug_struct("MaxData").field("max", max).finish(),
            Self::MaxStreamData { stream, max } => f
                .debug_struct("MaxStreamData")
                .field("stream", stream)
                .field("max", max)
                .finish(),
            Self::MaxStreams { direction, max } => f
                .debug_struct("MaxStreams")
                .field("direction", direction)
                .field("max", max)
                .finish(),
            Self::DataBlocked { limit } => f.debug_struct("DataBlocked").field("limit", limit).finish(),
            Self::StreamDataBlocked { stream, limit } => f
                .debug_struct("StreamDataBlocked")
                .field("stream", stream)
                .field("limit", limit)
                .finish(),
            Self::StreamsBlocked { direction, limit } => f
                .debug_struct("StreamsBlocked")
                .field("direction", direction)
                .field("limit", limit)
                .finish(),
            Self::RetireConnectionId { sequence } => f
                .debug_struct("RetireConnectionId")
                .field("sequence", sequence)
                .finish(),
            Self::PathChallenge { .. } => f.write_str("PathChallenge"),
            Self::PathResponse { .. } => f.write_str("PathResponse"),
            Self::HandshakeDone => f.write_str("HandshakeDone"),
        }
    }
}

/// The refusal of a frame of type `kind` whose fields are not valid.
const fn encoding(kind: u64) -> FrameError {
    FrameError {
        code: ErrorCode::FRAME_ENCODING_ERROR,
        frame_type: kind,
    }
}

/// The direction of a MAX_STREAMS or STREAMS_BLOCKED frame of type `kind`: its low bit.
const fn direction(kind: u64) -> Direction {
    if kind & 1 == 0 {
        Direction::Bidirectional
    } else {
        Direction::Unidirectional
    }
}

/// The low bit of the type of a frame with `direction`.
const fn bit(direction: Direction) -> u8 {
    match direction {
        Direction::Bidirectional => 0,
        Direction::Unidirectional => 1,
    }
}

/// The fields of an ACK frame, after its type. Each range must stay at or above packet number 0.
fn ack<'a>(reader: &mut Reader<'a>, ecn: bool) -> Option<Ack<'a>> {
    let (largest, delay, count, first) = (reader.varint()?, reader.varint()?, reader.varint()?, reader.varint()?);
    let mut low = largest.checked_sub(first)?;
    // Each range takes at least two bytes, so a count past the rest refuses before the loop.
    if count > (reader.rest().len() / 2) as u64 {
        return None;
    }
    let start = reader.at();
    let rest = reader.rest();
    for _ in 0..count {
        let (gap, length) = (reader.varint()?, reader.varint()?);
        low = low.checked_sub(gap)?.checked_sub(2)?.checked_sub(length)?;
    }
    let ranges = &rest[..reader.at() - start];
    let ecn = if ecn {
        Some(EcnCounts {
            ect0: reader.varint()?,
            ect1: reader.varint()?,
            ce: reader.varint()?,
        })
    } else {
        None
    };
    Some(Ack {
        largest,
        delay,
        first,
        count,
        span: largest - first - low,
        ranges,
        ecn,
    })
}

/// A field with its length before it.
fn sized<'a>(reader: &mut Reader<'a>) -> Option<&'a [u8]> {
    let len = usize::try_from(reader.varint()?).ok()?;
    reader.take(len)
}

fn sized_out(writer: &mut Writer<'_>, bytes: &[u8]) -> Option<()> {
    writer.varint(bytes.len() as u64)?;
    writer.bytes(bytes)
}

fn one(writer: &mut Writer<'_>, kind: u8, value: u64) -> Option<()> {
    writer.u8(kind)?;
    writer.varint(value)
}

fn two(writer: &mut Writer<'_>, kind: u8, first: u64, second: u64) -> Option<()> {
    one(writer, kind, first)?;
    writer.varint(second)
}
