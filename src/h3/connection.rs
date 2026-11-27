//! The HTTP/3 connection on the stream and flow-control state of one QUIC connection.

use core::alloc::Layout;
use core::fmt;
use core::mem;

use crate::body::{Outcome, Part as BodyPart, Trailers};
use crate::buffer::{Buffer as _, Lease, Pool, WriteLoan};
use crate::capacity::{Budget, Permit};
use crate::drive::{Error as HostError, Kind};
use crate::h2::message::{self, Refusal, ResponseFields};
use crate::message::{RequestHead, ResponseHead};
use crate::qpack;
use crate::quic::{self, StreamId, frame::Direction, packet::Side};
use crate::time::Instant;
use crate::value::Method;

use super::frame::{self, Integer, Kind as Frame, Part, Stream};
use super::send::{CONTROL, DECODER, ENCODER, Output};

/// Local limits for an HTTP/3 connection. QUIC owns stream and connection flow control.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent requests that the application can own.
    pub requests: usize,
    /// Maximum encoded bytes of one received field section.
    pub field_section_bytes: usize,
    /// Aggregate capacity of blocked field sections and the stream bytes held behind them.
    pub blocked_bytes: usize,
    /// Bytes available for a SETTINGS frame and for each outgoing critical stream buffer.
    pub control_bytes: usize,
    /// Local QPACK decoder limits, including the maximum decoded field size.
    pub decoder: qpack::Limits,
    /// Local limits on the QPACK encoder.
    pub encoder: qpack::EncoderLimits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests: 100,
            field_section_bytes: 64 << 10,
            control_bytes: 4096,
            blocked_bytes: 256 << 10,
            decoder: qpack::Limits {
                table_bytes: 4096,
                blocked_streams: 16,
                list_bytes: 64 << 10,
                work: 64 << 10,
            },
            encoder: qpack::EncoderLimits {
                table_bytes: 4096,
                sections: 100,
            },
        }
    }
}

/// HTTP/3 and QPACK application codes used by this engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Code {
    /// A graceful shutdown.
    NoError = 0x100,
    /// A peer failed a connection requirement.
    GeneralProtocol = 0x101,
    /// A local implementation failure.
    Internal = 0x102,
    /// A forbidden stream or a second critical stream of one type.
    StreamCreation = 0x103,
    /// A critical stream ended.
    ClosedCriticalStream = 0x104,
    /// A frame appeared out of sequence or on the wrong stream.
    FrameUnexpected = 0x105,
    /// A frame had invalid or truncated contents.
    Frame = 0x106,
    /// Work or storage exceeded an admitted limit.
    ExcessiveLoad = 0x107,
    /// A push or shutdown identifier broke its contract.
    Id = 0x108,
    /// The peer sent invalid settings.
    Settings = 0x109,
    /// A different frame preceded SETTINGS.
    MissingSettings = 0x10a,
    /// The server did not process the request.
    RequestRejected = 0x10b,
    /// An endpoint cancelled the request.
    RequestCancelled = 0x10c,
    /// A request ended before its head arrived.
    RequestIncomplete = 0x10d,
    /// The message was malformed.
    Message = 0x10e,
    /// QPACK could not decompress a field section.
    Decompression = 0x200,
    /// An invalid QPACK encoder instruction.
    EncoderStream = 0x201,
    /// An invalid QPACK decoder instruction.
    DecoderStream = 0x202,
}

impl From<frame::Error> for Code {
    fn from(value: frame::Error) -> Self {
        match value {
            frame::Error::ClosedCriticalStream => Self::ClosedCriticalStream,
            frame::Error::FrameUnexpected => Self::FrameUnexpected,
            frame::Error::Frame => Self::Frame,
            frame::Error::Id => Self::Id,
            frame::Error::Settings => Self::Settings,
            frame::Error::MissingSettings => Self::MissingSettings,
        }
    }
}

/// A failed operation. A connection error closes QUIC with the named application code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The connection ended with this HTTP/3 or QPACK code.
    Connection(Code),
    /// A local argument, capacity, or transport failure.
    Host(HostError),
}
impl From<HostError> for Error {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}
impl From<Code> for Error {
    fn from(c: Code) -> Self {
        Self::Connection(c)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(e) => e.fmt(f),
            Self::Connection(c) => write!(f, "HTTP/3 closed with {c:?} ({:#x})", *c as u64),
        }
    }
}
impl core::error::Error for Error {}

/// Peer settings. An omitted maximum field-section size has no advertised limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// Dynamic table capacity and blocked streams at the peer's decoder.
    pub qpack: qpack::Settings,
    /// Maximum decoded field-section size, including 32 bytes per field.
    pub field_section_bytes: Option<u64>,
}

/// An HTTP/3 event. A body event names the stream whose credit its bytes consume.
#[derive(Debug)]
pub enum Event {
    /// The peer's complete settings.
    Settings(Settings),
    /// The server received a checked request.
    Request(StreamId, RequestHead),
    /// The client received an informational response, including its fields.
    Informational(StreamId, ResponseHead),
    /// The client received the final response head.
    Response(StreamId, ResponseHead),
    /// Body data or its terminal outcome, including trailers.
    Body(StreamId, BodyPart),
    /// The peer stopped reading this direction with its application code.
    Stopped(StreamId, u64),
    /// The peer began or narrowed graceful shutdown. This is the first excluded identifier.
    GoAway(u64),
    /// The underlying connection ended. QUIC retains the peer's close code.
    Closed(Result<(), HostError>),
}

/// The result of one bounded turn. Keep driving QUIC at its own deadlines in every state.
#[derive(Debug)]
pub enum Step {
    /// Deliver the event, then drive again.
    Event(Event),
    /// Drive again before waiting for another packet.
    Again,
    /// HTTP/3 waits for QUIC progress, application output, or returned capacity.
    Wait,
}

pub(super) const ROOM: HostError = HostError::new(Kind::Overload, "the HTTP/3 connection reached its storage limit");
pub(super) fn misuse(reason: &'static str) -> Error {
    HostError::new(Kind::Misuse, reason).into()
}

fn storage<T>(n: usize, budget: &Budget) -> Result<(Vec<T>, Permit), HostError> {
    let size = Layout::array::<T>(n).map_err(|_| ROOM)?.size();
    let permit = budget.reserve(size as u64).map_err(|_| ROOM)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(n).map_err(|_| ROOM)?;
    Ok((bytes, permit))
}

pub(super) struct Scratch {
    pub(super) loan: WriteLoan<Vec<u8>>,
    charge: Permit,
}
impl Scratch {
    pub(super) fn new(cap: usize, budget: &Budget) -> Result<Self, HostError> {
        let (bytes, charge) = message::region(cap, budget).ok_or(ROOM)?;
        Ok(Self {
            loan: WriteLoan::new(bytes),
            charge,
        })
    }
    pub(super) fn drain(&mut self, pool: &mut Pool, budget: &Budget) -> Option<Lease> {
        let data = self.loan.filled();
        let lease = if let Ok(slot) = pool.acquire() {
            let mut out = WriteLoan::new(slot);
            assert_eq!(out.fill_from(data), data.len());
            Lease::from(out.into_inner())
        } else {
            let (mut bytes, charge) = message::region(data.len(), budget)?;
            bytes.extend_from_slice(data);
            message::charged(bytes, charge)
        };
        let mut buffer = mem::replace(&mut self.loan, WriteLoan::new(Vec::new())).into_inner();
        buffer.clear();
        self.loan = WriteLoan::new(buffer);
        Some(lease)
    }
    fn lease(self) -> Lease {
        message::charged(self.loan.into_inner(), self.charge)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Head,
    Body(Option<u64>),
    Trailers,
    End,
}
impl Phase {
    pub(super) fn data(self, len: u64) -> Result<Self, Code> {
        match self {
            Self::Body(Some(left)) => Ok(Self::Body(Some(left.checked_sub(len).ok_or(Code::Message)?))),
            Self::Body(None) => Ok(self),
            _ => Err(Code::FrameUnexpected),
        }
    }
    pub(super) fn finish(self) -> Result<(), Code> {
        match self {
            Self::Body(None | Some(0)) | Self::Trailers => Ok(()),
            Self::Body(Some(_)) => Err(Code::Message),
            _ => Err(Code::RequestIncomplete),
        }
    }
}

#[derive(Default, Clone, Copy)]
pub(super) enum MethodKind {
    #[default]
    Other,
    Head,
    Connect,
}
impl MethodKind {
    pub(super) fn of(bytes: &[u8]) -> Self {
        if bytes == Method::HEAD.as_bytes() {
            Self::Head
        } else if bytes == Method::CONNECT.as_bytes() {
            Self::Connect
        } else {
            Self::Other
        }
    }
    pub(super) fn length(self, status: u16, length: Option<u64>) -> Option<u64> {
        match self {
            Self::Head => Some(0),
            Self::Connect if (200..300).contains(&status) => None,
            _ => length,
        }
    }
}

pub(super) struct Request {
    pub(super) id: StreamId,
    pub(super) method: MethodKind,
    pub(super) send: Phase,
    pub(super) recv: Phase,
    pub(super) queued: bool,
    pub(super) settled: bool,
    decoder: frame::Decoder,
    section_len: usize,
    join: Option<Scratch>,
    blocked: Option<Lease>,
    suffix: Option<Scratch>,
    growth: Option<Scratch>,
    suffix_fin: bool,
    held: u64,
    trailers: Option<Trailers>,
}
impl Request {
    fn new(id: StreamId, side: Side) -> Self {
        Self {
            id,
            method: MethodKind::Other,
            send: Phase::Head,
            recv: Phase::Head,
            queued: false,
            settled: false,
            decoder: frame::Decoder::new(if side == Side::Client {
                Stream::Response
            } else {
                Stream::Request
            }),
            section_len: 0,
            join: None,
            blocked: None,
            suffix: None,
            growth: None,
            suffix_fin: false,
            held: 0,
            trailers: None,
        }
    }
}

enum Uni {
    Type(Integer),
    Control,
    Encoder,
    Decoder,
    Ignore,
}
enum Unblock {
    Idle,
    Scan,
    Decode(StreamId),
}
struct Input {
    id: StreamId,
    bytes: Lease,
    at: usize,
    fin: bool,
}

/// The HTTP state of one QUIC connection. The host owns QUIC and its datagram path.
pub struct Connection {
    pub(super) side: Side,
    pub(super) limits: Limits,
    pub(super) budget: Budget,
    pub(super) encoder: qpack::Encoder,
    decoder: qpack::Decoder,
    lines: qpack::Lines,
    pub(super) out: Output,
    pub(super) requests: Vec<Request>,
    _requests: Permit,
    uni: Vec<(StreamId, Uni)>,
    _uni: Permit,
    peer_streams: [Option<StreamId>; 3],
    control: frame::Decoder,
    settings: Settings,
    settings_seen: u8,
    settings_left: u64,
    pub(super) peer: Option<Settings>,
    pub(super) peer_goaway: Option<u64>,
    pub(super) local_goaway: Option<u64>,
    pub(super) highest: Option<StreamId>,
    push_credit: Option<u64>,
    unblock: Unblock,
    blocked_used: usize,
    input: Option<Input>,
    frame_turn: usize,
    visit_turn: usize,
    byte_turn: usize,
    pub(super) failed: Option<Error>,
}
impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("requests", &self.requests.len())
            .field("peer_settings", &self.peer)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl Connection {
    /// Makes the HTTP state for this transport. Offer the ALPN name `h3` in its TLS configuration.
    pub fn new(transport: &quic::Connection, mut limits: Limits, budget: &Budget) -> Result<Self, Error> {
        super::check_transport(transport.local_limits())?;
        if limits.requests == 0
            || limits.control_bytes < 64
            || limits.field_section_bytes < 2
            || limits.decoder.work == 0
            || [
                limits.decoder.table_bytes,
                limits.decoder.blocked_streams,
                limits.decoder.list_bytes,
                limits.field_section_bytes,
            ]
            .into_iter()
            .any(|n| n as u64 > crate::varint::MAX)
        {
            return Err(misuse(
                "invalid HTTP/3 request, field-section, or critical-stream limits",
            ));
        }
        // One lookup of the blocked sections must fit a drive turn. Advertise the effective limit.
        limits.decoder.blocked_streams = limits
            .decoder
            .blocked_streams
            .min(limits.requests)
            .min(transport.local_limits().turn.visits)
            .min(limits.blocked_bytes / 2);
        let side = transport.side();
        let (requests, r) = storage(limits.requests, budget)?;
        let (uni, u) = storage(
            usize::try_from(transport.local_limits().streams_uni_max).map_err(|_| ROOM)?,
            budget,
        )?;
        Ok(Self {
            side,
            limits,
            budget: budget.clone(),
            encoder: qpack::Encoder::new(limits.encoder, budget)?,
            decoder: qpack::Decoder::new(limits.decoder, budget)?,
            lines: qpack::Lines::new(limits.decoder, budget)?,
            out: Output::new(limits, budget)?,
            requests,
            _requests: r,
            uni,
            _uni: u,
            peer_streams: [None; 3],
            control: frame::Decoder::new(if side == Side::Client {
                Stream::ServerControl
            } else {
                Stream::ClientControl
            }),
            settings: Settings::default(),
            settings_seen: 0,
            settings_left: 0,
            peer: None,
            peer_goaway: None,
            local_goaway: None,
            highest: None,
            push_credit: None,
            unblock: Unblock::Idle,
            blocked_used: 0,
            input: None,
            frame_turn: transport.local_limits().turn.frames,
            visit_turn: transport.local_limits().turn.visits,
            byte_turn: usize::try_from(transport.local_limits().turn.bytes)
                .unwrap_or(usize::MAX)
                .max(1),
            failed: None,
        })
    }

    pub(super) fn at(&self, id: StreamId) -> Result<usize, usize> {
        self.requests.binary_search_by_key(&id, |s| s.id)
    }
    pub(super) fn index(&self, id: StreamId) -> Result<usize, Error> {
        self.at(id).map_err(|_| misuse("the HTTP/3 request is not open"))
    }
    pub(super) fn insert(&mut self, id: StreamId, at: usize) {
        self.requests.insert(at, Request::new(id, self.side));
    }
    pub(super) fn live(&self) -> Result<(), Error> {
        self.failed.map_or(Ok(()), Err)
    }

    /// Drives one HTTP turn. Pass each event from QUIC receive or drive in `input`.
    /// Keep the same input until consumed. With `None`, this also starts the critical streams and resumes queued work.
    pub fn drive(
        &mut self,
        q: &mut quic::Connection,
        input: &mut Option<quic::Event>,
        now: Instant,
    ) -> Result<Step, Error> {
        self.live()?;
        match self.turn(q, input) {
            Ok(step) => Ok(step),
            Err(error) => {
                let code = match error {
                    Error::Connection(code) => code,
                    Error::Host(e) if e.kind() == Kind::Overload => Code::ExcessiveLoad,
                    Error::Host(_) => Code::Internal,
                };
                self.failed = Some(error);
                q.close(code as u64, now)?;
                Err(error)
            }
        }
    }

    fn turn(&mut self, q: &mut quic::Connection, input: &mut Option<quic::Event>) -> Result<Step, Error> {
        if let Some(quic::Event::Closed(result)) = input {
            let result = *result;
            input.take();
            self.failed = Some(Error::Host(
                result
                    .err()
                    .unwrap_or(HostError::new(Kind::Cancelled, "the QUIC connection closed")),
            ));
            return Ok(Step::Event(Event::Closed(result)));
        }
        if !self.out.started() {
            if q.negotiated().is_none() {
                return Ok(Step::Wait);
            }
            self.start(q)?;
        }
        self.flush(q)?;
        self.refresh_credit(q)?;
        if self.encoder.feedback_pending() {
            self.encoder
                .receive_part(&[], self.frame_turn, self.visit_turn)
                .map_err(|_| Code::DecoderStream)?;
            return Ok(Step::Again);
        }
        if let Some(mut region) = self.input.take() {
            let event = self.read(q, &mut region)?;
            if region.at < region.bytes.initialized() || region.fin {
                self.input = Some(region);
            }
            return Ok(event.map_or(Step::Again, Step::Event));
        }
        if matches!(self.unblock, Unblock::Scan) {
            self.unblock = self
                .decoder
                .unblocked()
                .and_then(StreamId::new)
                .map_or(Unblock::Idle, Unblock::Decode);
            return Ok(Step::Again);
        }
        if let Unblock::Decode(id) = self.unblock {
            self.unblock = Unblock::Scan;
            let Ok(i) = self.at(id) else {
                return Ok(Step::Again);
            };
            let Some(section) = self.requests[i].blocked.take() else {
                return Ok(Step::Again);
            };
            self.blocked_used -= section.initialized();
            let next = self.decode(q, i, section)?;
            if self.requests.get(i).is_some_and(|r| r.id == id && r.blocked.is_none()) {
                let r = &mut self.requests[i];
                if let Some(suffix) = &r.suffix {
                    self.blocked_used -= suffix.loan.capacity();
                }
                if r.suffix.is_some() || r.suffix_fin {
                    self.input = Some(Input {
                        id,
                        bytes: r.suffix.take().map_or_else(empty, Scratch::lease),
                        at: 0,
                        fin: mem::take(&mut r.suffix_fin),
                    });
                }
            }
            return Ok(next.map_or(Step::Again, Step::Event));
        }
        let Some(event) = input.take() else {
            if self.out.more() {
                return Ok(Step::Again);
            }
            // A QUIC MAX_DATA or MAX_STREAM_DATA can grant credit without an application event.
            self.out.wake();
            return Ok(Step::Wait);
        };
        self.out.wake();
        let event = match event {
            quic::Event::Stream { stream, data, end } => {
                self.input = Some(Input {
                    id: stream,
                    bytes: data,
                    at: 0,
                    fin: end,
                });
                None
            }
            quic::Event::Reset { stream, code } => self.reset_in(q, stream, code)?,
            quic::Event::Stopped { stream, code } => {
                if self.out.critical(stream).is_some() {
                    return Err(Code::ClosedCriticalStream.into());
                }
                let Some(i) = self.request_slot(q, stream)? else {
                    return Ok(Step::Again);
                };
                self.out.wake();
                let r = &mut self.requests[i];
                r.settled = true;
                r.send = Phase::End;
                Some(Event::Stopped(stream, code))
            }
            quic::Event::Acknowledged { stream, offset, end } => {
                self.out.ack(stream, offset);
                if end && let Ok(i) = self.at(stream) {
                    self.requests[i].settled = true;
                }
                None
            }
            quic::Event::Closed(_)
            | quic::Event::Sent { .. }
            | quic::Event::Openable(_)
            | quic::Event::SideProbe(_)
            | quic::Event::Unreliable(_) => None,
        };
        Ok(event.map_or(Step::Again, Step::Event))
    }

    fn request_slot(&mut self, q: &mut quic::Connection, id: StreamId) -> Result<Option<usize>, Error> {
        if id.initiator() != Side::Client || id.direction() != Direction::Bidirectional {
            return Err(Code::StreamCreation.into());
        }
        match self.at(id) {
            Ok(i) => Ok(Some(i)),
            Err(i)
                if self.side == Side::Server
                    && self.local_goaway.is_none()
                    && self.requests.len() < self.limits.requests =>
            {
                q.set_priority(id, super::send::REQUEST_PRIORITY)?;
                self.insert(id, i);
                self.highest = Some(self.highest.map_or(id, |a| a.max(id)));
                Ok(Some(i))
            }
            Err(_) if self.side == Side::Server => {
                self.cancel_section(id)?;
                q.abort_stream(id, Code::RequestRejected as u64)?;
                q.close_stream(id)?;
                Ok(None)
            }
            Err(_) => Err(Code::StreamCreation.into()),
        }
    }

    fn read(&mut self, q: &mut quic::Connection, r: &mut Input) -> Result<Option<Event>, Error> {
        if r.id.direction() == Direction::Unidirectional {
            return self.read_uni(q, r);
        }
        let Some(i) = self.request_slot(q, r.id)? else {
            r.at = r.bytes.initialized();
            r.fin = false;
            return Ok(None);
        };
        if self.requests[i].recv == Phase::End {
            self.discard_input(q, r)?;
            return Ok(None);
        }
        if self.requests[i].blocked.is_some() {
            let data = &r.bytes.bytes()[r.at..];
            let n = data.len().min(self.byte_turn);
            if n > 0 {
                match self.requests[i].append_blocked(
                    &data[..n],
                    &self.budget,
                    &mut self.blocked_used,
                    self.limits.blocked_bytes,
                    self.byte_turn,
                ) {
                    Ok(used) => r.at += used,
                    Err(_) => return self.refuse(q, i, Code::ExcessiveLoad),
                }
            }
            if r.at == r.bytes.initialized() {
                self.requests[i].suffix_fin |= mem::take(&mut r.fin);
            }
            return Ok(None);
        }
        if r.at == r.bytes.initialized() {
            if !mem::take(&mut r.fin) {
                return Ok(None);
            }
            self.requests[i].decoder.finish().map_err(Code::from)?;
            if let Err(c) = self.requests[i].recv.finish() {
                return self.refuse(q, i, c);
            }
            let request = &mut self.requests[i];
            request.recv = Phase::End;
            return Ok(Some(Event::Body(
                r.id,
                BodyPart::End(Outcome::Complete(request.trailers.take())),
            )));
        }
        let start = r.at;
        let max = r.bytes.initialized().min(start.saturating_add(self.byte_turn));
        let mut input = &r.bytes.bytes()[start..max];
        let part = self.requests[i].decoder.next(&mut input).map_err(Code::from)?;
        r.at = max - input.len();
        let n = r.at - start;
        if !matches!(part, Some(Part::Bytes { kind: Frame::DATA, .. })) {
            q.release(r.id, n as u64)?;
        }
        match part {
            Some(Part::Header(h)) if h.kind == Frame::DATA => match self.requests[i].recv.data(h.len) {
                Ok(state) => self.requests[i].recv = state,
                Err(Code::FrameUnexpected) => return Err(Code::FrameUnexpected.into()),
                Err(c) => return self.refuse(q, i, c),
            },
            Some(Part::Header(h)) if h.kind == Frame::HEADERS => {
                if matches!(self.requests[i].recv, Phase::Trailers | Phase::End) {
                    return Err(Code::FrameUnexpected.into());
                }
                if h.len == 0 {
                    return Err(Code::Decompression.into());
                }
                if h.len > self.limits.field_section_bytes as u64 {
                    return self.refuse(q, i, Code::ExcessiveLoad);
                }
                self.requests[i].section_len = usize::try_from(h.len).map_err(|_| ROOM)?;
            }
            Some(Part::Bytes {
                kind: Frame::DATA,
                bytes,
                ..
            }) => {
                self.requests[i].held += bytes.len() as u64;
                let view = r
                    .bytes
                    .view(r.at - bytes.len()..r.at)
                    .expect("a DATA part lies in the input");
                return Ok(Some(Event::Body(r.id, BodyPart::Data(view))));
            }
            Some(Part::Bytes {
                kind: Frame::HEADERS,
                bytes,
                end,
            }) => {
                let state = &mut self.requests[i];
                let section = if state.join.is_none() && end {
                    r.bytes
                        .view(r.at - bytes.len()..r.at)
                        .expect("a field section lies in the input")
                } else {
                    if state.join.is_none() {
                        state.join = Some(Scratch::new(state.section_len, &self.budget)?);
                    }
                    let join = state.join.as_mut().expect("the header has a join");
                    assert_eq!(join.loan.fill_from(bytes), bytes.len());
                    if !end {
                        return Ok(None);
                    }
                    state.join.take().expect("the last part ends the join").lease()
                };
                return self.decode(q, i, section);
            }
            Some(Part::Id {
                kind: Frame::PUSH_PROMISE,
                ..
            }) => return Err(Code::Id.into()),
            _ => {}
        }
        Ok(None)
    }

    fn decode(&mut self, q: &mut quic::Connection, i: usize, section: Lease) -> Result<Option<Event>, Error> {
        let r = &mut self.requests[i];
        let id = r.id;
        let block =
            match self
                .decoder
                .decode_section(id.get(), section.bytes(), &mut self.lines, self.out.loan(DECODER), None)
            {
                Ok(block) => block,
                Err(qpack::DecodeError::Blocked) => {
                    let size = section.initialized();
                    if size > self.limits.blocked_bytes - self.blocked_used {
                        return self.refuse(q, i, Code::ExcessiveLoad);
                    }
                    let Ok(mut owned) = Scratch::new(size, &self.budget) else {
                        return self.refuse(q, i, Code::ExcessiveLoad);
                    };
                    self.blocked_used += size;
                    assert_eq!(owned.loan.fill_from(section.bytes()), section.initialized());
                    r.blocked = Some(owned.lease());
                    return Ok(None);
                }
                Err(qpack::DecodeError::TooLarge) => return self.refuse(q, i, Code::ExcessiveLoad),
                Err(qpack::DecodeError::Full(_)) => return Err(Code::ExcessiveLoad.into()),
                Err(qpack::DecodeError::Misuse) => return Err(Code::Internal.into()),
                Err(qpack::DecodeError::Malformed | qpack::DecodeError::TooManyBlocked) => {
                    return Err(Code::Decompression.into());
                }
            };
        let result: Result<Option<Event>, Refusal> = (|| {
            if r.recv != Phase::Head {
                r.recv.finish().map_err(|_| Refusal::Malformed)?;
                r.trailers = Some(Trailers {
                    lines: message::trailers(block, &self.budget)?,
                });
                r.recv = Phase::Trailers;
                return Ok(None);
            }
            if self.side == Side::Server {
                let head = message::request(block, &self.budget)?;
                r.method = MethodKind::of(head.method().as_bytes());
                r.recv = Phase::Body(head.length());
                Ok(Some(Event::Request(id, RequestHead::h3_form(head))))
            } else {
                let mut fields = ResponseFields::check(block.lines())?;
                let status = fields.status.code();
                if status >= 200 {
                    fields.length = r.method.length(status, fields.length);
                }
                let head = fields.retain(block, &self.budget)?;
                if status < 200 {
                    return Ok(Some(Event::Informational(id, ResponseHead::h3_form(head))));
                }
                r.recv = Phase::Body(head.length());
                Ok(Some(Event::Response(id, ResponseHead::h3_form(head))))
            }
        })();
        match result {
            Ok(e) => Ok(e),
            Err(Refusal::Malformed) => self.refuse(q, i, Code::Message),
            Err(Refusal::Capacity) => self.refuse(q, i, Code::ExcessiveLoad),
        }
    }

    fn discard_input(&self, q: &mut quic::Connection, r: &mut Input) -> Result<(), Error> {
        let n = r.bytes.initialized() - r.at;
        if n != 0 {
            q.release(r.id, n as u64)?;
        }
        r.at += n;
        r.fin = false;
        Ok(())
    }
    fn cancel_section(&mut self, id: StreamId) -> Result<(), Error> {
        self.decoder
            .cancel(id.get(), self.out.loan(DECODER))
            .map_err(|_| Code::ExcessiveLoad.into())
    }
    fn cancel_decode(&mut self, i: usize) -> Result<u64, Error> {
        let id = self.requests[i].id;
        if self.requests[i].recv != Phase::End {
            self.cancel_section(id)?;
        }
        let r = &mut self.requests[i];
        if let Some(section) = r.blocked.take() {
            self.blocked_used -= section.initialized();
        }
        if let Some(growth) = r.growth.take() {
            self.blocked_used -= growth.loan.capacity();
        }
        r.join = None;
        r.suffix_fin = false;
        Ok(r.suffix.take().map_or(0, |s| {
            self.blocked_used -= s.loan.capacity();
            s.loan.filled().len() as u64
        }))
    }
    fn refuse(&mut self, q: &mut quic::Connection, i: usize, c: Code) -> Result<Option<Event>, Error> {
        let id = self.requests[i].id;
        let held = self.cancel_decode(i)?;
        if held != 0 {
            q.release(id, held)?;
        }
        q.abort_stream(id, c as u64)?;
        self.out.wake();
        let r = &mut self.requests[i];
        r.recv = Phase::End;
        r.send = Phase::End;
        r.settled = true;
        let outcome = if c == Code::RequestIncomplete {
            Outcome::Truncated
        } else if c == Code::Message {
            Outcome::Malformed
        } else {
            Outcome::Reset(Some(c as u64))
        };
        Ok(Some(Event::Body(id, BodyPart::End(outcome))))
    }

    fn reset_in(&mut self, q: &mut quic::Connection, id: StreamId, code: u64) -> Result<Option<Event>, Error> {
        if id.direction() == Direction::Unidirectional {
            if self.peer_streams.contains(&Some(id)) {
                return Err(Code::ClosedCriticalStream.into());
            }
            if let Ok(i) = self.uni.binary_search_by_key(&id, |e| e.0) {
                self.uni.remove(i);
            }
            q.close_stream(id)?;
            return Ok(None);
        }
        if id.initiator() != Side::Client {
            return Err(Code::StreamCreation.into());
        }
        let Ok(i) = self.at(id) else {
            self.cancel_section(id)?;
            q.abort_stream(id, Code::RequestCancelled as u64)?;
            q.close_stream(id)?;
            return Ok(None);
        };
        if self.requests[i].recv == Phase::End {
            return Ok(None);
        }
        if self.side == Side::Server && self.requests[i].recv == Phase::Head {
            self.refuse(q, i, Code::RequestIncomplete)?;
            return Ok(Some(Event::Body(id, BodyPart::End(Outcome::Reset(Some(code))))));
        }
        let bytes = self.cancel_decode(i)?;
        if bytes != 0 {
            q.release(id, bytes)?;
        }
        self.requests[i].recv = Phase::End;
        Ok(Some(Event::Body(id, BodyPart::End(Outcome::Reset(Some(code))))))
    }

    fn read_uni(&mut self, q: &mut quic::Connection, r: &mut Input) -> Result<Option<Event>, Error> {
        let i = match self.uni.binary_search_by_key(&r.id, |e| e.0) {
            Ok(i) => i,
            Err(i) => {
                if self.uni.len() == self.uni.capacity() {
                    return Err(Code::ExcessiveLoad.into());
                }
                self.uni.insert(i, (r.id, Uni::Type(Integer::default())));
                i
            }
        };
        if r.at == r.bytes.initialized() {
            if !mem::take(&mut r.fin) {
                return Ok(None);
            }
            if self.peer_streams[CONTROL] == Some(r.id) {
                self.control.finish().map_err(Code::from)?;
            }
            if self.peer_streams.contains(&Some(r.id)) {
                return Err(Code::ClosedCriticalStream.into());
            }
            self.uni.remove(i);
            q.close_stream(r.id)?;
            return Ok(None);
        }
        let end = r.bytes.initialized().min(r.at.saturating_add(self.byte_turn));
        let mut bytes = &r.bytes.bytes()[r.at..end];
        let (mut event, start) = (None, r.at);
        match &mut self.uni[i].1 {
            Uni::Type(prefix) => {
                if let Some(ty) = prefix.read(&mut bytes) {
                    let (kind, critical) = match ty {
                        0 => (Uni::Control, Some(CONTROL)),
                        2 => (Uni::Encoder, Some(ENCODER)),
                        3 => (Uni::Decoder, Some(DECODER)),
                        1 if self.side == Side::Client => return Err(Code::Id.into()),
                        1 => return Err(Code::StreamCreation.into()),
                        _ => (Uni::Ignore, None),
                    };
                    if let Some(k) = critical
                        && self.peer_streams[k].replace(r.id).is_some()
                    {
                        return Err(Code::StreamCreation.into());
                    }
                    self.uni[i].1 = kind;
                }
            }
            Uni::Ignore => bytes = &[],
            Uni::Encoder => {
                let (n, inserted) = self
                    .decoder
                    .receive_part(bytes, self.out.loan(DECODER), self.frame_turn)
                    .map_err(|_| Code::EncoderStream)?;
                if inserted {
                    self.unblock = Unblock::Scan;
                }
                bytes = &bytes[n..];
            }
            Uni::Decoder => {
                let n = self
                    .encoder
                    .receive_part(bytes, self.frame_turn, self.visit_turn)
                    .map_err(|_| Code::DecoderStream)?;
                bytes = &bytes[n..];
            }
            Uni::Control => {
                let before = bytes.len();
                let part = self.control.next(&mut bytes).map_err(Code::from)?;
                if self.settings_left != 0 {
                    self.settings_left -= (before - bytes.len()) as u64;
                }
                match part {
                    Some(Part::Header(h)) if h.kind == Frame::SETTINGS => {
                        if h.len > self.limits.control_bytes as u64 {
                            return Err(Code::ExcessiveLoad.into());
                        }
                        self.settings_left = h.len;
                    }
                    Some(Part::Setting { id, value }) => {
                        let bit = match id {
                            1 => {
                                self.settings.qpack.table_bytes = value;
                                1
                            }
                            6 => {
                                self.settings.field_section_bytes = Some(value);
                                2
                            }
                            7 => {
                                self.settings.qpack.blocked_streams = value;
                                4
                            }
                            _ => 0,
                        };
                        if self.settings_seen & bit != 0 {
                            return Err(Code::Settings.into());
                        }
                        self.settings_seen |= bit;
                    }
                    Some(Part::Id {
                        kind: Frame::MAX_PUSH_ID,
                        id,
                    }) => {
                        if self.push_credit.is_some_and(|last| id < last) {
                            return Err(Code::Id.into());
                        }
                        self.push_credit = Some(id);
                    }
                    Some(Part::Id {
                        kind: Frame::CANCEL_PUSH,
                        ..
                    }) => return Err(Code::Id.into()),
                    Some(Part::Id {
                        kind: Frame::GOAWAY,
                        id,
                    }) => {
                        if self.peer_goaway.is_some_and(|last| id > last) {
                            return Err(Code::Id.into());
                        }
                        self.peer_goaway = Some(id);
                        event = Some(Event::GoAway(id));
                    }
                    _ => {}
                }
                if self.peer.is_none()
                    && self.settings_left == 0
                    && matches!(
                        part,
                        Some(
                            Part::Header(frame::Header {
                                kind: Frame::SETTINGS,
                                ..
                            }) | Part::Setting { .. }
                        )
                    )
                {
                    self.encoder.set_peer(self.settings.qpack).map_err(|_| Code::Settings)?;
                    self.peer = Some(self.settings);
                    event = Some(Event::Settings(self.settings));
                }
            }
        }
        r.at = end - bytes.len();
        q.release(r.id, (r.at - start) as u64)?;
        Ok(event)
    }

    /// Releases DATA bytes after their consumer takes them. This restores QUIC flow credit.
    pub fn release(&mut self, q: &mut quic::Connection, id: StreamId, n: u64) -> Result<(), Error> {
        let i = self.index(id)?;
        let left = self.requests[i]
            .held
            .checked_sub(n)
            .ok_or_else(|| misuse("release only HTTP/3 DATA bytes that the consumer holds"))?;
        q.release(id, n)?;
        self.requests[i].held = left;
        Ok(())
    }
    /// Cancels both directions of one request and releases its QPACK references.
    pub fn cancel(&mut self, q: &mut quic::Connection, id: StreamId) -> Result<(), Error> {
        self.live()?;
        let i = self.index(id)?;
        self.refuse(q, i, Code::RequestCancelled)?;
        Ok(())
    }
    /// Returns a finished request slot. Wait for the peer to acknowledge the sending direction.
    /// An unread body is released with its slot.
    pub fn retire(&mut self, q: &mut quic::Connection, id: StreamId) -> Result<bool, Error> {
        let i = self.index(id)?;
        let r = &self.requests[i];
        if self.input.as_ref().is_some_and(|input| input.id == id)
            || r.recv != Phase::End
            || r.send != Phase::End
            || !r.settled
            || r.queued
        {
            return Ok(false);
        }
        q.close_stream(id)?;
        self.requests.remove(i);
        Ok(true)
    }
}

pub(super) fn empty() -> Lease {
    Lease::from(&[][..])
}

impl Request {
    /// Copies at most one byte turn. Both buffers count toward the limit during growth.
    fn append_blocked(
        &mut self,
        data: &[u8],
        budget: &Budget,
        used: &mut usize,
        limit: usize,
        turn: usize,
    ) -> Result<usize, HostError> {
        let old = self.suffix.as_ref().map_or(&[][..], |s| s.loan.filled());
        let need = old.len().checked_add(data.len()).ok_or(ROOM)?;
        if self.suffix.as_ref().is_none_or(|s| s.loan.capacity() < need) {
            if self.growth.is_none() {
                let room = limit - *used;
                if need > room {
                    return Err(ROOM);
                }
                let cap = need.max(old.len().saturating_mul(2)).min(room);
                self.growth = Some(Scratch::new(cap, budget)?);
                *used += cap;
            }
            let growth = self.growth.as_mut().expect("the larger buffer is charged");
            let at = growth.loan.filled().len();
            let n = turn.min(old.len() - at);
            assert_eq!(growth.loan.fill_from(&old[at..at + n]), n);
            if at + n == old.len() {
                if let Some(old) = self.suffix.take() {
                    *used -= old.loan.capacity();
                }
                self.suffix = self.growth.take();
            }
            if n != 0 {
                return Ok(0);
            }
        }
        assert_eq!(
            self.suffix.as_mut().expect("the suffix has room").loan.fill_from(data),
            data.len()
        );
        Ok(data.len())
    }
}
