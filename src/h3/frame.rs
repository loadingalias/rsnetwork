//! Incremental HTTP/3 framing for one QUIC stream (RFC 9114, sections 6 and 7).

use core::fmt;

use crate::varint;

/// The type at the start of a unidirectional stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamType {
    /// The peer's control stream.
    Control,
    /// A server push stream. A push ID follows its type.
    Push,
    /// Instructions for the QPACK decoder.
    QpackEncoder,
    /// Instructions for the QPACK encoder.
    QpackDecoder,
    /// A stream whose contents the base protocol ignores.
    Extension(u64),
}

impl StreamType {
    /// Reads the type and its byte count. Keep an incomplete prefix for the next call.
    pub fn read(input: &[u8]) -> Option<(Self, usize)> {
        let (id, n) = varint::read(input)?;
        let ty = match id {
            0 => Self::Control,
            1 => Self::Push,
            2 => Self::QpackEncoder,
            3 => Self::QpackDecoder,
            _ => Self::Extension(id),
        };
        Some((ty, n))
    }
}

/// The sending side of a framed HTTP/3 stream. QPACK streams have their own instruction format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    /// The client's side of a request stream.
    Request,
    /// The server's side of a request stream.
    Response,
    /// The server's pushed response after its push ID.
    Push,
    /// The control stream from the client.
    ClientControl,
    /// The control stream from the server.
    ServerControl,
}

impl Stream {
    const fn control(self) -> bool {
        matches!(self, Self::ClientControl | Self::ServerControl)
    }
}

/// An HTTP/3 frame type, including an extension that the base protocol ignores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind(u64);

impl Kind {
    /// HTTP message content.
    pub const DATA: Self = Self(0);
    /// A QPACK field section.
    pub const HEADERS: Self = Self(1);
    /// Cancellation of a server push.
    pub const CANCEL_PUSH: Self = Self(3);
    /// Connection settings.
    pub const SETTINGS: Self = Self(4);
    /// A push ID and the promised request's field section.
    pub const PUSH_PROMISE: Self = Self(5);
    /// The first request or push that the sender can refuse during drain.
    pub const GOAWAY: Self = Self(7);
    /// The largest push ID the client permits.
    pub const MAX_PUSH_ID: Self = Self(13);

    /// The frame type for a wire value. RFC 9114 reserves four HTTP/2 frame types.
    pub const fn new(id: u64) -> Option<Self> {
        if id > varint::MAX || matches!(id, 0x02 | 0x06 | 0x08 | 0x09) {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Its wire value.
    pub const fn id(self) -> u64 {
        self.0
    }

    const fn allowed(self, stream: Stream) -> bool {
        match self {
            Self::DATA | Self::HEADERS => !stream.control(),
            Self::CANCEL_PUSH | Self::SETTINGS | Self::GOAWAY => stream.control(),
            Self::PUSH_PROMISE => matches!(stream, Stream::Response),
            Self::MAX_PUSH_ID => matches!(stream, Stream::ClientControl),
            _ => true,
        }
    }
}

/// The frame type and its payload length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The wire type.
    pub kind: Kind,
    /// The number of payload bytes, excluding this header.
    pub len: u64,
}

impl Header {
    /// Writes the shortest header and returns its byte count. A refusal leaves the output intact.
    pub fn write(self, output: &mut [u8]) -> Result<usize, WriteError> {
        let a = varint::len(self.kind.id()).expect("a frame kind fits a QUIC integer");
        let b = varint::len(self.len).ok_or(WriteError::Value)?;
        let header = output.get_mut(..a + b).ok_or(WriteError::Space)?;
        let (kind, length) = header.split_at_mut(a);
        varint::write(kind, self.kind.id(), a).expect("the kind fits its field");
        varint::write(length, self.len, b).expect("the length fits its field");
        Ok(a + b)
    }
}

/// A header could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The payload length exceeds the 62-bit wire range.
    Value,
    /// The output has too little room for the header.
    Space,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Value => "the HTTP/3 frame length exceeds the wire range",
            Self::Space => "the output has too little room for the HTTP/3 header",
        })
    }
}
impl core::error::Error for WriteError {}

/// A framing error and its RFC 9114 connection error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Error {
    /// The control stream closed.
    ClosedCriticalStream = 0x104,
    /// A frame type is forbidden on this stream.
    FrameUnexpected = 0x105,
    /// A frame had an incomplete field, extra bytes, or a truncated payload.
    Frame = 0x106,
    /// A server's GOAWAY identified a stream other than a client request.
    Id = 0x108,
    /// A setting identifier belonged to HTTP/2.
    Settings = 0x109,
    /// The first frame on a control stream differed from SETTINGS.
    MissingSettings = 0x10a,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ClosedCriticalStream => "H3_CLOSED_CRITICAL_STREAM",
            Self::FrameUnexpected => "H3_FRAME_UNEXPECTED",
            Self::Frame => "H3_FRAME_ERROR",
            Self::Id => "H3_ID_ERROR",
            Self::Settings => "H3_SETTINGS_ERROR",
            Self::MissingSettings => "H3_MISSING_SETTINGS",
        })
    }
}
impl core::error::Error for Error {}

/// One part of a frame. A header arrives before any payload, including for an empty frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Part<'a> {
    /// A complete header. Apply the connection's admission limits here.
    Header(Header),
    /// Body bytes or QPACK field-section bytes. `end` marks the last part of this frame.
    Bytes {
        /// DATA, HEADERS, or PUSH_PROMISE.
        kind: Kind,
        /// Bytes borrowed directly from the input region.
        bytes: &'a [u8],
        /// This part ends the frame.
        end: bool,
    },
    /// One identifier from CANCEL_PUSH, PUSH_PROMISE, GOAWAY, or MAX_PUSH_ID.
    Id {
        /// The frame that carries the identifier.
        kind: Kind,
        /// The stream or push identifier.
        id: u64,
    },
    /// One complete SETTINGS parameter. The connection applies supported settings.
    Setting {
        /// The setting identifier.
        id: u64,
        /// Its value.
        value: u64,
    },
    /// The decoder consumed these bytes of an extension frame.
    Skipped(usize),
}

impl fmt::Debug for Part<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header(h) => f.debug_tuple("Header").field(h).finish(),
            Self::Bytes { kind, bytes, end } => f
                .debug_struct("Bytes")
                .field("kind", kind)
                .field("len", &bytes.len())
                .field("end", end)
                .finish(),
            Self::Id { kind, id } => f.debug_struct("Id").field("kind", kind).field("id", id).finish(),
            Self::Setting { id, value } => f.debug_struct("Setting").field("id", id).field("value", value).finish(),
            Self::Skipped(n) => f.debug_tuple("Skipped").field(n).finish(),
        }
    }
}

/// A partial integer. A complete integer in the current region takes the direct path.
#[derive(Default)]
pub(super) struct Integer {
    bytes: [u8; 8],
    used: usize,
}

impl Integer {
    pub(super) fn read(&mut self, input: &mut &[u8]) -> Option<u64> {
        if self.used == 0 {
            if let Some((value, len)) = varint::read(input) {
                *input = &input[len..];
                return Some(value);
            }
            self.bytes[..input.len()].copy_from_slice(input);
            self.used = input.len();
            *input = &[];
            return None;
        }
        let width = varint::width(self.bytes[0]);
        let take = input.len().min(width - self.used);
        self.bytes[self.used..self.used + take].copy_from_slice(&input[..take]);
        self.used += take;
        *input = &input[take..];
        if self.used < width {
            return None;
        }
        self.used = 0;
        varint::read(&self.bytes[..width]).map(|(value, _)| value)
    }
}

#[derive(Clone, Copy, Debug)]
enum Field {
    Id,
    SettingId,
    SettingValue(u64),
}

#[derive(Clone, Copy, Debug)]
enum State {
    Type,
    Length(Kind),
    /// An integer field, or raw bytes when the frame carries content or an extension.
    Payload {
        kind: Kind,
        left: u64,
        field: Option<Field>,
    },
    Failed(Error),
}

/// The decoder for one framed stream. It keeps at most seven bytes of a split integer.
pub struct Decoder {
    stream: Stream,
    settings_seen: bool,
    state: State,
    integer: Integer,
}

impl fmt::Debug for Decoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("stream", &self.stream)
            .field("state", &self.state)
            .field("partial_integer_bytes", &self.integer.used)
            .finish()
    }
}

impl Decoder {
    /// Starts at the first frame, after any unidirectional stream prefix.
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            settings_seen: false,
            state: State::Type,
            integer: Integer::default(),
        }
    }

    /// Consumes input through one part. An incomplete field consumes the available prefix and returns `None`.
    /// Limit the input slice to the byte budget of this turn. An error ends decoding on this stream.
    pub fn next<'a>(&mut self, input: &mut &'a [u8]) -> Result<Option<Part<'a>>, Error> {
        let result = self.step(input);
        if let Err(e) = result {
            self.state = State::Failed(e);
        }
        result
    }

    fn step<'a>(&mut self, input: &mut &'a [u8]) -> Result<Option<Part<'a>>, Error> {
        loop {
            match self.state {
                State::Failed(e) => return Err(e),
                State::Type => {
                    let Some(id) = self.integer.read(input) else {
                        return Ok(None);
                    };
                    if self.stream.control() && !self.settings_seen && id != Kind::SETTINGS.id() {
                        return Err(Error::MissingSettings);
                    }
                    let kind = Kind::new(id).ok_or(Error::FrameUnexpected)?;
                    if !kind.allowed(self.stream) || (kind == Kind::SETTINGS && self.settings_seen) {
                        return Err(Error::FrameUnexpected);
                    }
                    self.state = State::Length(kind);
                }
                State::Length(kind) => {
                    let Some(len) = self.integer.read(input) else {
                        return Ok(None);
                    };
                    let field = match kind {
                        Kind::GOAWAY | Kind::CANCEL_PUSH | Kind::MAX_PUSH_ID => {
                            if !matches!(len, 1 | 2 | 4 | 8) {
                                return Err(Error::Frame);
                            }
                            Some(Field::Id)
                        }
                        Kind::PUSH_PROMISE => {
                            if len == 0 {
                                return Err(Error::Frame);
                            }
                            Some(Field::Id)
                        }
                        Kind::SETTINGS => {
                            self.settings_seen = true;
                            Some(Field::SettingId)
                        }
                        _ => None,
                    };
                    self.payload(kind, len, field);
                    return Ok(Some(Part::Header(Header { kind, len })));
                }
                State::Payload { kind, left, field } => {
                    if input.is_empty() {
                        return Ok(None);
                    }
                    let n = input.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    let mut available = &input[..n];
                    let Some(field) = field else {
                        let bytes = available;
                        *input = &input[n..];
                        let left = left - n as u64;
                        self.payload(kind, left, None);
                        return Ok(Some(match kind {
                            Kind::HEADERS | Kind::PUSH_PROMISE | Kind::DATA => Part::Bytes {
                                kind,
                                bytes,
                                end: left == 0,
                            },
                            _ => Part::Skipped(n),
                        }));
                    };
                    // The integer can read only through the end of this payload.
                    let value = self.integer.read(&mut available);
                    let used = n - available.len();
                    *input = &input[used..];
                    let left = left - used as u64;
                    let Some(value) = value else {
                        if left == 0 {
                            return Err(Error::Frame);
                        }
                        self.payload(kind, left, Some(field));
                        return Ok(None);
                    };
                    match field {
                        Field::Id => {
                            if kind != Kind::PUSH_PROMISE && left != 0 {
                                return Err(Error::Frame);
                            }
                            if kind == Kind::GOAWAY && self.stream == Stream::ServerControl && value % 4 != 0 {
                                return Err(Error::Id);
                            }
                            self.payload(kind, left, None);
                            return Ok(Some(Part::Id { kind, id: value }));
                        }
                        Field::SettingId => {
                            if (2..=5).contains(&value) {
                                return Err(Error::Settings);
                            }
                            if left == 0 {
                                return Err(Error::Frame);
                            }
                            self.payload(kind, left, Some(Field::SettingValue(value)));
                        }
                        Field::SettingValue(id) => {
                            self.payload(kind, left, Some(Field::SettingId));
                            return Ok(Some(Part::Setting { id, value }));
                        }
                    }
                }
            }
        }
    }

    fn payload(&mut self, kind: Kind, left: u64, field: Option<Field>) {
        self.state = if left == 0 {
            State::Type
        } else {
            State::Payload { kind, left, field }
        };
    }

    /// Checks a clean QUIC FIN. A reset can interrupt any frame. Discard its decoder on a reset.
    pub fn finish(&self) -> Result<(), Error> {
        match self.state {
            State::Failed(e) => Err(e),
            State::Type if self.integer.used == 0 => {
                if self.stream.control() {
                    Err(Error::ClosedCriticalStream)
                } else {
                    Ok(())
                }
            }
            _ => Err(Error::Frame),
        }
    }
}
