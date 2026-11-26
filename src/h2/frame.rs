//! The frame codec (RFC 9113, sections 4 and 6, and the PRIORITY_UPDATE frame of RFC 9218,
//! section 7.1): the frame header, the checks of each frame type, and a parser and a writer for
//! each frame.

use core::fmt;

use rstypes::buffer::{BufferMut, WriteLoan};

/// The first 24 bytes of the client connection preface (RFC 9113, section 3.4). A SETTINGS frame
/// follows them.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The length of a frame header (RFC 9113, section 4.1).
pub const HEAD: usize = 9;

/// The largest stream identifier, window size, and window increment: 2^31 - 1.
pub const MAX_STREAM: u32 = (1 << 31) - 1;

/// The largest payload that a frame header can give: 2^24 - 1.
const MAX_LENGTH: u32 = (1 << 24) - 1;

/// The initial and smallest `SETTINGS_MAX_FRAME_SIZE`: 2^14 (RFC 9113, section 4.2).
pub const MIN_FRAME_SIZE: u32 = 1 << 14;

/// The flags of RFC 9113, section 6.
pub(crate) const END_STREAM: u8 = 0x1;
pub(crate) const ACK: u8 = 0x1;
pub(crate) const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// The bits of `flag` when `set`.
pub(crate) const fn flag(set: bool, flag: u8) -> u8 {
    if set { flag } else { 0 }
}

/// The identifiers of the settings of RFC 9113, section 6.5.2.
pub(crate) const HEADER_TABLE_SIZE: u16 = 0x1;
pub(crate) const ENABLE_PUSH: u16 = 0x2;
pub(crate) const MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub(crate) const INITIAL_WINDOW_SIZE: u16 = 0x4;
pub(crate) const MAX_FRAME_SIZE: u16 = 0x5;
pub(crate) const MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// `SETTINGS_NO_RFC7540_PRIORITIES` (RFC 9218, section 2.1): 1 when the endpoint uses no
/// priority signal of RFC 7540.
pub(crate) const NO_RFC7540_PRIORITIES: u16 = 0x9;

/// An error code (RFC 9113, section 7). A code that this crate does not know keeps its value,
/// and it has no special meaning.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u32);

impl ErrorCode {
    /// The condition is not an error, for example a graceful shutdown.
    pub const NO_ERROR: Self = Self(0x0);
    /// A protocol error that has no more specific code.
    pub const PROTOCOL_ERROR: Self = Self(0x1);
    /// An unexpected internal error.
    pub const INTERNAL_ERROR: Self = Self(0x2);
    /// The peer broke the flow-control protocol.
    pub const FLOW_CONTROL_ERROR: Self = Self(0x3);
    /// No acknowledgement of a SETTINGS frame arrived in time.
    pub const SETTINGS_TIMEOUT: Self = Self(0x4);
    /// A frame arrived after the stream was half-closed.
    pub const STREAM_CLOSED: Self = Self(0x5);
    /// A frame has a size that is not valid.
    pub const FRAME_SIZE_ERROR: Self = Self(0x6);
    /// The endpoint refused the stream before any application processing.
    pub const REFUSED_STREAM: Self = Self(0x7);
    /// The stream is no longer needed.
    pub const CANCEL: Self = Self(0x8);
    /// The endpoint cannot keep the field section compression context.
    pub const COMPRESSION_ERROR: Self = Self(0x9);
    /// The connection of a CONNECT request was reset or closed abnormally.
    pub const CONNECT_ERROR: Self = Self(0xa);
    /// The peer causes too much load.
    pub const ENHANCE_YOUR_CALM: Self = Self(0xb);
    /// The transport does not meet the minimum security requirements.
    pub const INADEQUATE_SECURITY: Self = Self(0xc);
    /// The endpoint requires HTTP/1.1.
    pub const HTTP_1_1_REQUIRED: Self = Self(0xd);

    /// The name of the code in RFC 9113, or `None` for a code that this crate does not know.
    pub const fn name(self) -> Option<&'static str> {
        const NAMES: [&str; 14] = [
            "NO_ERROR",
            "PROTOCOL_ERROR",
            "INTERNAL_ERROR",
            "FLOW_CONTROL_ERROR",
            "SETTINGS_TIMEOUT",
            "STREAM_CLOSED",
            "FRAME_SIZE_ERROR",
            "REFUSED_STREAM",
            "CANCEL",
            "COMPRESSION_ERROR",
            "CONNECT_ERROR",
            "ENHANCE_YOUR_CALM",
            "INADEQUATE_SECURITY",
            "HTTP_1_1_REQUIRED",
        ];
        if (self.0 as usize) < NAMES.len() {
            Some(NAMES[self.0 as usize])
        } else {
            None
        }
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "ErrorCode({:#x})", self.0),
        }
    }
}

/// The type of a frame (RFC 9113, section 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// DATA, type 0x0.
    Data,
    /// HEADERS, type 0x1.
    Headers,
    /// PRIORITY, type 0x2.
    Priority,
    /// RST_STREAM, type 0x3.
    RstStream,
    /// SETTINGS, type 0x4.
    Settings,
    /// PUSH_PROMISE, type 0x5.
    PushPromise,
    /// PING, type 0x6.
    Ping,
    /// GOAWAY, type 0x7.
    GoAway,
    /// WINDOW_UPDATE, type 0x8.
    WindowUpdate,
    /// CONTINUATION, type 0x9.
    Continuation,
    /// PRIORITY_UPDATE of RFC 9218, type 0x10.
    PriorityUpdate,
    /// A type that neither RFC 9113 nor RFC 9218 defines. A receiver discards the frame
    /// (section 4.1).
    Unknown(u8),
}

impl Kind {
    /// The type of the code `code`.
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            0x10 => Self::PriorityUpdate,
            code => Self::Unknown(code),
        }
    }

    /// The code of the type.
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::GoAway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::PriorityUpdate => 0x10,
            Self::Unknown(code) => code,
        }
    }
}

/// A frame header (RFC 9113, section 4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The length of the payload: 24 bits.
    pub length: u32,
    /// The type.
    pub kind: Kind,
    /// The flags, with the bits that the type does not define.
    pub flags: u8,
    /// The stream identifier: 31 bits. 0 is the connection.
    pub stream: u32,
}

impl Head {
    /// Reads a frame header. Each value of 9 bytes is a header: the reserved bit is ignored, as
    /// section 4.1 requires.
    pub const fn parse(bytes: [u8; HEAD]) -> Self {
        let [l0, l1, l2, kind, flags, s0, s1, s2, s3] = bytes;
        Self {
            length: u32::from_be_bytes([0, l0, l1, l2]),
            kind: Kind::from_code(kind),
            flags,
            stream: u32::from_be_bytes([s0, s1, s2, s3]) & MAX_STREAM,
        }
    }

    /// The bytes of the header. The caller checks that the length has at most 24 bits and the
    /// stream identifier at most 31 bits.
    pub(crate) const fn encode(&self) -> [u8; HEAD] {
        let [_, l0, l1, l2] = self.length.to_be_bytes();
        let [s0, s1, s2, s3] = self.stream.to_be_bytes();
        [l0, l1, l2, self.kind.code(), self.flags, s0, s1, s2, s3]
    }

    /// Checks the rules of section 4.2 and of the frame type in section 6 that the header alone
    /// decides, before any byte of the payload. `max` is the `SETTINGS_MAX_FRAME_SIZE` of the
    /// receiver.
    ///
    /// Gives the length of the fixed fields at the start of the payload: the pad length, the
    /// priority fields, the promised stream, or the fields of a control frame. Each size error is
    /// a connection error: a PRIORITY of a wrong size too, because its stream can be idle, where
    /// a reset is not permitted (section 6.4).
    pub(crate) fn check(&self, max: u32) -> Result<usize, FrameError> {
        let size = FrameError::Connection(ErrorCode::FRAME_SIZE_ERROR);
        let protocol = FrameError::Connection(ErrorCode::PROTOCOL_ERROR);
        if self.length > max {
            return Err(size);
        }
        let padded = usize::from(self.flags & PADDED != 0);
        // The stream rule (`Some(true)` for stream 0 only, `Some(false)` for a stream only), the
        // length of the fixed fields, and whether the payload is exactly those fields.
        let (connection, fixed, exact) = match self.kind {
            Kind::Data => (Some(false), padded, false),
            Kind::Headers => (
                Some(false),
                padded + if self.flags & PRIORITY != 0 { 5 } else { 0 },
                false,
            ),
            Kind::Priority => (Some(false), 5, true),
            Kind::RstStream => (Some(false), 4, true),
            Kind::Settings => (Some(true), 0, false),
            Kind::PushPromise => (Some(false), padded + 4, false),
            Kind::Ping => (Some(true), 8, true),
            Kind::GoAway => (Some(true), 8, false),
            Kind::WindowUpdate => (None, 4, true),
            Kind::Continuation => (Some(false), 0, false),
            // RFC 9218, section 7.1: the stream identifier of the frame is 0.
            Kind::PriorityUpdate => (Some(true), 4, false),
            Kind::Unknown(_) => (None, 0, false),
        };
        if connection.is_some_and(|connection| connection != (self.stream == 0)) {
            return Err(protocol);
        }
        let length = self.length as usize;
        let settings = self.kind == Kind::Settings
            && (!self.length.is_multiple_of(6) || (self.flags & ACK != 0 && self.length != 0));
        if settings || length < fixed || (exact && length != fixed) {
            return Err(size);
        }
        Ok(fixed)
    }
}

/// The priority fields of RFC 7540, which RFC 9113 deprecates (section 5.3.2). A receiver checks
/// them and builds no priority tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    /// The dependency is exclusive.
    pub exclusive: bool,
    /// The stream that the stream depends on: 31 bits.
    pub dependency: u32,
    /// The weight, less one.
    pub weight: u8,
}

impl Priority {
    fn parse(bytes: [u8; 5]) -> Self {
        let [d0, d1, d2, d3, weight] = bytes;
        let dependency = u32::from_be_bytes([d0, d1, d2, d3]);
        Self {
            exclusive: dependency & !MAX_STREAM != 0,
            dependency: dependency & MAX_STREAM,
            weight,
        }
    }

    fn encode(self) -> [u8; 5] {
        let [d0, d1, d2, d3] = (self.dependency | if self.exclusive { 1 << 31 } else { 0 }).to_be_bytes();
        [d0, d1, d2, d3, self.weight]
    }
}

/// The fixed fields at the start of a payload, which [`Head::check`] measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fixed {
    Data {
        padding: Option<u8>,
    },
    Headers {
        padding: Option<u8>,
        priority: Option<Priority>,
    },
    Priority(Priority),
    RstStream(ErrorCode),
    Settings,
    PushPromise {
        padding: Option<u8>,
        promised: u32,
    },
    Ping([u8; 8]),
    GoAway {
        last_stream: u32,
        code: ErrorCode,
    },
    WindowUpdate(u32),
    Continuation,
    /// The prioritized stream of a PRIORITY_UPDATE.
    PriorityUpdate(u32),
    Unknown,
}

impl Fixed {
    /// Reads the fixed fields of `head` from `bytes`, which has exactly the length that
    /// [`Head::check`] gave, and checks their values.
    ///
    /// A pad length past the rest of the payload is a connection error (sections 6.1, 6.2, and
    /// 6.6). A stream that depends on itself is a connection error too: RFC 7540 made it an
    /// error, RFC 9113 does not define it, and a reset could hit an idle stream. A window
    /// increment of 0 is a stream error on a stream, and a connection error on the connection
    /// (section 6.9). A PRIORITY_UPDATE for stream 0 is a connection error (RFC 9218, section
    /// 7.1).
    pub(crate) fn parse(head: &Head, bytes: &[u8]) -> Result<Self, FrameError> {
        let protocol = FrameError::Connection(ErrorCode::PROTOCOL_ERROR);
        let (padding, rest) = match bytes.split_first() {
            Some((&pad, rest))
                if head.flags & PADDED != 0 && matches!(head.kind, Kind::Data | Kind::Headers | Kind::PushPromise) =>
            {
                (Some(pad), rest)
            }
            _ => (None, bytes),
        };
        // The bytes after the fixed fields: the pad length must leave room for its padding.
        let after = head.length as usize - bytes.len();
        if padding.is_some_and(|pad| usize::from(pad) > after) {
            return Err(protocol);
        }
        let word = |bytes: &[u8]| bytes.first_chunk().copied().map(u32::from_be_bytes).unwrap_or(0);
        Ok(match head.kind {
            Kind::Data => Self::Data { padding },
            Kind::Headers => {
                let priority = rest.first_chunk().copied().map(Priority::parse);
                if priority.is_some_and(|priority| priority.dependency == head.stream) {
                    return Err(protocol);
                }
                Self::Headers { padding, priority }
            }
            Kind::Priority => {
                let priority = rest.first_chunk().copied().map(Priority::parse).ok_or(protocol)?;
                if priority.dependency == head.stream {
                    return Err(protocol);
                }
                Self::Priority(priority)
            }
            Kind::RstStream => Self::RstStream(ErrorCode(word(rest))),
            Kind::Settings => Self::Settings,
            Kind::PushPromise => Self::PushPromise {
                padding,
                promised: word(rest) & MAX_STREAM,
            },
            Kind::Ping => Self::Ping(rest.first_chunk().copied().unwrap_or_default()),
            Kind::GoAway => Self::GoAway {
                last_stream: word(rest) & MAX_STREAM,
                code: ErrorCode(word(rest.get(4..).unwrap_or_default())),
            },
            Kind::WindowUpdate => match word(rest) & MAX_STREAM {
                0 if head.stream == 0 => return Err(protocol),
                0 => return Err(FrameError::Stream(ErrorCode::PROTOCOL_ERROR)),
                increment => Self::WindowUpdate(increment),
            },
            Kind::Continuation => Self::Continuation,
            Kind::PriorityUpdate => match word(rest) & MAX_STREAM {
                0 => return Err(protocol),
                prioritized => Self::PriorityUpdate(prioritized),
            },
            Kind::Unknown(_) => Self::Unknown,
        })
    }

    /// The length of the padding after the variable part.
    pub(crate) fn padding(&self) -> u8 {
        match *self {
            Self::Data { padding } | Self::Headers { padding, .. } | Self::PushPromise { padding, .. } => {
                padding.unwrap_or(0)
            }
            _ => 0,
        }
    }
}

/// The identifier and the value of one setting of 6 bytes.
pub(crate) const fn setting_of(bytes: [u8; 6]) -> (u16, u32) {
    let [i0, i1, v0, v1, v2, v3] = bytes;
    (u16::from_be_bytes([i0, i1]), u32::from_be_bytes([v0, v1, v2, v3]))
}

/// Checks the value of one setting (RFC 9113, section 6.5.2). A setting that this crate does not
/// know has no rule, and the receiver ignores it.
pub(crate) fn check_setting(id: u16, value: u32) -> Result<(), FrameError> {
    let error = |code| Err(FrameError::Connection(code));
    match id {
        ENABLE_PUSH if value > 1 => error(ErrorCode::PROTOCOL_ERROR),
        INITIAL_WINDOW_SIZE if value > MAX_STREAM => error(ErrorCode::FLOW_CONTROL_ERROR),
        MAX_FRAME_SIZE if !(MIN_FRAME_SIZE..=MAX_LENGTH).contains(&value) => error(ErrorCode::PROTOCOL_ERROR),
        // RFC 9218, section 2.1.
        NO_RFC7540_PRIORITIES if value > 1 => error(ErrorCode::PROTOCOL_ERROR),
        _ => Ok(()),
    }
}

/// The settings of a SETTINGS frame: its payload, 6 bytes for each setting (RFC 9113, section
/// 6.5.1), in their order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entries<'a>(&'a [u8]);

impl<'a> Entries<'a> {
    /// The settings in `bytes`, or `None` if its length is not a multiple of 6.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        bytes.len().is_multiple_of(6).then_some(Self(bytes))
    }

    /// The bytes of the settings.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Each setting, in its order: its identifier and its value.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (u16, u32)> + 'a {
        self.0.as_chunks::<6>().0.iter().map(|&setting| setting_of(setting))
    }
}

impl fmt::Debug for Entries<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// One frame (RFC 9113, section 6). The fields that carry bytes borrow the bytes of the frame.
///
/// [`parse`](Self::parse) reads a complete frame from one slice, and [`write`](Self::write) writes
/// one. An engine that reads frames across received regions uses the same checks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// DATA (section 6.1).
    Data {
        /// The stream: not 0.
        stream: u32,
        /// The data, with no padding.
        data: &'a [u8],
        /// The flag END_STREAM.
        end_stream: bool,
        /// The pad length when the flag PADDED is set. The padding bytes are zero.
        padding: Option<u8>,
    },
    /// HEADERS (section 6.2).
    Headers {
        /// The stream: not 0.
        stream: u32,
        /// A fragment of the field block.
        fragment: &'a [u8],
        /// The flag END_STREAM.
        end_stream: bool,
        /// The flag END_HEADERS: no CONTINUATION frame follows.
        end_headers: bool,
        /// The deprecated priority fields, when the flag PRIORITY is set.
        priority: Option<Priority>,
        /// The pad length when the flag PADDED is set.
        padding: Option<u8>,
    },
    /// PRIORITY (section 6.3), which RFC 9113 deprecates.
    Priority {
        /// The stream: not 0.
        stream: u32,
        /// The priority fields.
        priority: Priority,
    },
    /// RST_STREAM (section 6.4).
    RstStream {
        /// The stream: not 0.
        stream: u32,
        /// Why the stream ends.
        code: ErrorCode,
    },
    /// SETTINGS (section 6.5).
    Settings {
        /// The flag ACK: the frame acknowledges the peer's SETTINGS frame, and it has no setting.
        ack: bool,
        /// The settings.
        settings: Entries<'a>,
    },
    /// PUSH_PROMISE (section 6.6).
    PushPromise {
        /// The stream of the request that the push belongs to: not 0.
        stream: u32,
        /// The stream that the push reserves.
        promised: u32,
        /// A fragment of the field block.
        fragment: &'a [u8],
        /// The flag END_HEADERS.
        end_headers: bool,
        /// The pad length when the flag PADDED is set.
        padding: Option<u8>,
    },
    /// PING (section 6.7).
    Ping {
        /// The flag ACK: the frame answers a PING.
        ack: bool,
        /// The opaque data.
        opaque: [u8; 8],
    },
    /// GOAWAY (section 6.8).
    GoAway {
        /// The last stream that the sender processed or can process.
        last_stream: u32,
        /// Why the connection ends.
        code: ErrorCode,
        /// The additional debug data, which has no meaning.
        debug: &'a [u8],
    },
    /// WINDOW_UPDATE (section 6.9).
    WindowUpdate {
        /// The stream, or 0 for the connection.
        stream: u32,
        /// The increment: 1 to 2^31 - 1.
        increment: u32,
    },
    /// CONTINUATION (section 6.10).
    Continuation {
        /// The stream: not 0.
        stream: u32,
        /// A fragment of the field block.
        fragment: &'a [u8],
        /// The flag END_HEADERS.
        end_headers: bool,
    },
    /// PRIORITY_UPDATE (RFC 9218, section 7.1), on stream 0: a client changes the priority of a
    /// response.
    PriorityUpdate {
        /// The stream whose priority changes: not 0.
        prioritized: u32,
        /// The priority, in the form of the `priority` field: see
        /// [`Priority::parse`](crate::priority::Priority::parse).
        value: &'a [u8],
    },
    /// A frame of a type that neither RFC 9113 nor RFC 9218 defines.
    Unknown {
        /// The type code.
        kind: u8,
        /// The flags.
        flags: u8,
        /// The stream.
        stream: u32,
        /// The payload.
        payload: &'a [u8],
    },
}

impl<'a> Frame<'a> {
    /// Reads the frame at the start of `bytes`, and gives it with its length. `max` is the
    /// `SETTINGS_MAX_FRAME_SIZE` of the receiver.
    ///
    /// Gives `Ok(None)` when `bytes` holds only a part of a valid frame. The header is checked
    /// before the payload is read, so a frame that is too large or has a wrong length or stream
    /// refuses with only its 9 bytes. A [`FrameError::Stream`] is for a complete frame of
    /// `HEAD + length` bytes.
    pub fn parse(bytes: &'a [u8], max: u32) -> Result<Option<(Self, usize)>, FrameError> {
        let Some((&head, tail)) = bytes.split_first_chunk::<HEAD>() else {
            return Ok(None);
        };
        let head = Head::parse(head);
        let fixed_len = head.check(max)?;
        let Some(payload) = tail.get(..head.length as usize) else {
            return Ok(None);
        };
        let (fixed_bytes, rest) = payload.split_at(fixed_len);
        let fixed = Fixed::parse(&head, fixed_bytes)?;
        let variable = &rest[..rest.len() - usize::from(fixed.padding())];
        let flag = |flag: u8| head.flags & flag != 0;
        let stream = head.stream;
        let frame = match fixed {
            Fixed::Data { padding } => Self::Data {
                stream,
                data: variable,
                end_stream: flag(END_STREAM),
                padding,
            },
            Fixed::Headers { padding, priority } => Self::Headers {
                stream,
                fragment: variable,
                end_stream: flag(END_STREAM),
                end_headers: flag(END_HEADERS),
                priority,
                padding,
            },
            Fixed::Priority(priority) => Self::Priority { stream, priority },
            Fixed::RstStream(code) => Self::RstStream { stream, code },
            Fixed::Settings => {
                let settings = Entries(variable);
                for (id, value) in settings.iter() {
                    check_setting(id, value)?;
                }
                Self::Settings {
                    ack: flag(ACK),
                    settings,
                }
            }
            Fixed::PushPromise { padding, promised } => Self::PushPromise {
                stream,
                promised,
                fragment: variable,
                end_headers: flag(END_HEADERS),
                padding,
            },
            Fixed::Ping(opaque) => Self::Ping { ack: flag(ACK), opaque },
            Fixed::GoAway { last_stream, code } => Self::GoAway {
                last_stream,
                code,
                debug: variable,
            },
            Fixed::WindowUpdate(increment) => Self::WindowUpdate { stream, increment },
            Fixed::Continuation => Self::Continuation {
                stream,
                fragment: variable,
                end_headers: flag(END_HEADERS),
            },
            Fixed::PriorityUpdate(prioritized) => Self::PriorityUpdate {
                prioritized,
                value: variable,
            },
            Fixed::Unknown => Self::Unknown {
                kind: head.kind.code(),
                flags: head.flags,
                stream,
                payload: variable,
            },
        };
        Ok(Some((frame, HEAD + payload.len())))
    }

    /// Writes the frame into the free capacity of `out`, after the bytes that it holds. Padding
    /// bytes are zero, and each flag that the type does not define is unset.
    ///
    /// Refuses, and writes nothing, if a stream identifier, a window increment, or the length of
    /// the payload is past its field, or if `out` has too little free capacity.
    pub fn write<B: BufferMut>(&self, out: &mut WriteLoan<B>) -> Result<(), WriteError> {
        let pad = |padding: Option<u8>| (padding.map_or(0, |_| 1), padding.unwrap_or(0));
        // The header, the fixed fields (at most 8 bytes), the variable part, and the padding.
        let mut fixed = [0; 8];
        let (kind, flags, stream, fixed_len, variable, padding): (Kind, u8, u32, usize, &[u8], u8) = match *self {
            Self::Data {
                stream,
                data,
                end_stream,
                padding,
            } => {
                let (pad_len, padding_len) = pad(padding);
                fixed[0] = padding_len;
                let flags = flag(end_stream, END_STREAM) | flag(padding.is_some(), PADDED);
                (Kind::Data, flags, stream, pad_len, data, padding_len)
            }
            Self::Headers {
                stream,
                fragment,
                end_stream,
                end_headers,
                priority,
                padding,
            } => {
                let (pad_len, padding_len) = pad(padding);
                fixed[0] = padding_len;
                let mut len = pad_len;
                if let Some(priority) = priority {
                    fixed[len..len + 5].copy_from_slice(&priority.encode());
                    len += 5;
                }
                let flags = flag(end_stream, END_STREAM)
                    | flag(end_headers, END_HEADERS)
                    | flag(padding.is_some(), PADDED)
                    | flag(priority.is_some(), PRIORITY);
                (Kind::Headers, flags, stream, len, fragment, padding_len)
            }
            Self::Priority { stream, priority } => {
                fixed[..5].copy_from_slice(&priority.encode());
                (Kind::Priority, 0, stream, 5, &[], 0)
            }
            Self::RstStream { stream, code } => {
                fixed[..4].copy_from_slice(&code.0.to_be_bytes());
                (Kind::RstStream, 0, stream, 4, &[], 0)
            }
            Self::Settings { ack, settings } => (Kind::Settings, flag(ack, ACK), 0, 0, settings.0, 0),
            Self::PushPromise {
                stream,
                promised,
                fragment,
                end_headers,
                padding,
            } => {
                if promised > MAX_STREAM {
                    return Err(WriteError::Range);
                }
                let (pad_len, padding_len) = pad(padding);
                fixed[0] = padding_len;
                fixed[pad_len..pad_len + 4].copy_from_slice(&promised.to_be_bytes());
                let flags = flag(end_headers, END_HEADERS) | flag(padding.is_some(), PADDED);
                (Kind::PushPromise, flags, stream, pad_len + 4, fragment, padding_len)
            }
            Self::Ping { ack, opaque } => {
                fixed = opaque;
                (Kind::Ping, flag(ack, ACK), 0, 8, &[], 0)
            }
            Self::GoAway {
                last_stream,
                code,
                debug,
            } => {
                if last_stream > MAX_STREAM {
                    return Err(WriteError::Range);
                }
                fixed[..4].copy_from_slice(&last_stream.to_be_bytes());
                fixed[4..].copy_from_slice(&code.0.to_be_bytes());
                (Kind::GoAway, 0, 0, 8, debug, 0)
            }
            Self::WindowUpdate { stream, increment } => {
                if increment > MAX_STREAM {
                    return Err(WriteError::Range);
                }
                fixed[..4].copy_from_slice(&increment.to_be_bytes());
                (Kind::WindowUpdate, 0, stream, 4, &[], 0)
            }
            Self::Continuation {
                stream,
                fragment,
                end_headers,
            } => (
                Kind::Continuation,
                flag(end_headers, END_HEADERS),
                stream,
                0,
                fragment,
                0,
            ),
            Self::PriorityUpdate { prioritized, value } => {
                if prioritized > MAX_STREAM {
                    return Err(WriteError::Range);
                }
                fixed[..4].copy_from_slice(&prioritized.to_be_bytes());
                (Kind::PriorityUpdate, 0, 0, 4, value, 0)
            }
            Self::Unknown {
                kind,
                flags,
                stream,
                payload,
            } => (Kind::Unknown(kind), flags, stream, 0, payload, 0),
        };
        let length = fixed_len + variable.len() + usize::from(padding);
        let head = Head {
            length: u32::try_from(length)
                .ok()
                .filter(|&length| length <= MAX_LENGTH)
                .ok_or(WriteError::Range)?,
            kind,
            flags,
            stream,
        };
        if stream > MAX_STREAM {
            return Err(WriteError::Range);
        }
        let needed = HEAD + length;
        let available = out.capacity() - out.filled().len();
        if needed > available {
            return Err(WriteError::Full { needed, available });
        }
        out.fill_from(&head.encode());
        out.fill_from(&fixed[..fixed_len]);
        out.fill_from(variable);
        out.fill_from(&[0; 255][..usize::from(padding)]);
        Ok(())
    }
}

impl fmt::Debug for Frame<'_> {
    /// Shows the fields of the frame, and only the length of each byte field, so that no peer
    /// bytes reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Data {
                stream,
                data,
                end_stream,
                padding,
            } => f
                .debug_struct("Data")
                .field("stream", &stream)
                .field("data", &data.len())
                .field("end_stream", &end_stream)
                .field("padding", &padding)
                .finish(),
            Self::Headers {
                stream,
                fragment,
                end_stream,
                end_headers,
                priority,
                padding,
            } => f
                .debug_struct("Headers")
                .field("stream", &stream)
                .field("fragment", &fragment.len())
                .field("end_stream", &end_stream)
                .field("end_headers", &end_headers)
                .field("priority", &priority)
                .field("padding", &padding)
                .finish(),
            Self::Priority { stream, priority } => f
                .debug_struct("Priority")
                .field("stream", &stream)
                .field("priority", &priority)
                .finish(),
            Self::RstStream { stream, code } => f
                .debug_struct("RstStream")
                .field("stream", &stream)
                .field("code", &code)
                .finish(),
            Self::Settings { ack, settings } => f
                .debug_struct("Settings")
                .field("ack", &ack)
                .field("settings", &settings)
                .finish(),
            Self::PushPromise {
                stream,
                promised,
                fragment,
                end_headers,
                padding,
            } => f
                .debug_struct("PushPromise")
                .field("stream", &stream)
                .field("promised", &promised)
                .field("fragment", &fragment.len())
                .field("end_headers", &end_headers)
                .field("padding", &padding)
                .finish(),
            Self::Ping { ack, .. } => f.debug_struct("Ping").field("ack", &ack).finish_non_exhaustive(),
            Self::GoAway {
                last_stream,
                code,
                debug,
            } => f
                .debug_struct("GoAway")
                .field("last_stream", &last_stream)
                .field("code", &code)
                .field("debug", &debug.len())
                .finish(),
            Self::WindowUpdate { stream, increment } => f
                .debug_struct("WindowUpdate")
                .field("stream", &stream)
                .field("increment", &increment)
                .finish(),
            Self::Continuation {
                stream,
                fragment,
                end_headers,
            } => f
                .debug_struct("Continuation")
                .field("stream", &stream)
                .field("fragment", &fragment.len())
                .field("end_headers", &end_headers)
                .finish(),
            Self::PriorityUpdate { prioritized, value } => f
                .debug_struct("PriorityUpdate")
                .field("prioritized", &prioritized)
                .field("value", &value.len())
                .finish(),
            Self::Unknown {
                kind,
                flags,
                stream,
                payload,
            } => f
                .debug_struct("Unknown")
                .field("kind", &kind)
                .field("flags", &flags)
                .field("stream", &stream)
                .field("payload", &payload.len())
                .finish(),
        }
    }
}

/// A frame that breaks RFC 9113.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// End the connection with a GOAWAY of this code (section 5.4.1).
    Connection(ErrorCode),
    /// The frame is complete, and its stream breaks a rule: reset the stream with this code
    /// (section 5.4.2). The rules of the stream state decide whether its state permits a reset.
    Stream(ErrorCode),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(code) => write!(f, "the frame is a connection error of type {code:?}"),
            Self::Stream(code) => write!(f, "the frame is a stream error of type {code:?}"),
        }
    }
}

impl core::error::Error for FrameError {}

/// A refused frame write. It wrote nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output region has fewer free bytes than the frame. Write into a region with at least
    /// `needed` free bytes.
    Full {
        /// The bytes of the frame.
        needed: usize,
        /// The free bytes of the output region.
        available: usize,
    },
    /// A stream identifier or a window increment is past 2^31 - 1, or the payload is past
    /// 2^24 - 1 bytes.
    Range,
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { needed, available } => write!(
                f,
                "the frame needs {needed} bytes, but the output region has only {available} free bytes"
            ),
            Self::Range => f.write_str("a field of the frame is past its range"),
        }
    }
}

impl core::error::Error for WriteError {}
