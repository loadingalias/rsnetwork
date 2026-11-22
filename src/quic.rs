//! QUIC version 1 in the core (RFC 9000 and RFC 9001): the packet layer and the frame codec, with
//! no I/O.
//!
//! - **Packets.** [`packet::Datagrams`] walks the packets of a received region in place: the
//!   coalesced packets of each datagram, and each datagram of a region that segmentation offload
//!   filled. A packet opens in the region that it arrived in, and then freezes as a
//!   [`Lease`](crate::buffer::Lease), while the rest of the region stays writable for the next
//!   packet, which can need keys that the packet before it gave. No byte is copied before
//!   decryption. [`packet::Builder`] builds and seals a packet in an output region.
//! - **Protection.** rustls's QUIC interface gives the packet and header protection keys, which
//!   `rscrypto-rustls` implements with rscrypto: [`packet::initial_keys`] gives the keys of the
//!   Initial packets. The Retry integrity tag comes from the same provider. The core adds no
//!   cryptography.
//! - **Frames.** [`frame::Frame`] parses and writes each frame of RFC 9000, section 19, and the
//!   DATAGRAM frame of RFC 9221, as views of the payload of its packet.
//! - **Versions.** Version 1 only. [`packet::negotiation`] builds a Version Negotiation packet,
//!   and [`packet::Negotiation`] tells a client what one means (RFC 9000, section 6).
//! - **Randomness.** Each random value comes from the source that the caller gives, a
//!   [`SecureRandom`](rustls::crypto::SecureRandom), so a seeded source replays each packet byte
//!   for byte.

pub mod frame;
pub mod packet;

use core::fmt;

/// A QUIC version (RFC 9000, section 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Version(pub u32);

impl Version {
    /// The version of a Version Negotiation packet.
    pub const NEGOTIATION: Self = Self(0);
    /// QUIC version 1 (RFC 9000).
    pub const V1: Self = Self(1);

    /// Whether the version is one that RFC 9000, section 15, reserves to exercise version
    /// negotiation: `0x?a?a?a?a`.
    pub const fn is_reserved(self) -> bool {
        self.0 & 0x0f0f_0f0f == 0x0a0a_0a0a
    }
}

/// A connection ID of version 1: at most 20 bytes (RFC 9000, section 17.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; ConnectionId::MAX],
}

impl ConnectionId {
    /// The longest connection ID of version 1.
    pub const MAX: usize = 20;
    /// The connection ID with no byte.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; Self::MAX],
    };

    /// The connection ID of `bytes`, or `None` when it is longer than [`MAX`](Self::MAX).
    pub fn new(bytes: &[u8]) -> Option<Self> {
        let mut id = Self::EMPTY;
        id.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        id.len = u8::try_from(bytes.len()).ok()?;
        Some(id)
    }

    /// The bytes of the connection ID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId(")?;
        self.as_bytes().iter().try_for_each(|byte| write!(f, "{byte:02x}"))?;
        write!(f, ")")
    }
}

/// A transport error code (RFC 9000, section 20.1). A code that this crate does not know keeps its
/// value, and it has no special meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u64);

impl ErrorCode {
    /// The connection closes with no error.
    pub const NO_ERROR: Self = Self(0x0);
    /// The endpoint met an internal error.
    pub const INTERNAL_ERROR: Self = Self(0x1);
    /// The server refuses the connection.
    pub const CONNECTION_REFUSED: Self = Self(0x2);
    /// The peer sent more data than its flow-control limits allow.
    pub const FLOW_CONTROL_ERROR: Self = Self(0x3);
    /// The peer opened more streams than its limit allows.
    pub const STREAM_LIMIT_ERROR: Self = Self(0x4);
    /// A frame arrived on a stream in a state that does not permit it.
    pub const STREAM_STATE_ERROR: Self = Self(0x5);
    /// The final size of a stream changed, or data passed it.
    pub const FINAL_SIZE_ERROR: Self = Self(0x6);
    /// A frame is badly formatted.
    pub const FRAME_ENCODING_ERROR: Self = Self(0x7);
    /// A transport parameter is not valid.
    pub const TRANSPORT_PARAMETER_ERROR: Self = Self(0x8);
    /// The peer gave more connection IDs than the limit allows.
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self(0x9);
    /// The peer broke a rule of the protocol that has no more specific code.
    pub const PROTOCOL_VIOLATION: Self = Self(0xa);
    /// A token of a Retry or NEW_TOKEN frame is not valid.
    pub const INVALID_TOKEN: Self = Self(0xb);
    /// The application or the application protocol caused the close.
    pub const APPLICATION_ERROR: Self = Self(0xc);
    /// The peer sent more CRYPTO data than the endpoint can buffer.
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self(0xd);
    /// A key update is not valid.
    pub const KEY_UPDATE_ERROR: Self = Self(0xe);
    /// A key reached its limit of packets that fail to open.
    pub const AEAD_LIMIT_REACHED: Self = Self(0xf);
    /// No path can carry the connection.
    pub const NO_VIABLE_PATH: Self = Self(0x10);
}

/// The largest value of a variable-length integer: 2^62 - 1 (RFC 9000, section 16).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// The length of the shortest encoding of `value` as a variable-length integer, or `None` above
/// [`VARINT_MAX`].
pub(crate) const fn varint_len(value: u64) -> Option<usize> {
    match value {
        0..=0x3f => Some(1),
        0x40..=0x3fff => Some(2),
        0x4000..=0x3fff_ffff => Some(4),
        0x4000_0000..=VARINT_MAX => Some(8),
        _ => None,
    }
}

/// A reader of the fields of a header or a frame.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The offset of the next field.
    pub(crate) const fn at(&self) -> usize {
        self.at
    }

    /// The bytes after the last field.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    pub(crate) fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(self.at..self.at.checked_add(len)?)?;
        self.at += len;
        Some(taken)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// A variable-length integer (RFC 9000, section 16), and the length of its encoding.
    pub(crate) fn varint_with_len(&mut self) -> Option<(u64, usize)> {
        let first = *self.bytes.get(self.at)?;
        let len = 1 << (first >> 6);
        let bytes = self.take(len)?;
        let value = bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, &byte| (value << 8) | u64::from(byte));
        Some((value, len))
    }

    pub(crate) fn varint(&mut self) -> Option<u64> {
        self.varint_with_len().map(|(value, _)| value)
    }
}

/// A writer of the fields of a header or a frame into a slice.
pub(crate) struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub(crate) const fn new(out: &'a mut [u8]) -> Self {
        Self { out, at: 0 }
    }

    /// The bytes written.
    pub(crate) const fn len(&self) -> usize {
        self.at
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        let end = self.at.checked_add(bytes.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(bytes);
        self.at = end;
        Some(())
    }

    pub(crate) fn u8(&mut self, byte: u8) -> Option<()> {
        self.bytes(&[byte])
    }

    pub(crate) fn u32(&mut self, value: u32) -> Option<()> {
        self.bytes(&value.to_be_bytes())
    }

    /// `value` in its shortest encoding. `None` above [`VARINT_MAX`] or with no room.
    pub(crate) fn varint(&mut self, value: u64) -> Option<()> {
        self.varint_in(value, varint_len(value)?)
    }

    /// `value` in an encoding of `len` bytes: 1, 2, 4, or 8, and long enough for it.
    pub(crate) fn varint_in(&mut self, value: u64, len: usize) -> Option<()> {
        if varint_len(value)? > len {
            return None;
        }
        let prefix = match len {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return None,
        };
        let bytes = value.to_be_bytes();
        let start = 8 - len;
        self.bytes(&bytes[start..])?;
        self.out[self.at - len] |= prefix << 6;
        Some(())
    }
}
