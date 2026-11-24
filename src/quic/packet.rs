//! The packet layer of version 1 (RFC 9000, section 17, and RFC 9001, section 5): the headers,
//! the packet numbers, the opening of received packets in place, and the sealing of packets.
//!
//! A received region goes to [`Datagrams`], which gives each packet in its order. A packet opens
//! in two steps, in its place in the region: [`Protected::unmask`] removes the header protection
//! and gives the packet number and the key phase, and [`Unmasked::open`] decrypts the payload with
//! the packet key of that key phase. Then the packet freezes as a [`Lease`], and its frames are
//! views of it. The rest of the region stays writable, so the next packet of the datagram can
//! open with keys that this packet gave.

use core::fmt;
use core::num::NonZeroUsize;
use core::ops::Range;

use rscrypto_rustls::quic as provider;
use rstypes::buffer::{Backing, Buffer as _, BufferMut as _, Lease};
use rustls::crypto::SecureRandom;
pub use rustls::quic::{DirectionalKeys, HeaderProtectionKey, Keys, PacketKey, Side};

use super::frame::Frame;
use super::{ConnectionId, Reader, VARINT_MAX, Version, Writer};
use crate::drive::Ecn;

/// The first bit of a long header.
const LONG: u8 = 0x80;
/// The fixed bit: the second bit of the first byte of each packet of version 1.
const FIXED: u8 = 0x40;
/// The reserved bits after the removal of header protection: of a long header, and of a short
/// header (RFC 9000, sections 17.2 and 17.3.1).
const RESERVED_LONG: u8 = 0x0c;
const RESERVED_SHORT: u8 = 0x18;
/// The key phase bit of a short header, and its spin bit.
const KEY_PHASE: u8 = 0x04;
const SPIN: u8 = 0x20;
/// The bytes of the sample of header protection (RFC 9001, section 5.4.2).
const SAMPLE: usize = 16;
/// The longest packet number: 4 bytes.
const NUMBER_MAX: usize = 4;
/// The bytes of the tag of each AEAD of version 1.
pub const TAG: usize = 16;

/// The kind of a packet that carries frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An Initial packet.
    Initial,
    /// A 0-RTT packet.
    ZeroRtt,
    /// A Handshake packet.
    Handshake,
    /// A short-header packet: 1-RTT.
    OneRtt,
}

impl Kind {
    /// The packet number space of the kind (RFC 9000, section 12.3).
    pub const fn space(self) -> Space {
        match self {
            Self::Initial => Space::Initial,
            Self::Handshake => Space::Handshake,
            Self::ZeroRtt | Self::OneRtt => Space::Data,
        }
    }
}

/// A packet number space (RFC 9000, section 12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Space {
    /// The space of the Initial packets.
    Initial,
    /// The space of the Handshake packets.
    Handshake,
    /// The space of 0-RTT and 1-RTT packets.
    Data,
}

/// The header of a received packet, before its protection is removed (RFC 9000, section 17).
/// Each offset and range counts from the first byte of the packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header {
    /// A packet of version 1 that carries frames.
    Protected {
        /// The kind of the packet.
        kind: Kind,
        /// The destination connection ID.
        dcid: ConnectionId,
        /// The source connection ID. A short header has none.
        scid: ConnectionId,
        /// The token of an Initial packet. Each other kind has an empty range.
        token: Range<usize>,
        /// The offset of the packet number.
        number: usize,
        /// The bytes of the packet.
        len: usize,
    },
    /// A Retry packet of version 1. Check its tag with [`retry_is_valid`].
    Retry {
        /// The destination connection ID: the source of the client.
        dcid: ConnectionId,
        /// The source connection ID: the next destination of the client.
        scid: ConnectionId,
        /// The address token, before the integrity tag.
        token: Range<usize>,
        /// The bytes of the packet: the rest of the datagram.
        len: usize,
    },
    /// A Version Negotiation packet: the versions of the server, 4 bytes each, at `versions`.
    /// Its connection IDs can be longer than those of version 1.
    Negotiation {
        /// The destination connection ID: the source of the client.
        dcid: Range<usize>,
        /// The source connection ID: the destination of the client.
        scid: Range<usize>,
        /// The versions of the server.
        versions: Range<usize>,
        /// The bytes of the packet: the rest of the datagram.
        len: usize,
    },
    /// A long-header packet of another version. A server can answer it with [`negotiation`].
    Unsupported {
        /// The version of the packet.
        version: Version,
        /// The destination connection ID.
        dcid: Range<usize>,
        /// The source connection ID.
        scid: Range<usize>,
        /// The bytes of the packet: the rest of the datagram.
        len: usize,
    },
}

/// A header that is not valid: discard the rest of its datagram (RFC 9000, section 12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the QUIC packet header is not valid")
    }
}

impl core::error::Error for Malformed {}

impl Header {
    /// Parses the header of the packet at the start of `bytes`, the rest of a datagram. A short
    /// header has a destination connection ID of `short_dcid_len` bytes: the length of the
    /// connection IDs that this end issues. Refuses when the header is not valid: then discard the
    /// rest of the datagram.
    pub fn parse(bytes: &[u8], short_dcid_len: usize) -> Result<Self, Malformed> {
        Self::read(bytes, short_dcid_len).ok_or(Malformed)
    }

    fn read(bytes: &[u8], short_dcid_len: usize) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let first = reader.u8()?;
        if first & LONG == 0 {
            if first & FIXED == 0 {
                return None;
            }
            return Some(Self::Protected {
                kind: Kind::OneRtt,
                dcid: ConnectionId::new(reader.take(short_dcid_len)?)?,
                scid: ConnectionId::EMPTY,
                token: 0..0,
                number: reader.at(),
                len: bytes.len(),
            });
        }
        let version = Version(reader.u32()?);
        let dcid = id(&mut reader)?;
        let scid = id(&mut reader)?;
        if version == Version::NEGOTIATION {
            let versions = reader.at()..bytes.len();
            return (!versions.is_empty() && versions.len().is_multiple_of(4)).then_some(Self::Negotiation {
                dcid,
                scid,
                versions,
                len: bytes.len(),
            });
        }
        if version != Version::V1 {
            return Some(Self::Unsupported {
                version,
                dcid,
                scid,
                len: bytes.len(),
            });
        }
        if first & FIXED == 0 {
            return None;
        }
        // Version 1 drops a connection ID longer than 20 bytes (RFC 9000, section 17.2).
        let (dcid, scid) = (ConnectionId::new(&bytes[dcid])?, ConnectionId::new(&bytes[scid])?);
        let kind = match (first >> 4) & 0x3 {
            0 => Kind::Initial,
            1 => Kind::ZeroRtt,
            2 => Kind::Handshake,
            _ => {
                let token = reader.at()..bytes.len().checked_sub(provider::RETRY_INTEGRITY_TAG_LEN)?;
                return (token.start <= token.end).then_some(Self::Retry {
                    dcid,
                    scid,
                    token,
                    len: bytes.len(),
                });
            }
        };
        let token = if kind == Kind::Initial {
            let len = usize::try_from(reader.varint()?).ok()?;
            let start = reader.at();
            reader.take(len)?;
            start..reader.at()
        } else {
            0..0
        };
        let length = usize::try_from(reader.varint()?).ok()?;
        let number = reader.at();
        let len = number.checked_add(length)?;
        (len <= bytes.len()).then_some(Self::Protected {
            kind,
            dcid,
            scid,
            token,
            number,
            len,
        })
    }

    /// The end of the packet: the next packet of the datagram starts there.
    pub const fn end(&self) -> usize {
        match self {
            Self::Protected { len, .. }
            | Self::Retry { len, .. }
            | Self::Negotiation { len, .. }
            | Self::Unsupported { len, .. } => *len,
        }
    }
}

/// The range of the connection ID at `reader`, after its length byte.
fn id(reader: &mut Reader<'_>) -> Option<Range<usize>> {
    let len = usize::from(reader.u8()?);
    let start = reader.at();
    reader.take(len)?;
    Some(start..reader.at())
}

/// The packet number of a packet whose last `len` bytes of number are `truncated`, when the next
/// number of its space is `expected` (RFC 9000, appendix A.3).
pub fn decode_number(truncated: u64, len: usize, expected: u64) -> u64 {
    let window = 1_u64 << (8 * len);
    let half = window / 2;
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate.saturating_add(half) <= expected && candidate < (1 << 62) - window {
        candidate + window
    } else if candidate > expected.saturating_add(half) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

/// The bytes that the packet number `number` needs, when `largest_acked` is the largest number of
/// its space that the peer acknowledged: 1 to 4 (RFC 9000, section 17.1 and appendix A.2). `None`
/// when 4 bytes cannot give it.
pub fn number_len(number: u64, largest_acked: Option<u64>) -> Option<usize> {
    let unacked = match largest_acked {
        Some(largest) => number.checked_sub(largest)?,
        None => number.checked_add(1)?,
    };
    let window = unacked.checked_mul(2)?;
    (1..=NUMBER_MAX).find(|&len| window < 1 << (8 * len))
}

/// The keys of the Initial packets of a connection whose client chose `dcid` as the destination
/// of its first Initial packet, for `side` (RFC 9001, section 5.2).
pub fn initial_keys(dcid: &ConnectionId, side: Side) -> Keys {
    provider::initial_keys(dcid.as_bytes(), side)
}

/// Why a packet did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The packet has no room for the sample of its header protection, or carries no frames:
    /// discard it.
    Short,
    /// The packet key refused the packet: discard it (RFC 9001, section 5.5). The peer, or anyone
    /// on the path, can send such a packet, so it does not end the connection.
    Authentication,
    /// The packet opened, and breaks a rule of version 1: its reserved bits are not zero, or it
    /// has no frame. End the connection with `PROTOCOL_VIOLATION`.
    Violation,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Short => "the QUIC packet is too short to open",
            Self::Authentication => "the QUIC packet did not open with its key",
            Self::Violation => "the QUIC packet breaks a rule of version 1",
        })
    }
}

impl core::error::Error for OpenError {}

/// The packets of a received region, which open in place one at a time: the coalesced packets of
/// one datagram, or of each datagram of a region that segmentation offload filled.
#[derive(Debug)]
pub struct Datagrams {
    pub(super) ecn: Ecn,
    /// The bytes that no packet took yet.
    rest: Option<Backing>,
    /// The bytes of the rest that belong to the current datagram.
    datagram: usize,
    /// The size of each datagram of the region, or `None` for one datagram.
    segment: Option<NonZeroUsize>,
    short_dcid_len: usize,
}

impl Datagrams {
    /// The packets of `region`, whose initialized bytes are one datagram, or datagrams of
    /// `segment` bytes each, the last of them shorter or equal. A short header has a destination
    /// connection ID of `short_dcid_len` bytes.
    pub fn new(region: Backing, segment: Option<NonZeroUsize>, short_dcid_len: usize) -> Self {
        Self {
            ecn: Ecn::NotEct,
            rest: Some(region),
            datagram: 0,
            segment,
            short_dcid_len,
        }
    }

    /// Uses the ECN codepoint reported by the host for this receive region.
    pub fn with_ecn(mut self, ecn: Ecn) -> Self {
        self.ecn = ecn;
        self
    }

    /// Gives the next packet, still protected, or `None` at the end of the region. A header that
    /// is not valid discards the rest of its datagram, and gives [`Malformed`].
    pub fn next_packet(&mut self) -> Option<Result<Protected<'_>, Malformed>> {
        let rest = self.rest.as_ref()?;
        if rest.initialized() == 0 {
            self.rest = None;
            return None;
        }
        if self.datagram == 0 {
            let all = rest.initialized();
            self.datagram = self.segment.map_or(all, |segment| segment.get().min(all));
        }
        match Header::parse(&rest.bytes()[..self.datagram], self.short_dcid_len) {
            Ok(header) => Some(Ok(Protected {
                inner: Some((self, header)),
            })),
            Err(malformed) => {
                drop(self.take(self.datagram));
                Some(Err(malformed))
            }
        }
    }

    /// Freezes the first `len` bytes of the rest, which belong to the current datagram.
    fn take(&mut self, len: usize) -> Lease {
        let rest = self.rest.take().expect("a packet is in the rest of the region");
        let (taken, rest) = rest
            .freeze_prefix(len)
            .expect("a packet is in the initialized bytes of the region");
        self.rest = Some(rest);
        self.datagram -= len;
        taken
    }

    /// The bytes of the next `len` bytes of the rest, writable.
    fn bytes_mut(&mut self, len: usize) -> &mut [u8] {
        let rest = self.rest.as_mut().expect("a packet is in the rest of the region");
        &mut rest.bytes_mut()[..len]
    }
}

/// A received packet that waits to open. A packet that drops unopened is discarded.
#[derive(Debug)]
pub struct Protected<'a> {
    /// The packets and the header, until the packet leaves the region.
    inner: Option<(&'a mut Datagrams, Header)>,
}

impl<'a> Protected<'a> {
    fn inner(&self) -> &(&'a mut Datagrams, Header) {
        self.inner.as_ref().expect("the packet is there until it leaves")
    }

    /// The header of the packet.
    pub fn header(&self) -> &Header {
        &self.inner().1
    }

    /// The bytes of the packet, still protected: for example the connection IDs of a header of
    /// another version, or of a Version Negotiation packet.
    pub fn bytes(&self) -> &[u8] {
        let (datagrams, header) = self.inner();
        let rest = datagrams.rest.as_ref().expect("a packet is in the rest of the region");
        &rest.bytes()[..header.end()]
    }

    /// Takes the packet with no opening, as a frozen view of the region: a Retry, a Version
    /// Negotiation, or a packet whose keys the connection does not have yet.
    pub fn take(mut self) -> Lease {
        let (datagrams, header) = self.inner.take().expect("the packet is there until it leaves");
        datagrams.take(header.end())
    }

    /// Removes the header protection of a packet that carries frames with `key`, in place, and
    /// decodes its packet number against `expected`, the next number of its space. Refuses, and
    /// discards the packet, when it has no room for the sample, and with [`OpenError::Short`] for a
    /// header with no protection, such as a Retry.
    pub fn unmask(mut self, key: &dyn HeaderProtectionKey, expected: u64) -> Result<Unmasked<'a>, OpenError> {
        let Header::Protected { kind, number, len, .. } = self.inner().1 else {
            return Err(OpenError::Short);
        };
        let packet = self
            .inner
            .as_mut()
            .expect("the packet is there until it leaves")
            .0
            .bytes_mut(len);
        let sample_at = number + NUMBER_MAX;
        let Some(sample) = packet.get(sample_at..sample_at + SAMPLE) else {
            return Err(OpenError::Short);
        };
        let sample: [u8; SAMPLE] = sample.try_into().expect("the sample has its length");
        let (first, rest) = packet.split_first_mut().expect("a header has its first byte");
        let numbers = &mut rest[number - 1..number - 1 + NUMBER_MAX];
        if key.decrypt_in_place(&sample, first, numbers).is_err() {
            return Err(OpenError::Short);
        }
        let number_len = usize::from(*first & 0x3) + 1;
        let truncated = numbers[..number_len]
            .iter()
            .fold(0, |value, &byte| (value << 8) | u64::from(byte));
        let reserved = if kind == Kind::OneRtt {
            RESERVED_SHORT
        } else {
            RESERVED_LONG
        };
        let (violation, key_phase) = (*first & reserved != 0, kind == Kind::OneRtt && *first & KEY_PHASE != 0);
        Ok(Unmasked {
            inner: self.inner.take(),
            number: decode_number(truncated, number_len, expected),
            payload: number + number_len..len,
            key_phase,
            violation,
        })
    }
}

impl Drop for Protected<'_> {
    fn drop(&mut self) {
        if let Some((datagrams, header)) = self.inner.take() {
            drop(datagrams.take(header.end()));
        }
    }
}

/// A received packet whose header protection is gone, and whose payload waits to open. A packet
/// that drops unopened is discarded.
#[derive(Debug)]
pub struct Unmasked<'a> {
    /// The packets and the header, until the packet leaves the region.
    inner: Option<(&'a mut Datagrams, Header)>,
    number: u64,
    /// The protected payload, with its tag.
    payload: Range<usize>,
    key_phase: bool,
    /// The reserved bits are not zero.
    violation: bool,
}

impl Unmasked<'_> {
    /// The packet number.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// The key phase of a short header: the packet key that opens it. A long header has `false`.
    pub const fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// Decrypts the payload in place with `key`, and gives the packet, frozen. Refuses, and
    /// discards the packet, as [`OpenError`] says.
    pub fn open(mut self, key: &dyn PacketKey) -> Result<Packet, OpenError> {
        let (datagrams, header) = self.inner.take().expect("the packet is there until it leaves");
        let packet = datagrams.bytes_mut(header.end());
        let (head, payload) = packet.split_at_mut(self.payload.start);
        let opened = key.decrypt_in_place(self.number, head, payload, None);
        let plaintext = opened.map(<[u8]>::len);
        let bytes = datagrams.take(header.end());
        let plaintext = plaintext.map_err(|_| OpenError::Authentication)?;
        if self.violation || plaintext == 0 {
            return Err(OpenError::Violation);
        }
        Ok(Packet {
            header,
            number: self.number,
            key_phase: self.key_phase,
            payload: self.payload.start..self.payload.start + plaintext,
            bytes,
        })
    }
}

impl Drop for Unmasked<'_> {
    fn drop(&mut self) {
        if let Some((datagrams, header)) = self.inner.take() {
            drop(datagrams.take(header.end()));
        }
    }
}

/// A packet that opened in place, frozen in its region.
#[derive(Clone, Debug)]
pub struct Packet {
    header: Header,
    number: u64,
    key_phase: bool,
    /// The plaintext payload in `bytes`.
    payload: Range<usize>,
    bytes: Lease,
}

impl Packet {
    /// The header of the packet.
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The packet number.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// The key phase of a short header. A long header has `false`.
    pub const fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// The frames of the packet, as a view of the region that it arrived in. Parse them with
    /// [`Frame::parse`].
    pub fn payload(&self) -> Lease {
        self.bytes
            .view(self.payload.clone())
            .expect("the payload is in the packet")
    }
}

/// The header of a packet that this end sends.
#[derive(Clone, Copy, Debug)]
pub enum Outgoing<'a> {
    /// An Initial packet.
    Initial {
        /// The destination connection ID.
        dcid: &'a ConnectionId,
        /// The source connection ID.
        scid: &'a ConnectionId,
        /// The address token of a client, or empty.
        token: &'a [u8],
    },
    /// A 0-RTT packet.
    ZeroRtt {
        /// The destination connection ID.
        dcid: &'a ConnectionId,
        /// The source connection ID.
        scid: &'a ConnectionId,
    },
    /// A Handshake packet.
    Handshake {
        /// The destination connection ID.
        dcid: &'a ConnectionId,
        /// The source connection ID.
        scid: &'a ConnectionId,
    },
    /// A short-header packet: 1-RTT.
    OneRtt {
        /// The destination connection ID.
        dcid: &'a ConnectionId,
        /// The latency spin bit (RFC 9000, section 17.4).
        spin: bool,
        /// The key phase of the packet key.
        key_phase: bool,
    },
}

/// Why a packet could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The output has no room for it.
    Full,
    /// A value does not fit its field: a packet number length other than 1 to 4, or a value above
    /// 2^62 - 1.
    Value,
    /// The packet key refused to seal, for example because it reached its limit.
    Seal,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "the output has no room for the QUIC packet",
            Self::Value => "a value does not fit its field of the QUIC packet",
            Self::Seal => "the packet key refused to seal the QUIC packet",
        })
    }
}

impl core::error::Error for BuildError {}

/// A packet that this end builds in place in its output: the header, the frames, and then the
/// seal, which encrypts the payload and protects the header in place.
#[derive(Debug)]
pub struct Builder<'a> {
    out: &'a mut [u8],
    /// The offset of the Length field of a long header, and its width.
    length: Option<(usize, usize)>,
    /// The offset of the packet number, and its length.
    at: usize,
    number_len: usize,
    number: u64,
    /// The end of the frames.
    end: usize,
}

impl<'a> Builder<'a> {
    /// Starts a packet with `header` and the packet number `number` in `number_len` bytes, at the
    /// start of `out`. Give `number_len` from [`number_len`]. Refuses when `out` has no room for the
    /// header and the tag, or a value does not fit.
    pub fn new(out: &'a mut [u8], header: Outgoing<'_>, number: u64, number_len: usize) -> Result<Self, BuildError> {
        if !(1..=NUMBER_MAX).contains(&number_len) || number > VARINT_MAX {
            return Err(BuildError::Value);
        }
        let size = out.len();
        let mut writer = Writer::new(out);
        let low = u8::try_from(number_len - 1).expect("1 to 4 bytes");
        let long = |kind: u8, writer: &mut Writer<'_>, dcid: &ConnectionId, scid: &ConnectionId| {
            writer.u8(LONG | FIXED | (kind << 4) | low)?;
            writer.u32(Version::V1.0)?;
            for id in [dcid, scid] {
                writer.u8(u8::try_from(id.as_bytes().len()).ok()?)?;
                writer.bytes(id.as_bytes())?;
            }
            Some(())
        };
        let length = match header {
            Outgoing::Initial { dcid, scid, token } => {
                long(0, &mut writer, dcid, scid).ok_or(BuildError::Full)?;
                writer.varint(token.len() as u64).ok_or(BuildError::Full)?;
                writer.bytes(token).ok_or(BuildError::Full)?;
                true
            }
            Outgoing::ZeroRtt { dcid, scid } => long(1, &mut writer, dcid, scid)
                .ok_or(BuildError::Full)
                .map(|()| true)?,
            Outgoing::Handshake { dcid, scid } => long(2, &mut writer, dcid, scid)
                .ok_or(BuildError::Full)
                .map(|()| true)?,
            Outgoing::OneRtt { dcid, spin, key_phase } => {
                let bits = (if spin { SPIN } else { 0 }) | (if key_phase { KEY_PHASE } else { 0 });
                writer.u8(FIXED | bits | low).ok_or(BuildError::Full)?;
                writer.bytes(dcid.as_bytes()).ok_or(BuildError::Full)?;
                false
            }
        };
        // The Length field takes 2 bytes, or 4 when the rest of the output can pass 16,383 bytes.
        let length = length
            .then(|| {
                let at = writer.len();
                let width = if size - at <= 0x3fff { 2 } else { 4 };
                writer.varint_in(0, width).map(|()| (at, width))
            })
            .map(|length| length.ok_or(BuildError::Full))
            .transpose()?;
        let at = writer.len();
        let truncated = number.to_be_bytes();
        writer.bytes(&truncated[8 - number_len..]).ok_or(BuildError::Full)?;
        let end = writer.len();
        if end + TAG > size {
            return Err(BuildError::Full);
        }
        Ok(Self {
            out,
            length,
            at,
            number_len,
            number,
            end,
        })
    }

    /// The room for frames, after the frames so far and before the tag.
    pub const fn room(&self) -> usize {
        self.out.len() - TAG - self.end
    }

    /// Writes an ACK directly into the room for frames. Only a complete frame advances the packet.
    pub(super) fn write_ack(&mut self, write: impl FnOnce(&mut [u8]) -> Option<usize>) -> bool {
        let stop = self.out.len() - TAG;
        if let Some(len) = write(&mut self.out[self.end..stop]) {
            self.end += len;
            return true;
        }
        false
    }

    /// Writes `frame` after the frames so far. Refuses, and writes nothing, when it does not fit.
    pub fn frame(&mut self, frame: &Frame<'_>) -> Result<(), BuildError> {
        let room = self.out.len() - TAG;
        let written = frame
            .write(&mut self.out[self.end..room])
            .map_err(|error| match error {
                super::frame::WriteError::Full => BuildError::Full,
                super::frame::WriteError::Value => BuildError::Value,
            })?;
        self.end += written;
        Ok(())
    }

    /// Pads the payload with PADDING frames, so that the sealed packet has at least `len` bytes,
    /// for example 1,200 bytes for a datagram with an Initial packet of a client (RFC 9000, section
    /// 14.1). Refuses when the output has no room for it.
    pub fn pad_to(&mut self, len: usize) -> Result<(), BuildError> {
        let end = len.saturating_sub(TAG).max(self.end);
        if end + TAG > self.out.len() {
            return Err(BuildError::Full);
        }
        self.out[self.end..end].fill(0);
        self.end = end;
        Ok(())
    }

    /// Seals the packet with `keys`: it pads the payload for the sample of the header protection,
    /// writes the Length field, encrypts the payload in place, and protects the header. Gives the
    /// bytes of the packet.
    pub fn seal(mut self, keys: &DirectionalKeys) -> Result<usize, BuildError> {
        // The sample starts 4 bytes after the packet number, and the tag gives 16 of its bytes.
        let least = self.at + NUMBER_MAX;
        if self.end < least {
            self.pad_to(least + TAG)?;
        }
        let end = self.end + TAG;
        if let Some((at, width)) = self.length {
            let length = (end - self.at) as u64;
            let mut writer = Writer::new(&mut self.out[at..at + width]);
            writer.varint_in(length, width).ok_or(BuildError::Full)?;
        }
        let payload_at = self.at + self.number_len;
        let (head, rest) = self.out[..end].split_at_mut(payload_at);
        let (payload, tag) = rest.split_at_mut(self.end - payload_at);
        let sealed = keys
            .packet
            .encrypt_in_place(self.number, head, payload, None)
            .map_err(|_| BuildError::Seal)?;
        tag.copy_from_slice(sealed.as_ref());
        let sample_at = self.at + NUMBER_MAX;
        let sample: [u8; SAMPLE] = self.out[sample_at..sample_at + SAMPLE]
            .try_into()
            .expect("the sample is in the packet");
        let (first, rest) = self.out.split_first_mut().expect("a header has its first byte");
        let numbers = &mut rest[self.at - 1..self.at - 1 + self.number_len];
        keys.header
            .encrypt_in_place(&sample, first, numbers)
            .map_err(|_| BuildError::Seal)?;
        Ok(end)
    }
}

/// Builds a Retry packet of version 1 at the start of `out`, to the client whose Initial packet
/// had the source connection ID `dcid` and the destination connection ID `original`: `scid` is the
/// connection ID of this server, and `token` its address token (RFC 9000, section 17.2.5). The
/// unused bits of the first byte come from `random`. Gives the bytes of the packet.
pub fn retry(
    out: &mut [u8],
    (dcid, scid, original): (&ConnectionId, &ConnectionId, &ConnectionId),
    token: &[u8],
    random: &dyn SecureRandom,
) -> Result<usize, BuildError> {
    let mut unused = [0];
    random.fill(&mut unused).map_err(|_| BuildError::Seal)?;
    let mut writer = Writer::new(out);
    let written = (|| {
        writer.u8(LONG | FIXED | (3 << 4) | (unused[0] & 0x0f))?;
        writer.u32(Version::V1.0)?;
        for id in [dcid, scid] {
            writer.u8(u8::try_from(id.as_bytes().len()).ok()?)?;
            writer.bytes(id.as_bytes())?;
        }
        writer.bytes(token)
    })();
    written.ok_or(BuildError::Full)?;
    let len = writer.len();
    let tag = provider::retry_integrity_tag(original.as_bytes(), &out[..len]).ok_or(BuildError::Value)?;
    let end = len + tag.len();
    out.get_mut(len..end).ok_or(BuildError::Full)?.copy_from_slice(&tag);
    Ok(end)
}

/// Whether `packet`, a Retry packet, has the integrity tag of a server that answered an Initial
/// packet to `original`, its destination connection ID (RFC 9001, section 5.8). A client
/// discards a Retry packet whose tag is not valid.
pub fn retry_is_valid(packet: &[u8], original: &ConnectionId) -> bool {
    provider::is_valid_retry(original.as_bytes(), packet)
}

/// Builds a Version Negotiation packet at the start of `out`, in answer to `packet`, a packet of
/// another version with the header `header` (RFC 9000, section 17.2.1). It lists version 1 and
/// one reserved version, which exercises the version negotiation of the client (section 6.3). The
/// unused bits of the first byte and the reserved version come from `random`. Gives the bytes of
/// the packet, or `None` when `header` is not of another version.
///
/// A server answers at most one packet of each datagram, and none of a datagram shorter than
/// 1,200 bytes (section 6.1).
pub fn negotiation(
    out: &mut [u8],
    (packet, header): (&[u8], &Header),
    random: &dyn SecureRandom,
) -> Result<Option<usize>, BuildError> {
    let Header::Unsupported { dcid, scid, .. } = header else {
        return Ok(None);
    };
    let mut drawn = [0; 5];
    random.fill(&mut drawn).map_err(|_| BuildError::Seal)?;
    let reserved = (u32::from_be_bytes([drawn[1], drawn[2], drawn[3], drawn[4]]) & 0xf0f0_f0f0) | 0x0a0a_0a0a;
    let mut writer = Writer::new(out);
    let written = (|| {
        // The fixed bit is set, so the packet can share a port with other protocols.
        writer.u8(LONG | FIXED | (drawn[0] & 0x3f))?;
        writer.u32(Version::NEGOTIATION.0)?;
        // The connection IDs of the packet, each in the place of the other.
        for id in [&packet[scid.clone()], &packet[dcid.clone()]] {
            writer.u8(u8::try_from(id.len()).ok()?)?;
            writer.bytes(id)?;
        }
        writer.u32(Version::V1.0)?;
        writer.u32(reserved)
    })();
    written.ok_or(BuildError::Full)?;
    Ok(Some(writer.len()))
}

/// What a Version Negotiation packet means to a client of version 1 (RFC 9000, section 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Negotiation {
    /// The client discards the packet, and goes on.
    Discard,
    /// The server has no version that the client supports: the client abandons the connection
    /// attempt.
    Abandon,
}

impl Negotiation {
    /// What `packet`, a Version Negotiation packet with the header `header`, means to a client
    /// whose first packet had the destination `dcid`, the source `scid`, and the version
    /// `selected`. `processed` tells whether the client processed another packet of the
    /// connection before it, also an earlier Version Negotiation packet.
    ///
    /// The client discards the packet after another packet, when its connection IDs are not the
    /// two of the client in the place of each other, and when it lists `selected`. Else a client
    /// of version 1 only abandons the attempt.
    pub fn of(
        (packet, header): (&[u8], &Header),
        (dcid, scid, selected): (&ConnectionId, &ConnectionId, Version),
        processed: bool,
    ) -> Self {
        let Header::Negotiation {
            dcid: to,
            scid: from,
            versions,
            ..
        } = header
        else {
            return Self::Discard;
        };
        let ours = packet[to.clone()] == *scid.as_bytes() && packet[from.clone()] == *dcid.as_bytes();
        let listed = packet[versions.clone()]
            .as_chunks::<4>()
            .0
            .iter()
            .any(|version| Version(u32::from_be_bytes(*version)) == selected);
        if processed || !ours || listed {
            Self::Discard
        } else {
            Self::Abandon
        }
    }
}
