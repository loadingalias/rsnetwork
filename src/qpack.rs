//! QPACK (RFC 9204): the field compression of HTTP/3.
//!
//! An HTTP/3 connection has one [`Encoder`] for the field sections that it sends and one
//! [`Decoder`] for the field sections that it receives. Each is the one owner of its dynamic table,
//! and no other connection shares it. Thus a compression context never crosses a connection, and
//! a pool that keys connections by principal and privacy partition keeps contexts in their
//! partitions.
//!
//! QPACK sends the changes of a dynamic table on two streams of their own: the encoder stream
//! carries the insertions of the encoder, and the decoder stream carries the acknowledgements and
//! the cancellations of the decoder. The codec does no I/O. It reads the bytes of these streams
//! that the caller gives, and it writes their bytes into regions of the caller. A field section
//! names only entries that the decoder received, or it waits, blocked, until they arrive.
//!
//! Each charges its memory to the caller's budget when it is made, and no call allocates. Thus a
//! malformed instruction or field section refuses with no allocation. The decoder bounds the work
//! of each read of the encoder stream, and the number of blocked streams.
//!
//! A field line that is sensitive goes as a literal that is never indexed (RFC 9204, section
//! 7.1.3), with the rule of HPACK: the caller's mark, `authorization`, `proxy-authorization`, and
//! a `cookie` or `set-cookie` value of fewer than 20 bytes. Such a line never goes into a dynamic
//! table. The decoder keeps the mark of each line that it receives.
//!
//! ```
//! use core::num::NonZeroU64;
//!
//! use rsnetwork::buffer::{Backing, Buffer as _, WriteLoan};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::qpack::{Decoder, Encoder, EncoderLimits, FieldLine, Limits, Lines, Settings};
//!
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let limits = Limits { table_bytes: 4096, blocked_streams: 16, list_bytes: 16 * 1024, work: 64 * 1024 };
//! let mut decoder = Decoder::new(limits, &budget)?;
//! let mut lines = Lines::new(limits, &budget)?;
//! let mut encoder = Encoder::new(EncoderLimits { table_bytes: 4096, sections: 64 }, &budget)?;
//! // The settings that the peer's decoder sent.
//! encoder.set_peer(Settings { table_bytes: 4096, blocked_streams: 16 })?;
//!
//! let line = |name, value| FieldLine { name, value, never_indexed: false };
//! let request = [line(b":method", b"GET"), line(b":path", b"/notes"), line(b"x-trace", b"7f3a")];
//! let region = || WriteLoan::new(Backing::from(Vec::with_capacity(256)));
//! let (mut section, mut encoder_stream, mut decoder_stream) = (region(), region(), region());
//! let prefix = encoder.encode(0, request.iter().copied(), &mut section, &mut encoder_stream)?;
//! // A field section is its prefix and then its lines.
//! let bytes = [prefix.bytes(), section.filled()].concat();
//!
//! decoder.receive(encoder_stream.filled(), &mut decoder_stream)?;
//! let block = decoder.decode(0, &bytes, &mut lines, &mut decoder_stream)?;
//! let decoded: Vec<_> = block.lines().map(|line| (line.name, line.value)).collect();
//! assert_eq!(decoded[2], (&b"x-trace"[..], &b"7f3a"[..]));
//! // The acknowledgement goes back to the encoder on the decoder stream.
//! encoder.receive(decoder_stream.filled())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod decoder;
mod encoder;
mod table;

use core::fmt;

use rstypes::buffer::{BufferMut, WriteLoan};

pub use decoder::{Decoder, Lines};
pub use encoder::Encoder;

use crate::hpack::integer;
pub use crate::hpack::{Block, FieldLine};

/// The limits of a [`Decoder`], which the caller sets. HTTP/3 sends the first three in its
/// SETTINGS frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest capacity of the dynamic table: the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` that the
    /// endpoint sends. A capacity above it is an error of the encoder stream.
    pub table_bytes: usize,
    /// The most streams that wait for insertions at one time: the
    /// `SETTINGS_QPACK_BLOCKED_STREAMS` that the endpoint sends.
    pub blocked_streams: usize,
    /// The largest decoded field section, in the size of RFC 9114, section 4.2.2: the bytes of
    /// each name and value, and 32 for each line. It is the `SETTINGS_MAX_FIELD_SECTION_SIZE`
    /// that the endpoint sends.
    pub list_bytes: usize,
    /// The work of one call to [`Decoder::receive`]: the bytes that it reads, and each byte that
    /// it copies to the dynamic table.
    pub work: usize,
}

/// The limits of an [`Encoder`], which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderLimits {
    /// The largest capacity of the dynamic table that the encoder uses. The capacity is the
    /// smaller of this limit and the limit of the peer.
    pub table_bytes: usize,
    /// The most field sections with references to the dynamic table that wait for their
    /// acknowledgement. When this many wait, the next sections use only the static table and
    /// literals.
    pub sections: usize,
}

/// The settings of the peer's decoder, from the SETTINGS frame of HTTP/3 (RFC 9204, section 5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
    pub table_bytes: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`.
    pub blocked_streams: u64,
}

/// The prefix of an encoded field section (RFC 9204, section 4.5.1): its Required Insert Count
/// and its Base. The prefix comes before the lines of the section.
///
/// The prefix depends on each line of the section, so [`Encoder::encode`] gives it after the
/// lines. Write it before them, for example in the region of the frame header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    bytes: [u8; 22],
    len: usize,
}

impl Prefix {
    /// The bytes of the prefix: at most 22.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prefix").field("len", &self.len).finish()
    }
}

/// A region with too few free bytes for the call. Nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full {
    /// The bytes that the call can need.
    pub needed: usize,
    /// The free bytes of the region.
    pub available: usize,
}

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { needed, available } = self;
        write!(
            f,
            "the call can need {needed} bytes, but the region has only {available} free bytes"
        )
    }
}

impl core::error::Error for Full {}

/// A field section that the decoder did not give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The section names entries that the encoder stream did not bring yet (RFC 9204, section
    /// 2.2.1). Keep the section, and decode it again when [`Decoder::unblocked`] gives its stream.
    Blocked,
    /// The decoded lines are larger than `list_bytes`. The decoder wrote the Section
    /// Acknowledgment, so the tables stay in step: refuse the stream.
    TooLarge,
    /// The section would block one stream more than `blocked_streams` (RFC 9204, section 2.1.2).
    /// End the connection with `QPACK_DECOMPRESSION_FAILED`.
    TooManyBlocked,
    /// The section breaks RFC 9204, or the encoder stream failed before it. End the connection
    /// with `QPACK_DECOMPRESSION_FAILED`.
    Malformed,
    /// The region for the decoder stream has no room for the Section Acknowledgment. Write the
    /// decoder stream, and decode the section again.
    Full(Full),
    /// The lines are smaller than the limits of the decoder need. Make them with [`Lines::new`]
    /// and the limits of the decoder. Nothing changed.
    Misuse,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked => f.write_str("the field section waits for insertions on the encoder stream"),
            Self::TooLarge => f.write_str("the decoded field lines are larger than the list limit"),
            Self::TooManyBlocked => f.write_str("the field section blocks more streams than the limit"),
            Self::Malformed => f.write_str("the field section breaks RFC 9204"),
            Self::Full(full) => full.fmt(f),
            Self::Misuse => f.write_str("the lines are smaller than the limits of the decoder need"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// A refused encode or setting. It wrote and changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The region for the field section has fewer free bytes than the longest section of the
    /// lines.
    Full(Full),
    /// The settings of the peer came after earlier settings. HTTP/3 sends them once (RFC 9114,
    /// section 7.2.4).
    Settings,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(full) => full.fmt(f),
            Self::Settings => f.write_str("the settings of the peer came a second time"),
        }
    }
}

impl core::error::Error for EncodeError {}

/// An instruction that breaks RFC 9204. The state of the dynamic table is not known, so end the
/// connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// An instruction on the encoder stream: end the connection with
    /// `QPACK_ENCODER_STREAM_ERROR`.
    Encoder,
    /// An instruction on the decoder stream: end the connection with
    /// `QPACK_DECODER_STREAM_ERROR`.
    Decoder,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoder => "an instruction on the encoder stream breaks RFC 9204",
            Self::Decoder => "an instruction on the decoder stream breaks RFC 9204",
        })
    }
}

impl core::error::Error for StreamError {}

/// The bytes of an integer that the end of a read of a stream cut (RFC 7541, section 5.1). An
/// integer has at most 11 bytes: a first byte and 10 continuation bytes.
#[derive(Clone, Copy, Default)]
struct Stash {
    bytes: [u8; 11],
    len: usize,
}

impl Stash {
    /// The first byte of the next integer: the first byte of the stash, or of `rest`.
    fn first(&self, rest: &[u8]) -> Option<u8> {
        if self.len > 0 {
            Some(self.bytes[0])
        } else {
            rest.first().copied()
        }
    }

    /// Moves the bytes of the next integer from `rest` to the stash until the integer is
    /// complete. Gives the integer and its first byte, or `None` when `rest` ends first. Gives
    /// `Err` for an integer that does not fit in a `u64`.
    fn integer(&mut self, rest: &mut &[u8], prefix: u32) -> Result<Option<(u64, u8)>, ()> {
        let max = (1_u16 << prefix) - 1;
        while let Some((&byte, after)) = rest.split_first() {
            *rest = after;
            let at = self.len;
            *self.bytes.get_mut(at).ok_or(())? = byte;
            self.len += 1;
            let done = if at == 0 {
                u16::from(byte) & max < max
            } else {
                byte & 0x80 == 0
            };
            if done {
                self.len = 0;
                let (value, _) = integer::decode(&self.bytes[..=at], prefix).ok_or(())?;
                return Ok(Some((value, self.bytes[0])));
            }
        }
        Ok(None)
    }
}

/// The free bytes of a region.
fn free<B: BufferMut>(out: &WriteLoan<B>) -> usize {
    out.capacity() - out.filled().len()
}

/// Writes `value` as an integer with a prefix of `prefix` bits after the `flags` bits.
fn put<B: BufferMut>(out: &mut WriteLoan<B>, value: u64, prefix: u32, flags: u8) {
    integer::encode(value, prefix, flags, |bytes| {
        out.fill_from(bytes);
    });
}
