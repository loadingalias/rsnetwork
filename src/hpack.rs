//! HPACK (RFC 7541): the header compression of HTTP/2.
//!
//! An HTTP/2 connection has one [`Encoder`] for the blocks that it sends and one [`Decoder`] for
//! the blocks that it receives. Each is the one owner of its dynamic table, and no other
//! connection shares it. Thus a compression context never crosses a connection, and a pool that
//! keys connections by principal and privacy partition keeps contexts in their partitions.
//!
//! Each charges its dynamic table to the caller's budget when it is made. The decoder writes the
//! lines of a block into the [`Lines`] that the caller lends for the call, so an idle connection
//! keeps only its two tables. No encode or decode allocates, so a malformed or oversized block
//! refuses with no allocation. The decoder checks the work of each block before each copy.
//!
//! A field line that is sensitive goes as a literal that is never indexed (RFC 7541, section
//! 6.2.3): it never goes into a dynamic table, so a peer on the same connection cannot find it by
//! the size of a block. The caller marks a line with [`FieldLine::never_indexed`], and the
//! encoder also selects each line that the sensitive-field rule names: `authorization`,
//! `proxy-authorization`, and a `cookie` or `set-cookie` value of fewer than 20 bytes. The
//! decoder keeps the mark of each line that it receives, so a forwarder sends the line in the
//! same form.
//!
//! ```
//! use core::num::NonZeroU64;
//!
//! use rsnetwork::buffer::{Backing, Buffer as _, WriteLoan};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::hpack::{Decoder, Encoder, FieldLine, Limits, Lines};
//!
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let mut encoder = Encoder::new(4096, &budget)?;
//! let limits = Limits { table_bytes: 4096, list_bytes: 16 * 1024, work: 64 * 1024 };
//! let mut decoder = Decoder::new(limits, &budget)?;
//! // The space for the decoded lines of one block, which a host can take from a pool for each block.
//! let mut lines = Lines::new(limits, &budget)?;
//!
//! let line = |name, value| FieldLine { name, value, never_indexed: false };
//! let request = [
//!     line(b":method", b"GET"),
//!     line(b":path", b"/notes"),
//!     line(b"authorization", b"Bearer mF_9.B5f-4.1JqM"),
//! ];
//! let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(256)));
//! encoder.encode(request.iter().copied(), &mut out)?;
//!
//! let block = decoder.decode(out.filled(), &mut lines)?;
//! let decoded: Vec<_> = block.lines().map(|line| (line.name, line.value, line.never_indexed)).collect();
//! assert_eq!(decoded[1], (&b":path"[..], &b"/notes"[..], false));
//! // The rule sent the credential as never indexed, and the decoder keeps the mark.
//! assert_eq!(decoded[2], (&b"authorization"[..], &b"Bearer mF_9.B5f-4.1JqM"[..], true));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub(crate) mod decoder;
mod encoder;
pub(crate) mod huffman;
pub(crate) mod integer;
pub(crate) mod table;

use core::fmt;

pub use decoder::{Block, Decoder, Lines};
pub use encoder::Encoder;

/// One field line of a header block: a name and a value, as bytes, and its mark.
///
/// HPACK carries any bytes. HTTP/2 checks the names and the values of a block after the decode
/// (RFC 9113, section 8.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FieldLine<'a> {
    /// The name.
    pub name: &'a [u8],
    /// The value.
    pub value: &'a [u8],
    /// The line is sent as a literal that is never indexed (RFC 7541, section 6.2.3). The
    /// decoder sets it for each line that the peer sent so. The encoder sends each line with
    /// the mark so, and also each line that the sensitive-field rule selects.
    pub never_indexed: bool,
}

impl fmt::Debug for FieldLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldLine")
            .field("name", &self.name.len())
            .field("value", &self.value.len())
            .field("never_indexed", &self.never_indexed)
            .finish()
    }
}

/// Whether the encoder sends a line as never indexed when the caller did not mark it.
///
/// A credential is always sensitive. A short cookie has little entropy, so a peer that can add
/// lines to the same connection can find it by the size of a block (RFC 7541, section 7.1.3).
/// A long cookie is indexed. An HTTP/2 sender splits a `cookie` into its crumbs (RFC 9113,
/// section 8.2.3), and the rule applies to each crumb. The QPACK encoder uses the same rule.
pub(crate) fn sensitive(name: &[u8], value: &[u8]) -> bool {
    let is = |sensitive: &[u8]| name.eq_ignore_ascii_case(sensitive);
    is(b"authorization") || is(b"proxy-authorization") || ((is(b"cookie") || is(b"set-cookie")) && value.len() < 20)
}

/// The limits of a [`Decoder`], which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest dynamic table: the `SETTINGS_HEADER_TABLE_SIZE` that the endpoint sends. A
    /// size update above it is malformed.
    pub table_bytes: usize,
    /// The largest decoded list of one block, in the size of RFC 7541, section 4.1: the bytes of
    /// each name and value, and 32 for each line. It is the `SETTINGS_MAX_HEADER_LIST_SIZE` that
    /// the endpoint sends.
    pub list_bytes: usize,
    /// The most work of one block: its bytes, and each byte that the decoder copies to the
    /// decoded lines and to the dynamic table.
    pub work: usize,
}

/// A refused header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoded lines are larger than `list_bytes`. The block changed the dynamic table as the
    /// encoder expects, so the connection can continue: refuse the stream.
    TooLarge,
    /// The block breaks RFC 7541. End the connection with `COMPRESSION_ERROR`.
    Malformed,
    /// The block needs more work than `work`. The dynamic table cannot stay in step with the
    /// encoder, so end the connection.
    Overload,
    /// The lines are smaller than the limits of the decoder need. Make them with [`Lines::new`]
    /// and the limits of the decoder. The decoder did not change.
    Misuse,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "the decoded field lines are larger than the list limit",
            Self::Malformed => "the header block breaks RFC 7541",
            Self::Overload => "the header block needs more work than the work limit",
            Self::Misuse => "the lines are smaller than the limits of the decoder need",
        })
    }
}

impl core::error::Error for DecodeError {}

/// A refused encode. It wrote and changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output region has fewer free bytes than the longest block of the lines. Encode into
    /// a region with at least `needed` free bytes.
    Full {
        /// The bytes of the longest block.
        needed: usize,
        /// The free bytes of the output region.
        available: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::Full { needed, available } = self;
        write!(
            f,
            "the block can need {needed} bytes, but the output region has only {available} free bytes"
        )
    }
}

impl core::error::Error for EncodeError {}
