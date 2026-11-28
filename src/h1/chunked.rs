//! The decoder of the chunked transfer coding (RFC 9112, section 7.1).

use core::ops::Range;

use super::head::{BodyLimits, Limits, ParseError, Search, scan};
use crate::value::is_tchar;

/// Decodes a chunked body in the bytes that arrive, in any pieces, with no copy.
///
/// The decoder keeps its place between calls, so a size line, an extension, or a line end can
/// split at each byte. Chunk data stays in the input: the decoder gives its position. Only the
/// trailer section must be in one piece of input, as a head must.
#[derive(Clone, Debug)]
pub struct ChunkDecoder {
    state: State,
    limits: BodyLimits,
    /// The limits of the trailer field lines.
    fields: Limits,
    /// The sum of the chunk sizes so far.
    total: u64,
    /// The search for the end of the trailer section.
    search: Search,
}

/// What a call of [`ChunkDecoder::decode`] found at the start of its input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkStep {
    /// The first `framing` bytes are framing, and the `data` bytes after them are chunk data.
    /// Consume both. When they are all of the input, give the bytes that arrive after it.
    Data {
        /// The framing bytes at the start of the input.
        framing: usize,
        /// The chunk data after them.
        data: usize,
    },
    /// The first `len` bytes end the body: the framing, the trailer section, and its empty line.
    End {
        /// The bytes that end the body.
        len: usize,
        /// The position of the trailer field lines, each with its CR LF, in those bytes.
        trailers: Range<usize>,
    },
    /// The trailer section continues after the input. Give the same bytes again, with the bytes
    /// that arrive after them, in one piece.
    More,
}

/// The place of the decoder in the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// In the size digits: the size so far, and its number of digits.
    Size {
        size: u64,
        digits: u8,
    },
    /// After the size digits, in the extensions: the size, the extension bytes so far, and the
    /// place in their grammar.
    Extension {
        size: u64,
        len: usize,
        at: Ext,
    },
    /// After the CR of a size line.
    SizeEnd {
        size: u64,
    },
    /// In the data of a chunk, with this many bytes left.
    Data {
        left: u64,
    },
    /// After the data of a chunk: its CR, then its LF.
    DataCr,
    DataLf,
    /// After the last chunk line, in the trailer section.
    Trailers,
    /// After the end of the body.
    Done,
}

/// The place in the grammar of the chunk extensions (RFC 9112, section 7.1.1):
/// `*( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ext {
    /// After the size or a complete extension: whitespace, `;`, or the CR.
    Lead,
    /// After whitespace there: more whitespace or `;`.
    LeadSpace,
    /// After `;`: whitespace or the first byte of a name.
    Semicolon,
    /// In a name.
    Name,
    /// After whitespace after a name: more whitespace, `=`, or `;`.
    NameSpace,
    /// After `=`: whitespace, a token, or a quoted string.
    Equals,
    /// In a token value.
    Token,
    /// In a quoted string.
    Quoted,
    /// After a backslash in a quoted string.
    Escape,
}

impl ChunkDecoder {
    /// Makes a decoder for a body within `limits`. Its trailer field lines have the field limits
    /// of `fields`.
    pub const fn new(limits: BodyLimits, fields: Limits) -> Self {
        Self {
            state: State::Size { size: 0, digits: 0 },
            limits,
            fields,
            total: 0,
            search: Search::new(),
        }
    }

    /// Reads the start of the body bytes that remain, and gives what it found there.
    ///
    /// Refuses a size or an extension that RFC 9112 does not permit, a line end that is not CR
    /// LF, data that is not followed by CR LF, a `Content-Length` or `Transfer-Encoding` trailer
    /// field, and each limit of [`BodyLimits`].
    pub fn decode(&mut self, input: &[u8]) -> Result<ChunkStep, ParseError> {
        let mut at = 0;
        while let Some(&byte) = input.get(at) {
            match self.state {
                State::Data { left } => {
                    let available = input.len() - at;
                    let data = usize::try_from(left).map_or(available, |left| left.min(available));
                    self.state = match left - data as u64 {
                        0 => State::DataCr,
                        left => State::Data { left },
                    };
                    return Ok(ChunkStep::Data { framing: at, data });
                }
                State::Trailers if at > 0 => break,
                State::Trailers => return self.trailers(input),
                State::Done => break,
                _ => self.framing(byte)?,
            }
            at += 1;
        }
        Ok(ChunkStep::Data { framing: at, data: 0 })
    }

    /// Reads one byte of framing.
    fn framing(&mut self, byte: u8) -> Result<(), ParseError> {
        self.state = match self.state {
            State::Size { size, digits } => match char::from(byte).to_digit(16) {
                // Sixteen hexadecimal digits hold each `u64`.
                Some(digit) if digits < 16 => State::Size {
                    size: (size << 4) | u64::from(digit),
                    digits: digits + 1,
                },
                Some(_) => return Err(ParseError::Framing),
                None if digits == 0 => return Err(ParseError::Framing),
                None => {
                    self.total = self
                        .total
                        .checked_add(size)
                        .filter(|&total| total <= self.limits.body_bytes)
                        .ok_or(ParseError::BodyTooLarge)?;
                    return self.extension(size, 0, Ext::Lead, byte);
                }
            },
            State::Extension { size, len, at } => return self.extension(size, len, at, byte),
            State::SizeEnd { size } if byte == b'\n' => match size {
                0 => State::Trailers,
                size => State::Data { left: size },
            },
            State::DataCr if byte == b'\r' => State::DataLf,
            State::DataLf if byte == b'\n' => State::Size { size: 0, digits: 0 },
            _ => return Err(ParseError::Framing),
        };
        Ok(())
    }

    /// Reads one byte after the size digits, at `at` in the grammar of the extensions, after
    /// `len` extension bytes.
    fn extension(&mut self, size: u64, len: usize, at: Ext, byte: u8) -> Result<(), ParseError> {
        let space = matches!(byte, b' ' | b'\t');
        let token = is_tchar(byte);
        let next = match at {
            Ext::Lead | Ext::Name | Ext::Token if byte == b'\r' => {
                self.state = State::SizeEnd { size };
                return Ok(());
            }
            Ext::Lead | Ext::LeadSpace | Ext::Name | Ext::NameSpace | Ext::Token if byte == b';' => Ext::Semicolon,
            Ext::Lead | Ext::LeadSpace | Ext::Token if space => Ext::LeadSpace,
            Ext::Semicolon | Ext::Equals if space => at,
            Ext::Semicolon | Ext::Name if token => Ext::Name,
            Ext::Name | Ext::NameSpace if space => Ext::NameSpace,
            Ext::Name | Ext::NameSpace if byte == b'=' => Ext::Equals,
            Ext::Equals | Ext::Token if token => Ext::Token,
            Ext::Equals if byte == b'"' => Ext::Quoted,
            Ext::Quoted if byte == b'"' => Ext::Lead,
            Ext::Quoted if byte == b'\\' => Ext::Escape,
            // qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
            Ext::Quoted if byte == b'\t' || (byte >= b' ' && byte != 0x7f) => Ext::Quoted,
            // quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
            Ext::Escape if byte == b'\t' || (byte >= b' ' && byte != 0x7f) => Ext::Quoted,
            _ => return Err(ParseError::Framing),
        };
        let len = len + 1;
        if len > self.limits.extension_bytes {
            return Err(ParseError::ExtensionTooLarge);
        }
        self.state = State::Extension { size, len, at: next };
        Ok(())
    }

    /// Reads the trailer section at the start of `input`, which the last chunk line ended.
    fn trailers(&mut self, input: &[u8]) -> Result<ChunkStep, ParseError> {
        let end = match input {
            [b'\r', b'\n', ..] => 2,
            [b'\r'] => return Ok(ChunkStep::More),
            [b'\r', ..] => return Err(ParseError::Framing),
            _ => match self.search.head(input, self.limits.trailer_bytes)? {
                Some(section) => {
                    let limits = Limits {
                        head_bytes: self.limits.trailer_bytes,
                        fields: self.limits.trailer_fields,
                        ..self.fields
                    };
                    let (facts, _) = scan(section, &limits)?;
                    // A sender must not send a framing field as a trailer field (RFC 9110,
                    // section 6.5.1). A peer that merges the trailers could frame by it.
                    if facts.length.is_some() || facts.coding.is_some() {
                        return Err(ParseError::Framing);
                    }
                    section.len()
                }
                None => return Ok(ChunkStep::More),
            },
        };
        self.state = State::Done;
        Ok(ChunkStep::End {
            len: end,
            trailers: 0..end - 2,
        })
    }
}

#[cfg(test)]
mod tests;
