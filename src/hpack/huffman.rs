//! The Huffman code of RFC 7541, Appendix B, for string literals. QPACK uses the same code
//! (RFC 9204, section 4.1.2).
//!
//! The code is canonical: in the order of length and then symbol, each code is the next value.
//! Thus the decoder needs only the limit of the codes of each length, which the compiler
//! calculates from [`CODES`].

/// The code of each symbol, aligned to its least significant bit, and its length in bits: the
/// bytes 0 to 255, and then EOS (256). The rows are the rows of RFC 7541, Appendix B, which a
/// script took from the text of the RFC.
pub(crate) const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The longest code, in bits.
const LONGEST: usize = 30;

/// The decode tables of the canonical code.
struct Canonical {
    /// The symbols in the order of their codes.
    symbols: [u16; 257],
    /// The first code of each length.
    first: [u32; LONGEST + 1],
    /// The position in `symbols` of the first symbol of each length.
    start: [usize; LONGEST + 1],
    /// The end of the codes of each length, aligned to bit 31: a window of 32 bits that is less
    /// than it starts with a code of this length or a shorter one.
    end: [u64; LONGEST + 1],
    /// The shortest length.
    shortest: usize,
}

const TABLES: Canonical = canonical();

#[expect(
    clippy::cast_possible_truncation,
    reason = "a symbol is at most 256, so it fits in a u16"
)]
const fn canonical() -> Canonical {
    let mut count = [0_u32; LONGEST + 1];
    let mut symbol = 0;
    while symbol < CODES.len() {
        count[CODES[symbol].1 as usize] += 1;
        symbol += 1;
    }
    let mut tables = Canonical {
        symbols: [0; 257],
        first: [0; LONGEST + 1],
        start: [0; LONGEST + 1],
        end: [0; LONGEST + 1],
        shortest: 0,
    };
    let (mut code, mut position, mut len) = (0_u32, 0, 1);
    while len <= LONGEST {
        if tables.shortest == 0 && count[len] > 0 {
            tables.shortest = len;
        }
        tables.first[len] = code;
        tables.start[len] = position;
        tables.end[len] = ((code + count[len]) as u64) << (32 - len);
        position += count[len] as usize;
        code = (code + count[len]) << 1;
        len += 1;
    }
    let mut next = tables.start;
    symbol = 0;
    while symbol < CODES.len() {
        let len = CODES[symbol].1 as usize;
        tables.symbols[next[len]] = symbol as u16;
        next[len] += 1;
        symbol += 1;
    }
    tables
}

/// A Huffman string that RFC 7541, section 5.2, forbids: it holds EOS, or its padding is longer
/// than 7 bits or has a zero bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Invalid;

/// Decodes the Huffman string `code` to its end, and gives the number of decoded bytes.
///
/// It appends the decoded bytes to `out` only while `out` holds fewer than `limit` bytes, so the
/// caller can check a string longer than its space and keep the bytes in a fixed capacity.
pub(crate) fn decode(code: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize, Invalid> {
    let mut partial = Partial::default();
    let decoded = partial.decode(code, out, limit)?;
    partial.finish()?;
    Ok(decoded)
}

/// A Huffman string that arrives in pieces: the bits of the last piece after its last complete
/// code. QPACK reads the strings of the encoder stream in the pieces that the transport gives.
#[derive(Clone, Copy, Default)]
pub(crate) struct Partial {
    /// The low `bits` bits are the bits to decode, in order from the most significant.
    acc: u64,
    bits: u32,
}

impl Partial {
    /// Decodes each code that `code` completes after the bits of the earlier pieces, and gives
    /// the number of decoded bytes. It keeps the bits after the last complete code for the next
    /// piece.
    ///
    /// It appends the decoded bytes to `out` only while `out` holds fewer than `limit` bytes.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the window is the 32 bits after the read bits, and a code is at most 30 bits"
    )]
    pub(crate) fn decode(&mut self, code: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize, Invalid> {
        let (mut acc, mut bits, mut decoded) = (self.acc, self.bits, 0_usize);
        let mut input = code.iter();
        loop {
            while bits <= 56 {
                let Some(&byte) = input.next() else { break };
                acc = (acc << 8) | u64::from(byte);
                bits += 8;
            }
            // The next 32 bits, with zero bits after the end of the piece. A code that the bits
            // complete has the same first bits, so the zero bits do not change its length.
            let window = if bits >= 32 {
                (acc >> (bits - 32)) as u32
            } else {
                (acc << (32 - bits)) as u32
            };
            let mut len = TABLES.shortest;
            while u64::from(window) >= TABLES.end[len] {
                len += 1;
            }
            // The refill stops before 57 bits only at the end of the piece, so a longer code than
            // the rest continues in the next piece, or the rest is the padding.
            if len as u32 > bits {
                (self.acc, self.bits) = (acc, bits);
                return Ok(decoded);
            }
            let index = TABLES.start[len] + ((window >> (32 - len)) - TABLES.first[len]) as usize;
            // Each symbol is a byte, except EOS.
            let byte = u8::try_from(TABLES.symbols[index]).map_err(|_| Invalid)?;
            bits -= len as u32;
            if out.len() < limit {
                out.push(byte);
            }
            decoded += 1;
        }
    }

    /// Checks the end of the string: the bits after the last code are the padding, at most 7
    /// bits, all of them one (RFC 7541, section 5.2).
    pub(crate) fn finish(self) -> Result<(), Invalid> {
        let ones = (1_u64 << self.bits) - 1;
        if self.bits < 8 && self.acc & ones == ones {
            Ok(())
        } else {
            Err(Invalid)
        }
    }
}

/// The length in bytes of the Huffman string of `bytes`, with its padding.
pub(crate) fn encoded_len(bytes: &[u8]) -> usize {
    let bits: u64 = bytes.iter().map(|&byte| u64::from(CODES[usize::from(byte)].1)).sum();
    usize::try_from(bits.div_ceil(8)).unwrap_or(usize::MAX)
}

/// Encodes `bytes` as a Huffman string, padded with one bits to a byte (RFC 7541, section 5.2).
/// It gives the string to `put` in pieces.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each byte is the next 8 bits of the code"
)]
pub(crate) fn encode(bytes: &[u8], mut put: impl FnMut(&[u8])) {
    let mut piece = [0_u8; 64];
    let mut used = 0;
    // The low `bits` bits of `acc` wait to be written, in order from the most significant.
    let (mut acc, mut bits) = (0_u64, 0_u32);
    for &byte in bytes {
        let (code, len) = CODES[usize::from(byte)];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            piece[used] = (acc >> bits) as u8;
            used += 1;
            if used == piece.len() {
                put(&piece);
                used = 0;
            }
        }
    }
    if bits > 0 {
        piece[used] = ((acc << (8 - bits)) | ((1 << (8 - bits)) - 1)) as u8;
        used += 1;
    }
    put(&piece[..used]);
}

#[cfg(test)]
mod tests;
