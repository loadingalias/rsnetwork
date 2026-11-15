//! The integers of RFC 7541, section 5.1: a value in the low bits of a first byte, the prefix,
//! and continuation bytes of 7 bits each. QPACK uses the same integers (RFC 9204, section 4.1.1).

/// Decodes the integer at the start of `bytes`, whose first byte has a prefix of `prefix` bits (1
/// to 8). Gives the value and the number of its bytes.
///
/// Gives `None` when the bytes end before the integer, or when the value does not fit in a
/// `u64`. Thus an integer has at most 10 continuation bytes, also when they add only zeros.
pub(crate) fn decode(bytes: &[u8], prefix: u32) -> Option<(u64, usize)> {
    let max = (1_u64 << prefix) - 1;
    let value = u64::from(*bytes.first()?) & max;
    if value < max {
        return Some((value, 1));
    }
    let mut value = value;
    for (position, &byte) in bytes.iter().enumerate().skip(1) {
        let shift = 7 * u32::try_from(position - 1).ok()?;
        let bits = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .filter(|bits| bits >> shift == u64::from(byte & 0x7f))?;
        value = value.checked_add(bits)?;
        if byte & 0x80 == 0 {
            return Some((value, position + 1));
        }
    }
    None
}

/// The number of bytes of `value` as an integer with a prefix of `prefix` bits.
pub(crate) fn len(value: u64, prefix: u32) -> usize {
    let max = (1_u64 << prefix) - 1;
    let mut len = 1;
    if value >= max {
        let mut rest = value - max;
        len += 1;
        while rest >= 0x80 {
            rest >>= 7;
            len += 1;
        }
    }
    len
}

/// Encodes `value` as an integer with a prefix of `prefix` bits, after the `flags` bits of the
/// first byte above the prefix, and gives its bytes to `put`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each byte holds a value that is less than its prefix or less than 0x80"
)]
pub(crate) fn encode(value: u64, prefix: u32, flags: u8, mut put: impl FnMut(&[u8])) {
    let max = (1_u64 << prefix) - 1;
    let mut bytes = [0_u8; 11];
    if value < max {
        bytes[0] = flags | value as u8;
        put(&bytes[..1]);
        return;
    }
    bytes[0] = flags | max as u8;
    let mut rest = value - max;
    let mut used = 1;
    while rest >= 0x80 {
        bytes[used] = (rest & 0x7f) as u8 | 0x80;
        rest >>= 7;
        used += 1;
    }
    bytes[used] = rest as u8;
    put(&bytes[..=used]);
}
