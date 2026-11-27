//! The variable-length integers shared by HTTP/3 and QUIC (RFC 9000, section 16).

pub(crate) const MAX: u64 = (1 << 62) - 1;

pub(crate) const fn len(value: u64) -> Option<usize> {
    match value {
        0..=0x3f => Some(1),
        0x40..=0x3fff => Some(2),
        0x4000..=0x3fff_ffff => Some(4),
        0x4000_0000..=MAX => Some(8),
        _ => None,
    }
}

pub(crate) const fn width(first: u8) -> usize {
    1 << (first >> 6)
}

pub(crate) fn read(bytes: &[u8]) -> Option<(u64, usize)> {
    let &first = bytes.first()?;
    let width = width(first);
    let value = bytes
        .get(1..width)?
        .iter()
        .fold(u64::from(first & 0x3f), |v, &b| (v << 8) | u64::from(b));
    Some((value, width))
}

/// Writes only when the value fits the requested width and the output has room.
pub(crate) fn write(out: &mut [u8], value: u64, width: usize) -> Option<()> {
    if len(value)? > width {
        return None;
    }
    let prefix = match width {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return None,
    };
    let bytes = out.get_mut(..width)?;
    bytes.copy_from_slice(&value.to_be_bytes()[8 - width..]);
    bytes[0] |= prefix << 6;
    Some(())
}
