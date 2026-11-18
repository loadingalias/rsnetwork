//! The static table of RFC 9204, Appendix A, and the dynamic table of one encoder or decoder,
//! with the absolute indices of RFC 9204, section 3.2.4.

use crate::hpack::table::{Bytes, Table};

/// The entries of the static table: index 0 is the first row. The rows are the rows of RFC 9204,
/// Appendix A, which a script took from the XML source of the RFC. The text form of the RFC
/// breaks long values at a space and drops the space, so the script read the XML source.
pub(crate) const STATIC: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"strict-transport-security", b"max-age=31536000; includesubdomains"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

/// The index of the entry of the static table with `name` and `value`, and the smallest index of
/// an entry with `name`.
pub(crate) fn find_static(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
    let mut named = None;
    for (index, &(entry_name, entry_value)) in STATIC.iter().enumerate() {
        if entry_name == name {
            named.get_or_insert(index);
            if entry_value == value {
                return (Some(index), named);
            }
        }
    }
    (None, named)
}

/// A dynamic table of QPACK: the ring of HPACK, and the absolute index of each entry.
pub(crate) struct Dynamic {
    pub(crate) ring: Table,
    /// The Insert Count: the number of insertions since the table was made (RFC 9204, section
    /// 3.2.4). The newest entry has the absolute index `inserted - 1`.
    pub(crate) inserted: u64,
}

impl Dynamic {
    /// Makes an empty table whose capacity can reach `limit`, with its memory, or `None` if the
    /// memory is not available. Charge [`Table::memory`] first. The capacity starts at zero
    /// (RFC 9204, section 3.2.2).
    pub(crate) fn new(limit: usize) -> Option<Self> {
        let mut ring = Table::new(limit)?;
        ring.set_max(0);
        Some(Self { ring, inserted: 0 })
    }

    /// The name and the value of the entry with absolute index `index`, if the table holds it.
    pub(crate) fn get(&self, index: u64) -> Option<(Bytes<'_>, Bytes<'_>)> {
        let position = self.inserted.checked_sub(index)?.checked_sub(1)?;
        self.ring.get(usize::try_from(position).ok()?)
    }

    /// Adds an entry after it evicts the oldest entries until the entry fits. The caller checks
    /// that the entry is at most the capacity.
    pub(crate) fn insert(&mut self, name: &[u8], value: &[u8]) {
        self.ring.insert(name, value);
        self.inserted += 1;
    }

    /// The absolute index of the entry with `name` and `value`, and of the newest entry with
    /// `name` whose absolute index is less than `below`.
    pub(crate) fn find(&self, name: &[u8], value: &[u8], below: u64) -> (Option<u64>, Option<u64>) {
        let (mut exact, mut named) = (None, None);
        for position in 0..self.ring.len() {
            let Some((entry_name, entry_value)) = self.ring.get(position) else {
                break;
            };
            if !entry_name.is(name) {
                continue;
            }
            let index = self.inserted - 1 - position as u64;
            if exact.is_none() && entry_value.is(value) {
                exact = Some(index);
            }
            if named.is_none() && index < below {
                named = Some(index);
            }
            if exact.is_some() && named.is_some() {
                break;
            }
        }
        (exact, named)
    }
}
