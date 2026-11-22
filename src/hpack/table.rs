//! The static table of RFC 7541, Appendix A, and the dynamic table of one encoder or decoder.

use std::collections::VecDeque;

/// The entries of the static table: index 1 is the first row. The rows are the rows of RFC 7541,
/// Appendix A, which a script took from the text of the RFC.
pub(crate) const STATIC: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// The size that an entry adds to its name and value (RFC 7541, section 4.1).
pub(crate) const OVERHEAD: usize = 32;

/// The bytes of a name or a value in the dynamic table: a first part, and a second part when the
/// bytes wrap at the end of the ring.
#[derive(Clone, Copy)]
pub(crate) struct Bytes<'a>(pub(crate) &'a [u8], pub(crate) &'a [u8]);

impl Bytes<'_> {
    pub(crate) fn len(&self) -> usize {
        self.0.len() + self.1.len()
    }

    /// Whether the bytes are `other`.
    pub(crate) fn is(&self, other: &[u8]) -> bool {
        other.len() == self.len() && other.starts_with(self.0) && other.ends_with(self.1)
    }

    /// Whether the bytes are `other`, with no regard to the case of ASCII letters.
    fn is_folded(&self, other: &[u8]) -> bool {
        other.len() == self.len()
            && other[..self.0.len()].eq_ignore_ascii_case(self.0)
            && other[self.0.len()..].eq_ignore_ascii_case(self.1)
    }
}

/// One entry: where its name starts in the ring, and the lengths of its name and value. The value
/// comes after the name.
struct Entry {
    start: usize,
    name: usize,
    value: usize,
}

/// A dynamic table (RFC 7541, section 2.3.2): its entries, newest first, in a ring of bytes.
///
/// The ring holds `limit` bytes, and the table never holds more, so an insertion never
/// allocates. The memory is allocated when the table is made.
pub(crate) struct Table {
    ring: Vec<u8>,
    /// The position of the first byte of the oldest entry.
    head: usize,
    /// The bytes of the entries in the ring.
    used: usize,
    /// The entries, newest first.
    entries: VecDeque<Entry>,
    /// The size of the table: the sum of the sizes of its entries.
    size: usize,
    /// The maximum size that the encoder set.
    max: usize,
}

impl Table {
    /// The memory of a table whose maximum size can reach `limit`, or `None` if it does not fit
    /// in a `usize`.
    pub(crate) fn memory(limit: usize) -> Option<usize> {
        (limit / OVERHEAD).checked_mul(size_of::<Entry>())?.checked_add(limit)
    }

    /// Makes an empty table whose maximum size is `limit`, with its memory, or `None` if the
    /// memory is not available. Charge [`memory`](Self::memory) first.
    pub(crate) fn new(limit: usize) -> Option<Self> {
        let mut ring = Vec::new();
        ring.try_reserve_exact(limit).ok()?;
        ring.resize(limit, 0);
        let mut entries = VecDeque::new();
        entries.try_reserve_exact(limit / OVERHEAD).ok()?;
        Some(Self {
            ring,
            head: 0,
            used: 0,
            entries,
            size: 0,
            max: limit,
        })
    }

    /// The largest maximum size: the size of the ring.
    pub(crate) fn limit(&self) -> usize {
        self.ring.len()
    }

    /// The maximum size that the encoder set.
    pub(crate) fn max(&self) -> usize {
        self.max
    }

    /// The size of the table: the sum of the sizes of its entries.
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// The number of entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The name and the value of entry `index`, where 0 is the newest.
    pub(crate) fn get(&self, index: usize) -> Option<(Bytes<'_>, Bytes<'_>)> {
        let entry = self.entries.get(index)?;
        let value = (entry.start + entry.name) % self.ring.len();
        Some((self.span(entry.start, entry.name), self.span(value, entry.value)))
    }

    fn span(&self, start: usize, len: usize) -> Bytes<'_> {
        let first = len.min(self.ring.len() - start);
        Bytes(&self.ring[start..start + first], &self.ring[..len - first])
    }

    /// Sets the maximum size, and evicts the oldest entries until the table fits in it. The
    /// caller checks that `max` is at most the limit.
    pub(crate) fn set_max(&mut self, max: usize) {
        self.max = max;
        while self.size > self.max {
            self.evict();
        }
    }

    /// Adds an entry (RFC 7541, section 4.4). It first evicts the oldest entries until the new
    /// entry fits. An entry larger than the maximum size empties the table and is not added.
    pub(crate) fn insert(&mut self, name: &[u8], value: &[u8]) {
        self.insert_with(name, value, false);
    }

    /// Adds an entry as [`insert`](Self::insert) does, with its name in lowercase.
    pub(crate) fn insert_folded(&mut self, name: &[u8], value: &[u8]) {
        self.insert_with(name, value, true);
    }

    fn insert_with(&mut self, name: &[u8], value: &[u8], fold: bool) {
        let size = name.len().saturating_add(value.len()).saturating_add(OVERHEAD);
        while !self.entries.is_empty() && self.size + size > self.max {
            self.evict();
        }
        if size > self.max {
            return;
        }
        // The entries hold at most `max - OVERHEAD` bytes with the new one, so it fits in the
        // ring, and the count stays in the capacity of `entries`.
        let start = (self.head + self.used) % self.ring.len();
        self.write(name, fold);
        self.write(value, false);
        self.entries.push_front(Entry {
            start,
            name: name.len(),
            value: value.len(),
        });
        self.size += size;
    }

    /// Writes `bytes` after the entries, in lowercase when `fold` is true.
    fn write(&mut self, bytes: &[u8], fold: bool) {
        let len = self.ring.len();
        let at = (self.head + self.used) % len;
        let first = bytes.len().min(len - at);
        let (front, back) = bytes.split_at(first);
        self.ring[at..at + first].copy_from_slice(front);
        self.ring[..back.len()].copy_from_slice(back);
        if fold {
            self.ring[at..at + first].make_ascii_lowercase();
            self.ring[..back.len()].make_ascii_lowercase();
        }
        self.used += bytes.len();
    }

    /// Evicts each entry.
    pub(crate) fn clear(&mut self) {
        while !self.entries.is_empty() {
            self.evict();
        }
    }

    fn evict(&mut self) {
        let Some(entry) = self.entries.pop_back() else { return };
        let bytes = entry.name + entry.value;
        self.size -= bytes + OVERHEAD;
        self.used -= bytes;
        self.head = if self.entries.is_empty() {
            0
        } else {
            (self.head + bytes) % self.ring.len()
        };
    }

    /// The smallest index of an entry with `name` and `value`, and of an entry with `name`, in
    /// the static table and then in this table (RFC 7541, section 2.3.3). The names compare with
    /// no regard to case: the encoder sends and inserts each name in lowercase.
    pub(crate) fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let (mut exact, mut named) = (None, None);
        let dynamic =
            (0..self.len()).filter_map(|index| self.get(index).map(|entry| (STATIC.len() + 1 + index, entry)));
        for (index, (entry_name, entry_value)) in STATIC
            .iter()
            .enumerate()
            .map(|(index, &(entry_name, entry_value))| (index + 1, (Bytes(entry_name, &[]), Bytes(entry_value, &[]))))
            .chain(dynamic)
        {
            if entry_name.is_folded(name) {
                named.get_or_insert(index);
                if entry_value.is(value) {
                    exact = Some(index);
                    break;
                }
            }
        }
        (exact, named)
    }
}
