//! The stream data that arrived out of order (RFC 9000, section 2.2): the store of one
//! connection, and the place of each stream in it.
//!
//! Data in order never comes here: it goes up as a view of its received region. Data after a gap
//! is copied one time into pages of [`PAGE`] bytes, so the engine keeps no received region while a
//! peer holds back the bytes before it. Each page covers a fixed range of its stream, and has a
//! map of its filled bytes. Thus a gap costs no state, an insert takes the same time for each
//! arrival order, and no count of gaps or pieces limits a path that loses packets.
//!
//! The pages come from pools that the budget pays for before they allocate. A page that fills
//! goes up as views of its slot, with no second copy, and the slot returns to its pool after the
//! last view drops. The store holds no memory while no stream has data out of order.

use core::alloc::Layout;
use core::num::NonZeroU32;
use core::ops::Range;
use std::collections::VecDeque;

use rstypes::buffer::{Backing, BufferMut as _, Lease, Pool, WriteLoan};
use rstypes::capacity::{Budget, Credit};

/// The bytes of one page. A page holds the data of about three full packets, so a stream with one
/// small piece out of order keeps little memory, and a filled page goes up in one event.
const PAGE: usize = 4096;
/// [`PAGE`] as a stream offset.
const PAGE_OFFSET: u64 = PAGE as u64;
/// The words of the map of one page: one bit for each byte.
const WORDS: usize = PAGE / 64;
/// The slots of the first pool of a store: 16 KiB. Each later pool doubles the slots of the store.
const POOL_PAGES_MIN: u32 = 4;
/// No page, and the end of the list of free entries.
const NONE: u32 = u32::MAX;
/// The zeros that make each byte of a new page readable.
static ZEROS: [u8; PAGE] = [0; PAGE];

/// Why the store did not take data. The packet of the data is then not received: it gets no
/// acknowledgement, and the peer sends its frames again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refused {
    /// The pages of the store reached the bound of the caller.
    Bound,
    /// The budget refused the memory.
    Budget,
}

/// Makes room for at least one more item in a vector or a queue that is full, of `len` items and
/// `capacity` places of `item` bytes each: it charges the new places to `credit`, and then
/// `reserve` allocates that many more. Gives the bytes that it charged.
pub(super) fn grow(
    (len, capacity, item): (usize, usize, usize),
    credit: &mut Credit,
    reserve: impl FnOnce(usize) -> bool,
) -> Result<u64, Refused> {
    if len < capacity {
        return Ok(0);
    }
    let more = capacity.max(4);
    let bytes = (more * item) as u64;
    credit.charge(bytes).map_err(|_| Refused::Budget)?;
    if !reserve(more) {
        let refunded = credit.refund(bytes);
        assert!(refunded.is_ok(), "a credit refunds what it charged");
        return Err(Refused::Budget);
    }
    Ok(bytes)
}

/// The offset of `offset` inside its page.
const fn within(offset: u64) -> usize {
    (offset % PAGE_OFFSET) as usize
}

/// One page: the writable rest of its slot, and the map of its filled bytes.
#[derive(Debug)]
struct Page {
    /// The bytes of the page from `at`, or `None` in a free entry.
    backing: Option<Backing>,
    /// The offset in the page of the first byte of `backing`. The bytes before it went up, or
    /// arrived in order and never came here.
    at: usize,
    /// One bit for each byte of the page that holds data.
    fill: [u64; WORDS],
    /// The next free entry.
    next: u32,
}

impl Page {
    /// Marks the bytes of `range` as filled.
    fn mark(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let (first, last) = (range.start / 64, (range.end - 1) / 64);
        for (word, bits) in self.fill.iter_mut().enumerate().take(last + 1).skip(first) {
            let low = if word == first { range.start % 64 } else { 0 };
            let high = if word == last { (range.end - 1) % 64 } else { 63 };
            *bits |= (u64::MAX >> (63 - high)) & (u64::MAX << low);
        }
    }

    /// The end of the filled bytes that start at `from`: `from` when its byte is not filled.
    fn run_end(&self, from: usize) -> usize {
        let mut word = from / 64;
        if word >= WORDS {
            return PAGE;
        }
        let mut gaps = !self.fill[word] & (u64::MAX << (from % 64));
        loop {
            if gaps != 0 {
                return word * 64 + gaps.trailing_zeros() as usize;
            }
            word += 1;
            if word == WORDS {
                return PAGE;
            }
            gaps = !self.fill[word];
        }
    }
}

/// The pages of one stream, in the order of their offsets: the number of each page in the
/// stream, and the index of its entry in the store. A gap between two pages has no entry, so its
/// size costs no memory and no work.
#[derive(Debug, Default)]
pub(super) struct Reorder {
    pages: VecDeque<(u64, u32)>,
    /// The bytes of `pages` that the store charged.
    charged: u64,
}

/// The store of the data that arrived out of order on each stream of one connection.
#[derive(Debug)]
pub(super) struct Reassembly {
    /// The pools of the page slots, each with as many slots as the pools before it together.
    pools: Vec<Pool>,
    pages: Vec<Page>,
    /// The first free entry of `pages`.
    free: u32,
    /// The pages that hold data.
    used: u32,
    /// The slots of the pools.
    slots: u32,
    /// The most pages that hold data at one time.
    bound: u32,
    budget: Budget,
    /// The charge of `pools`, of `pages`, and of the page list of each stream.
    credit: Credit,
}

impl Reassembly {
    /// A store that holds at most `bytes_max` bytes in pages.
    pub(super) fn new(bytes_max: u64, budget: &Budget) -> Self {
        Self {
            pools: Vec::new(),
            pages: Vec::new(),
            free: NONE,
            used: 0,
            slots: 0,
            bound: u32::try_from(bytes_max / PAGE_OFFSET).unwrap_or(NONE - 1).min(NONE - 1),
            budget: budget.clone(),
            credit: budget.credit(0),
        }
    }

    /// Copies `data`, the bytes of a stream at `offset`, into the pages of `reorder`. Each byte is
    /// after the last byte that went up. A refusal keeps the bytes that it copied before: they are
    /// valid data of the stream, and the peer sends the frame again.
    pub(super) fn insert(&mut self, reorder: &mut Reorder, mut offset: u64, mut data: &[u8]) -> Result<(), Refused> {
        while !data.is_empty() {
            let start = within(offset);
            let len = data.len().min(PAGE - start);
            let entry = self.entry(reorder, offset / PAGE_OFFSET)?;
            let page = &mut self.pages[entry];
            // The bytes before `at` went up before, so a frame that repeats them changes nothing.
            let skip = page.at.saturating_sub(start).min(len);
            if let Some(backing) = &mut page.backing {
                let from = start + skip - page.at;
                backing.bytes_mut()[from..from + len - skip].copy_from_slice(&data[skip..len]);
            }
            page.mark(start + skip..start + len);
            offset += len as u64;
            data = &data[len..];
        }
        Ok(())
    }

    /// The index of the page `number` of `reorder`, which it makes when the stream has none.
    fn entry(&mut self, reorder: &mut Reorder, number: u64) -> Result<usize, Refused> {
        let pages = &mut reorder.pages;
        let at = match pages.binary_search_by_key(&number, |&(page, _)| page) {
            Ok(at) => return Ok(pages[at].1 as usize),
            Err(at) => at,
        };
        reorder.charged += grow(
            (pages.len(), pages.capacity(), size_of::<(u64, u32)>()),
            &mut self.credit,
            |more| pages.try_reserve_exact(more).is_ok(),
        )?;
        let index = self.page()?;
        reorder.pages.insert(at, (number, index));
        Ok(index as usize)
    }

    /// Makes a page of zeros, and gives the index of its entry.
    fn page(&mut self) -> Result<u32, Refused> {
        if self.used >= self.bound {
            return Err(Refused::Bound);
        }
        let backing = self.slot()?;
        let mut loan = WriteLoan::new(backing);
        let filled = loan.fill_from(&ZEROS);
        assert_eq!(filled, PAGE, "a slot has the bytes of one page");
        let page = Page {
            backing: Some(loan.into_inner()),
            at: 0,
            fill: [0; WORDS],
            next: NONE,
        };
        let index = if let Some(free) = self.pages.get_mut(self.free as usize) {
            let index = self.free;
            self.free = free.next;
            *free = page;
            index
        } else {
            let pages = &mut self.pages;
            grow(
                (pages.len(), pages.capacity(), size_of::<Page>()),
                &mut self.credit,
                |more| pages.try_reserve_exact(more).is_ok(),
            )?;
            self.pages.push(page);
            u32::try_from(self.pages.len() - 1).map_err(|_| Refused::Bound)?
        };
        self.used += 1;
        Ok(index)
    }

    /// Takes a free slot of the pools. When each slot is in use, it adds a pool with as many
    /// slots as the store has, so the pools hold at most two times the pages in use.
    fn slot(&mut self) -> Result<Backing, Refused> {
        for pool in self.pools.iter_mut().rev() {
            if let Ok(backing) = pool.acquire() {
                return Ok(backing);
            }
        }
        let pools = &mut self.pools;
        grow(
            (pools.len(), pools.capacity(), size_of::<Pool>()),
            &mut self.credit,
            |more| pools.try_reserve_exact(more).is_ok(),
        )?;
        let layout = Layout::new::<[u8; PAGE]>();
        // A budget with little room gives a smaller pool.
        let mut slots = self.slots.clamp(POOL_PAGES_MIN, self.bound.max(POOL_PAGES_MIN));
        let mut pool = loop {
            match NonZeroU32::new(slots).map(|slots| Pool::new(&self.budget, slots, layout)) {
                Some(Ok(pool)) => break pool,
                Some(Err(_)) if slots > 1 => slots /= 2,
                _ => return Err(Refused::Budget),
            }
        };
        let backing = pool.acquire().map_err(|_| Refused::Budget)?;
        self.pools.push(pool);
        self.slots = self.slots.saturating_add(slots);
        Ok(backing)
    }

    /// Frees the page of entry `index`. Its slot returns to its pool after the last view of it
    /// drops. The pools go when no page holds data.
    fn release(&mut self, index: u32) {
        if let Some(page) = self.pages.get_mut(index as usize) {
            page.backing = None;
            page.next = self.free;
            self.free = index;
            self.used -= 1;
        }
        if self.used == 0 {
            self.pools.clear();
            self.slots = 0;
        }
    }

    /// Drops the bytes of `reorder` before `next`, which arrived in order after their copy came
    /// here, and gives the entry of the page of `next` when the stream has it.
    fn front(&mut self, reorder: &mut Reorder, next: u64) -> Option<u32> {
        let number = next / PAGE_OFFSET;
        while let Some(&(page, index)) = reorder.pages.front()
            && page < number
        {
            reorder.pages.pop_front();
            self.release(index);
        }
        let (_, index) = reorder.pages.front().copied().filter(|&(page, _)| page == number)?;
        let page = self.pages.get_mut(index as usize)?;
        let start = within(next);
        if start > page.at
            && let Some(backing) = page.backing.take()
        {
            // The freeze of the passed bytes drops with its lease, and the rest stays writable.
            page.backing = Some(match backing.freeze_prefix(start - page.at) {
                Ok((_, rest)) => rest,
                Err(backing) => backing,
            });
            page.at = start;
        }
        Some(index)
    }

    /// Whether `reorder` holds the byte at `next`, the next byte of its stream in order.
    pub(super) fn ready(&mut self, reorder: &mut Reorder, next: u64) -> bool {
        self.front(reorder, next)
            .and_then(|index| self.pages.get(index as usize))
            .is_some_and(|page| page.run_end(within(next)) > within(next))
    }

    /// Takes the bytes of `reorder` from `next`, the next byte of its stream in order, up to the
    /// first gap or the end of their page: a view of the slot of the page, with no copy.
    pub(super) fn take(&mut self, reorder: &mut Reorder, next: u64) -> Option<Lease> {
        let index = self.front(reorder, next)?;
        let page = self.pages.get_mut(index as usize)?;
        let start = within(next);
        let end = page.run_end(start);
        if end == start {
            return None;
        }
        let (lease, rest) = page.backing.take()?.freeze_prefix(end - start).ok()?;
        if end == PAGE {
            reorder.pages.pop_front();
            self.release(index);
        } else {
            page.backing = Some(rest);
            page.at = end;
        }
        Some(lease)
    }

    /// Frees each page of `reorder`, and its list.
    pub(super) fn clear(&mut self, reorder: &mut Reorder) {
        for (_, index) in core::mem::take(&mut reorder.pages) {
            self.release(index);
        }
        let refunded = self.credit.refund(core::mem::take(&mut reorder.charged));
        assert!(refunded.is_ok(), "a credit refunds what it charged");
    }
}
