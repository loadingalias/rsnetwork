//! The counting allocator of the allocation tests. Each test binary that includes this module
//! counts the allocations of each thread. A binary has one global allocator, so each binary that
//! counts includes this module, and no other.
//!
//! A test can also name the owner of the allocations of a thread in [`OWNER`]. A header before
//! each allocation keeps its owner, so a free on behalf of another owner still subtracts from the
//! right one. [`LIVE`] holds the live heap of each owner, and the allocator calls [`CHECK`] after
//! each allocation or growth of an owned block. A reallocation changes the size of its block in
//! place, as the charge of a capacity counts it.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

/// The owners that a test can name, 1 to `OWNERS`. Owner 0 is no owner.
pub(crate) const OWNERS: usize = 2;

/// The check after each allocation or growth of an owned block: its owner and the live heap of
/// that owner.
pub(crate) type Check = fn(usize, u64);

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    /// The owner of each allocation that this thread makes, or 0.
    pub(crate) static OWNER: Cell<usize> = const { Cell::new(0) };
    /// The bytes of the live blocks of each owner, by the size of each layout.
    pub(crate) static LIVE: Cell<[u64; OWNERS + 1]> = const { Cell::new([0; OWNERS + 1]) };
    pub(crate) static CHECK: Cell<Option<Check>> = const { Cell::new(None) };
}

/// Counts the allocations of each thread, and keeps the live heap of each owner.
struct Counting;

/// The header before a block: its owner. Its size is a multiple of the alignment of the block,
/// so the block stays aligned.
fn header(layout: Layout) -> usize {
    layout.align().max(16)
}

/// Adds `grown` bytes to the live heap of `owner`, takes away `shrunk`, and runs the check when
/// the heap grew.
fn account(owner: usize, grown: usize, shrunk: usize) {
    let mut live = LIVE.get();
    let Some(heap) = live.get_mut(owner) else { return };
    *heap = heap.wrapping_add(grown as u64).wrapping_sub(shrunk as u64);
    let heap = *heap;
    LIVE.set(live);
    if owner != 0
        && grown > shrunk
        && let Some(check) = CHECK.get()
    {
        check(owner, heap);
    }
}

#[expect(
    unsafe_code,
    reason = "the test allocator counts each allocation, puts its owner in a header, and forwards it to the system allocator"
)]
// SAFETY: each method gives the system allocator a block that starts `header` bytes before the
// block of the caller, with the alignment of the header, so the block of the caller keeps its own
// alignment and size. `dealloc` and `realloc` compute the same header from the same layout.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        let header = header(layout);
        let Some(outer) = layout
            .size()
            .checked_add(header)
            .and_then(|size| Layout::from_size_align(size, header).ok())
        else {
            return core::ptr::null_mut();
        };
        // SAFETY: `outer` has a size of at least `header`, which is not zero.
        let base = unsafe { System.alloc(outer) };
        if base.is_null() {
            return base;
        }
        // An owner that does not fit in the header is no owner.
        let owner = u8::try_from(OWNER.get()).unwrap_or(0);
        // SAFETY: the block has at least `header` bytes, so its first byte is writable.
        unsafe { base.write(owner) };
        account(usize::from(owner), layout.size(), 0);
        // SAFETY: the block has `header` bytes before the block of the caller.
        unsafe { base.add(header) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let header = header(layout);
        // SAFETY: `alloc` or `realloc` gave `ptr` at `header` bytes after the base of its block.
        let base = unsafe { ptr.sub(header) };
        // SAFETY: the first byte of the block holds its owner.
        let owner = usize::from(unsafe { base.read() });
        account(owner, 0, layout.size());
        // SAFETY: the system allocator gave `base` with this layout.
        unsafe { System.dealloc(base, Layout::from_size_align_unchecked(layout.size() + header, header)) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        let header = header(layout);
        let Some(outer_size) = new_size.checked_add(header) else {
            return core::ptr::null_mut();
        };
        // SAFETY: as in `dealloc`.
        let base = unsafe { ptr.sub(header) };
        // SAFETY: the system allocator gave `base` with this layout. The block keeps its
        // alignment, and its header moves with its bytes.
        let base = unsafe {
            System.realloc(
                base,
                Layout::from_size_align_unchecked(layout.size() + header, header),
                outer_size,
            )
        };
        if base.is_null() {
            return base;
        }
        // SAFETY: the header moved with the block, so its first byte holds its owner.
        let owner = usize::from(unsafe { base.read() });
        account(owner, new_size, layout.size());
        // SAFETY: as in `alloc`.
        unsafe { base.add(header) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Runs `work` and gives its result with the number of allocations that it made on this thread.
///
/// It first counts one known allocation. Thus a count of zero cannot come from a counter that
/// does not count.
pub(crate) fn allocations<T>(work: impl FnOnce() -> T) -> (T, u64) {
    let control = ALLOCATIONS.get();
    drop(core::hint::black_box(Vec::<u8>::with_capacity(1)));
    assert!(ALLOCATIONS.get() > control, "the counter sees no allocation");
    let before = ALLOCATIONS.get();
    let result = work();
    (result, ALLOCATIONS.get() - before)
}
