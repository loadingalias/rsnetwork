//! The counting allocator of the allocation tests. Each test binary that includes this module
//! counts the allocations of each thread. A binary has one global allocator, so each binary that
//! counts includes this module, and no other.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

/// Counts the allocations of each thread.
struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

#[expect(
    unsafe_code,
    reason = "the test allocator counts each allocation and forwards it to the system allocator"
)]
// SAFETY: each method forwards its arguments to the system allocator, which meets the contract.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        // SAFETY: the caller meets the contract of `alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller meets the contract of `dealloc`.
        unsafe { System.dealloc(ptr, layout) }
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
