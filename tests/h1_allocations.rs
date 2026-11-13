//! The H1 core allocates nothing to parse a request head, to give its body, or to write a response
//! head. The body stays in the received region. A parser that copies the head or the body into an
//! allocated buffer fails this test. It is a test binary of its own, because a binary has one
//! global allocator.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
use rsnetwork::h1::{Framing, Limits, ParseError, RequestParser, write_head};

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
fn allocations<T>(work: impl FnOnce() -> T) -> (T, u64) {
    let control = ALLOCATIONS.get();
    drop(core::hint::black_box(Vec::<u8>::with_capacity(1)));
    assert!(ALLOCATIONS.get() > control, "the counter sees no allocation");
    let before = ALLOCATIONS.get();
    let result = work();
    (result, ALLOCATIONS.get() - before)
}

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
};

#[test]
fn a_request_and_its_response_head_need_no_allocation_and_no_body_copy() {
    // A receive filled this region: a head, a body of 5 bytes, and the start of the next request.
    let received = Lease::from(
        b"POST /notes HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGET / HTTP/1.1\r\n".to_vec(),
    );
    let mut parser = RequestParser::new(LIMITS);
    let mut out = WriteLoan::new(Vec::with_capacity(256));
    let ((consumed, body), count) = allocations(|| {
        let head = parser.parse(received.bytes()).unwrap().unwrap();
        assert_eq!(head.framing(), Framing::Length(5));
        assert_eq!(head.fields().count(), 2);
        let body = received.view(head.consumed()..head.consumed() + 5).unwrap();
        write_head(&mut out, 200, &[], Framing::Length(5)).unwrap();
        (head.consumed(), body)
    });
    assert_eq!(count, 0);
    assert_eq!(body.bytes(), b"hello");
    assert_eq!(body.as_ptr(), received.as_ptr().wrapping_add(consumed));
}

#[test]
fn a_head_over_its_limit_refuses_with_no_allocation() {
    let received = [b'a'; 1024];
    let mut parser = RequestParser::new(LIMITS);
    let (result, count) = allocations(|| {
        for end in 1..received.len() {
            assert_eq!(parser.parse(&received[..end]), Ok(None));
        }
        parser.parse(&received)
    });
    assert_eq!((result, count), (Err(ParseError::HeadTooLarge), 0));
}
