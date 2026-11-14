//! The H1 core allocates nothing to parse a request head, to give its body, to keep the head, or to
//! write a response head. The body and the kept head stay in the received region. A parser that
//! copies the head or the body into an allocated buffer fails this test.

use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroU64};

use rsnetwork::buffer::{Buffer as _, Lease, Pool, PoolEmpty, WriteLoan};
use rsnetwork::h1::{Framing, Limits, ParseError, RequestParser, write_head};
use rsnetwork::value::Status;
use rstypes::capacity::Budget;

mod counting;

use counting::allocations;

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
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
        write_head(&mut out, Status::new(200).unwrap(), &[], Framing::Length(5)).unwrap();
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

/// Two pipelined heads in one pool slot stay after the region drops, with no allocation. Each is a
/// view of the slot, so the one slot and its one charge hold both. The slot returns to its pool
/// only when the last head drops. A head that copies its bytes lets the slot return early.
#[test]
fn kept_heads_hold_their_one_slot_until_the_last_drops() {
    let budget = Budget::new(NonZeroU64::new(4096).unwrap());
    let slot = Layout::from_size_align(1024, 8).unwrap();
    let mut pool = Pool::new(&budget, NonZeroU32::new(1).unwrap(), slot).unwrap();
    let mut received = WriteLoan::new(pool.acquire().unwrap());
    received.fill_from(b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\nGET /b HTTP/1.1\r\nHost: b.example\r\n\r\n");
    let received = Lease::from(received.into_inner());

    let mut parser = RequestParser::new(LIMITS);
    let ((first, second), count) = allocations(|| {
        let first = parser.parse(received.bytes()).unwrap().unwrap();
        let rest = &received.bytes()[first.consumed()..];
        let second = parser.parse(rest).unwrap().unwrap();
        (first.retain(&received).unwrap(), second.retain(&received).unwrap())
    });
    assert_eq!(count, 0);
    drop(received);
    assert_eq!(pool.acquire().unwrap_err(), PoolEmpty);

    assert_eq!(first.head().target().as_bytes(), b"/a");
    drop(first);
    assert_eq!(pool.acquire().unwrap_err(), PoolEmpty);

    assert_eq!(second.head().authority().as_bytes(), b"b.example");
    drop(second);
    pool.acquire().unwrap();
}
