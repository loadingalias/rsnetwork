//! The H1 core allocates nothing to parse a request head, to give its body, or to write a response
//! head. The body stays in the received region. A parser that copies the head or the body into an
//! allocated buffer fails this test.

use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
use rsnetwork::h1::{Framing, Limits, ParseError, RequestParser, write_head};

mod counting;

use counting::allocations;

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
