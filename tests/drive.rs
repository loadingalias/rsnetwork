//! The contracts of the drive interface: exact acknowledgements of output and of consumed input,
//! and errors with no peer text. Each expected address, length, and byte comes from the bytes that
//! the test gives, not from the code under test.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{AckError, Ecn, Endpoint, Error, Inbound, Kind, Outbound, Received};
use rsnetwork::h1::{Framing, Limits, RequestParser};

const LIMIT: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// A budget that pays for each queue of a test.
fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 20).unwrap())
}

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080),
    ecn: Ecn::NotEct,
    segment: None,
};

fn received(bytes: &[u8]) -> Received {
    Received {
        region: Lease::from(bytes.to_vec()),
        endpoint: ENDPOINT,
        capacity: 1 << 16,
    }
}

/// The offset of the front region of `inbound` in a region that starts at `base`, and its bytes.
fn front(inbound: &Inbound, base: *const u8) -> Option<(usize, &[u8])> {
    let region = &inbound.front()?.region;
    Some((region.as_ptr().addr() - base.addr(), region.bytes()))
}

/// A duplicate acknowledgement, an acknowledgement of an output that the queue did not give, and
/// an acknowledgement of more bytes than the output has each refuse. After each refusal, the
/// queue gives the same outputs as with no refusal. A host that acknowledges again, or that mixes
/// the outputs of two connections, cannot make a queue drop bytes that the transport did not take.
#[test]
fn an_acknowledgement_that_names_no_outstanding_bytes_refuses_and_changes_nothing() {
    // The id of the third output of another queue, which this queue did not give.
    let mut other = Outbound::new(LIMIT, &budget()).unwrap();
    other.push(Lease::from(b"abc".to_vec())).unwrap();
    let mut foreign = None;
    for _ in 0..3 {
        let output = other.submit().unwrap();
        other.ack(output.id, 1).unwrap();
        foreign = Some(output.id);
    }
    let foreign = foreign.unwrap();

    let mut outbound = Outbound::new(LIMIT, &budget()).unwrap();
    outbound.push(Lease::from(b"0123456789".to_vec())).unwrap();
    let first = outbound.submit().unwrap();
    assert_eq!(outbound.ack(first.id, 11), Err(AckError::TooLarge));
    assert_eq!(outbound.ack(foreign, 0), Err(AckError::Unknown));
    assert!(outbound.submit().is_none(), "the first output is still outstanding");

    outbound.ack(first.id, 4).unwrap();
    assert_eq!(outbound.ack(first.id, 4), Err(AckError::Duplicate));
    let second = outbound.submit().unwrap();
    assert_eq!(outbound.ack(first.id, 0), Err(AckError::Duplicate));
    assert_eq!(second.region.bytes(), b"456789");
    assert_eq!(second.region.as_ptr(), first.region.as_ptr().wrapping_add(4));
    outbound.ack(second.id, 6).unwrap();
    assert!(outbound.submit().is_none(), "the queue is empty");
}

/// The driver can refuse a body while its head is in flight. Only the accepted prefix frees space.
#[test]
fn an_ordered_send_retains_its_regions_through_refusal_and_partial_kernel_acceptance() {
    let mut queue = Outbound::new(NonZeroUsize::new(2).unwrap(), &budget()).unwrap();
    queue.push(Lease::from(&b"HEAD"[..])).unwrap();
    let body = Lease::from(b"abcdef".to_vec());
    queue.push(body.clone()).unwrap();
    let head = queue.submit().unwrap();
    assert_eq!(head.region.bytes(), b"HEAD");
    assert_eq!(queue.admit(head.id), Ok(4));
    let offer = queue.submit().unwrap();
    assert_eq!(queue.ack(offer.id, 1), Err(AckError::OutOfOrder));
    queue.ack(offer.id, 0).unwrap();
    assert_eq!(queue.admit(offer.id), Err(AckError::Duplicate));
    assert_eq!(queue.accept_through(5), Err(AckError::TooLarge));
    let last = queue
        .push(Lease::from(&b"!"[..]))
        .expect_err("both slots still hold bytes");

    let retry = queue.submit().unwrap();
    assert_eq!(retry.region.as_ptr(), body.as_ptr());
    assert_eq!(retry.region.bytes(), b"abcdef");
    assert_eq!(queue.admit(retry.id), Ok(10));
    assert!(queue.submit().is_none());
    queue.accept_through(2).unwrap();
    assert_eq!(queue.free(), 0, "the kernel accepted only part of the head");
    queue.accept_through(7).unwrap();
    let remaining = queue.outstanding();
    assert_eq!((remaining.regions, remaining.bytes), (1, 3));
    assert_eq!((remaining.admitted_regions, remaining.admitted_bytes), (1, 3));
    queue.accept_through(7).unwrap();
    queue.accept_through(2).unwrap();
    assert_eq!(queue.outstanding(), remaining);

    queue.push(last).unwrap();
    let offer = queue.submit().unwrap();
    assert_eq!(offer.region.bytes(), b"!");
    queue.accept_through(10).unwrap();
    assert_eq!(
        queue.admit(offer.id),
        Ok(11),
        "the offer survives retirement of the body"
    );
    queue.accept_through(11).unwrap();
    assert!(queue.outstanding().is_empty());
}

/// A partial acceptance advances a stable offset: the next output is the rest of the same region,
/// at its address, with no copy. A refused submission accepts no byte and leaves the same bytes.
/// When a region has no byte left, the next output is the next region.
#[test]
fn a_partial_acceptance_gives_the_rest_of_the_region_at_its_address() {
    let mut outbound = Outbound::new(LIMIT, &budget()).unwrap();
    let head = Lease::from(b"HTTP/1.1 200 \r\ncontent-length: 5\r\n\r\n".to_vec());
    let base = head.as_ptr();
    outbound.push(head).unwrap();
    outbound.push(Lease::from(b"hello".to_vec())).unwrap();

    let mut sent = Vec::new();
    for accepted in [0, 9, 0, 1, 26] {
        let output = outbound.submit().unwrap();
        assert_eq!(output.region.as_ptr(), base.wrapping_add(sent.len()));
        sent.extend_from_slice(&output.region.bytes()[..accepted]);
        outbound.ack(output.id, accepted).unwrap();
    }
    assert_eq!(sent, b"HTTP/1.1 200 \r\ncontent-length: 5\r\n\r\n");
    assert_eq!(
        outbound.submit().map(|output| output.region.bytes().to_vec()),
        Some(b"hello".to_vec())
    );
}

/// The bytes of a region that two requests and a CONNECT tunnel share. Each byte after a consumed
/// prefix keeps its owner and its address: the body after the first head, the pipelined second
/// request, and the tunnel bytes after the CONNECT head. A region that arrives later queues after
/// them. Consumption of more bytes than the front region has refuses and changes nothing.
#[test]
fn consumption_keeps_each_byte_after_the_prefix_with_its_owner() {
    const REQUESTS: &[u8] = b"GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello\
        GET /b HTTP/1.1\r\nHost: b\r\n\r\n\
        CONNECT b.example:443 HTTP/1.1\r\nHost: b.example\r\n\r\n\x16\x03\x01tunnel";
    let mut inbound = Inbound::new(LIMIT, &budget()).unwrap();
    let first = received(REQUESTS);
    let base = first.region.as_ptr();
    inbound.push(first).unwrap();
    let mut parser = RequestParser::new(LIMITS);
    let mut parse = |inbound: &Inbound| {
        let head = parser.parse(inbound.front().unwrap().region.bytes()).unwrap().unwrap();
        (head.consumed(), head.framing())
    };

    // Drive 1: the first head. A second region arrives before the next drive.
    let (head, framing) = parse(&inbound);
    assert_eq!(framing, Framing::Length(5));
    inbound.consume(head).unwrap();
    inbound.push(received(b"later")).unwrap();
    assert_eq!(front(&inbound, base), Some((head, &REQUESTS[head..])));

    // Drive 2: the body goes to its consumer as a view, and the engine consumes it.
    let body = inbound.front().unwrap().region.view(..5).unwrap();
    inbound.consume(5).unwrap();
    assert_eq!((body.as_ptr(), body.bytes()), (base.wrapping_add(head), &b"hello"[..]));
    let second = head + 5;
    assert_eq!(front(&inbound, base), Some((second, &REQUESTS[second..])));

    // Drive 3: the pipelined request.
    let (head, _) = parse(&inbound);
    inbound.consume(head).unwrap();
    let connect = second + head;
    assert_eq!(front(&inbound, base), Some((connect, &REQUESTS[connect..])));

    // Drive 4: the CONNECT head. The tunnel takes exactly the bytes after it.
    let (head, _) = parse(&inbound);
    assert_eq!(inbound.consume(REQUESTS.len() - connect + 1), Err(AckError::TooLarge));
    inbound.consume(head).unwrap();
    let tunnel = inbound.take_front().unwrap();
    assert_eq!(tunnel.region.bytes(), b"\x16\x03\x01tunnel");
    assert_eq!(tunnel.region.as_ptr(), base.wrapping_add(connect + head));
    assert_eq!(
        inbound.front().map(|received| received.region.bytes()),
        Some(&b"later"[..])
    );
}

/// A client consumes an informational response, as a response parser does. The final response
/// after it keeps its owner and its address, also when the next region arrives before the next
/// drive.
#[test]
fn an_informational_response_leaves_the_final_response_with_its_owner() {
    const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
    const RESPONSES: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 \r\ncontent-length: 2\r\n\r\nok";
    let mut inbound = Inbound::new(LIMIT, &budget()).unwrap();
    let first = received(RESPONSES);
    let base = first.region.as_ptr();
    inbound.push(first).unwrap();

    inbound.consume(CONTINUE.len()).unwrap();
    inbound.push(received(b"HTTP/1.1 204 \r\n\r\n")).unwrap();
    assert_eq!(
        front(&inbound, base),
        Some((CONTINUE.len(), &RESPONSES[CONTINUE.len()..]))
    );
}

/// A request with a credential and a body fails on its framing. The parse error, the error of the
/// drive, and the `Debug` output of the queues, their regions, and an output show neither the
/// credential nor the body. A static region is in the test because its own `Debug` shows its
/// bytes.
#[test]
fn no_error_or_debug_output_shows_a_credential_or_a_body() {
    const REQUEST: &[u8] = b"POST /upload HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer s3cr3t\r\n\
        Content-Length: 6\r\nContent-Length: 6\r\n\r\nsecret";
    let mut inbound = Inbound::new(LIMIT, &budget()).unwrap();
    inbound.push(received(REQUEST)).unwrap();
    let refusal = RequestParser::new(LIMITS)
        .parse(inbound.front().unwrap().region.bytes())
        .unwrap_err();
    let error = Error::from(refusal);
    assert_eq!(error.kind(), Kind::Malformed);

    let mut outbound = Outbound::new(LIMIT, &budget()).unwrap();
    outbound.push(Lease::from(&b"secret body"[..])).unwrap();
    let output = outbound.submit().unwrap();
    for text in [
        format!("{refusal} {refusal:?}"),
        format!("{error} {error:?}"),
        format!("{inbound:?} {:?}", inbound.front().unwrap()),
        format!("{outbound:?} {output:?}"),
    ] {
        assert!(
            !text.contains("s3cr3t") && !text.contains("Bearer") && !text.contains("secret"),
            "{text}"
        );
    }
}
