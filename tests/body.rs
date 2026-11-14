//! The contracts of the body model: a direct read into an admitted region, the distinct terminal
//! outcomes, the order of the outcome after the bytes, and bounded collection. Each expected byte
//! and outcome comes from RFC 9112 and the bytes that the test gives, not from the code under test.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::body::{Collect, Consumer, Outcome, Read};
use rsnetwork::buffer::{Backing, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits, Server, ServerEvent};
use rsnetwork::value::{Authority, Method, Target};

mod counting;

use counting::allocations;

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 16,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
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

fn queues() -> (Inbound, Outbound, Budget) {
    let limit = NonZeroUsize::new(8).unwrap();
    (
        Inbound::new(limit).unwrap(),
        Outbound::new(limit).unwrap(),
        Budget::new(NonZeroU64::new(1 << 20).unwrap()),
    )
}

/// A chunked request body arrives one byte in each region, after its head. A consumer copies it
/// straight into one admitted region, with no allocation: no internal chunk, no assembly buffer.
/// The body is complete only after its last chunk, its trailers, and its outcome.
#[test]
fn a_chunked_body_reads_into_an_admitted_region_with_no_allocation() {
    let (mut inbound, mut outbound, budget) = queues();
    let mut server = Server::new(LIMITS, BODY, &outbound, &budget).unwrap();
    inbound
        .push(received(
            b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        ))
        .unwrap();
    let (Some(ServerEvent::Request(_)), _) = server.drive(&mut inbound, &mut outbound) else {
        panic!("a request head");
    };
    let chunks = b"5;e=1\r\nhello\r\n7\r\n, world\r\n";
    let mut regions: Vec<Received> = chunks.iter().map(|&byte| received(&[byte])).collect();
    regions.push(received(b"0\r\nX-Sum: 12\r\n\r\n"));
    let mut region = WriteLoan::new(Vec::with_capacity(64));
    let mut consumer = Consumer::new();

    let (collected, count) = allocations(|| {
        let mut collected = Collect::More;
        for each in regions {
            inbound.push(each).unwrap();
            while let (Some(event), _) = server.drive(&mut inbound, &mut outbound) {
                match event {
                    ServerEvent::Data(data) => consumer.data(data).unwrap(),
                    ServerEvent::End(outcome) => consumer.end(outcome),
                    other => panic!("{other:?}"),
                }
                collected = consumer.collect(&mut region);
            }
        }
        collected
    });
    assert_eq!(count, 0);
    let Collect::Complete(Some(trailers)) = collected else {
        panic!("{collected:?}");
    };
    let trailer = trailers.fields().next().unwrap();
    assert_eq!((trailer.name(), trailer.value()), (&b"X-Sum"[..], &b"12"[..]));
    assert_eq!(region.filled(), b"hello, world");
    assert_eq!(consumer.delivered(), 12);
}

/// Each response body ends with the outcome that its framing and its input give. The end of
/// input completes a body that the close delimits, and cuts a body with a length or with chunks,
/// which is then truncated: never complete. A chunk framing error makes the body malformed. A
/// consumer collects a complete value only for a complete body, and the bytes of an interrupted
/// body stay visible as a part.
#[test]
fn a_body_is_complete_only_when_its_framing_says_so() {
    for (response, end, expected, bytes) in [
        (
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-A: 1\r\n\r\n"[..],
            false,
            "complete",
            &b"hello"[..],
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
            true,
            "truncated",
            b"hello",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhello",
            true,
            "truncated",
            b"hello",
        ),
        (b"HTTP/1.0 200 OK\r\n\r\nhello", true, "complete", b"hello"),
        (b"HTTP/1.1 200 OK\r\n\r\nhello", true, "complete", b"hello"),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX\r\n",
            false,
            "malformed",
            b"hello",
        ),
    ] {
        let (mut inbound, mut outbound, budget) = queues();
        let mut client = Client::new(LIMITS, BODY, &outbound, &budget).unwrap();
        let head = Backing::from(Vec::with_capacity(256));
        let target = Target::new(b"/").unwrap();
        let authority = Authority::new(b"a.example").unwrap();
        client
            .request(
                &mut outbound,
                Method::GET,
                target,
                authority,
                &[],
                Framing::Length(0),
                head,
            )
            .unwrap();
        client.finish(&mut outbound).unwrap();
        inbound.push(received(response)).unwrap();
        if end {
            inbound.end();
        }
        let mut consumer = Consumer::new();
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        let mut collected = Collect::More;
        while let (Some(event), _) = client.drive(&mut inbound) {
            match event {
                ClientEvent::Response(_) => {}
                ClientEvent::Data(data) => consumer.data(data).unwrap(),
                ClientEvent::End(outcome) => consumer.end(outcome),
                other => panic!("{other:?}"),
            }
            collected = consumer.collect(&mut region);
        }
        let seen = match &collected {
            Collect::Complete(_) => "complete",
            Collect::Interrupted(Outcome::Truncated) => "truncated",
            Collect::Interrupted(Outcome::Malformed) => "malformed",
            other => panic!("{other:?}"),
        };
        assert_eq!(seen, expected, "{}", response.escape_ascii());
        assert_eq!(region.filled(), bytes, "{}", response.escape_ascii());
    }
}

/// The outcome of a body shows only after its last waiting byte, also when the outcome arrived
/// first. A consumer takes the next part only after the waiting one, so the regions of the caller
/// pace the body.
#[test]
fn the_outcome_comes_after_the_last_byte() {
    let mut consumer = Consumer::new();
    consumer.data(Lease::from(b"0123456789".to_vec())).unwrap();
    assert!(consumer.data(Lease::from(b"x".to_vec())).is_err(), "a part waits");
    consumer.end(Outcome::Complete(None));
    let mut first = WriteLoan::new(Vec::with_capacity(4));
    assert!(matches!(consumer.read_into(&mut first), Read::Bytes(4)));
    assert!(matches!(consumer.read_into(&mut first), Read::Full));
    let mut second = WriteLoan::new(Vec::with_capacity(16));
    assert!(matches!(consumer.read_into(&mut second), Read::Bytes(6)));
    assert!(matches!(
        consumer.read_into(&mut second),
        Read::Done(Outcome::Complete(None))
    ));
    assert_eq!([first.filled(), second.filled()].concat(), b"0123456789");
}

/// A collection past the free capacity of its region refuses with `TooLarge`. The region keeps
/// the first bytes, and the rest waits in the consumer, where a read into another region finds
/// it.
#[test]
fn collection_past_its_bound_refuses_and_keeps_its_first_bytes() {
    let mut consumer = Consumer::new();
    consumer.data(Lease::from(b"0123456789ab".to_vec())).unwrap();
    consumer.end(Outcome::Complete(None));
    let mut region = WriteLoan::new(Vec::with_capacity(8));
    assert!(matches!(
        consumer.collect(&mut region),
        Collect::TooLarge { collected: 8 }
    ));
    assert_eq!(region.filled(), b"01234567");
    let mut rest = WriteLoan::new(Vec::with_capacity(8));
    assert!(matches!(consumer.collect(&mut rest), Collect::Complete(None)));
    assert_eq!(rest.filled(), b"89ab");
}

/// The `Debug` output of a consumer, an outcome, and a body shows no byte of the body, also for a
/// static region, whose own `Debug` shows its bytes.
#[test]
fn no_debug_output_shows_a_body_byte() {
    let secret = Lease::from(&b"secret body"[..]);
    let mut consumer = Consumer::new();
    consumer.data(secret.clone()).unwrap();
    consumer.end(Outcome::Truncated);
    let text = format!(
        "{consumer:?} {:?} {:?}",
        rsnetwork::body::Body::Buffered(secret),
        Outcome::Complete(None)
    );
    assert!(!text.contains("secret"), "{text}");
}
