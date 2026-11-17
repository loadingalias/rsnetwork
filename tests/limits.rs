//! The contracts of admission and of the limits of each drive turn: a slow peer, a turn with more
//! work than its limit, and a refused admission. Each expected charge and count comes from the
//! limits that the test sets, not from the code under test.

use core::assert_matches;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::value::Status;

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
    drain_bytes: 1 << 16,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

/// The time of the host, which the tests keep at the start of their clock.
const NOW: Option<Instant> = Some(Instant::new(ClockDomain::new(1, Suspend::Pauses), 0));

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

/// The queues of a connection, with a budget of their own, so that a test of an engine budget
/// sees only the charges of the engine.
fn queues() -> (Inbound, Outbound) {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let limit = NonZeroUsize::new(8).unwrap();
    (
        Inbound::new(limit, &budget).unwrap(),
        Outbound::new(limit, &budget).unwrap(),
    )
}

/// A slow peer sends a head that never completes, one byte in each turn. The engine retains one
/// join of the head limit, charged to the budget, and no other byte: the declared bound. At the
/// limit, it refuses the head with 431 and ends the connection. When the engine drops, each charge
/// returns. An engine that buffers the head with no charge passes the budget unseen.
#[test]
fn a_slow_peer_retains_one_charged_head_and_is_refused_at_its_limit() {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let total = budget.available();
    let (mut inbound, mut outbound) = queues();
    let turn = TurnLimits {
        bytes: 1 << 20,
        frames: 1 << 10,
    };
    let mut server = Server::new(LIMITS, BODY, turn, &outbound, &budget).unwrap();
    let admitted = budget.available();
    let head = [b"GET /".as_slice(), &[b'a'; 2048]].concat();
    for (at, byte) in head.iter().enumerate() {
        inbound.push(received(&[*byte])).unwrap();
        let (event, turn) = server.drive(&mut inbound, &mut outbound, NOW);
        assert!(event.is_none(), "byte {at}");
        if at + 1 < LIMITS.head_bytes {
            assert_eq!(turn.progress, Progress::Blocked(Blocked::Input), "byte {at}");
            assert_eq!(budget.available(), admitted - LIMITS.head_bytes as u64, "byte {at}");
            assert!(inbound.front().is_none(), "byte {at}");
        } else {
            assert_matches!(turn.progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Overload, "byte {at}: {:?}",
                turn.progress);
            break;
        }
    }
    let response = outbound.submit().unwrap();
    assert!(response.region.bytes().starts_with(b"HTTP/1.1 431 "));
    drop(response);
    drop(server);
    assert_eq!(budget.available(), total);
}

/// A drain of 1000 chunks of one byte, after a response before the end of the request body, stops
/// at the frame limit of each turn and reports that work remains. Later turns go on, and the next
/// request comes after the drain. A turn with a byte limit stops in the same way between regions.
#[test]
fn a_turn_with_more_work_than_its_limit_stops_and_reports_the_rest() {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let (mut inbound, mut outbound) = queues();
    let turn = TurnLimits {
        bytes: 1 << 20,
        frames: 10,
    };
    let mut server = Server::new(LIMITS, BODY, turn, &outbound, &budget).unwrap();
    inbound
        .push(received(
            b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        ))
        .unwrap();
    let (Some(ServerEvent::Request(_)), _) = server.drive(&mut inbound, &mut outbound, NOW) else {
        panic!("a request head");
    };
    let head = Backing::from(Vec::with_capacity(64));
    let status = Status::new(413).unwrap();
    server
        .respond(&mut outbound, status, &[], Framing::Length(0), head)
        .unwrap();
    server.finish(&mut outbound).unwrap();

    let chunks = [
        b"1\r\na\r\n".repeat(1000).as_slice(),
        b"0\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n",
    ]
    .concat();
    let region = Lease::from(chunks);
    let start = region.as_ptr().addr();
    inbound
        .push(Received {
            region,
            endpoint: ENDPOINT,
            capacity: 1 << 16,
        })
        .unwrap();
    let mut pending = 0;
    let mut consumed = 0;
    loop {
        let (event, turn) = server.drive(&mut inbound, &mut outbound, NOW);
        if let Some(event) = event {
            assert_matches!(event, ServerEvent::Request(_));
            break;
        }
        assert_eq!(turn.progress, Progress::Pending);
        let now = inbound.front().unwrap().region.as_ptr().addr() - start;
        assert!(now - consumed <= 10 * 6, "a turn read {} bytes", now - consumed);
        consumed = now;
        pending += 1;
    }
    assert_eq!(pending, 100);

    // Eight regions of 10 bytes of a body that the engine drains, with 30 bytes in each turn: three
    // regions, three more, and then the last two and a wait for the rest of the body.
    let turn = TurnLimits { bytes: 30, frames: 10 };
    let (mut inbound, mut outbound) = queues();
    let mut server = Server::new(LIMITS, BODY, turn, &outbound, &budget).unwrap();
    inbound
        .push(received(b"PUT /up HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\n"))
        .unwrap();
    server.drive(&mut inbound, &mut outbound, NOW);
    let head = Backing::from(Vec::with_capacity(64));
    server
        .respond(&mut outbound, status, &[], Framing::Length(0), head)
        .unwrap();
    server.finish(&mut outbound).unwrap();
    for _ in 0..8 {
        inbound.push(received(&[b'x'; 10])).unwrap();
    }
    let turns: Vec<Progress> = (0..3)
        .map(|_| server.drive(&mut inbound, &mut outbound, NOW).1.progress)
        .collect();
    assert_eq!(
        turns,
        [Progress::Pending, Progress::Pending, Progress::Blocked(Blocked::Input)]
    );
    assert!(inbound.front().is_none());
}

/// A refused admission returns an overload error and allocates nothing: each queue and the pool of
/// an engine reserve their memory from the budget before they allocate it.
#[test]
fn a_refused_admission_is_an_overload_and_allocates_nothing() {
    let poor = Budget::new(NonZeroU64::new(1).unwrap());
    let limit = NonZeroUsize::new(8).unwrap();
    let (_, outbound) = queues();
    let turn = TurnLimits { bytes: 1, frames: 1 };
    let (kinds, count) = allocations(|| {
        [
            Inbound::new(limit, &poor).err().map(|error| error.kind()),
            Outbound::new(limit, &poor).err().map(|error| error.kind()),
            Server::new(LIMITS, BODY, turn, &outbound, &poor)
                .err()
                .map(|error| error.kind()),
        ]
    });
    assert_eq!(kinds, [Some(Kind::Overload); 3]);
    assert_eq!(count, 0);
}

/// The server ignores empty lines before a request line (RFC 9112, section 2.2), and their bytes
/// count against the head limit. Thus a peer that sends only empty lines gets 431 at the limit,
/// and an empty line and a head that pass the limit together refuse with 431 too. An engine that
/// discards empty lines with no count reads them for as long as the peer sends them.
#[test]
fn empty_lines_before_a_request_line_count_against_the_head_limit() {
    let turn = TurnLimits {
        bytes: 1 << 20,
        frames: 1 << 10,
    };
    // A request head of `bytes` bytes after one empty line.
    let after_an_empty_line = |bytes: usize| {
        let target = vec![b'a'; bytes - b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".len()];
        [b"\r\nGET /", &target[..], b" HTTP/1.1\r\nHost: a\r\n\r\n"].concat()
    };
    for (input, accepted) in [
        (b"\r\n".repeat(LIMITS.head_bytes / 2 + 1), false),
        (after_an_empty_line(LIMITS.head_bytes - 2), true),
        (after_an_empty_line(LIMITS.head_bytes - 1), false),
    ] {
        let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
        let (mut inbound, mut outbound) = queues();
        let mut server = Server::new(LIMITS, BODY, turn, &outbound, &budget).unwrap();
        inbound.push(received(&input)).unwrap();
        let (event, turn) = server.drive(&mut inbound, &mut outbound, NOW);
        if accepted {
            assert_matches!(event, Some(ServerEvent::Request(_)), "{turn:?}");
        } else {
            assert!(event.is_none());
            assert_matches!(turn.progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Overload, "{turn:?}");
            let response = outbound.submit().unwrap();
            assert_eq!(
                response.region.bytes(),
                b"HTTP/1.1 431 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
            );
        }
    }
}
