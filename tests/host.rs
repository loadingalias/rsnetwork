//! The contracts of the caller-driven host: client and server connections against each other in
//! memory with injected time, the deadline on its own turn, the head timeout, the clock refusals,
//! and the report of a connection that drops before its release. `tests/tcp.rs` runs the host
//! over loopback sockets through `host::Tcp`.
//! Each expected byte, deadline, and outcome comes from the test's own input and clock.

use core::assert_matches;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rsnetwork::body::Outcome;
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::value::{Authority, Method, Status, Target};

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1 << 10,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
    visits: 1 << 12,
};

const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The time `seconds` after the start of the test clock.
fn at(seconds: u64) -> Instant {
    Instant::new(CLOCK, seconds * 1_000_000_000)
}

fn received(bytes: &[u8]) -> Received {
    Received {
        region: Lease::from(bytes.to_vec()),
        endpoint: ENDPOINT,
        capacity: 1 << 16,
    }
}

fn queues(budget: &Budget) -> (Inbound, Outbound) {
    let limit = NonZeroUsize::new(16).unwrap();
    (
        Inbound::new(limit, budget).unwrap(),
        Outbound::new(limit, budget).unwrap(),
    )
}

fn open_server(timeout: Option<Duration>) -> Connection<Server> {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let (inbound, outbound) = queues(&budget);
    let server = Server::new(LIMITS, BODY, TURN, &outbound, &budget)
        .unwrap()
        .head_timeout(timeout);
    Connection::new(server, inbound, outbound, Some(CLOCK)).unwrap()
}

fn open_client() -> Connection<Client> {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let (inbound, outbound) = queues(&budget);
    let client = Client::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    Connection::new(client, inbound, outbound, Some(CLOCK)).unwrap()
}

/// The wait of a connection whose engine waits for input, with the deadline at `deadline`.
fn input(deadline: Option<Instant>) -> Wait {
    Wait::Until {
        blocked: Blocked::Input,
        deadline: deadline.map(Deadline::at),
    }
}

/// Sends each output of `from` into `to`, as a transport that accepts all of it does.
fn wire<A: Engine, B: Engine>(from: &mut Connection<A>, to: &mut Connection<B>) {
    while let Some(output) = from.output() {
        to.receive(received(output.region.bytes())).unwrap();
        from.ack(output.id, output.region.initialized()).unwrap();
    }
}

/// Drives `connection` at `now` until it waits, and gives its events.
fn drive<E: Engine>(connection: &mut Connection<E>, now: Instant) -> Vec<E::Event> {
    let mut events = Vec::new();
    while let Some(event) = connection.drive(Some(now)).unwrap() {
        events.push(event);
    }
    events
}

/// A client and a server connection exchange a request and a response through memory, with the
/// time that the test gives. Each side then waits for its next input, and the server's wait has
/// the deadline of its next head.
#[test]
fn a_client_and_a_server_exchange_through_memory_with_injected_time() {
    let (mut client, mut server) = (open_client(), open_server(Some(Duration::from_secs(5))));
    let (engine, outbound) = client.parts();
    let head = Backing::from(Vec::with_capacity(256));
    let target = Target::new(b"/notes").unwrap();
    let authority = Authority::new(b"a.example").unwrap();
    engine
        .request(outbound, Method::GET, target, authority, &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(outbound).unwrap();
    wire(&mut client, &mut server);

    let events = drive(&mut server, at(1));
    assert_matches!(
        &events[..],
        [ServerEvent::Request(_), ServerEvent::End(Outcome::Complete(None))]
    );
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(200).unwrap(), &[], Framing::Length(2), head)
        .unwrap();
    engine.send(outbound, &Lease::from(b"ok".to_vec())).unwrap();
    engine.finish(outbound).unwrap();
    wire(&mut server, &mut client);
    drive(&mut server, at(2));
    assert_eq!(server.wait(), input(Some(at(7))));

    let events = drive(&mut client, at(2));
    let [
        ClientEvent::Response(response),
        ClientEvent::Data(data),
        ClientEvent::End(Outcome::Complete(None)),
    ] = &events[..]
    else {
        panic!("{events:?}");
    };
    assert_eq!((response.head().status().code(), data.bytes()), (200, &b"ok"[..]));
    assert_eq!(client.wait(), input(None));
}

/// A deadline that the engine starts on a turn reaches the host on that turn, also with no new
/// input: on the first drive, and on the drive after a response, when the next head deadline
/// starts. A host that read the deadline only after new input would wait with no deadline.
#[test]
fn a_new_deadline_reaches_the_host_on_its_turn() {
    let mut server = open_server(Some(Duration::from_secs(5)));
    assert!(drive(&mut server, at(0)).is_empty());
    assert_eq!(server.wait(), input(Some(at(5))));

    server.receive(received(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")).unwrap();
    assert_eq!(drive(&mut server, at(1)).len(), 2);
    assert_eq!(server.wait(), input(None));
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(204).unwrap(), &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(outbound).unwrap();
    assert!(drive(&mut server, at(3)).is_empty());
    assert_eq!(server.wait(), input(Some(at(8))));
}

/// At its head deadline, a server connection with no byte of a head closes with no error and no
/// output. A connection with part of a head gets a 408 and ends with a deadline error. The
/// connection then releases after the transport accepts its output. When the output queue is
/// full, the 408 waits for room, and the connection ends after it (RFC 9110, section 15.5.9).
#[test]
fn the_head_timeout_closes_an_idle_connection_and_answers_a_slow_head_with_408() {
    let mut server = open_server(Some(Duration::from_secs(5)));
    drive(&mut server, at(0));
    drive(&mut server, at(4));
    assert_eq!(server.wait(), input(Some(at(5))));
    drive(&mut server, at(5));
    assert_eq!(server.wait(), Wait::Ended(Ok(())));
    assert_eq!(server.release(), Some(Ok(())));

    let mut server = open_server(Some(Duration::from_secs(5)));
    drive(&mut server, at(0));
    server.receive(received(b"GET /slow HTTP/1.1\r\nHo")).unwrap();
    drive(&mut server, at(2));
    drive(&mut server, at(5));
    assert_matches!(server.wait(), Wait::Ended(Err(error)) if error.kind() == Kind::Deadline);
    assert_eq!(server.release(), None);
    let response = server.output().unwrap();
    assert_eq!(
        response.region.bytes(),
        b"HTTP/1.1 408 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
    server.ack(response.id, response.region.initialized()).unwrap();
    assert_matches!(server.release(), Some(Err(error)) if error.kind() == Kind::Deadline);

    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let inbound = Inbound::new(NonZeroUsize::new(16).unwrap(), &budget).unwrap();
    let outbound = Outbound::new(NonZeroUsize::new(1).unwrap(), &budget).unwrap();
    let engine = Server::new(LIMITS, BODY, TURN, &outbound, &budget)
        .unwrap()
        .head_timeout(Some(Duration::from_secs(5)));
    let mut server = Connection::new(engine, inbound, outbound, Some(CLOCK)).unwrap();
    server
        .receive(received(b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHo"))
        .unwrap();
    assert_eq!(drive(&mut server, at(0)).len(), 2);
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(200).unwrap(), &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(outbound).unwrap();
    drive(&mut server, at(1));
    drive(&mut server, at(6));
    assert_eq!(
        server.wait(),
        Wait::Until {
            blocked: Blocked::Output,
            deadline: None
        }
    );
    let response = server.output().unwrap();
    assert_eq!(response.region.bytes(), b"HTTP/1.1 200 \r\ncontent-length: 0\r\n\r\n");
    server.ack(response.id, response.region.initialized()).unwrap();
    drive(&mut server, at(6));
    assert_matches!(server.wait(), Wait::Ended(Err(error)) if error.kind() == Kind::Deadline);
    let response = server.output().unwrap();
    assert_eq!(
        response.region.bytes(),
        b"HTTP/1.1 408 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
}

/// A host with no clock cannot run the head timeout, so its connection refuses with an
/// unsupported capability. With the timeout off, or for a client, it needs no clock. A time on
/// another clock than the connection's refuses as misuse.
#[test]
fn a_host_with_no_clock_or_another_clock_refuses() {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    let (inbound, outbound) = queues(&budget);
    let timed = Server::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    let refused = Connection::new(timed, inbound, outbound, None);
    assert_eq!(
        refused.map(|_| ()).map_err(|error| error.kind()),
        Err(Kind::Unsupported)
    );

    let (inbound, outbound) = queues(&budget);
    let untimed = Server::new(LIMITS, BODY, TURN, &outbound, &budget)
        .unwrap()
        .head_timeout(None);
    let mut untimed = Connection::new(untimed, inbound, outbound, None).unwrap();
    assert_eq!(untimed.drive(None).map(|event| event.is_none()), Ok(true));

    let mut server = open_server(Some(Duration::from_secs(5)));
    let other = Instant::new(ClockDomain::new(2, Suspend::Advances), 0);
    assert_eq!(
        server.drive(Some(other)).map(|_| ()).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    assert_eq!(
        server.drive(None).map(|_| ()).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
}

/// A connection releases only after its terminal turn, when the transport accepted each output.
/// A connection that drops before it reports the regions and bytes that the transport has not
/// accepted, and the output that waits for its acknowledgement.
#[test]
fn a_connection_that_drops_before_its_release_reports_the_outstanding_output() {
    let mut server = open_server(None);
    server
        .receive(received(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"))
        .unwrap();
    drive(&mut server, at(0));
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(200).unwrap(), &[], Framing::Chunked, head)
        .unwrap();
    engine.send(outbound, &Lease::from(b"hello".to_vec())).unwrap();
    engine.finish(outbound).unwrap();
    drive(&mut server, at(0));
    assert_eq!(server.wait(), Wait::Ended(Ok(())));
    assert_eq!(server.release(), None);

    let first = server.output().unwrap();
    let first_len = first.region.initialized() as u64;
    assert_eq!(server.admit(first.id), Ok(first_len));
    assert_eq!(server.release(), None);
    let submitted = server.output().unwrap();
    let outstanding = server.abandon();
    assert_eq!(outstanding.submitted, Some(submitted.id));
    assert_eq!(
        (outstanding.admitted_regions, outstanding.admitted_bytes),
        (1, first_len)
    );
    assert_eq!(outstanding.regions, 5);
    let head = b"HTTP/1.1 200 \r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n";
    assert_eq!(
        outstanding.bytes,
        (head.len() + b"5\r\nhello\r\n0\r\n\r\n".len()) as u64
    );
}
