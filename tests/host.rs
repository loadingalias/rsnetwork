//! The contracts of the caller-driven host: client and server connections against each other in
//! memory with injected time and over loopback std sockets, the deadline on its own turn, the head
//! timeout, the clock refusals, and the report of a connection that drops before its release.
//! Each expected byte, deadline, and outcome comes from the test's own input and clock.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

use rsnetwork::body::Outcome;
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Wait};
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
    assert!(matches!(
        &events[..],
        [ServerEvent::Request(_), ServerEvent::End(Outcome::Complete(None))]
    ));
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(200).unwrap(), &[], Framing::Length(2), head)
        .unwrap();
    engine.send(outbound, &Lease::from(b"ok".to_vec())).unwrap();
    engine.finish(outbound).unwrap();
    wire(&mut server, &mut client);
    drive(&mut server, at(2));
    assert_eq!(server.wait(), Wait::Until(Some(Deadline::at(at(7)))));

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
    assert_eq!(client.wait(), Wait::Until(None));
}

/// A deadline that the engine starts on a turn reaches the host on that turn, also with no new
/// input: on the first drive, and on the drive after a response, when the next head deadline
/// starts. A host that read the deadline only after new input would wait with no deadline.
#[test]
fn a_new_deadline_reaches_the_host_on_its_turn() {
    let mut server = open_server(Some(Duration::from_secs(5)));
    assert!(drive(&mut server, at(0)).is_empty());
    assert_eq!(server.wait(), Wait::Until(Some(Deadline::at(at(5)))));

    server.receive(received(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")).unwrap();
    assert_eq!(drive(&mut server, at(1)).len(), 2);
    assert_eq!(server.wait(), Wait::Until(None));
    let (engine, outbound) = server.parts();
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .respond(outbound, Status::new(204).unwrap(), &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(outbound).unwrap();
    assert!(drive(&mut server, at(3)).is_empty());
    assert_eq!(server.wait(), Wait::Until(Some(Deadline::at(at(8)))));
}

/// At its head deadline, a server connection with no byte of a head closes with no error and no
/// output. A connection with part of a head gets a 408 and ends with a deadline error. The
/// connection then releases after the transport accepts its output.
#[test]
fn the_head_timeout_closes_an_idle_connection_and_answers_a_slow_head_with_408() {
    let mut server = open_server(Some(Duration::from_secs(5)));
    drive(&mut server, at(0));
    drive(&mut server, at(4));
    assert!(matches!(server.wait(), Wait::Until(Some(_))));
    drive(&mut server, at(5));
    assert_eq!(server.wait(), Wait::Ended(Ok(())));
    assert_eq!(server.release(), Some(Ok(())));

    let mut server = open_server(Some(Duration::from_secs(5)));
    drive(&mut server, at(0));
    server.receive(received(b"GET /slow HTTP/1.1\r\nHo")).unwrap();
    drive(&mut server, at(2));
    drive(&mut server, at(5));
    assert!(matches!(server.wait(), Wait::Ended(Err(error)) if error.kind() == Kind::Deadline));
    assert_eq!(server.release(), None);
    let response = server.output().unwrap();
    assert_eq!(
        response.region.bytes(),
        b"HTTP/1.1 408 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
    server.ack(response.id, response.region.initialized()).unwrap();
    assert!(matches!(server.release(), Some(Err(error)) if error.kind() == Kind::Deadline));
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

    let submitted = server.output().unwrap();
    let outstanding = server.abandon();
    assert_eq!(outstanding.submitted, Some(submitted.id));
    assert_eq!(outstanding.regions, 5);
    let head = b"HTTP/1.1 200 \r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n";
    assert_eq!(
        outstanding.bytes,
        (head.len() + b"5\r\nhello\r\n0\r\n\r\n".len()) as u64
    );
}

/// A client and a server connection exchange a request and a response over loopback std sockets
/// in nonblocking mode, with the time of a std clock. The test moves the bytes between the sockets
/// and the connections, as an event loop does.
#[test]
fn a_client_and_a_server_exchange_over_loopback_std_sockets() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut far, _) = listener.accept().unwrap();
    near.set_nonblocking(true).unwrap();
    far.set_nonblocking(true).unwrap();
    let start = std::time::Instant::now();
    let clock = |start: std::time::Instant| {
        let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap();
        Instant::new(CLOCK, nanos)
    };

    let (mut client, mut server) = (open_client(), open_server(Some(Duration::from_secs(5))));
    let (engine, outbound) = client.parts();
    let head = Backing::from(Vec::with_capacity(256));
    let target = Target::new(b"/hello").unwrap();
    let authority = Authority::new(b"127.0.0.1").unwrap();
    engine
        .request(outbound, Method::GET, target, authority, &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(outbound).unwrap();

    let mut answered = false;
    let mut body = Vec::new();
    for _ in 0..100_000 {
        pump(&mut near, &mut client);
        pump(&mut far, &mut server);
        while let Some(event) = server.drive(Some(clock(start))).unwrap() {
            if let ServerEvent::End(_) = event
                && !answered
            {
                let (engine, outbound) = server.parts();
                let head = Backing::from(Vec::with_capacity(256));
                engine
                    .respond(outbound, Status::new(200).unwrap(), &[], Framing::Chunked, head)
                    .unwrap();
                engine.send(outbound, &Lease::from(b"over loopback".to_vec())).unwrap();
                engine.finish(outbound).unwrap();
                answered = true;
            }
        }
        while let Some(event) = client.drive(Some(clock(start))).unwrap() {
            match event {
                ClientEvent::Data(data) => body.extend_from_slice(data.bytes()),
                ClientEvent::End(outcome) => {
                    assert!(matches!(outcome, Outcome::Complete(None)), "{outcome:?}");
                    assert_eq!(body, b"over loopback");
                    return;
                }
                ClientEvent::Response(_) | ClientEvent::Informational(_) | ClientEvent::Handoff => {}
            }
        }
    }
    panic!("no response after 100000 loop turns");
}

/// Moves bytes between a nonblocking socket and a connection: what the socket received into the
/// connection, and the output of the connection into the socket, with an acknowledgement of the
/// bytes that the socket accepted.
fn pump<E: Engine>(socket: &mut TcpStream, connection: &mut Connection<E>) {
    let mut region = vec![0; 4096];
    match socket.read(&mut region) {
        Ok(0) => connection.end_input(),
        Ok(len) => {
            region.truncate(len);
            connection.receive(received(&region)).unwrap();
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Err(error) => panic!("{error}"),
    }
    while let Some(output) = connection.output() {
        match socket.write(output.region.bytes()) {
            Ok(accepted) => connection.ack(output.id, accepted).unwrap(),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                connection.ack(output.id, 0).unwrap();
                break;
            }
            Err(error) => panic!("{error}"),
        }
    }
}
