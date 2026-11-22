//! The HTTP/1.1 client over TCP and over TLS, against the server engine of the core. The test is
//! the binding: it moves the bytes of the transport, and the application side makes only the calls
//! of the exchange. The rules: one deadline over the head and the whole body, reuse only of a clean
//! connection, and a body that the close delimits that ends with no `close_notify` is not complete.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::collections::VecDeque;
use std::sync::Arc;

use rsnetwork::body::{Collect, Outcome, Part, Read};
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{Http1, Limits, Request};
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{self, BodyLimits, Framing, Server, ServerEvent};
use rsnetwork::h2;
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::message::ResponseHead;
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Entropy, Identity, Limits as TlsLimits, PrivateKeyDer, Resumption,
    ServerConfig, ServerOptions, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Method, Status, Target};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

const HEAD: h1::Limits = h1::Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

/// The rest of an unread body that the connection drains: at most 64 bytes.
const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

/// The HTTP/2 limits, which an HTTP/1.1 client does not use.
const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 8,
        max_header_list_size: 4096,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 1 << 20,
};

const LIMITS: Limits = Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: NonZeroUsize::new(16).unwrap(),
};

const TLS: TlsLimits = TlsLimits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    ecn: Ecn::NotEct,
    segment: None,
};

/// A wall clock that stays at one time.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn clock() -> ClockDomain {
    ClockDomain::new(1, Suspend::Pauses)
}

/// The time `ms` milliseconds after the start of a test.
fn at(ms: u64) -> Instant {
    Instant::new(clock(), ms * 1_000_000)
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 24).unwrap())
}

fn get() -> Request<'static> {
    Request {
        method: Method::GET,
        target: Target::new(b"/").unwrap(),
        authority: Authority::new(b"server.test").unwrap(),
        fields: &[],
        length: Some(0),
    }
}

fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Plain,
    Tls,
}

/// One response of the server: its framing, the parts of its body, and whether it ends.
struct Reply {
    framing: Framing,
    parts: Vec<Vec<u8>>,
    finish: bool,
}

impl Reply {
    fn whole(body: &[u8]) -> Self {
        Self {
            framing: Framing::Length(body.len() as u64),
            parts: vec![body.to_vec()],
            finish: true,
        }
    }
}

/// The server end: the server engine over TCP or over TLS.
#[expect(
    clippy::large_enum_variant,
    reason = "each pair holds one server end in place, as the client does"
)]
enum Peer {
    Plain(Connection<Server>),
    Tls(Connection<Tls<Server>>),
}

/// Runs `$body` with `$connection` bound to the connection of each transport of the server.
macro_rules! each {
    ($peer:expr, $connection:ident => $body:expr) => {
        match $peer {
            Peer::Plain($connection) => $body,
            Peer::Tls($connection) => $body,
        }
    };
}

/// A client, a server that answers with its replies in order, and the transport between them.
struct Pair {
    client: Http1,
    server: Peer,
    replies: VecDeque<Reply>,
    /// The requests that reached the server.
    requests: usize,
    to_client: VecDeque<Vec<u8>>,
    to_server: VecDeque<Vec<u8>>,
    /// The transport ends before the last record of the server, its `close_notify`.
    cut: bool,
    /// The end of the transport is a reset, not an end of input.
    reset: bool,
}

/// An alert record over TLS 1.3: its header, the alert, its content type, and its tag.
const ALERT_RECORD: usize = 5 + 2 + 1 + 16;

fn queues(budget: &Budget) -> (Inbound, Outbound) {
    let limit = NonZeroUsize::new(16).unwrap();
    (
        Inbound::new(limit, budget).unwrap(),
        Outbound::new(limit, budget).unwrap(),
    )
}

fn server_config(protocols: &[&[u8]]) -> ServerConfig {
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![certificate(SERVER.0)],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols,
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

fn client_config(protocols: &[&[u8]]) -> ClientConfig {
    ClientConfig::new(ClientOptions {
        roots: &[certificate(CA)],
        identity: None,
        protocols,
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

impl Pair {
    fn new(transport: Transport, replies: Vec<Reply>) -> Self {
        Self::with(transport, replies, (&[b"http/1.1"], &[b"http/1.1"]))
    }

    /// A pair whose ends offer and accept `protocols` over TLS.
    fn with(transport: Transport, replies: Vec<Reply>, (offered, accepted): (&[&[u8]], &[&[u8]])) -> Self {
        let budget = budget();
        let (inbound, outbound) = queues(&budget);
        let engine = Server::new(HEAD, BODY, TURN, &outbound, &budget).unwrap();
        let (client, server) = match transport {
            Transport::Plain => (
                Http1::plain(LIMITS, clock(), &budget).unwrap(),
                Peer::Plain(Connection::new(engine, inbound, outbound, Some(clock())).unwrap()),
            ),
            Transport::Tls => {
                let tls = Tls::server(&server_config(accepted), engine, (inbound, outbound), TLS, &budget).unwrap();
                let (inbound, outbound) = queues(&budget);
                (
                    Http1::tls(&client_config(offered), "server.test", (LIMITS, TLS), clock(), &budget).unwrap(),
                    Peer::Tls(Connection::new(tls, inbound, outbound, Some(clock())).unwrap()),
                )
            }
        };
        Self {
            client,
            server,
            replies: replies.into(),
            requests: 0,
            to_client: VecDeque::new(),
            to_server: VecDeque::new(),
            cut: false,
            reset: false,
        }
    }

    /// The binding: drives the server, which answers each request with its next reply, and moves
    /// each output of both ends to the other, until no byte moves.
    fn transport(&mut self) {
        for _ in 0..256 {
            self.serve();
            while let Some(output) = each!(&mut self.server, connection => connection.output()) {
                self.to_client.push_back(output.region.bytes().to_vec());
                let accepted = output.region.initialized();
                each!(&mut self.server, connection => connection.ack(output.id, accepted)).unwrap();
            }
            if self.cut && matches!(each!(&self.server, connection => connection.wait()), Wait::Ended(_)) {
                self.cut = false;
                let last = self
                    .to_client
                    .back_mut()
                    .expect("the server ended with its close_notify");
                last.truncate(last.len() - ALERT_RECORD);
                self.to_client.push_back(Vec::new());
            }
            while let Some(output) = self.client.output() {
                self.to_server.push_back(output.region.bytes().to_vec());
                self.client.ack(output.id, output.region.initialized()).unwrap();
            }
            let to_client = self.to_client.pop_front().map(|bytes| {
                // An empty part is the end of the transport.
                if bytes.is_empty() && self.reset {
                    self.client.reset();
                } else if bytes.is_empty() {
                    self.client.end_input();
                } else if let Err(rest) = give_client(&mut self.client, bytes) {
                    self.to_client.push_front(rest);
                }
            });
            let to_server = self.to_server.pop_front().map(|bytes| {
                each!(&mut self.server, connection => give(connection, &bytes));
            });
            if to_client.is_none() && to_server.is_none() {
                return;
            }
        }
        panic!("the transport still moves bytes after 256 rounds");
    }

    /// Drives the server until it waits, and answers each request.
    fn serve(&mut self) {
        for _ in 0..256 {
            let event = each!(&mut self.server, connection => connection.drive(Some(at(0)))).unwrap();
            match event {
                Some(ServerEvent::Request(_)) => {
                    self.requests += 1;
                    let reply = self.replies.pop_front().expect("a reply for each request");
                    let (server, outbound) = match &mut self.server {
                        Peer::Plain(connection) => connection.parts(),
                        Peer::Tls(connection) => connection.parts().0.parts(),
                    };
                    let head = Backing::from(Vec::with_capacity(256));
                    server
                        .respond(outbound, Status::new(200).unwrap(), &[], reply.framing, head)
                        .unwrap();
                    for part in reply.parts {
                        server.send(outbound, &Lease::from(part)).unwrap();
                    }
                    if reply.finish {
                        server.finish(outbound).unwrap();
                    }
                }
                Some(_) => {}
                None if each!(&self.server, connection => connection.wait()) != Wait::Now => return,
                None => {}
            }
        }
        panic!("the server did not wait after 256 drives");
    }
}

/// Gives `bytes` to the client in the input region that it lends, or as a read-only region.
/// Gives them back when the client cannot take them now.
fn give_client(client: &mut Http1, bytes: Vec<u8>) -> Result<(), Vec<u8>> {
    let Some(region) = client.region().unwrap() else {
        let received = Received {
            region: Lease::from(bytes),
            endpoint: ENDPOINT,
            capacity: 1 << 20,
        };
        return client
            .receive(received)
            .map_err(|received| received.region.bytes().to_vec());
    };
    let mut loan = WriteLoan::new(region);
    let added = loan.fill_from(&bytes);
    client.received(loan.into_inner(), ENDPOINT, 1 << 20).unwrap();
    match bytes.get(added..) {
        Some(rest) if !rest.is_empty() => Err(rest.to_vec()),
        _ => Ok(()),
    }
}

/// Gives `bytes` to the server, as the client gives them.
fn give<E: Engine>(to: &mut Connection<E>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match to.region().unwrap() {
            Some(region) => {
                let mut loan = WriteLoan::new(region);
                let added = loan.fill_from(bytes);
                to.received(loan.into_inner(), ENDPOINT, 1 << 20).unwrap();
                bytes = &bytes[added..];
            }
            None => {
                let region = Lease::from(bytes.to_vec());
                to.receive(Received {
                    region,
                    endpoint: ENDPOINT,
                    capacity: 1 << 20,
                })
                .unwrap();
                return;
            }
        }
    }
}

/// The response head of the request in flight. As a binding does, the transport moves the bytes
/// between the calls.
fn head(pair: &mut Pair, now: Instant) -> ResponseHead {
    for _ in 0..16 {
        if let Some(head) = pair.client.response(now).unwrap() {
            return head;
        }
        pair.transport();
    }
    panic!("no response head after 16 calls");
}

/// Sends `request` on the client of `pair`, with the transport between the tries.
fn send(
    pair: &mut Pair,
    request: &Request<'_>,
    deadline: Deadline,
    now: Instant,
) -> Result<(), rsnetwork::drive::Error> {
    for _ in 0..16 {
        if pair.client.send(request, deadline, now)? {
            return Ok(());
        }
        pair.transport();
    }
    panic!("the client did not take the request after 16 tries");
}

#[test]
fn a_slow_body_meets_its_original_deadline_with_its_partial_progress() {
    for transport in [Transport::Plain, Transport::Tls] {
        // A body of 100 bytes, of which the server sends 10, and then nothing.
        let mut pair = Pair::new(
            transport,
            vec![Reply {
                framing: Framing::Length(100),
                parts: vec![b"0123456789".to_vec()],
                finish: false,
            }],
        );
        let deadline = Deadline::at(at(1_000));
        send(&mut pair, &get(), deadline, at(0)).unwrap();
        let head = head(&mut pair, at(10));
        assert_eq!(head.status(), Status::new(200).unwrap(), "{transport:?}");

        // From here, the application calls only the body.
        let mut region = WriteLoan::new(Vec::with_capacity(256));
        while region.filled().len() < 10 {
            match pair.client.read_into(at(500), &mut region).unwrap() {
                Read::Bytes(_) => {}
                Read::Wait => pair.transport(),
                read => panic!("{transport:?}: the body gave {read:?}"),
            }
        }
        assert_eq!(region.filled(), b"0123456789", "{transport:?}");
        assert!(matches!(
            pair.client.read_into(at(500), &mut region).unwrap(),
            Read::Wait
        ));
        // The binding wakes at the deadline of the exchange.
        assert_eq!(
            pair.client.wait(),
            Wait::Until {
                blocked: Blocked::Input,
                deadline: Some(deadline)
            },
            "{transport:?}"
        );
        pair.transport();
        let error = pair.client.read_into(at(1_000), &mut region).unwrap_err();
        assert_eq!(
            (error.kind(), error.reason()),
            (Kind::Deadline, "the deadline came before the end of the response"),
            "{transport:?}"
        );
        assert_eq!(pair.client.delivered(), 10, "{transport:?}");
        assert_eq!(pair.client.wait(), Wait::Ended(Err(error)), "{transport:?}");
    }
}

#[test]
fn over_tls_the_deadline_covers_the_handshake() {
    let mut pair = Pair::new(Transport::Tls, Vec::new());
    let deadline = Deadline::at(at(1_000));
    // The request waits for the handshake, and the server never answers.
    assert!(pair.client.send(&get(), deadline, at(0)).unwrap());
    assert_eq!(pair.client.response(at(999)).unwrap().map(|_| ()), None);
    let error = pair.client.response(at(1_000)).unwrap_err();
    assert_eq!(
        (error.kind(), error.reason()),
        (Kind::Deadline, "the deadline came before the response head")
    );
}

#[test]
fn an_unread_body_drains_before_the_next_request_or_the_connection_closes() {
    let deadline = Deadline::at(at(1_000));
    for transport in [Transport::Plain, Transport::Tls] {
        // The body arrives in two parts. The application reads the first, and leaves the second,
        // 32 bytes, unread. That is within the drain, so the connection carries the next
        // request, and its response is exactly its own.
        let first = Reply {
            framing: Framing::Length(40),
            parts: vec![vec![b'a'; 8], vec![b'b'; 32]],
            finish: true,
        };
        let mut pair = Pair::new(transport, vec![first, Reply::whole(b"second")]);
        send(&mut pair, &get(), deadline, at(0)).unwrap();
        head(&mut pair, at(1));
        let Some(Part::Data(data)) = pair.client.next(at(1)).unwrap() else {
            panic!("{transport:?}: the first part of the body has not arrived");
        };
        assert_eq!(data.bytes(), [b'a'; 8], "{transport:?}");
        send(&mut pair, &get(), deadline, at(2)).unwrap();
        head(&mut pair, at(3));
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        let collected = loop {
            match pair.client.collect(at(3), &mut region).unwrap() {
                Collect::More => pair.transport(),
                collected => break collected,
            }
        };
        assert!(
            matches!(collected, Collect::Complete(None)),
            "{transport:?}: {collected:?}"
        );
        assert_eq!((region.filled(), pair.requests), (&b"second"[..], 2), "{transport:?}");

        // Here the rest of the body, 992 bytes, is still to come, and longer than the drain: the
        // connection closes, and carries no other request.
        let long = Reply {
            framing: Framing::Length(1000),
            parts: vec![vec![b'a'; 8]],
            finish: false,
        };
        let mut pair = Pair::new(transport, vec![long, Reply::whole(b"second")]);
        send(&mut pair, &get(), deadline, at(0)).unwrap();
        head(&mut pair, at(1));
        assert!(
            matches!(pair.client.next(at(1)).unwrap(), Some(Part::Data(_))),
            "{transport:?}"
        );
        let error = send(&mut pair, &get(), deadline, at(2)).unwrap_err();
        assert_eq!(
            (error.kind(), error.reason()),
            (Kind::Misuse, "the connection ended: make a new client"),
            "{transport:?}"
        );
        pair.transport();
        assert_eq!(pair.requests, 1, "{transport:?}");
    }
}

#[test]
fn over_tls_a_body_that_the_close_delimits_is_complete_only_after_close_notify() {
    let reply = || Reply {
        framing: Framing::Close,
        parts: vec![b"until the close".to_vec()],
        finish: true,
    };
    let body = |pair: &mut Pair| {
        let mut parts = Vec::new();
        for _ in 0..16 {
            match pair.client.next(at(1)).unwrap() {
                Some(Part::Data(data)) => parts.extend_from_slice(data.bytes()),
                Some(Part::End(outcome)) => return (parts, outcome),
                None => pair.transport(),
            }
        }
        panic!("the body did not end after 16 calls");
    };
    let deadline = Deadline::at(at(1_000));

    // The server sends `close_notify` after the body.
    let mut pair = Pair::new(Transport::Tls, vec![reply()]);
    send(&mut pair, &get(), deadline, at(0)).unwrap();
    head(&mut pair, at(1));
    let (parts, outcome) = body(&mut pair);
    assert_eq!(parts, b"until the close");
    assert!(matches!(outcome, Outcome::Complete(None)), "{outcome:?}");

    // The transport ends before the `close_notify` record, the last bytes that the server sends.
    let mut pair = Pair::new(Transport::Tls, vec![reply()]);
    pair.cut = true;
    send(&mut pair, &get(), deadline, at(0)).unwrap();
    head(&mut pair, at(1));
    let (parts, outcome) = body(&mut pair);
    assert_eq!(parts, b"until the close");
    assert!(matches!(outcome, Outcome::Truncated), "{outcome:?}");
}

#[test]
fn over_tls_a_server_that_selects_another_protocol_ends_the_client() {
    let mut pair = Pair::with(Transport::Tls, Vec::new(), (&[b"h2", b"http/1.1"], &[b"h2"]));
    let deadline = Deadline::at(at(1_000));
    assert!(pair.client.send(&get(), deadline, at(0)).unwrap());
    let error = (0..16)
        .find_map(|_| match pair.client.response(at(1)) {
            Ok(_) => {
                pair.transport();
                None
            }
            Err(error) => Some(error),
        })
        .expect("the client ends");
    assert_eq!(
        (error.kind(), error.reason()),
        (Kind::Unsupported, "the server selected a protocol other than HTTP/1.1")
    );
}

#[test]
fn a_close_after_the_exchange_sends_close_notify_and_releases_the_client() {
    let mut pair = Pair::new(Transport::Tls, vec![Reply::whole(b"done")]);
    send(&mut pair, &get(), Deadline::at(at(1_000)), at(0)).unwrap();
    head(&mut pair, at(1));
    let mut region = WriteLoan::new(Vec::with_capacity(64));
    let collected = loop {
        match pair.client.collect(at(1), &mut region).unwrap() {
            Collect::More => pair.transport(),
            collected => break collected,
        }
    };
    assert!(matches!(collected, Collect::Complete(None)));
    assert_eq!(pair.client.release(), None);
    pair.client.close(at(2)).unwrap();
    pair.transport();
    assert_eq!(pair.client.release(), Some(Ok(())));
    let Peer::Tls(server) = &mut pair.server else {
        panic!("the pair runs over TLS")
    };
    assert_eq!(server.parts().0.closure(), Some(rsnetwork::tls::Closure::Notified));
}

#[test]
fn a_reset_ends_a_body_that_the_close_delimits_as_reset_not_complete() {
    let reply = || Reply {
        framing: Framing::Close,
        parts: vec![b"until the close".to_vec()],
        finish: true,
    };
    let body = |pair: &mut Pair| {
        let mut parts = Vec::new();
        for _ in 0..16 {
            match pair.client.next(at(1)).unwrap() {
                Some(Part::Data(data)) => parts.extend_from_slice(data.bytes()),
                Some(Part::End(outcome)) => return (parts, outcome),
                None => pair.transport(),
            }
        }
        panic!("the body did not end after 16 calls");
    };
    let deadline = Deadline::at(at(1_000));

    // Over TCP, the transport fails after the bytes of the body.
    let mut pair = Pair::new(Transport::Plain, vec![reply()]);
    send(&mut pair, &get(), deadline, at(0)).unwrap();
    head(&mut pair, at(1));
    pair.client.reset();
    let (parts, outcome) = body(&mut pair);
    assert_eq!(parts, b"until the close");
    assert_matches!(outcome, Outcome::Reset(None));

    // Over TLS, the transport fails before the `close_notify` record.
    let mut pair = Pair::new(Transport::Tls, vec![reply()]);
    (pair.cut, pair.reset) = (true, true);
    send(&mut pair, &get(), deadline, at(0)).unwrap();
    head(&mut pair, at(1));
    let (parts, outcome) = body(&mut pair);
    assert_eq!(parts, b"until the close");
    assert_matches!(outcome, Outcome::Reset(None));
}

#[test]
fn a_response_before_the_end_of_the_request_body_leaves_the_client_working() {
    for transport in [Transport::Plain, Transport::Tls] {
        // The server answers at the request head, before the body, in three parts.
        let reply = Reply {
            framing: Framing::Length(9),
            parts: vec![b"one".to_vec(), b"two".to_vec(), b"six".to_vec()],
            finish: true,
        };
        let mut pair = Pair::new(transport, vec![reply]);
        let post = Request {
            method: Method::POST,
            length: Some(9),
            ..get()
        };
        send(&mut pair, &post, Deadline::at(at(1_000)), at(0)).unwrap();
        for part in [b"abc", b"def", b"ghi"] {
            pair.transport();
            pair.client.write(&Lease::from(&part[..]), at(0)).unwrap();
        }
        pair.client.finish(at(0)).unwrap();
        head(&mut pair, at(0));
        let mut parts = Vec::new();
        let outcome = loop {
            match pair.client.next(at(0)).unwrap() {
                Some(Part::Data(data)) => parts.extend_from_slice(data.bytes()),
                Some(Part::End(outcome)) => break outcome,
                None => pair.transport(),
            }
        };
        assert_eq!(parts, b"onetwosix", "{transport:?}");
        assert_matches!(outcome, Outcome::Complete(None), "{transport:?}");
    }
}
