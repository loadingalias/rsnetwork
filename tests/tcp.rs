//! The binding of a caller-driven host to a nonblocking std TCP socket (`host::Tcp`), over
//! loopback sockets. Each test is the event loop of its host: it calls the connection, and then
//! pumps its socket. The rules: the socket moves each byte of the HTTP/1.1 client and server and of
//! the TLS stream, over TCP and over TLS, and a TLS connection decrypts in place. The socket waits
//! for no event that cannot help. The end of the stream and a reset are two outcomes. The linger
//! half-closes the socket. A connection releases only after the socket accepted each output, and a
//! close before that reports the output and resets the peer.
#![cfg(feature = "tcp")]
// A peer that resets its connection sets a linger of zero, as `host::Tcp` does.
#![feature(tcp_linger)]

use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Backing, Buffer as _, Lease, Pool};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::{Inbound, Kind, Outbound, TurnLimits};
use rsnetwork::h1::{self, BodyLimits, ClientEvent, Framing, Server, ServerEvent};
use rsnetwork::h2;
use rsnetwork::host::{Connection, Io, Next, Tcp, Wait};
use rsnetwork::message::{self, ResponseHead, Version};
use rsnetwork::server::{self, Cleartext, Delivery, Linger, Response};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Copies, Entropy, Identity, Limits as TlsLimits, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions, Stream, StreamLimits, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Field, Method, Status, Target};

const CA: &[u8] = include_bytes!("tls/ca.der");
const IDENTITY: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

const HEAD: h1::Limits = h1::Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 64 << 20,
    drain_bytes: 64,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

const QUEUE: NonZeroUsize = NonZeroUsize::new(16).unwrap();

const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 8,
        max_header_list_size: 4096,
        initial_window_size: 1 << 20,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 8 << 20,
};

const CLIENT: client::Limits = client::Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: QUEUE,
};

const SERVER: server::Limits = server::Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: QUEUE,
    head_timeout: Some(Duration::from_secs(30)),
    linger: Linger {
        time: Duration::from_secs(30),
        bytes: 1 << 20,
    },
    cleartext: Cleartext::Http1,
};

const TLS: TlsLimits = TlsLimits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

/// The response body of an exchange: 4 MiB in parts of 64 KiB, each a view of one region.
const PARTS: usize = 64;
const PART: usize = 64 * 1024;

/// A response body larger than the socket buffers of a loopback connection: 64 MiB in parts of
/// 8 MiB, each a view of one region, so the output queue holds each part at once.
const LARGE_PARTS: usize = 8;
const LARGE_PART: usize = 8 << 20;

/// The longest time that one test can run before it fails.
const GUARD: Duration = Duration::from_secs(60);

/// A wall clock that stays at one time, for the validity of the certificates.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

/// The monotonic clock of the host.
struct Clock(std::time::Instant);

impl Clock {
    fn new() -> Self {
        Self(std::time::Instant::now())
    }

    fn now(&self) -> Instant {
        Instant::new(CLOCK, u64::try_from(self.0.elapsed().as_nanos()).unwrap())
    }

    fn deadline(&self) -> Deadline {
        Deadline::at(Instant::new(
            CLOCK,
            u64::try_from((self.0.elapsed() + GUARD).as_nanos()).unwrap(),
        ))
    }

    /// Fails the test when it ran longer than [`GUARD`].
    fn guard(&self) {
        assert!(self.0.elapsed() < GUARD, "the test made no progress in {GUARD:?}");
    }
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 26).unwrap())
}

/// A pool of 16 receive regions of 16 KiB, charged to `budget`.
fn pool(budget: &Budget) -> Pool {
    Pool::new(
        budget,
        NonZeroU32::new(16).unwrap(),
        Layout::array::<u8>(16 * 1024).unwrap(),
    )
    .unwrap()
}

/// The pool of a TLS connection, which lends its own input region: one region of 4 KiB, for the
/// linger of a server.
fn tls_pool(budget: &Budget) -> Pool {
    Pool::new(budget, NonZeroU32::MIN, Layout::array::<u8>(4096).unwrap()).unwrap()
}

/// Two ends of one loopback TCP connection.
fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (far, _) = listener.accept().unwrap();
    (near, far)
}

fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

fn server_config(protocols: &[&[u8]]) -> ServerConfig {
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![certificate(IDENTITY.0)],
            key: PrivateKeyDer::try_from(IDENTITY.1.to_vec()).unwrap(),
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

/// The client of one version, for the tests that run on each: an HTTP/1.1 client, or an HTTP/2
/// client with the stream of its one request.
#[expect(
    clippy::large_enum_variant,
    reason = "a test holds one client in place, as an application does"
)]
enum Client {
    H1(client::Http1),
    H2(client::Http2, Option<message::Stream>),
}

impl Client {
    /// Sends `request`. Gives whether the client took it.
    fn send(&mut self, request: &Request<'_>, deadline: Deadline, now: Instant) -> bool {
        match self {
            Self::H1(client) => client.send(request, deadline, now).unwrap(),
            Self::H2(client, stream) => {
                *stream = client.send(request, deadline, now).unwrap();
                stream.is_some()
            }
        }
    }

    fn stream(stream: Option<message::Stream>) -> message::Stream {
        stream.expect("the request went out")
    }

    fn write(&mut self, data: &Lease, now: Instant) -> Result<(), rsnetwork::drive::Error> {
        match self {
            Self::H1(client) => client.write(data, now),
            Self::H2(client, stream) => client.write(Self::stream(*stream), data, now),
        }
    }

    fn finish(&mut self, now: Instant) -> Result<(), rsnetwork::drive::Error> {
        match self {
            Self::H1(client) => client.finish(now),
            Self::H2(client, stream) => client.finish(Self::stream(*stream), now),
        }
    }

    fn response(&mut self, now: Instant) -> Option<ResponseHead> {
        match self {
            Self::H1(client) => client.response(now).unwrap(),
            Self::H2(client, stream) => client.response(Self::stream(*stream), now).unwrap(),
        }
    }

    fn next(&mut self, now: Instant) -> Option<Part> {
        match self {
            Self::H1(client) => client.next(now).unwrap(),
            Self::H2(client, stream) => client.next(Self::stream(*stream), now).unwrap(),
        }
    }

    fn close(&mut self, now: Instant) {
        match self {
            Self::H1(client) => client.close(now).unwrap(),
            Self::H2(client, _) => client.close(now).unwrap(),
        }
    }

    fn pump(&mut self, socket: &mut Tcp) -> Next {
        match self {
            Self::H1(client) => pump(socket, client),
            Self::H2(client, _) => pump(socket, client),
        }
    }

    fn release(&self) -> Option<Result<(), rsnetwork::drive::Error>> {
        match self {
            Self::H1(client) => client.release(),
            Self::H2(client, _) => client.release(),
        }
    }

    fn close_socket(&self, socket: Tcp) -> bool {
        match self {
            Self::H1(client) => socket.close(client).is_empty(),
            Self::H2(client, _) => socket.close(client).is_empty(),
        }
    }
}

/// A client and a server of `version`, each with its socket. Over TCP, each socket has a receive
/// pool. Over TLS, the server offers `h2` and `http/1.1` and the client the one of its version,
/// and each socket has a pool of one region: TLS lends its input region.
fn pair(tls: bool, version: Version) -> ((Client, Tcp), (server::Http, Tcp)) {
    let (near, far) = sockets();
    let budget = budget();
    let h2 = version == Version::Http2;
    let cleartext = if h2 { Cleartext::Http2 } else { Cleartext::Http1 };
    let limits = server::Limits { cleartext, ..SERVER };
    let protocols: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
    let (client, server) = if tls {
        let config = client_config(protocols);
        let client = if h2 {
            Client::H2(
                client::Http2::tls(&config, "server.test", (CLIENT, TLS), CLOCK, &budget).unwrap(),
                None,
            )
        } else {
            Client::H1(client::Http1::tls(&config, "server.test", (CLIENT, TLS), CLOCK, &budget).unwrap())
        };
        let config = server_config(&[b"h2", b"http/1.1"]);
        (
            client,
            server::Http::tls(&config, (limits, TLS), CLOCK, &budget).unwrap(),
        )
    } else {
        let client = if h2 {
            Client::H2(client::Http2::plain(CLIENT, CLOCK, &budget).unwrap(), None)
        } else {
            Client::H1(client::Http1::plain(CLIENT, CLOCK, &budget).unwrap())
        };
        (client, server::Http::plain(limits, CLOCK, &budget).unwrap())
    };
    let pool = if tls { tls_pool } else { pool };
    (
        (client, Tcp::new(near, pool(&budget)).unwrap()),
        (server, Tcp::new(far, pool(&budget)).unwrap()),
    )
}

fn pump<C: Io>(socket: &mut Tcp, connection: &mut C) -> Next {
    socket.pump(connection).unwrap()
}

/// Whether a write took its bytes. A full output queue refuses with `Overload`: send the output,
/// and write again.
fn written(result: Result<(), rsnetwork::drive::Error>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) if error.kind() == Kind::Overload => false,
        Err(error) => panic!("{error}"),
    }
}

/// On HTTP/1.1 and HTTP/2, over TCP and over TLS, a client sends a request body of 256 KiB, and
/// the server answers with a body of 4 MiB. Each body has more parts than the output queue holds,
/// so each write meets a full queue, which over TLS only a drive frees. Each side gets each byte.
/// The server delivers its response complete, the client closes, and each connection releases
/// with no output left.
#[test]
fn a_client_and_a_server_exchange_their_bodies_through_their_sockets_on_each_version_over_tcp_and_over_tls() {
    for (tls, version) in [false, true]
        .into_iter()
        .flat_map(|tls| [(tls, Version::Http11), (tls, Version::Http2)])
    {
        let clock = Clock::new();
        let ((mut client, mut near), (mut server, mut far)) = pair(tls, version);
        // The request body: 256 KiB in parts of 8 KiB, each a view of one region.
        let upload = Lease::from(vec![b'q'; 8 * 1024]);
        let (uploads, sent) = (32, 256 * 1024);
        let request = Request {
            method: Method::POST,
            target: Target::new(b"/upload").unwrap(),
            authority: Authority::new(b"server.test").unwrap(),
            fields: &[],
            length: Some(sent as u64),
        };
        let mut uploaded_parts = 0;

        let part = Lease::from(vec![b'x'; PART]);
        let length = (PARTS * PART) as u64;
        let (mut uploaded, mut downloaded, mut parts) = (0, 0, 0);
        let (mut request_end, mut response_end, mut head) = (None, None, None);
        let (mut sending, mut serving, mut closed) = (true, None, false);
        let ends = loop {
            clock.guard();
            let now = clock.now();
            if sending {
                sending = !client.send(&request, clock.deadline(), now);
            }
            // The client sends its body while the output queue takes it.
            while !sending && uploaded_parts < uploads && written(client.write(&upload, now)) {
                uploaded_parts += 1;
                if uploaded_parts == uploads {
                    client.finish(now).unwrap();
                }
            }
            // The handler: the request, its body, and the response.
            if serving.is_none() {
                serving = server.request(now).unwrap().map(|(stream, head)| {
                    assert_eq!(head.version(), version, "tls: {tls}");
                    stream
                });
            }
            while let Some(stream) = serving
                && request_end.is_none()
            {
                match server.next(stream, now).unwrap() {
                    Some(Part::Data(data)) => uploaded += data.initialized(),
                    Some(Part::End(outcome)) => {
                        request_end = Some(outcome);
                        let response = Response {
                            status: Status::new(200).unwrap(),
                            fields: &[],
                            length: Some(length),
                        };
                        assert!(server.respond(stream, &response, now).unwrap());
                    }
                    None => break,
                }
            }
            while let Some(stream) = serving
                && request_end.is_some()
                && parts < PARTS
                && written(server.write(stream, &part, now))
            {
                parts += 1;
                if parts == PARTS {
                    server.finish(stream, now).unwrap();
                }
            }
            if parts == PARTS {
                assert!(server.request(now).unwrap().is_none(), "the client sends one request");
            }
            // The client: the response head, its body, and the close.
            if head.is_none() && !sending {
                head = client.response(now).map(|response| response.status().code());
            }
            while head.is_some() && response_end.is_none() {
                match client.next(now) {
                    Some(Part::Data(data)) => downloaded += data.initialized(),
                    Some(Part::End(outcome)) => response_end = Some(outcome),
                    None => break,
                }
            }
            if let Some(stream) = serving
                && response_end.is_some()
                && !closed
            {
                assert_eq!(
                    server.delivery(stream),
                    Some(Delivery::Complete { accepted: length }),
                    "tls: {tls}"
                );
                server.close(stream);
                client.close(now);
                closed = true;
            }
            let (client_next, server_next) = (client.pump(&mut near), pump(&mut far, &mut server));
            if (client_next, server_next) == (Next::Released, Next::Released) {
                break (client.release().unwrap(), server.release().unwrap());
            }
        };
        assert_eq!(ends.0, Ok(()), "tls: {tls}, {version:?}");
        assert_eq!(ends.1.result, Ok(()), "tls: {tls}, {version:?}");
        assert_eq!(uploaded, sent);
        assert_matches!(request_end, Some(Outcome::Complete(None)));
        assert_eq!(head, Some(200));
        assert_eq!(downloaded as u64, length);
        assert_matches!(response_end, Some(Outcome::Complete(None)));
        assert!(client.close_socket(near));
        assert!(far.close(&server).is_empty());
    }
}

/// A TLS connection over its socket receives into the region that it lends: a request and a
/// response copy no received byte, only the encryption writes each sent byte.
#[test]
fn over_tls_a_connection_through_its_socket_copies_no_received_byte() {
    let (near, far) = sockets();
    let (client_budget, server_budget) = (budget(), budget());
    let queues = |budget: &Budget| {
        (
            Inbound::new(QUEUE, budget).unwrap(),
            Outbound::new(QUEUE, budget).unwrap(),
        )
    };
    let (inbound, outbound) = queues(&client_budget);
    let engine = h1::Client::new(HEAD, BODY, TURN, &outbound, &client_budget).unwrap();
    let tls = Tls::client(
        &client_config(&[]),
        "server.test",
        engine,
        (inbound, outbound),
        TLS,
        &client_budget,
    )
    .unwrap();
    let (inbound, outbound) = queues(&client_budget);
    let mut client = Connection::new(tls, inbound, outbound, Some(CLOCK)).unwrap();
    let (inbound, outbound) = queues(&server_budget);
    let engine = Server::new(HEAD, BODY, TURN, &outbound, &server_budget).unwrap();
    let tls = Tls::server(&server_config(&[]), engine, (inbound, outbound), TLS, &server_budget).unwrap();
    let (inbound, outbound) = queues(&server_budget);
    let mut server = Connection::new(tls, inbound, outbound, Some(CLOCK)).unwrap();
    let (mut near, mut far) = (
        Tcp::new(near, tls_pool(&client_budget)).unwrap(),
        Tcp::new(far, tls_pool(&server_budget)).unwrap(),
    );

    let (tls, _) = client.parts();
    let (engine, outbound) = tls.parts();
    let close = Field::new(b"connection", b"close").unwrap();
    let head = Backing::from(Vec::with_capacity(256));
    let (target, authority) = (Target::new(b"/").unwrap(), Authority::new(b"server.test").unwrap());
    engine
        .request(
            outbound,
            Method::GET,
            target,
            authority,
            &[close],
            Framing::Length(0),
            head,
        )
        .unwrap();
    engine.finish(outbound).unwrap();
    let clock = Clock::new();
    let mut body = Vec::new();
    loop {
        clock.guard();
        while let Some(event) = server.drive(Some(clock.now())).unwrap() {
            if let ServerEvent::End(_) = event {
                let (tls, _) = server.parts();
                let (engine, outbound) = tls.parts();
                let head = Backing::from(Vec::with_capacity(256));
                engine
                    .respond(outbound, Status::new(200).unwrap(), &[], Framing::Length(5), head)
                    .unwrap();
                engine.send(outbound, &Lease::from(b"hello".to_vec())).unwrap();
                engine.finish(outbound).unwrap();
            }
        }
        while let Some(event) = client.drive(Some(clock.now())).unwrap() {
            if let ClientEvent::Data(data) = event {
                body.extend_from_slice(data.bytes());
            }
        }
        if (pump(&mut near, &mut client), pump(&mut far, &mut server)) == (Next::Released, Next::Released) {
            break;
        }
    }
    assert_eq!((client.release(), server.release()), (Some(Ok(())), Some(Ok(()))));
    assert_eq!(body, b"hello");
    for copies in [client.parts().0.copies(), server.parts().0.copies()] {
        assert_eq!(Copies { encrypted: 0, ..copies }, Copies::default());
        assert!(copies.encrypted > 0);
    }
}

/// A TLS stream over its sockets carries a query to the server and its answer back. The answer
/// ends `Complete` at the `close_notify` of the server, and both ends release.
#[test]
fn a_tls_stream_through_its_sockets_carries_bytes_each_way_and_ends_complete() {
    let (near, far) = sockets();
    let limits = StreamLimits {
        tls: TLS,
        queue: QUEUE,
        handshake_timeout: Some(GUARD),
    };
    let (client_config, server_config) = (client_config(&[b"db"]), server_config(&[b"db"]));
    let mut client = Stream::connect(&client_config, "server.test", limits, CLOCK, &budget()).unwrap();
    let mut server = Stream::accept(&server_config, limits, CLOCK, &budget()).unwrap();
    let (mut near, mut far) = (
        Tcp::new(near, tls_pool(&budget())).unwrap(),
        Tcp::new(far, tls_pool(&budget())).unwrap(),
    );
    let clock = Clock::new();
    // The query: 128000 bytes in parts of 4000 bytes, more parts than the output queue holds.
    let part = Lease::from(vec![b'?'; 4000]);
    let (parts, query) = (32, vec![b'?'; 32 * 4000]);
    let (mut asked, mut answer, mut end, mut closed, mut sent) = (Vec::new(), Vec::new(), None, false, 0);
    loop {
        clock.guard();
        let now = clock.now();
        while sent < parts && written(client.write(&part, now)) {
            sent += 1;
        }
        while !closed && let Some(part) = server.next(now).unwrap() {
            match part {
                Part::Data(data) => asked.extend_from_slice(data.bytes()),
                Part::End(outcome) => panic!("the query ended {outcome:?}"),
            }
        }
        if asked.len() == query.len() && !closed {
            server.write(&Lease::from(b"42".to_vec()), now).unwrap();
            server.close(now).unwrap();
            closed = true;
        }
        server.drive(now).unwrap();
        while end.is_none()
            && let Some(part) = client.next(now).unwrap()
        {
            match part {
                Part::Data(data) => answer.extend_from_slice(data.bytes()),
                Part::End(outcome) => {
                    end = Some(outcome);
                    client.close(now).unwrap();
                }
            }
        }
        client.drive(now).unwrap();
        if (pump(&mut near, &mut client), pump(&mut far, &mut server)) == (Next::Released, Next::Released) {
            break;
        }
    }
    assert_eq!((client.release(), server.release()), (Some(Ok(())), Some(Ok(()))));
    assert_eq!((asked, answer), (query, b"42".to_vec()));
    assert_matches!(end, Some(Outcome::Complete(None)));
    assert!(near.close(&client).is_empty());
    assert!(far.close(&server).is_empty());
}

/// A plain server connection of the core with its socket, and the raw socket of its peer. The
/// peer sent a request with `connection: close`, and the server queued a response of 64 MiB and
/// ended. The peer read nothing, so the socket is full and waits to write. Gives the bytes of the
/// response.
fn filled(clock: &Clock) -> (Connection<Server>, Tcp, TcpStream, usize) {
    let (near, mut peer) = sockets();
    let budget = budget();
    let (inbound, outbound) = (
        Inbound::new(QUEUE, &budget).unwrap(),
        Outbound::new(QUEUE, &budget).unwrap(),
    );
    let engine = Server::new(HEAD, BODY, TURN, &outbound, &budget).unwrap();
    let mut server = Connection::new(engine, inbound, outbound, Some(CLOCK)).unwrap();
    let mut socket = Tcp::new(near, pool(&budget)).unwrap();
    peer.write_all(b"GET / HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n")
        .unwrap();
    peer.set_nonblocking(true).unwrap();
    let part = Lease::from(vec![b'x'; LARGE_PART]);
    let length = LARGE_PARTS * LARGE_PART;
    let mut answered = false;
    while !answered {
        clock.guard();
        while let Some(event) = server.drive(Some(clock.now())).unwrap() {
            if let ServerEvent::End(_) = event {
                let (engine, outbound) = server.parts();
                let head = Backing::from(Vec::with_capacity(256));
                let framing = Framing::Length(length as u64);
                engine
                    .respond(outbound, Status::new(200).unwrap(), &[], framing, head)
                    .unwrap();
                for _ in 0..LARGE_PARTS {
                    engine.send(outbound, &part).unwrap();
                }
                engine.finish(outbound).unwrap();
                answered = true;
            }
        }
        pump(&mut socket, &mut server);
    }
    loop {
        clock.guard();
        server.drive(Some(clock.now())).unwrap();
        match pump(&mut socket, &mut server) {
            Next::Wait { write: true, .. } => break,
            Next::Released => panic!("the connection released with its output in the socket"),
            Next::Now | Next::Wait { .. } => {}
        }
    }
    assert_eq!(
        server.wait(),
        Wait::Ended(Ok(())),
        "the engine ended with its output queued"
    );
    let head = b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 67108864\r\n\r\n".len();
    (server, socket, peer, head + length)
}

/// Reads `peer` until the end of the stream or a failure, and gives the bytes and the failure.
fn read_to_end(peer: &mut TcpStream, clock: &Clock) -> (usize, Option<ErrorKind>) {
    let mut bytes = vec![0; 1 << 16];
    let mut count = 0;
    loop {
        clock.guard();
        match peer.read(&mut bytes) {
            Ok(0) => return (count, None),
            Ok(read) => count += read,
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(error) => return (count, Some(error.kind())),
        }
    }
}

/// An engine that ended with 64 MiB of output, more than the socket buffers hold, does not release
/// while its peer reads nothing. When the peer reads, the connection releases after the socket
/// accepted each byte, and the peer reads each byte and then the end of the stream.
#[test]
fn a_connection_releases_only_after_its_socket_accepted_each_byte_of_its_output() {
    let clock = Clock::new();
    let (mut server, mut socket, mut peer, total) = filled(&clock);
    assert!(server.release().is_none());
    assert!(server.outstanding().bytes > 0);
    let mut bytes = vec![0; 1 << 16];
    let mut read = 0;
    while pump(&mut socket, &mut server) != Next::Released {
        clock.guard();
        match peer.read(&mut bytes) {
            Ok(count) => {
                assert!(count > 0, "the stream ended before the release");
                read += count;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(server.release(), Some(Ok(())));
    assert!(socket.close(&server).is_empty());
    let (rest, failure) = read_to_end(&mut peer, &clock);
    assert_eq!((read + rest, failure), (total, None));
}

/// A close before the release reports the output that the socket did not accept, and resets the
/// connection: the peer reads part of the response and then a reset, never the end of the stream.
#[test]
fn a_close_before_the_release_reports_the_output_that_did_not_go_and_resets_the_peer() {
    let clock = Clock::new();
    let (server, socket, mut peer, total) = filled(&clock);
    let outstanding = socket.close(&server);
    assert_eq!(outstanding, server.outstanding());
    assert!(outstanding.bytes > 0);
    // A lost reset is not sent again. The FIN of the peer is, and a connection that ended with a
    // reset answers it with a reset. A connection that ended with its own FIN takes it. When the
    // reset came first, the socket of the peer is not connected.
    match peer.shutdown(Shutdown::Write) {
        Err(error) if error.kind() != ErrorKind::NotConnected => panic!("{error}"),
        Ok(()) | Err(_) => {}
    }
    let (read, failure) = read_to_end(&mut peer, &clock);
    assert_eq!(failure, Some(ErrorKind::ConnectionReset));
    assert!(read as u64 + outstanding.bytes <= total as u64);
}

/// A plain client reads a response head with `content-length: 100` and 10 bytes of its body. Then
/// its peer ends the stream, or resets the connection: the socket gives the end of input and the
/// body ends `Truncated`, or it gives the reset and the body ends `Reset`.
#[test]
fn the_end_of_the_stream_ends_a_body_truncated_and_a_reset_ends_it_reset() {
    for reset in [false, true] {
        let clock = Clock::new();
        let (near, mut peer) = sockets();
        let budget = budget();
        let mut client = client::Http1::plain(CLIENT, CLOCK, &budget).unwrap();
        let mut socket = Tcp::new(near, pool(&budget)).unwrap();
        let request = Request {
            method: Method::GET,
            target: Target::new(b"/").unwrap(),
            authority: Authority::new(b"a").unwrap(),
            fields: &[],
            length: Some(0),
        };
        assert!(client.send(&request, clock.deadline(), clock.now()).unwrap());
        pump(&mut socket, &mut client);
        let mut request = [0; 64];
        let count = peer.read(&mut request).unwrap();
        assert!(request[..count].ends_with(b"\r\n\r\n"), "one read takes the request");
        peer.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n0123456789")
            .unwrap();
        if reset {
            peer.set_linger(Some(Duration::ZERO)).unwrap();
            drop(peer);
        } else {
            peer.shutdown(Shutdown::Write).unwrap();
        }
        let mut head = None;
        let end = loop {
            clock.guard();
            if head.is_none() {
                head = client.response(clock.now()).unwrap();
            }
            if head.is_some()
                && let Some(Part::End(outcome)) = client.next(clock.now()).unwrap()
            {
                break outcome;
            }
            pump(&mut socket, &mut client);
        };
        if reset {
            assert_matches!(end, Outcome::Reset(None));
        } else {
            assert_matches!(end, Outcome::Truncated);
        }
    }
}

/// A server answers 413 and does not read a body of 100000 bytes, so it closes and lingers. At the
/// linger, the socket half-closes: the peer reads the response and then the end of the stream
/// while the server still lingers. The end of input of the peer then ends the linger.
#[test]
fn at_the_linger_the_socket_half_closes_so_the_peer_reads_the_response_and_its_end() {
    let clock = Clock::new();
    let (near, mut peer) = sockets();
    let budget = budget();
    let mut server = server::Http::plain(SERVER, CLOCK, &budget).unwrap();
    let mut socket = Tcp::new(near, pool(&budget)).unwrap();
    peer.write_all(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 100000\r\n\r\nfirst bytes")
        .unwrap();
    peer.set_nonblocking(true).unwrap();
    let stream = loop {
        if let Some((stream, _)) = server.request(clock.now()).unwrap() {
            break stream;
        }
        clock.guard();
        pump(&mut socket, &mut server);
    };
    let too_large = Response {
        status: Status::new(413).unwrap(),
        fields: &[],
        length: Some(0),
    };
    assert!(server.respond(stream, &too_large, clock.now()).unwrap());
    let mut response = Vec::new();
    let mut bytes = [0; 1024];
    loop {
        clock.guard();
        assert!(server.request(clock.now()).unwrap().is_none());
        assert_ne!(pump(&mut socket, &mut server), Next::Released);
        match peer.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => panic!("{error}"),
        }
    }
    assert!(
        matches!(server.wait(), Wait::Linger { .. }),
        "the end came during the linger"
    );
    assert!(response.starts_with(b"HTTP/1.1 413 \r\n"));
    peer.write_all(b"late bytes").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    while pump(&mut socket, &mut server) != Next::Released {
        clock.guard();
        assert!(server.request(clock.now()).unwrap().is_none());
    }
    assert_eq!(server.release().map(|closed| closed.result), Some(Ok(())));
}

/// A client that keeps the views of the body that it read holds each slot of a pool of two. The
/// socket then waits for no event of the socket, so a poller does not wake for bytes that it
/// cannot read. When the client drops the views, the socket reads the rest.
#[test]
fn a_socket_whose_pool_is_in_use_waits_for_no_event_until_the_views_drop() {
    let clock = Clock::new();
    let (near, mut peer) = sockets();
    let budget = budget();
    let mut client = client::Http1::plain(CLIENT, CLOCK, &budget).unwrap();
    let slot = Layout::array::<u8>(64).unwrap();
    let pool = Pool::new(&budget, NonZeroU32::new(2).unwrap(), slot).unwrap();
    let mut socket = Tcp::new(near, pool).unwrap();
    let request = Request {
        method: Method::GET,
        target: Target::new(b"/").unwrap(),
        authority: Authority::new(b"a").unwrap(),
        fields: &[],
        length: Some(0),
    };
    assert!(client.send(&request, clock.deadline(), clock.now()).unwrap());
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n";
    peer.write_all(head).unwrap();
    peer.write_all(&[b'b'; 1000]).unwrap();
    let mut kept = Vec::new();
    let mut response = None;
    loop {
        clock.guard();
        if response.is_none() {
            response = client.response(clock.now()).unwrap();
        }
        while response.is_some()
            && let Some(Part::Data(data)) = client.next(clock.now()).unwrap()
        {
            kept.push(data);
        }
        // Only the views that the client keeps can free a slot: the socket waits for no event.
        if let Next::Wait {
            read: false,
            write: false,
            ..
        } = pump(&mut socket, &mut client)
        {
            break;
        }
    }
    assert!(
        client.delivered() < 1000,
        "the slots that the client holds stop the body"
    );
    drop((kept, response));
    let mut body = 0;
    loop {
        clock.guard();
        match client.next(clock.now()).unwrap() {
            Some(Part::Data(data)) => body += data.initialized(),
            Some(Part::End(outcome)) => {
                assert_matches!(outcome, Outcome::Complete(None));
                break;
            }
            None => {
                pump(&mut socket, &mut client);
            }
        }
    }
    assert!(body > 0 && client.delivered() == 1000);
}
