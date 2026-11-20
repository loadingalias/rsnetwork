//! TLS 1.3 between an HTTP/1.1 client engine and an HTTP/1.1 server engine on the caller-driven
//! host: the negotiated group, the copies of each receive form, trust failures, mTLS, rotation,
//! resumption, and the end of input. The certificates come from `tls/generate.sh`.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Error, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits as HeadLimits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ChaCha20Rng, ClientConfig, ClientOptions, Closure, Copies, Entropy, Group, Handshake, Identity,
    Limits, PrivateKeyDer, Resumption, ServerConfig, ServerOptions, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Field, Method, Status, Target};

const CA: &[u8] = include_bytes!("tls/ca.der");
const OTHER_CA: &[u8] = include_bytes!("tls/other-ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const ROTATED: (&[u8], &[u8]) = (include_bytes!("tls/rotated.der"), include_bytes!("tls/rotated.key.der"));
const CLIENT: (&[u8], &[u8]) = (include_bytes!("tls/client.der"), include_bytes!("tls/client.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;
/// 2037-01-01, after the validity of each test certificate.
const EXPIRED: u64 = 2_114_380_800;

const BODY: &[u8] = b"hello over tls";

const HEAD: HeadLimits = HeadLimits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY_LIMITS: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1024,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

const LIMITS: Limits = Limits {
    input_bytes: 32 * 1024,
    turn: TURN,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    ecn: Ecn::NotEct,
    segment: None,
};

const SESSIONS: Resumption = Resumption::Process(NonZeroUsize::new(8).unwrap());

/// A wall clock that stays at one time.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

fn identity((chain, key): (&[u8], &[u8])) -> Identity {
    Identity {
        chain: vec![certificate(chain)],
        key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
    }
}

fn server_config(client_roots: Option<&[u8]>, resumption: Resumption) -> ServerConfig {
    let client_roots = client_roots.map(|root| [certificate(root)]);
    ServerConfig::new(ServerOptions {
        identity: identity(SERVER),
        client_roots: client_roots.as_ref().map(|roots| &roots[..]),
        protocols: &[b"http/1.1"],
        resumption,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

fn client_config(root: &[u8], identity: Option<Identity>, now: u64, resumption: Resumption) -> ClientConfig {
    ClientConfig::new(ClientOptions {
        roots: &[certificate(root)],
        identity,
        protocols: &[b"h2", b"http/1.1"],
        resumption,
        clock: Arc::new(At(now)),
        entropy: Entropy::System,
    })
    .unwrap()
}

fn clock() -> ClockDomain {
    ClockDomain::new(1, Suspend::Pauses)
}

fn now() -> Option<Instant> {
    Some(Instant::new(clock(), 0))
}

fn queues(budget: &Budget) -> (Inbound, Outbound) {
    let limit = NonZeroUsize::new(16).unwrap();
    (
        Inbound::new(limit, budget).unwrap(),
        Outbound::new(limit, budget).unwrap(),
    )
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 22).unwrap())
}

/// How the transport gives each received region to a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receive {
    /// Into the tail of the input region that the connection lends.
    Lent,
    /// In a region of the host, as a kernel-selected receive gives it.
    Host,
    /// In a read-only region, through the inbound queue.
    Queued,
}

/// A client and a server connection, each with its own budget, and the transport between them.
struct Pair {
    client: Connection<Tls<Client>>,
    server: Connection<Tls<Server>>,
    server_budget: Budget,
    /// How each end receives.
    receive: Receive,
    /// The number of received regions that each output reaches the peer in, one in each round.
    parts: usize,
    /// The received regions that wait for their round, toward the client and toward the server.
    to_client: VecDeque<Vec<u8>>,
    to_server: VecDeque<Vec<u8>>,
    /// Each received region, in the order of the transport.
    transcript: Vec<u8>,
    /// The response body that the client received, and whether the response ended.
    body: Vec<u8>,
    ended: bool,
}

impl Pair {
    fn new(client: &ClientConfig, name: &str, server: &ServerConfig) -> Self {
        let (client_budget, server_budget) = (budget(), budget());
        let (inbound, outbound) = queues(&client_budget);
        let engine = Client::new(HEAD, BODY_LIMITS, TURN, &outbound, &client_budget).unwrap();
        let tls = Tls::client(client, name, engine, (inbound, outbound), LIMITS, &client_budget).unwrap();
        let (inbound, outbound) = queues(&client_budget);
        let client = Connection::new(tls, inbound, outbound, Some(clock())).unwrap();
        let (inbound, outbound) = queues(&server_budget);
        let engine = Server::new(HEAD, BODY_LIMITS, TURN, &outbound, &server_budget).unwrap();
        let tls = Tls::server(server, engine, (inbound, outbound), LIMITS, &server_budget).unwrap();
        let (inbound, outbound) = queues(&server_budget);
        let server = Connection::new(tls, inbound, outbound, Some(clock())).unwrap();
        Self {
            client,
            server,
            server_budget,
            receive: Receive::Lent,
            parts: 1,
            to_client: VecDeque::new(),
            to_server: VecDeque::new(),
            transcript: Vec::new(),
            body: Vec::new(),
            ended: false,
        }
    }

    /// Queues a GET request with `fields` on the client.
    fn request(&mut self, fields: &[Field<'_>]) {
        let (tls, _) = self.client.parts();
        let (client, outbound) = tls.parts();
        client
            .request(
                outbound,
                Method::GET,
                Target::new(b"/").unwrap(),
                Authority::new(b"server.test").unwrap(),
                fields,
                Framing::Length(0),
                Backing::from(Vec::with_capacity(256)),
            )
            .unwrap();
        client.finish(outbound).unwrap();
    }

    /// Drives both ends and moves their output, one received region in each direction in each
    /// round, until no byte moves.
    fn run(&mut self) {
        for _ in 0..1024 {
            drive(&mut self.server, |server, event| {
                if let ServerEvent::Request(_) = event {
                    let (tls, _) = server.parts();
                    let (server, outbound) = tls.parts();
                    let head = Backing::from(Vec::with_capacity(256));
                    let length = Framing::Length(BODY.len() as u64);
                    server
                        .respond(outbound, Status::new(200).unwrap(), &[], length, head)
                        .unwrap();
                    server.send(outbound, &Lease::from(BODY.to_vec())).unwrap();
                    server.finish(outbound).unwrap();
                }
            });
            let (body, ended) = (&mut self.body, &mut self.ended);
            drive(&mut self.client, |_, event| match event {
                ClientEvent::Data(data) => body.extend_from_slice(data.bytes()),
                ClientEvent::End(_) => *ended = true,
                _ => {}
            });
            take(&mut self.server, &mut self.to_client, self.parts);
            take(&mut self.client, &mut self.to_server, self.parts);
            let moved = [
                self.to_client.pop_front().map(|part| {
                    self.transcript.extend_from_slice(&part);
                    give(&mut self.client, &part, self.receive);
                }),
                self.to_server.pop_front().map(|part| {
                    self.transcript.extend_from_slice(&part);
                    give(&mut self.server, &part, self.receive);
                }),
            ];
            if moved == [None, None] {
                return;
            }
        }
        panic!("the connections still move bytes after 1024 rounds");
    }

    fn client_error(&self) -> Option<Error> {
        match self.client.wait() {
            Wait::Ended(Err(error)) => Some(error),
            _ => None,
        }
    }

    fn server_error(&self) -> Option<Error> {
        match self.server.wait() {
            Wait::Ended(Err(error)) => Some(error),
            _ => None,
        }
    }
}

/// Drives `connection` until it waits, and gives each event to `on`.
fn drive<E: Engine>(connection: &mut Connection<E>, mut on: impl FnMut(&mut Connection<E>, E::Event)) {
    for _ in 0..1024 {
        match connection.drive(now()).unwrap() {
            Some(event) => on(connection, event),
            None if connection.wait() != Wait::Now => return,
            None => {}
        }
    }
    panic!("the connection did not wait after 1024 drives");
}

/// Takes each output of `from` in `parts` received regions for its peer, and acknowledges it.
fn take<A: Engine>(from: &mut Connection<A>, to: &mut VecDeque<Vec<u8>>, parts: usize) {
    while let Some(output) = from.output() {
        let bytes = output.region.bytes();
        to.extend(bytes.chunks(bytes.len().div_ceil(parts)).map(<[u8]>::to_vec));
        from.ack(output.id, bytes.len()).unwrap();
    }
}

/// Gives `bytes` to `to` as one received region of the form `receive`.
fn give<B: Engine>(to: &mut Connection<B>, mut bytes: &[u8], receive: Receive) {
    match receive {
        Receive::Lent => {
            while !bytes.is_empty() {
                let mut loan = WriteLoan::new(to.region().unwrap().unwrap());
                let added = loan.fill_from(bytes);
                to.received(loan.into_inner(), ENDPOINT, 1 << 20).unwrap();
                bytes = &bytes[added..];
            }
        }
        Receive::Host => to.received(Backing::from(bytes.to_vec()), ENDPOINT, 1 << 20).unwrap(),
        Receive::Queued => to
            .receive(Received {
                region: Lease::from(bytes.to_vec()),
                endpoint: ENDPOINT,
                capacity: 1 << 20,
            })
            .unwrap(),
    }
}

fn copies(pair: &mut Pair) -> (Copies, Copies) {
    (pair.client.parts().0.copies(), pair.server.parts().0.copies())
}

#[test]
fn a_request_negotiates_x25519mlkem768_with_no_copy_but_encryption_and_leaves_no_region_when_idle() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    let mut pair = Pair::new(&client, "server.test", &server);
    let server_idle = pair.server_budget.available();
    pair.request(&[]);
    pair.run();
    assert_eq!((pair.client_error(), pair.server_error()), (None, None));
    assert_eq!(pair.body, BODY);
    assert!(pair.ended);
    for negotiated in [pair.client.parts().0.negotiated(), pair.server.parts().0.negotiated()] {
        let negotiated = negotiated.unwrap();
        assert_eq!(negotiated.group, Group::X25519_MLKEM768);
        assert_eq!(negotiated.protocol, Some(&b"http/1.1"[..]));
        assert_eq!(negotiated.handshake, Handshake::Full);
    }
    // Decryption in place copies nothing: only encryption writes each sent byte once.
    let (client_copies, server_copies) = copies(&mut pair);
    for copies in [client_copies, server_copies] {
        assert_eq!(Copies { encrypted: 0, ..copies }, Copies::default());
        assert!(copies.encrypted > 0);
    }
    // The idle server holds no input region and no output: its budget is back where it started.
    assert_eq!(pair.server_budget.available(), server_idle);
}

#[test]
fn a_record_split_across_two_regions_decrypts_and_copies_at_most_the_rest_of_one_record() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    for receive in [Receive::Lent, Receive::Host] {
        let mut pair = Pair::new(&client, "server.test", &server);
        pair.request(&[]);
        pair.run();
        // A second request, whose response record arrives in two regions.
        pair.body.clear();
        pair.ended = false;
        let before = copies(&mut pair).0;
        pair.receive = receive;
        pair.parts = 2;
        pair.request(&[]);
        pair.run();
        assert_eq!(pair.client_error(), None, "{receive:?}");
        assert_eq!(pair.body, BODY, "{receive:?}");
        let partial = copies(&mut pair).0.partial - before.partial;
        match receive {
            // The second half arrives in the tail of the same region.
            Receive::Lent => assert_eq!(partial, 0),
            // The rest of the record moves from the second region: less than one record.
            _ => assert!(
                partial > 0 && partial < rsnetwork::tls::RECORD_BYTES_MAX as u64,
                "{partial}"
            ),
        }
    }
}

#[test]
fn an_expired_wrong_name_or_unknown_root_certificate_refuses_with_a_trust_error() {
    let server = server_config(None, Resumption::Off);
    let cases = [
        (
            client_config(CA, None, EXPIRED, Resumption::Off),
            "server.test",
            "the peer certificate expired",
        ),
        (
            client_config(CA, None, VALID, Resumption::Off),
            "other.test",
            "the peer certificate is not valid for its name",
        ),
        (
            client_config(OTHER_CA, None, VALID, Resumption::Off),
            "server.test",
            "the peer certificate chain reaches no trusted root",
        ),
    ];
    for (client, name, reason) in cases {
        let mut pair = Pair::new(&client, name, &server);
        pair.run();
        let error = pair.client_error().unwrap();
        assert_eq!((error.kind(), error.reason()), (Kind::Trust, reason));
        assert_eq!(pair.client.parts().0.negotiated(), None);
    }
}

#[test]
fn a_server_that_requires_a_client_certificate_accepts_its_chain_and_refuses_a_client_with_none() {
    let server = server_config(Some(CA), Resumption::Off);
    let mut pair = Pair::new(
        &client_config(CA, Some(identity(CLIENT)), VALID, Resumption::Off),
        "server.test",
        &server,
    );
    pair.request(&[]);
    pair.run();
    assert_eq!((pair.client_error(), pair.server_error()), (None, None));
    assert_eq!(pair.body, BODY);

    let mut pair = Pair::new(&client_config(CA, None, VALID, Resumption::Off), "server.test", &server);
    pair.request(&[]);
    pair.run();
    let error = pair.server_error().unwrap();
    assert_eq!(error.kind(), Kind::Trust);
    assert!(pair.body.is_empty());
}

#[test]
fn a_rotated_identity_serves_each_later_handshake_and_a_mismatched_key_keeps_the_old_one() {
    let server = server_config(None, Resumption::Off);
    let client = client_config(CA, None, VALID, Resumption::Off);
    let handshake = |name: &str| {
        let mut pair = Pair::new(&client, name, &server);
        pair.run();
        pair.client_error()
    };
    assert_eq!(handshake("rotated.test").map(|error| error.kind()), Some(Kind::Trust));

    let error = server
        .rotate(Identity {
            chain: vec![certificate(ROTATED.0)],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        })
        .unwrap_err();
    assert_eq!(error.reason(), "the private key does not match the certificate");
    assert_eq!(handshake("server.test"), None);

    server.rotate(identity(ROTATED)).unwrap();
    assert_eq!(handshake("rotated.test"), None);
    assert_eq!(handshake("server.test").map(|error| error.kind()), Some(Kind::Trust));
}

#[test]
fn a_second_connection_of_the_same_process_resumes_its_session() {
    let (client, server) = (client_config(CA, None, VALID, SESSIONS), server_config(None, SESSIONS));
    assert_eq!((client.resumption(), server.resumption()), (SESSIONS, SESSIONS));
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let mut pair = Pair::new(&client, "server.test", &server);
        pair.request(&[]);
        pair.run();
        assert_eq!(pair.body, BODY);
        kinds.push(pair.client.parts().0.negotiated().unwrap().handshake);
    }
    assert_eq!(kinds, [Handshake::Full, Handshake::Resumed]);
}

#[test]
fn the_end_of_input_tells_a_close_notify_from_a_transport_end_without_one() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    // The server closes after its response, and sends close_notify.
    let mut pair = Pair::new(&client, "server.test", &server);
    pair.receive = Receive::Queued;
    pair.request(&[Field::new(b"connection", b"close").unwrap()]);
    pair.run();
    assert_eq!(pair.body, BODY);
    assert_eq!(pair.client.parts().0.closure(), Some(Closure::Notified));
    // Each received byte came in a read-only region, so decryption needed a writable copy.
    assert!(pair.client.parts().0.copies().received > 0);

    // The transport ends with no close_notify.
    let mut pair = Pair::new(&client, "server.test", &server);
    pair.request(&[]);
    pair.run();
    pair.client.end_input();
    pair.run();
    assert_eq!(pair.client.parts().0.closure(), Some(Closure::Unnotified));

    // The transport ends inside a record: the input cannot complete, so the connection ends.
    let mut pair = Pair::new(&client, "server.test", &server);
    pair.request(&[]);
    pair.run();
    pair.request(&[]);
    drive(&mut pair.client, |_, _| {});
    let mut request = VecDeque::new();
    take(&mut pair.client, &mut request, 1);
    give(&mut pair.server, &request[0], Receive::Lent);
    drive(&mut pair.server, |server, event| {
        if let ServerEvent::Request(_) = event {
            let (tls, _) = server.parts();
            let (server, outbound) = tls.parts();
            let head = Backing::from(Vec::with_capacity(256));
            server
                .respond(outbound, Status::new(204).unwrap(), &[], Framing::Length(0), head)
                .unwrap();
            server.finish(outbound).unwrap();
        }
    });
    let output = pair.server.output().unwrap();
    let bytes = output.region.bytes();
    give(&mut pair.client, &bytes[..bytes.len() / 2], Receive::Lent);
    pair.client.end_input();
    drive(&mut pair.client, |_, _| {});
    let error = pair.client_error().unwrap();
    assert_eq!(
        (error.kind(), error.reason()),
        (Kind::Partial, "the transport ended inside a TLS record")
    );
}

#[test]
fn a_certificate_chain_larger_than_one_record_completes_when_it_arrives_in_parts() {
    // Unused copies of the root make the Certificate message span two records.
    let mut chain = vec![certificate(SERVER.0)];
    chain.extend((0..45).map(|_| certificate(CA)));
    assert!(chain.iter().map(|certificate| certificate.len()).sum::<usize>() > 1 << 14);
    let server = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain,
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"http/1.1"],
        resumption: Resumption::Off,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let client = client_config(CA, None, VALID, Resumption::Off);
    let mut pair = Pair::new(&client, "server.test", &server);
    // In parts of about 1 KiB, a received region ends after the first record of the message and
    // before its last: rustls keeps the complete record until the rest comes.
    pair.parts = 20;
    pair.request(&[]);
    pair.run();
    assert_eq!((pair.client_error(), pair.server_error()), (None, None));
    assert_eq!(pair.body, BODY);
}

#[test]
fn a_seeded_run_replays_each_byte_of_its_handshake_and_request() {
    let run = |seed: u8| {
        let root = ChaCha20Rng::from_seed([seed; ChaCha20Rng::SEED_SIZE]);
        let client = ClientConfig::new(ClientOptions {
            roots: &[certificate(CA)],
            identity: None,
            protocols: &[b"http/1.1"],
            resumption: Resumption::Off,
            clock: Arc::new(At(VALID)),
            entropy: Entropy::Seeded(root.child(b"client\0\0", 0)),
        })
        .unwrap();
        let server = ServerConfig::new(ServerOptions {
            identity: identity(SERVER),
            client_roots: None,
            protocols: &[b"http/1.1"],
            resumption: Resumption::Off,
            clock: Arc::new(At(VALID)),
            entropy: Entropy::Seeded(root.child(b"server\0\0", 0)),
        })
        .unwrap();
        let mut pair = Pair::new(&client, "server.test", &server);
        pair.request(&[]);
        pair.run();
        assert_eq!(pair.body, BODY);
        pair.transcript
    };
    let first = run(1);
    assert!(first.len() > 1000);
    assert_eq!(first, run(1));
    // Another seed gives other bytes, so the seed and not a constant made them.
    assert_ne!(first, run(2));
}
