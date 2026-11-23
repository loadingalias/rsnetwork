//! TLS 1.3 between an HTTP/1.1 client engine and an HTTP/1.1 server engine on the caller-driven
//! host: the negotiated group, the copies of each receive form, trust failures, mTLS, rotation,
//! resumption, and the end of input. An unmodified rustls server is the independent peer of the
//! record layer of the core: its suites, KeyUpdates, session tickets, and refused records. The
//! certificates come from `tls/generate.sh`.

use core::alloc::Layout;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use rscrypto::aead::Nonce96;
use rscrypto::aead::expert::AeadWithNonce as _;
use rscrypto::{Aes128Gcm, Aes128GcmKey};
use rscrypto_rustls::cipher_suite::{
    TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
};
use rustls::crypto::cipher::OutboundPlain;
use rustls::crypto::{CryptoProvider, Identity as Chain};
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets, ServerSide, Tcp, Tls13CipherSuite, VecInput};

use rsnetwork::buffer::{Backing, Buffer as _, BufferMut as _, Lease, Pool, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Error, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits as HeadLimits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    Authentication, CertificateDer, ChaCha20Rng, ClientConfig, ClientOptions, Closure, Copies, Entropy, Group,
    Handshake, Identity, Limits, PrivateKeyDer, Resumption, ServerConfig, ServerOptions, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Field, Method, Status, Target};

const CA: &[u8] = include_bytes!("tls/ca.der");
const OTHER_CA: &[u8] = include_bytes!("tls/other-ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const ROTATED: (&[u8], &[u8]) = (include_bytes!("tls/rotated.der"), include_bytes!("tls/rotated.key.der"));
const CLIENT: (&[u8], &[u8]) = (include_bytes!("tls/client.der"), include_bytes!("tls/client.key.der"));
// An ML-DSA-65 root and intermediate, and a leaf for `server.test` with each parameter set.
const MLDSA_CA: &[u8] = include_bytes!("tls/mldsa-ca.der");
const MLDSA_INTERMEDIATE: &[u8] = include_bytes!("tls/mldsa-intermediate.der");
const MLDSA44: (&[u8], &[u8]) = (include_bytes!("tls/mldsa44.der"), include_bytes!("tls/mldsa44.key.der"));
const MLDSA65: (&[u8], &[u8]) = (include_bytes!("tls/mldsa65.der"), include_bytes!("tls/mldsa65.key.der"));
const MLDSA87: (&[u8], &[u8]) = (include_bytes!("tls/mldsa87.der"), include_bytes!("tls/mldsa87.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;
/// 2037-01-01, after the validity of each test certificate.
const EXPIRED: u64 = 2_114_380_800;

const BODY: &[u8] = b"hello over tls";
/// The record of `BODY`: its header, the body, its content type, and its tag.
const BODY_RECORD: usize = 5 + BODY.len() + 1 + 16;

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
    key_records_max: u64::MAX,
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
        budget: &budget(),
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
        budget: &budget(),
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

/// A client connection to the server `name`, with its own budget.
fn client(config: &ClientConfig, name: &str, limits: Limits) -> Connection<Tls<Client>> {
    client_with_queue(config, name, limits, 16)
}

/// A client connection whose engine takes at most `places` plaintext regions at a time.
fn client_with_queue(config: &ClientConfig, name: &str, limits: Limits, places: usize) -> Connection<Tls<Client>> {
    let budget = budget();
    let inbound = Inbound::new(NonZeroUsize::new(places).unwrap(), &budget).unwrap();
    let outbound = Outbound::new(NonZeroUsize::new(16).unwrap(), &budget).unwrap();
    let engine = Client::new(HEAD, BODY_LIMITS, TURN, &outbound, &budget).unwrap();
    let tls = Tls::client(config, name, engine, (inbound, outbound), limits, &budget).unwrap();
    let (inbound, outbound) = queues(&budget);
    Connection::new(tls, inbound, outbound, Some(clock())).unwrap()
}

/// Queues a GET request with `fields` on `client`.
fn request(client: &mut Connection<Tls<Client>>, fields: &[Field<'_>]) {
    let (tls, _) = client.parts();
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

impl Pair {
    fn new(client_config: &ClientConfig, name: &str, server: &ServerConfig) -> Self {
        let server_budget = budget();
        let client = client(client_config, name, LIMITS);
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
        request(&mut self.client, fields);
    }

    /// Drives both ends and moves their output, one received region in each direction in each
    /// round, until no byte moves.
    fn run(&mut self) {
        for _ in 0..1024 {
            drive(&mut self.server, answer);
            self.drive_client();
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

    /// Drives the client until it waits, and keeps the body and the end of its response.
    fn drive_client(&mut self) {
        let (body, ended) = (&mut self.body, &mut self.ended);
        drive(&mut self.client, |_, event| match event {
            ClientEvent::Data(data) => body.extend_from_slice(data.bytes()),
            ClientEvent::End(_) => *ended = true,
            _ => {}
        });
    }

    /// Sends a GET request to the server, and gives the ciphertext of its response, which the
    /// client has not received. The body of the response is its last record.
    fn response(&mut self) -> Vec<u8> {
        self.body.clear();
        self.ended = false;
        self.request(&[]);
        drive(&mut self.client, |_, _| {});
        let mut to_server = VecDeque::new();
        take(&mut self.client, &mut to_server, 1);
        for part in to_server {
            give(&mut self.server, &part, Receive::Lent);
        }
        drive(&mut self.server, answer);
        let mut to_client = VecDeque::new();
        take(&mut self.server, &mut to_client, 1);
        let response: Vec<u8> = to_client.into_iter().flatten().collect();
        // The header of the last record: application data of `BODY_RECORD` bytes.
        let body = response.len() - BODY_RECORD;
        let [high, low] = u16::try_from(BODY_RECORD - 5).unwrap().to_be_bytes();
        assert_eq!(response[body..body + 5], [23, 3, 3, high, low]);
        response
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

/// Answers each request with `BODY`.
fn answer(server: &mut Connection<Tls<Server>>, event: ServerEvent) {
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
    // After the handshake, the server is idle: it keeps the state of its kernel connection.
    pair.run();
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
    // The idle server holds no input region and no output: its budget is back where it was
    // before the request.
    assert_eq!(pair.server_budget.available(), server_idle);
}

#[test]
fn a_response_sealed_into_a_pool_slot_of_the_host_is_at_its_address_with_no_copy_but_encryption() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    let mut pair = Pair::new(&client, "server.test", &server);
    pair.run();
    // A pool of the host on the budget of the server, with one slot of 4 KiB.
    let mut pool = Pool::new(&pair.server_budget, NonZeroU32::MIN, Layout::array::<u8>(4096).unwrap()).unwrap();
    let slot = pool.acquire().unwrap();
    let address = slot.as_ptr().addr();
    pair.server.output_region(slot).unwrap();
    pair.request(&[]);
    drive(&mut pair.client, |_, _| {});
    take(&mut pair.client, &mut pair.to_server, 1);
    while let Some(part) = pair.to_server.pop_front() {
        give(&mut pair.server, &part, Receive::Lent);
    }
    drive(&mut pair.server, answer);
    let output = pair.server.output().unwrap();
    assert_eq!(
        output.region.bytes().as_ptr().addr(),
        address,
        "the records are in the slot"
    );
    assert!(pair.server.output().is_none(), "the slot holds the whole response");
    pair.to_client.push_back(output.region.bytes().to_vec());
    pair.server.ack(output.id, output.region.initialized()).unwrap();
    drop(output);
    pair.run();
    assert_eq!((pair.client_error(), pair.server_error()), (None, None));
    assert_eq!(pair.body, BODY);
    let (_, copies) = copies(&mut pair);
    assert_eq!(Copies { encrypted: 0, ..copies }, Copies::default());
    assert!(copies.encrypted > 0);

    // With no region of the host, the engine seals into its own output.
    pair.body.clear();
    pair.request(&[]);
    drive(&mut pair.client, |_, _| {});
    take(&mut pair.client, &mut pair.to_server, 1);
    while let Some(part) = pair.to_server.pop_front() {
        give(&mut pair.server, &part, Receive::Lent);
    }
    drive(&mut pair.server, answer);
    let output = pair.server.output().unwrap();
    assert_ne!(output.region.bytes().as_ptr().addr(), address);
}

#[test]
fn a_region_of_the_host_too_small_for_a_record_of_one_byte_refuses_and_comes_back() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    let mut pair = Pair::new(&client, "server.test", &server);
    // A record of one byte of data takes its 5-byte header, the byte, its content type, and a
    // 16-byte tag: 23 bytes.
    let (error, region) = pair
        .server
        .output_region(Backing::from(Vec::with_capacity(22)))
        .unwrap_err();
    assert_eq!(error.kind(), Kind::Misuse);
    assert_eq!(region.capacity(), 22);
    pair.server
        .output_region(Backing::from(Vec::with_capacity(23)))
        .unwrap();
    assert_eq!(
        pair.server.take_output_region().map(|region| region.capacity()),
        Some(23)
    );
}

#[test]
fn a_record_split_across_two_regions_opens_in_place_with_no_copy() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    // The bytes after each seam: in the record of the head, and in the header, the body, the
    // content type, and the tag of the record of the body.
    let seams = [BODY_RECORD + 10, BODY_RECORD - 2, BODY_RECORD - 9, BODY_RECORD - 19, 3];
    for receive in [Receive::Lent, Receive::Host] {
        let mut pair = Pair::new(&client, "server.test", &server);
        pair.request(&[]);
        pair.run();
        for after in seams {
            let response = pair.response();
            let (first, second) = response.split_at(response.len() - after);
            give(&mut pair.client, first, receive);
            pair.drive_client();
            give(&mut pair.client, second, receive);
            pair.drive_client();
            let delivered = (pair.client_error(), &pair.body[..], pair.ended);
            assert_eq!(
                delivered,
                (None, BODY, true),
                "{receive:?}, {after} bytes after the seam"
            );
        }
        // Each received byte opened where it arrived: only encryption copied.
        let copied = Copies {
            encrypted: 0,
            ..copies(&mut pair).0
        };
        assert_eq!(copied, Copies::default(), "{receive:?}");
    }
}

#[test]
fn a_record_with_a_wrong_tag_in_two_regions_ends_the_connection_and_gives_no_byte_of_it() {
    let mut pair = Pair::new(
        &client_config(CA, None, VALID, Resumption::Off),
        "server.test",
        &server_config(None, Resumption::Off),
    );
    pair.request(&[]);
    pair.run();
    let mut response = pair.response();
    *response.last_mut().unwrap() ^= 1;
    // The first 4 bytes of the body are in the first region, and the client drives between the
    // regions.
    let (first, second) = response.split_at(response.len() - BODY_RECORD + 9);
    give(&mut pair.client, first, Receive::Host);
    pair.drive_client();
    give(&mut pair.client, second, Receive::Host);
    pair.drive_client();
    let error = pair.client_error().unwrap();
    assert_eq!(
        (error.kind(), error.reason()),
        (Kind::Malformed, "a TLS record failed its authentication")
    );
    assert_eq!(pair.body, b"");
}

#[test]
fn a_record_in_two_regions_reaches_an_engine_that_takes_one_region_at_a_time() {
    let (client, server) = (
        client_config(CA, None, VALID, Resumption::Off),
        server_config(None, Resumption::Off),
    );
    let mut pair = Pair::new(&client, "server.test", &server);
    pair.client = client_with_queue(&client, "server.test", LIMITS, 1);
    pair.request(&[]);
    pair.run();
    let response = pair.response();
    // The body is in both regions, so its plaintext reaches the engine as two regions.
    let (first, second) = response.split_at(response.len() - BODY_RECORD + 9);
    give(&mut pair.client, first, Receive::Host);
    pair.drive_client();
    give(&mut pair.client, second, Receive::Host);
    pair.drive_client();
    assert_eq!((pair.client_error(), &pair.body[..], pair.ended), (None, BODY, true));
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
fn each_ml_dsa_certificate_of_the_server_names_its_own_parameter_set() {
    let client = client_config(MLDSA_CA, None, VALID, Resumption::Off);
    for ((leaf, key), authentication) in [
        (MLDSA44, Authentication::MlDsa44),
        (MLDSA65, Authentication::MlDsa65),
        (MLDSA87, Authentication::MlDsa87),
    ] {
        let server = ServerConfig::new(ServerOptions {
            identity: Identity {
                chain: vec![certificate(leaf), certificate(MLDSA_INTERMEDIATE)],
                key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
            },
            client_roots: None,
            protocols: &[b"http/1.1"],
            resumption: Resumption::Off,
            budget: &budget(),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::System,
        })
        .unwrap();
        let mut pair = Pair::new(&client, "server.test", &server);
        pair.run();
        let evidence = pair.client.parts().0.negotiated().expect("the handshake completed");
        assert_eq!(
            evidence.peer,
            Some(rsnetwork::tls::Peer {
                certificate: leaf,
                authentication
            })
        );
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
fn a_session_ticket_in_two_regions_of_the_host_joins_and_resumes_the_next_connection() {
    let (client, server) = (client_config(CA, None, VALID, SESSIONS), server_config(None, SESSIONS));
    let mut first = Pair::new(&client, "server.test", &server);
    // Each output reaches the client in two regions of the host, so a ticket record is in both.
    first.receive = Receive::Host;
    first.parts = 2;
    first.request(&[]);
    first.run();
    assert_eq!(first.body, BODY);
    assert!(
        copies(&mut first).0.handshake > 0,
        "no ticket record was in two regions"
    );
    let mut second = Pair::new(&client, "server.test", &server);
    second.request(&[]);
    second.run();
    assert_eq!(
        second.client.parts().0.negotiated().unwrap().handshake,
        Handshake::Resumed
    );
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
        budget: &budget(),
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
            budget: &budget(),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::Seeded(root.child(b"client\0\0", 0)),
        })
        .unwrap();
        let server = ServerConfig::new(ServerOptions {
            identity: identity(SERVER),
            client_roots: None,
            protocols: &[b"http/1.1"],
            resumption: Resumption::Off,
            budget: &budget(),
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

/// The three suites of the provider.
const SUITES: [&Tls13CipherSuite; 3] = [
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
];

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\n\r\nhello over tls";

/// The configuration of an unmodified rustls server with one suite of the provider, records of at
/// most `fragment` bytes, and the extraction of its keys, so that a test can seal and open records
/// as the peer.
fn peer_config(suite: &'static Tls13CipherSuite, fragment: Option<usize>) -> Arc<rustls::ServerConfig> {
    let provider = CryptoProvider {
        tls13_cipher_suites: Cow::Owned(vec![suite]),
        ..rscrypto_rustls::default_provider()
    };
    let chain = Arc::new(Chain::from_cert_chain(vec![certificate(SERVER.0)]).unwrap());
    let key = PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_details(Arc::new(provider), Arc::new(At(VALID)))
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.max_fragment_size = fragment;
    config.enable_secret_extraction = true;
    Arc::new(config)
}

/// An unmodified rustls server: the independent peer of a client engine.
struct Peer {
    connection: rustls::Connection<ServerSide, Tcp>,
    input: VecInput,
    /// The application data that the peer received.
    data: Vec<u8>,
}

impl Peer {
    fn new(config: &Arc<rustls::ServerConfig>) -> Self {
        Self {
            connection: rustls::Connection::<ServerSide, Tcp>::new(Arc::clone(config)).unwrap(),
            input: VecInput::default(),
            data: Vec::new(),
        }
    }

    /// Reads the bytes of the client, and gives the bytes of the answer.
    fn receive(&mut self, mut bytes: &[u8]) -> Vec<u8> {
        while !bytes.is_empty() {
            self.input.read(&mut bytes).unwrap();
        }
        let mut answer = Vec::new();
        let mut handler = self.connection.read_tls(&mut self.input, &mut answer);
        while let Some(payload) = handler.next_payload() {
            self.data.extend_from_slice(payload.unwrap().bytes());
        }
        drop(handler);
        answer
    }

    fn send(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut records = Vec::new();
        self.connection
            .write(OutboundPlain::Single(plaintext), &mut records)
            .unwrap();
        records
    }

    /// A KeyUpdate of the peer that asks the client for one.
    fn update(&mut self) -> Vec<u8> {
        let mut records = Vec::new();
        self.connection.refresh_traffic_keys(&mut records).unwrap();
        records
    }

    /// The keys of the peer and their sequence numbers.
    fn keys(self) -> ExtractedSecrets {
        self.connection.dangerous_extract_secrets().unwrap()
    }
}

/// Moves bytes between `client` and `peer` until the client sends nothing, and adds the
/// response body that the client receives to `body`.
fn exchange(client: &mut Connection<Tls<Client>>, peer: &mut Peer, body: &mut Vec<u8>) {
    for _ in 0..1024 {
        drive(client, |_, event| {
            if let ClientEvent::Data(data) = event {
                body.extend_from_slice(data.bytes());
            }
        });
        let mut sent = VecDeque::new();
        take(client, &mut sent, 1);
        if sent.is_empty() {
            return;
        }
        for part in sent {
            let answer = peer.receive(&part);
            if !answer.is_empty() {
                give(client, &answer, Receive::Lent);
            }
        }
    }
    panic!("the client still sends after 1024 rounds");
}

/// One request of `client` and the response of `peer`.
fn round(client: &mut Connection<Tls<Client>>, peer: &mut Peer, body: &mut Vec<u8>) {
    request(client, &[]);
    exchange(client, peer, body);
    let response = peer.send(RESPONSE);
    give(client, &response, Receive::Lent);
    exchange(client, peer, body);
}

#[test]
fn a_key_update_that_the_peer_asks_for_changes_both_keys_over_each_suite() {
    let config = client_config(CA, None, VALID, Resumption::Off);
    for suite in SUITES {
        let mut peer = Peer::new(&peer_config(suite, None));
        let mut client = client(&config, "server.test", LIMITS);
        let mut body = Vec::new();
        exchange(&mut client, &mut peer, &mut body);
        round(&mut client, &mut peer, &mut body);
        // The peer changes its key and asks for a KeyUpdate. The client answers with its own.
        let update = peer.update();
        give(&mut client, &update, Receive::Lent);
        exchange(&mut client, &mut peer, &mut body);
        // The next response opens with the new key of the peer.
        round(&mut client, &mut peer, &mut body);
        assert_eq!(
            client.wait(),
            Wait::Until {
                blocked: rsnetwork::drive::Blocked::Input,
                deadline: None
            }
        );
        assert_eq!(body, [BODY, BODY].concat(), "{:?}", suite.common.suite);
        assert_eq!(peer.data.windows(6).filter(|bytes| bytes == b"GET / ").count(), 2);
        // The second request is the first record under the new key of the client.
        assert_eq!(peer.keys().rx.0, 1, "{:?}", suite.common.suite);
    }
}

#[test]
fn a_record_of_the_peer_in_two_regions_of_the_host_opens_in_place_over_each_suite() {
    let config = client_config(CA, None, VALID, Resumption::Off);
    for suite in SUITES {
        let mut peer = Peer::new(&peer_config(suite, None));
        let mut client = client(&config, "server.test", LIMITS);
        let mut body = Vec::new();
        exchange(&mut client, &mut peer, &mut body);
        request(&mut client, &[]);
        exchange(&mut client, &mut peer, &mut body);
        // The response is one record, and each region holds a half of it.
        let response = peer.send(RESPONSE);
        let (first, second) = response.split_at(response.len() / 2);
        give(&mut client, first, Receive::Host);
        exchange(&mut client, &mut peer, &mut body);
        give(&mut client, second, Receive::Host);
        exchange(&mut client, &mut peer, &mut body);
        assert_eq!(body, BODY, "{:?}", suite.common.suite);
        let copied = Copies {
            encrypted: 0,
            ..client.parts().0.copies()
        };
        assert_eq!(copied, Copies::default(), "{:?}", suite.common.suite);
    }
}

#[test]
fn a_key_at_its_record_limit_sends_a_key_update_and_the_connection_keeps_working() {
    let mut peer = Peer::new(&peer_config(TLS13_AES_128_GCM_SHA256, None));
    let limits = Limits {
        key_records_max: 2,
        ..LIMITS
    };
    let mut client = client(&client_config(CA, None, VALID, Resumption::Off), "server.test", limits);
    let mut body = Vec::new();
    exchange(&mut client, &mut peer, &mut body);
    for _ in 0..3 {
        round(&mut client, &mut peer, &mut body);
    }
    assert_eq!(body, [BODY, BODY, BODY].concat());
    // Each key seals one request and then its KeyUpdate. So the third request is the first record
    // under its key, where one key for each request would make it the third.
    assert_eq!(peer.keys().rx.0, 1);
}

#[test]
fn a_session_ticket_in_several_records_joins_and_resumes_the_next_connection() {
    // Records of at most 64 bytes split each handshake message, also each session ticket.
    let config = peer_config(TLS13_AES_128_GCM_SHA256, Some(64));
    let client_config = client_config(CA, None, VALID, SESSIONS);
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let mut peer = Peer::new(&config);
        let mut client = client(&client_config, "server.test", LIMITS);
        let mut body = Vec::new();
        exchange(&mut client, &mut peer, &mut body);
        round(&mut client, &mut peer, &mut body);
        assert_eq!(body, BODY);
        let tls = client.parts().0;
        kinds.push(tls.negotiated().unwrap().handshake);
        assert!(tls.copies().handshake > 0);
    }
    assert_eq!(kinds, [Handshake::Full, Handshake::Resumed]);
}

/// The AES-128-GCM key of one direction of the peer, and the sequence number of its next record:
/// an opener and sealer of the test, with no code of the crate.
struct Keys {
    cipher: Aes128Gcm,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn new((seq, secrets): &(u64, ConnectionTrafficSecrets)) -> Self {
        let ConnectionTrafficSecrets::Aes128Gcm { key, iv } = secrets else {
            panic!("the peer has one suite");
        };
        Self {
            cipher: Aes128Gcm::new(&Aes128GcmKey::from_bytes(key.as_ref().try_into().unwrap())),
            iv: iv.as_ref().try_into().unwrap(),
            seq: *seq,
        }
    }

    fn nonce(&mut self) -> Nonce96 {
        let mut nonce = self.iv;
        for (byte, seq) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        self.seq += 1;
        Nonce96::from_bytes(nonce)
    }

    /// A protected record of the inner content type `kind` (RFC 8446, section 5.2).
    fn seal(&mut self, kind: u8, content: &[u8]) -> Vec<u8> {
        let mut inner = [content, &[kind]].concat();
        let [high, low] = u16::try_from(inner.len() + 16).unwrap().to_be_bytes();
        let header = [23, 3, 3, high, low];
        let nonce = self.nonce();
        let tag = self.cipher.encrypt_in_place(&nonce, &header, &mut inner).unwrap();
        [&header[..], &inner, tag.as_ref()].concat()
    }

    /// The inner plaintext of one protected record: its content and its type.
    fn open(&mut self, record: &[u8]) -> Vec<u8> {
        let (header, rest) = record.split_at(5);
        let (text, tag) = rest.split_at(rest.len() - 16);
        let mut text = text.to_vec();
        let nonce = self.nonce();
        let tag = Aes128Gcm::tag_from_slice(tag).unwrap();
        self.cipher.decrypt_in_place(&nonce, header, &mut text, &tag).unwrap();
        text
    }
}

/// Makes a record that the protocol refuses, with the keys of the peer.
type Bad = fn(&mut Keys) -> Vec<u8>;

#[test]
fn a_long_record_a_wrong_tag_or_an_unknown_content_type_ends_with_malformed_and_its_alert() {
    let config = client_config(CA, None, VALID, Resumption::Off);
    let cases: [(Bad, &str, u8); 3] = [
        // 2^14 + 257 bytes after the header: one more than the protocol allows.
        (
            |_| vec![23, 3, 3, 0x41, 0x01],
            "a TLS record is longer than the protocol allows",
            22,
        ),
        (
            |keys| {
                let mut record = keys.seal(23, b"data");
                *record.last_mut().unwrap() ^= 1;
                record
            },
            "a TLS record failed its authentication",
            20,
        ),
        (
            |keys| keys.seal(0x63, b"data"),
            "a TLS record has an unknown content type",
            10,
        ),
    ];
    for (record, reason, alert) in cases {
        let mut peer = Peer::new(&peer_config(TLS13_AES_128_GCM_SHA256, None));
        let mut client = client(&config, "server.test", LIMITS);
        exchange(&mut client, &mut peer, &mut Vec::new());
        let secrets = peer.keys();
        let (mut tx, mut rx) = (Keys::new(&secrets.tx), Keys::new(&secrets.rx));
        give(&mut client, &record(&mut tx), Receive::Lent);
        drive(&mut client, |_, _| {});
        let Wait::Ended(Err(error)) = client.wait() else {
            panic!("the client did not end: {:?}", client.wait());
        };
        assert_eq!((error.kind(), error.reason()), (Kind::Malformed, reason));
        let mut sent = VecDeque::new();
        take(&mut client, &mut sent, 1);
        let sent: Vec<u8> = sent.into_iter().flatten().collect();
        // A fatal alert, and then the alert content type.
        assert_eq!(rx.open(&sent), [2, alert, 21], "{reason}");
    }
}
