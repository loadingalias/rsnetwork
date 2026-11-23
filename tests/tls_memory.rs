//! The memory of rustls in a TLS connection stays within the charges of each end. The test
//! allocator names the owner of each allocation: the client end or the server end. After each
//! allocation of an end, the live heap of that end must stay at or below the charges of its
//! budgets: the budget of each of its connections, and the budget of its configuration, which pays
//! for the stored sessions. The profiles are the shapes that make rustls allocate the most: a
//! chain of many one-byte certificates, a chain larger than a record, mTLS, and resumption.

use core::cell::{Cell, RefCell};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits as HeadLimits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Entropy, Handshake, Identity, Limits, PrivateKeyDer, Resumption,
    ServerConfig, ServerOptions, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Method, Status, Target};

mod counting;

use counting::allocations;

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const CLIENT: (&[u8], &[u8]) = (include_bytes!("tls/client.der"), include_bytes!("tls/client.key.der"));
// An ML-DSA-65 root and intermediate, and leaves of ML-DSA-65 and ML-DSA-87.
const MLDSA_CA: &[u8] = include_bytes!("tls/mldsa-ca.der");
const MLDSA_INTERMEDIATE: &[u8] = include_bytes!("tls/mldsa-intermediate.der");
const MLDSA65: (&[u8], &[u8]) = (include_bytes!("tls/mldsa65.der"), include_bytes!("tls/mldsa65.key.der"));
const MLDSA87: (&[u8], &[u8]) = (include_bytes!("tls/mldsa87.der"), include_bytes!("tls/mldsa87.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

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

/// An input region that holds the largest Certificate message of the profiles.
const LIMITS: Limits = Limits {
    input_bytes: 64 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The owners of the test allocator.
const CLIENT_END: usize = 1;
const SERVER_END: usize = 2;

thread_local! {
    /// The budgets of each end.
    static BUDGETS: RefCell<[Vec<Budget>; 2]> = const { RefCell::new([Vec::new(), Vec::new()]) };
    /// The most bytes by which the live heap of each end passed its charges.
    static EXCESS: Cell<[u64; 2]> = const { Cell::new([0; 2]) };
}

/// The check of the allocator: the live heap of `owner` against the charges of its budgets.
fn check(owner: usize, live: u64) {
    // The registration of a budget borrows the list, and the allocator then skips the check.
    let Ok(charged) = BUDGETS.with(|budgets| {
        budgets.try_borrow().map(|budgets| {
            budgets[owner - 1]
                .iter()
                .map(|budget| budget.bound() - budget.available())
                .sum::<u64>()
        })
    }) else {
        return;
    };
    let mut excess = EXCESS.get();
    excess[owner - 1] = excess[owner - 1].max(live.saturating_sub(charged));
    EXCESS.set(excess);
}

/// Runs `f` with each allocation in it owned by `owner`.
fn owned<T>(owner: usize, f: impl FnOnce() -> T) -> T {
    let before = counting::OWNER.replace(owner);
    let result = f();
    counting::OWNER.set(before);
    result
}

/// A budget of `bound` units for `owner`, whose charges the check counts.
fn budget(owner: usize, bound: u64) -> Budget {
    let budget = Budget::new(NonZeroU64::new(bound).unwrap());
    BUDGETS.with_borrow_mut(|budgets| budgets[owner - 1].push(budget.clone()));
    budget
}

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

/// `count` certificate entries of one byte each. A peer checks only the path from the end-entity
/// certificate to a root, so it keeps these entries and their copies.
fn tiny(count: usize) -> Vec<CertificateDer<'static>> {
    (0..count).map(|_| CertificateDer::from(vec![0])).collect()
}

fn identity((leaf, key): (&[u8], &[u8]), extra: Vec<CertificateDer<'static>>) -> Identity {
    let mut chain = vec![certificate(leaf)];
    chain.extend(extra);
    Identity {
        chain,
        key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
    }
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

/// A budget that no check counts, for the cases that test a refusal or a store.
fn unchecked() -> Budget {
    Budget::new(NonZeroU64::new(1 << 24).unwrap())
}

/// A shape of a connection between a client and a server.
struct Profile {
    name: &'static str,
    /// The leaf of the server with its key, and the root that the client trusts.
    server: ((&'static [u8], &'static [u8]), &'static [u8]),
    /// The certificates after the leaf of the server.
    server_chain: Vec<CertificateDer<'static>>,
    /// The certificates after the leaf of the client, for mTLS, or `None`.
    client_chain: Option<Vec<CertificateDer<'static>>>,
    resumption: Resumption,
    /// The connections in a row: each later one resumes when the profile has resumption.
    connections: usize,
    /// The requests on each connection.
    requests: usize,
    /// The received regions that each output reaches the peer in.
    parts: usize,
    limits: Limits,
}

impl Profile {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            server: (SERVER, CA),
            server_chain: Vec::new(),
            client_chain: None,
            resumption: Resumption::Off,
            connections: 1,
            requests: 1,
            parts: 1,
            limits: LIMITS,
        }
    }
}

/// The configurations of a profile, each with its own budget for its stored sessions.
fn configs(profile: &Profile) -> (ClientConfig, ServerConfig, Budget, Budget) {
    let (client_budget, server_budget) = (budget(CLIENT_END, 1 << 24), budget(SERVER_END, 1 << 24));
    let client = ClientConfig::new(ClientOptions {
        roots: &[certificate(profile.server.1)],
        identity: profile.client_chain.clone().map(|chain| identity(CLIENT, chain)),
        protocols: &[b"h2", b"http/1.1"],
        resumption: profile.resumption,
        budget: &client_budget,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let client_roots = profile.client_chain.as_ref().map(|_| [certificate(CA)]);
    let server = ServerConfig::new(ServerOptions {
        identity: identity(profile.server.0, profile.server_chain.clone()),
        client_roots: client_roots.as_ref().map(|roots| &roots[..]),
        protocols: &[b"http/1.1"],
        resumption: profile.resumption,
        budget: &server_budget,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    (client, server, client_budget, server_budget)
}

/// A client and a server connection, each owned by its end, and the transport between them.
struct Pair {
    client: Connection<Tls<Client>>,
    server: Connection<Tls<Server>>,
    parts: usize,
    to_client: VecDeque<Vec<u8>>,
    to_server: VecDeque<Vec<u8>>,
    /// The response bodies that the client received, and the responses that ended.
    body: Vec<u8>,
    ended: usize,
}

impl Pair {
    /// A pair whose connections charge `client_budget` and `server_budget`.
    fn new(
        (client, server): (&ClientConfig, &ServerConfig),
        (client_budget, server_budget): (&Budget, &Budget),
        limits: Limits,
        parts: usize,
    ) -> Self {
        let client = owned(CLIENT_END, || {
            let (inbound, outbound) = queues(client_budget);
            let engine = Client::new(HEAD, BODY_LIMITS, TURN, &outbound, client_budget).unwrap();
            let tls = Tls::client(
                client,
                "server.test",
                engine,
                (inbound, outbound),
                limits,
                client_budget,
            )
            .unwrap();
            let (inbound, outbound) = queues(client_budget);
            Connection::new(tls, inbound, outbound, Some(clock())).unwrap()
        });
        let server = owned(SERVER_END, || {
            let (inbound, outbound) = queues(server_budget);
            let engine = Server::new(HEAD, BODY_LIMITS, TURN, &outbound, server_budget).unwrap();
            let tls = Tls::server(server, engine, (inbound, outbound), limits, server_budget).unwrap();
            let (inbound, outbound) = queues(server_budget);
            Connection::new(tls, inbound, outbound, Some(clock())).unwrap()
        });
        Self {
            client,
            server,
            parts,
            to_client: VecDeque::new(),
            to_server: VecDeque::new(),
            body: Vec::new(),
            ended: 0,
        }
    }

    /// Queues a GET request on the client.
    fn request(&mut self) {
        let head = Backing::from(Vec::with_capacity(256));
        owned(CLIENT_END, || {
            let (tls, _) = self.client.parts();
            let (client, outbound) = tls.parts();
            client
                .request(
                    outbound,
                    Method::GET,
                    Target::new(b"/").unwrap(),
                    Authority::new(b"server.test").unwrap(),
                    &[],
                    Framing::Length(0),
                    head,
                )
                .unwrap();
            client.finish(outbound).unwrap();
        });
    }

    /// One round: each end drives until it waits, and one received region moves in each
    /// direction. Gives whether a byte moved.
    fn round(&mut self) -> bool {
        drive(SERVER_END, &mut self.server, |server, event| {
            if let ServerEvent::Request(_) = event {
                let head = Backing::from(Vec::with_capacity(256));
                let body = Lease::from(BODY.to_vec());
                owned(SERVER_END, || {
                    let (tls, _) = server.parts();
                    let (server, outbound) = tls.parts();
                    let length = Framing::Length(BODY.len() as u64);
                    server
                        .respond(outbound, Status::new(200).unwrap(), &[], length, head)
                        .unwrap();
                    server.send(outbound, &body).unwrap();
                    server.finish(outbound).unwrap();
                });
            }
        });
        let (body, ended) = (&mut self.body, &mut self.ended);
        drive(CLIENT_END, &mut self.client, |_, event| match event {
            ClientEvent::Data(data) => body.extend_from_slice(data.bytes()),
            ClientEvent::End(_) => *ended += 1,
            _ => {}
        });
        take(SERVER_END, &mut self.server, &mut self.to_client, self.parts);
        take(CLIENT_END, &mut self.client, &mut self.to_server, self.parts);
        let to_client = self
            .to_client
            .pop_front()
            .map(|part| give(CLIENT_END, &mut self.client, &part));
        let to_server = self
            .to_server
            .pop_front()
            .map(|part| give(SERVER_END, &mut self.server, &part));
        to_client.is_some() || to_server.is_some()
    }

    /// Runs rounds until no byte moves.
    fn run(&mut self) {
        for _ in 0..4096 {
            if !self.round() {
                return;
            }
        }
        panic!("the connections still move bytes after 4096 rounds");
    }

    fn handshake(&mut self) -> Option<Handshake> {
        self.client
            .parts()
            .0
            .negotiated()
            .map(|negotiated| negotiated.handshake)
    }

    /// Drops both connections, each in its owner.
    fn close(self) {
        let Self { client, server, .. } = self;
        owned(CLIENT_END, || drop(client));
        owned(SERVER_END, || drop(server));
    }
}

/// Drives `connection` of `owner` until it waits, and gives each event to `on`.
fn drive<E: Engine>(owner: usize, connection: &mut Connection<E>, mut on: impl FnMut(&mut Connection<E>, E::Event)) {
    for _ in 0..4096 {
        match owned(owner, || connection.drive(now())).unwrap() {
            Some(event) => on(connection, event),
            None if connection.wait() != Wait::Now => return,
            None => {}
        }
    }
    panic!("the connection did not wait after 4096 drives");
}

/// Takes each output of `from` in `parts` received regions for its peer, and acknowledges it.
fn take<E: Engine>(owner: usize, from: &mut Connection<E>, to: &mut VecDeque<Vec<u8>>, parts: usize) {
    while let Some(output) = owned(owner, || from.output()) {
        let bytes = output.region.bytes();
        to.extend(bytes.chunks(bytes.len().div_ceil(parts)).map(<[u8]>::to_vec));
        let (id, len) = (output.id, bytes.len());
        owned(owner, || {
            drop(output);
            from.ack(id, len).unwrap();
        });
    }
}

/// Gives `bytes` to `to` of `owner`, in the input region that it lends.
fn give<E: Engine>(owner: usize, to: &mut Connection<E>, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let added = owned(owner, || {
            let mut loan = WriteLoan::new(to.region().unwrap().unwrap());
            let added = loan.fill_from(bytes);
            to.received(loan.into_inner(), ENDPOINT, 1 << 20).unwrap();
            added
        });
        bytes = &bytes[added..];
    }
}

/// Runs each connection of `profile`, and gives the most bytes by which the live heap of each end
/// passed its charges, with the handshake of each connection.
fn run(profile: &Profile) -> ([u64; 2], Vec<Option<Handshake>>) {
    let (client, server, ..) = configs(profile);
    EXCESS.set([0; 2]);
    let mut handshakes = Vec::new();
    for _ in 0..profile.connections {
        let budgets = (budget(CLIENT_END, 1 << 30), budget(SERVER_END, 1 << 30));
        let mut pair = Pair::new(
            (&client, &server),
            (&budgets.0, &budgets.1),
            profile.limits,
            profile.parts,
        );
        for _ in 0..profile.requests {
            pair.request();
            pair.run();
        }
        assert_eq!(
            (pair.body.len(), pair.ended),
            (BODY.len() * profile.requests, profile.requests),
            "{}: the client waits for {:?}, the server for {:?}",
            profile.name,
            pair.client.wait(),
            pair.server.wait()
        );
        handshakes.push(pair.handshake());
        pair.close();
    }
    (EXCESS.get(), handshakes)
}

#[test]
fn the_heap_of_each_end_stays_within_its_charges_in_each_profile() {
    counting::CHECK.set(Some(check));
    let sessions = Resumption::Process(NonZeroUsize::new(8).unwrap());
    let profiles = [
        Profile::new("a full handshake"),
        Profile {
            client_chain: Some(Vec::new()),
            ..Profile::new("mTLS")
        },
        Profile {
            resumption: sessions,
            connections: 2,
            ..Profile::new("resumption")
        },
        // 60 copies of the root: a Certificate message of two records.
        Profile {
            server_chain: (0..60).map(|_| certificate(CA)).collect(),
            ..Profile::new("a chain larger than one record")
        },
        // 2^11 + 1 entries: the list of entries that rustls decodes has twice their capacity.
        Profile {
            server_chain: tiny(2049),
            ..Profile::new("a chain of one-byte entries in one flight")
        },
        Profile {
            server_chain: tiny(8193),
            parts: 7,
            ..Profile::new("a chain of one-byte entries in parts")
        },
        // A client Certificate message of exactly 2^14 bytes, so that it fills one record: 8 bytes
        // of headers, the leaf of 372 bytes with its 5 bytes, 2665 entries of 6 bytes, and one of
        // 9. rustls keeps the chain after that record, and checks it in the next.
        Profile {
            client_chain: Some({
                let mut chain = tiny(2665);
                chain.push(CertificateDer::from(vec![0; 4]));
                chain
            }),
            ..Profile::new("mTLS with a Certificate message in its own record")
        },
        Profile {
            server_chain: tiny(2049),
            client_chain: Some(tiny(2049)),
            resumption: sessions,
            connections: 2,
            ..Profile::new("mTLS resumption with chains of one-byte entries")
        },
        Profile {
            requests: 3,
            limits: Limits {
                key_records_max: 2,
                ..LIMITS
            },
            ..Profile::new("KeyUpdates in both directions")
        },
        // ML-DSA signs the handshake and each certificate of the chain.
        Profile {
            server: (MLDSA65, MLDSA_CA),
            server_chain: vec![certificate(MLDSA_INTERMEDIATE)],
            ..Profile::new("an ML-DSA-65 chain")
        },
        Profile {
            server: (MLDSA87, MLDSA_CA),
            server_chain: vec![certificate(MLDSA_INTERMEDIATE)],
            client_chain: Some(Vec::new()),
            ..Profile::new("mTLS with an ML-DSA-87 server")
        },
    ];
    for profile in &profiles {
        let (excess, handshakes) = run(profile);
        assert_eq!(
            excess,
            [0, 0],
            "{}: the excess of the client and of the server",
            profile.name
        );
        let resumed = profile.resumption != Resumption::Off;
        for (connection, handshake) in handshakes.into_iter().enumerate() {
            let expected = if resumed && connection > 0 {
                Handshake::Resumed
            } else {
                Handshake::Full
            };
            assert_eq!(handshake, Some(expected), "{}: connection {connection}", profile.name);
        }
    }
}

#[test]
fn a_client_or_server_that_the_budget_refuses_allocates_nothing() {
    let (client, server, ..) = configs(&Profile::new("refused"));
    let roomy = unchecked();
    let refusing = Budget::new(NonZeroU64::MIN);
    let (inbound, outbound) = queues(&roomy);
    let engine = Client::new(HEAD, BODY_LIMITS, TURN, &outbound, &roomy).unwrap();
    let (refused, count) =
        allocations(|| Tls::client(&client, "server.test", engine, (inbound, outbound), LIMITS, &refusing).map(drop));
    assert_eq!((refused.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));

    let (inbound, outbound) = queues(&roomy);
    let engine = Server::new(HEAD, BODY_LIMITS, TURN, &outbound, &roomy).unwrap();
    let (refused, count) =
        allocations(|| Tls::server(&server, engine, (inbound, outbound), LIMITS, &refusing).map(drop));
    assert_eq!((refused.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));
}

#[test]
fn a_call_that_the_budget_cannot_pay_for_waits_for_capacity_and_then_completes() {
    let (client, server, ..) = configs(&Profile::new("capacity"));
    let budgets = (unchecked(), unchecked());
    let mut pair = Pair::new((&client, &server), (&budgets.0, &budgets.1), LIMITS, 1);
    // The server has room for its input region, but not for the call that reads the ClientHello.
    let held = budgets
        .1
        .reserve(budgets.1.available() - LIMITS.input_bytes as u64 - 4096)
        .unwrap();
    pair.request();
    for _ in 0..4 {
        pair.round();
    }
    let Wait::Until {
        blocked: Blocked::Capacity(units),
        ..
    } = pair.server.wait()
    else {
        panic!("the server waits for {:?}", pair.server.wait());
    };
    assert!(units > 0);
    drop(held);
    pair.run();
    assert_eq!((pair.body.as_slice(), pair.ended), (BODY, 1));
    pair.close();
}

#[test]
fn a_server_store_that_its_budget_refuses_sends_no_ticket_and_the_connection_works() {
    let (client, server, client_budget, server_budget) = configs(&Profile {
        resumption: Resumption::Process(NonZeroUsize::new(8).unwrap()),
        ..Profile::new("full store")
    });
    // The store has its places, and no unit for a session.
    let _full = server_budget.reserve(server_budget.available()).unwrap();
    let empty = client_budget.available();
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let budgets = (unchecked(), unchecked());
        let mut pair = Pair::new((&client, &server), (&budgets.0, &budgets.1), LIMITS, 1);
        pair.request();
        pair.run();
        assert_eq!((pair.body.as_slice(), pair.ended), (BODY, 1));
        // The client got no ticket, so its store charges nothing.
        assert_eq!(client_budget.available(), empty);
        kinds.push(pair.handshake());
        pair.close();
    }
    assert_eq!(kinds, [Some(Handshake::Full); 2]);
}

#[test]
fn the_charge_of_a_client_ticket_returns_when_rustls_takes_or_evicts_it() {
    // A store of one ticket: the second of the two tickets of each handshake evicts the first.
    let (client, server, client_budget, _) = configs(&Profile {
        resumption: Resumption::Process(NonZeroUsize::MIN),
        ..Profile::new("one ticket")
    });
    let empty = client_budget.available();
    let mut charges = Vec::new();
    for connection in 0..3 {
        let budgets = (unchecked(), unchecked());
        let mut pair = Pair::new((&client, &server), (&budgets.0, &budgets.1), LIMITS, 1);
        // rustls took the ticket when it wrote the ClientHello.
        assert_eq!(client_budget.available(), empty, "connection {connection}");
        pair.request();
        pair.run();
        let expected = if connection == 0 {
            Handshake::Full
        } else {
            Handshake::Resumed
        };
        assert_eq!(pair.handshake(), Some(expected));
        charges.push(empty - client_budget.available());
        pair.close();
    }
    // After each connection, the store keeps one ticket with its charge.
    assert!(charges[0] > 0);
    assert_eq!(charges, [charges[0]; 3]);
}

#[test]
fn the_charge_of_each_output_is_the_memory_that_it_frees() {
    let (client, server, ..) = configs(&Profile::new("outputs"));
    let budgets = (budget(CLIENT_END, 1 << 30), budget(SERVER_END, 1 << 30));
    let mut pair = Pair::new((&client, &server), (&budgets.0, &budgets.1), LIMITS, 1);
    // The ClientHello is the first output of the client, after its first drive. When the
    // transport accepts it, its bytes and the lease that owns them drop, and the budget gets back
    // exactly that memory.
    owned(CLIENT_END, || pair.client.drive(now())).unwrap();
    let output = owned(CLIENT_END, || pair.client.output()).unwrap();
    let (id, len) = (output.id, output.region.initialized());
    drop(output);
    let (free, live) = (budgets.0.available(), counting::LIVE.get()[CLIENT_END]);
    owned(CLIENT_END, || pair.client.ack(id, len)).unwrap();
    let freed = live - counting::LIVE.get()[CLIENT_END];
    assert!(freed > len as u64, "the output and its lease free {freed} bytes");
    assert_eq!(budgets.0.available() - free, freed);
    pair.close();
}
