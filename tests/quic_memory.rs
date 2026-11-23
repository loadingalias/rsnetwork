//! The memory of a QUIC connection against its charges: at each allocation, the live heap of each
//! end stays within the charges of its budgets, in the handshake and with stream data out of order
//! (N303, N305, [NET Resource and Progress Bounds]). A stream limit costs no memory for the
//! streams that are not in use.

mod counting;

use counting::allocations;

use core::cell::{Cell, RefCell};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Kind;
use rsnetwork::quic::frame::Direction;
use rsnetwork::quic::packet::{Datagrams, Header, Kind as PacketKind};
use rsnetwork::quic::{Connection, Event, Limits};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Entropy, Handshake, Identity, PrivateKeyDer, Resumption, ServerConfig,
    ServerOptions, TimeProvider, UnixTime,
};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const MLDSA_CA: &[u8] = include_bytes!("tls/mldsa-ca.der");
const MLDSA_INTERMEDIATE: &[u8] = include_bytes!("tls/mldsa-intermediate.der");
const MLDSA65: (&[u8], &[u8]) = (include_bytes!("tls/mldsa65.der"), include_bytes!("tls/mldsa65.key.der"));
const MLDSA87: (&[u8], &[u8]) = (include_bytes!("tls/mldsa87.der"), include_bytes!("tls/mldsa87.key.der"));
/// 2027-01-01, inside the validity of each certificate.
const VALID: u64 = 1_798_761_600;
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

/// A budget for `owner`, whose charges the check counts.
fn budget(owner: usize) -> Budget {
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
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

fn now() -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), 0)
}

/// A shape of a handshake between a client and a server.
struct Profile {
    name: &'static str,
    /// The leaf of the server with its key.
    leaf: (&'static [u8], &'static [u8]),
    /// The certificates of the server after its leaf.
    chain: Vec<&'static [u8]>,
    /// The root that the client trusts.
    root: &'static [u8],
    resumption: Resumption,
    /// The connections in a row: each later one resumes when the profile has resumption.
    connections: usize,
    /// The server sends each of its packets in its own region, from the last one, so its CRYPTO
    /// data waits out of order.
    reversed: bool,
    /// The packets that one 1-RTT key of the server seals, and the PINGs that it sends after the
    /// handshake.
    keys: (u64, usize),
    /// The bytes that the client sends on one stream after the handshake. The server gets its
    /// datagrams in groups of 32, each from its last datagram, so the data waits out of order.
    stream_bytes: usize,
    /// The streams of each direction that each end lets its peer open.
    streams: u64,
}

impl Profile {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            leaf: SERVER,
            chain: Vec::new(),
            root: CA,
            resumption: Resumption::Off,
            connections: 1,
            reversed: false,
            keys: (u64::MAX, 0),
            stream_bytes: 0,
            streams: 100,
        }
    }
}

/// The datagrams that `connection` of `owner` sends.
fn send(owner: usize, connection: &mut Connection) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    for _ in 0..512 {
        let mut out = vec![0; 1500];
        match owned(owner, || connection.transmit(&mut out, now())).unwrap() {
            Some(len) => {
                out.truncate(len);
                datagrams.push(out);
            }
            None => return datagrams,
        }
    }
    panic!("a connection sends at most 512 datagrams at once");
}

/// Gives `datagram`, a region of the transport, to `connection` of `owner`, and gives the stream
/// bytes of its events.
fn give(owner: usize, connection: &mut Connection, datagram: Vec<u8>) -> usize {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram), None, len);
    let mut bytes = 0;
    while let (Some(event), _) = owned(owner, || connection.receive(&mut datagrams, now())) {
        if let Event::Stream { data, .. } = event {
            bytes += data.as_ref().len();
        }
    }
    bytes
}

/// Each long-header packet of `datagrams` in its own region: the Initial packets in order, and
/// then the others from the last one.
fn reversed(datagrams: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for datagram in &datagrams {
        let mut rest = &datagram[..];
        while let Ok(header) = Header::parse(rest, 0)
            && !rest.is_empty()
        {
            let (packet, after) = rest.split_at(header.end());
            packets.push(packet.to_vec());
            rest = after;
        }
    }
    // The Initial packets go first, in order: their ServerHello gives the Handshake keys.
    let initial = |packet: &Vec<u8>| {
        matches!(
            Header::parse(packet, 0),
            Ok(Header::Protected {
                kind: PacketKind::Initial,
                ..
            })
        )
    };
    let (mut first, rest): (Vec<_>, Vec<_>) = packets.into_iter().partition(initial);
    first.extend(rest.into_iter().rev());
    first
}

/// Runs the connections of `profile`, and gives the excess of each end, the handshake of each
/// connection, and the live heap of each end before its last connection drops.
fn run(profile: &Profile) -> ([u64; 2], Vec<Option<Handshake>>, [u64; 2]) {
    EXCESS.set([0; 2]);
    BUDGETS.with_borrow_mut(|budgets| budgets.iter_mut().for_each(Vec::clear));
    let ((leaf, key), chain, root) = (profile.leaf, &profile.chain, profile.root);
    // The configurations belong to the application: only the sessions of their stores are
    // charged, to their own budgets.
    let client_config = {
        ClientConfig::new(ClientOptions {
            roots: &[certificate(root)],
            identity: None,
            protocols: &[b"h3"],
            resumption: profile.resumption,
            budget: &budget(CLIENT_END),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::System,
        })
        .unwrap()
    };
    let server_config = {
        let mut certificates = vec![certificate(leaf)];
        certificates.extend(chain.iter().map(|der| certificate(der)));
        ServerConfig::new(ServerOptions {
            identity: Identity {
                chain: certificates,
                key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
            },
            client_roots: None,
            protocols: &[b"h3"],
            resumption: profile.resumption,
            budget: &budget(SERVER_END),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::System,
        })
        .unwrap()
    };
    let client_limits = Limits {
        streams_bidi_max: profile.streams,
        streams_uni_max: profile.streams,
        ..Limits::DEFAULT
    };
    let server_limits = Limits {
        key_packets_max: profile.keys.0,
        ..client_limits
    };
    let mut handshakes = Vec::new();
    let mut live = [0; 2];
    for _ in 0..profile.connections {
        let client_budget = budget(CLIENT_END);
        let server_budget = budget(SERVER_END);
        let mut client = owned(CLIENT_END, || {
            Connection::client(&client_config, "server.test", client_limits, &client_budget, now())
        })
        .unwrap();
        let mut server: Option<Connection> = None;
        for _ in 0..64 {
            let to_server = send(CLIENT_END, &mut client);
            let to_client = server
                .as_mut()
                .map(|server| send(SERVER_END, server))
                .unwrap_or_default();
            if to_server.is_empty() && to_client.is_empty() {
                break;
            }
            for datagram in to_server {
                let server = server.get_or_insert_with(|| {
                    let header = Header::parse(&datagram, 0).unwrap();
                    owned(SERVER_END, || {
                        Connection::server(&server_config, &header, server_limits, &server_budget, now())
                    })
                    .unwrap()
                });
                give(SERVER_END, server, datagram);
            }
            let to_client = if profile.reversed && !client.is_confirmed() && !to_client.is_empty() {
                reversed(to_client)
            } else {
                to_client
            };
            for datagram in to_client {
                give(CLIENT_END, &mut client, datagram);
            }
        }
        let server = server.as_mut().expect("the client reached the server");
        for _ in 0..profile.keys.1 {
            owned(SERVER_END, || server.ping());
            for datagram in send(SERVER_END, server) {
                give(CLIENT_END, &mut client, datagram);
            }
        }
        assert!(client.is_confirmed(), "{}: the handshake completed", profile.name);
        handshakes.push(client.negotiated().map(|evidence| evidence.handshake));
        if profile.stream_bytes > 0 {
            let stream = owned(CLIENT_END, || client.open(Direction::Unidirectional))
                .unwrap()
                .expect("the server lets the client open a stream");
            // The data of the application is its own memory.
            let data = Lease::from(vec![7; profile.stream_bytes]);
            owned(CLIENT_END, || client.send(stream, data, true)).unwrap();
            let datagrams = send(CLIENT_END, &mut client);
            let received: usize = datagrams
                .chunks(32)
                .flat_map(|group| group.iter().rev())
                .map(|datagram| give(SERVER_END, server, datagram.clone()))
                .sum();
            assert_eq!(received, profile.stream_bytes, "{}: the stream arrived", profile.name);
        }
        let heap = counting::LIVE.get();
        live = [heap[CLIENT_END], heap[SERVER_END]];
    }
    (EXCESS.get(), handshakes, live)
}

#[test]
fn the_heap_of_each_end_of_a_quic_connection_stays_within_its_charges() {
    counting::CHECK.set(Some(check));
    let sessions = Resumption::Process(NonZeroUsize::new(8).unwrap());
    let profiles = [
        Profile::new("a full handshake"),
        Profile {
            leaf: MLDSA65,
            chain: vec![MLDSA_INTERMEDIATE],
            root: MLDSA_CA,
            ..Profile::new("an ML-DSA-65 chain")
        },
        Profile {
            leaf: MLDSA87,
            chain: vec![MLDSA_INTERMEDIATE],
            root: MLDSA_CA,
            ..Profile::new("an ML-DSA-87 chain")
        },
        // About 55 KB of chain, which waits out of order in the CRYPTO buffer of the client.
        Profile {
            leaf: MLDSA65,
            chain: vec![MLDSA_INTERMEDIATE; 9],
            root: MLDSA_CA,
            reversed: true,
            ..Profile::new("a large chain out of order")
        },
        Profile {
            resumption: sessions,
            connections: 2,
            ..Profile::new("resumption")
        },
        Profile {
            keys: (2, 3),
            ..Profile::new("a key update of the server")
        },
        // About 170 datagrams, which wait in the pages of the server out of order.
        Profile {
            stream_bytes: 200 * 1024,
            ..Profile::new("a stream out of order")
        },
    ];
    for profile in &profiles {
        let (excess, handshakes, _) = run(profile);
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
fn a_stream_limit_of_10_000_allocates_nothing_for_the_streams_that_are_not_in_use() {
    // Each end lets its peer open 100 streams, and then 10,000: the same handshake and the same
    // one stream of data keep the same heap (NET-MEM-7).
    let heap = |streams| {
        let profile = Profile {
            stream_bytes: 4 * 1024,
            streams,
            ..Profile::new("a stream limit")
        };
        run(&profile).2
    };
    let (few, many) = (heap(100), heap(10_000));
    assert!(few[0] > 0 && few[1] > 0, "the heap of each end is counted");
    assert_eq!(few, many);
}

#[test]
fn a_client_or_server_that_the_budget_refuses_allocates_nothing() {
    let config = ClientConfig::new(ClientOptions {
        roots: &[certificate(CA)],
        identity: None,
        protocols: &[b"h3"],
        resumption: Resumption::Off,
        budget: &Budget::new(NonZeroU64::new(1 << 20).unwrap()),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let small = Budget::new(NonZeroU64::new(1024).unwrap());
    let (refused, count) =
        allocations(|| Connection::client(&config, "server.test", Limits::DEFAULT, &small, now()).map(drop));
    assert_eq!((refused.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));

    // The first datagram of a client, for the header of the server.
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let mut client = Connection::client(&config, "server.test", Limits::DEFAULT, &budget, now()).unwrap();
    let mut out = vec![0; 1500];
    let len = client.transmit(&mut out, now()).unwrap().unwrap();
    let header = Header::parse(&out[..len], 0).unwrap();
    let server = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![certificate(SERVER.0)],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"h3"],
        resumption: Resumption::Off,
        budget: &budget,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let (refused, count) =
        allocations(|| Connection::server(&server, &header, Limits::DEFAULT, &small, now()).map(drop));
    assert_eq!((refused.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));
}
