//! The QUIC handshake of the connection engine (N303): RFC 9000 and RFC 9001 over a transport in
//! memory, with the certificates of `tests/tls/`.

use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use rsnetwork::buffer::Backing;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Error, Kind, Progress};
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Kind as PacketKind, Outgoing, Side};
use rsnetwork::quic::params::{Migration, ParameterError, Parameters, PreferredAddress, Sender};
use rsnetwork::quic::{CRYPTO_BUFFER_BYTES_MAX, Connection, ConnectionId, Limits};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    Authentication, CertificateDer, ClientConfig, ClientOptions, Entropy, Group, Handshake, Identity, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions, TimeProvider, UnixTime,
};

const CA: &[u8] = include_bytes!("tls/ca.der");
const OTHER_CA: &[u8] = include_bytes!("tls/other-ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const MLDSA_CA: &[u8] = include_bytes!("tls/mldsa-ca.der");
const MLDSA_INTERMEDIATE: &[u8] = include_bytes!("tls/mldsa-intermediate.der");
const MLDSA44: (&[u8], &[u8]) = (include_bytes!("tls/mldsa44.der"), include_bytes!("tls/mldsa44.key.der"));
const MLDSA65: (&[u8], &[u8]) = (include_bytes!("tls/mldsa65.der"), include_bytes!("tls/mldsa65.key.der"));
const MLDSA87: (&[u8], &[u8]) = (include_bytes!("tls/mldsa87.der"), include_bytes!("tls/mldsa87.key.der"));

/// A leaf certificate and its key.
type Leaf = (&'static [u8], &'static [u8]);
/// The certificates of a server after its leaf.
type Chain = &'static [&'static [u8]];

/// 2027-01-01, inside the validity of each certificate.
const VALID: u64 = 1_798_761_600;
const ALPN: &[u8] = b"h3";
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

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 24).unwrap())
}

/// The instant `ms` milliseconds after the start of the clock of each test.
fn at(ms: u64) -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), ms * 1_000_000)
}

fn client_config(root: &[u8], resumption: Resumption) -> ClientConfig {
    ClientConfig::new(ClientOptions {
        roots: &[certificate(root)],
        identity: None,
        protocols: &[ALPN],
        resumption,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

/// A server with the leaf `(leaf, key)`, and `chain` after it.
fn server_config((leaf, key): (&[u8], &[u8]), chain: &[&[u8]], resumption: Resumption) -> ServerConfig {
    let mut certificates = vec![certificate(leaf)];
    certificates.extend(chain.iter().map(|der| certificate(der)));
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: certificates,
            key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[ALPN],
        resumption,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

/// The datagrams of each direction, with the order in which a test delivers them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Sent,
    /// Each coalesced packet in its own region: the Initial packets first, in order, and then the
    /// other packets from the last one.
    HandshakeReversed,
}

/// A client and the server that its first datagram makes, and the datagrams between them.
struct Pair {
    client: Connection,
    server: Option<Connection>,
    config: ServerConfig,
    limits: Limits,
    to_server: VecDeque<Vec<u8>>,
    to_client: VecDeque<Vec<u8>>,
}

impl Pair {
    fn new(client: &ClientConfig, server: ServerConfig, limits: (Limits, Limits)) -> Self {
        Self {
            client: Connection::client(client, "server.test", limits.0, &budget(), at(0)).unwrap(),
            server: None,
            config: server,
            limits: limits.1,
            to_server: VecDeque::new(),
            to_client: VecDeque::new(),
        }
    }

    fn server(&mut self) -> &mut Connection {
        self.server
            .as_mut()
            .expect("the first datagram of the client made the server")
    }

    /// The datagrams that `connection` sends now.
    fn send(connection: &mut Connection, now: Instant) -> Vec<Vec<u8>> {
        let mut datagrams = Vec::new();
        for _ in 0..512 {
            let mut out = vec![0; 1500];
            match connection.transmit(&mut out, now).unwrap() {
                Some(len) => {
                    out.truncate(len);
                    datagrams.push(out);
                }
                None => return datagrams,
            }
        }
        panic!("a connection sends at most 512 datagrams at once");
    }

    /// Gives `datagram` to `connection`, whose connection IDs have `cid_bytes` bytes.
    fn give(connection: &mut Connection, datagram: Vec<u8>, now: Instant) -> Progress {
        let len = connection.local_cid().as_bytes().len();
        let mut datagrams = Datagrams::new(Backing::from(datagram), None, len);
        connection.receive(&mut datagrams, now).progress
    }

    fn deliver(&mut self, datagram: Vec<u8>, now: Instant) -> Progress {
        if self.server.is_none() {
            let header = Header::parse(&datagram, 0).unwrap();
            self.server = Some(Connection::server(&self.config, &header, self.limits, &budget(), now).unwrap());
        }
        Self::give(self.server(), datagram, now)
    }

    /// Moves the datagrams of both ends until no datagram moves, with the server datagrams in
    /// `order`.
    fn run(&mut self, now: Instant, order: Order) {
        for _ in 0..64 {
            self.to_server.extend(Self::send(&mut self.client, now));
            if let Some(server) = &mut self.server {
                self.to_client.extend(Self::send(server, now));
            }
            if self.to_server.is_empty() && self.to_client.is_empty() {
                return;
            }
            while let Some(datagram) = self.to_server.pop_front() {
                self.deliver(datagram, now);
            }
            let mut to_client: Vec<_> = self.to_client.drain(..).collect();
            if order == Order::HandshakeReversed {
                let packets: Vec<Vec<u8>> = to_client.iter().flat_map(|datagram| packets(datagram)).collect();
                let (initial, rest): (Vec<_>, Vec<_>) = packets.into_iter().partition(|d| is_initial(d));
                to_client = initial.into_iter().chain(rest.into_iter().rev()).collect();
            }
            for datagram in to_client {
                Self::give(&mut self.client, datagram, now);
            }
        }
        panic!("the handshake moves no datagram after 64 rounds");
    }

    fn client_outcome(&mut self, now: Instant) -> Progress {
        self.client.drive(now).progress
    }
}

/// Whether `datagram` starts with an Initial packet.
fn is_initial(datagram: &[u8]) -> bool {
    matches!(
        Header::parse(datagram, 0),
        Ok(Header::Protected {
            kind: PacketKind::Initial,
            ..
        })
    )
}

/// The coalesced long-header packets of `datagram`, each on its own.
fn packets(datagram: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut rest = datagram;
    while let Ok(header) = Header::parse(rest, 0)
        && !rest.is_empty()
    {
        let (packet, after) = rest.split_at(header.end());
        packets.push(packet.to_vec());
        rest = after;
    }
    packets
}

/// The kinds of the packets of `datagram`, coalesced, with a short header of `cid_bytes`.
fn kinds(datagram: &[u8], cid_bytes: usize) -> Vec<PacketKind> {
    let mut kinds = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let Ok(header) = Header::parse(rest, cid_bytes) else {
            break;
        };
        if let Header::Protected { kind, .. } = header {
            kinds.push(kind);
        }
        rest = &rest[header.end()..];
    }
    kinds
}

fn terminal(progress: Progress) -> Option<Result<(), Error>> {
    match progress {
        Progress::Terminal(outcome) => Some(outcome),
        _ => None,
    }
}

#[test]
fn a_client_and_a_server_complete_the_handshake_with_classical_and_ml_dsa_chains() {
    // The root of the client, the leaf of the server, its chain, and the class of the leaf.
    let cases: [(&[u8], Leaf, Chain, Authentication); 4] = [
        (CA, SERVER, &[], Authentication::EcdsaP256),
        (MLDSA_CA, MLDSA65, &[MLDSA_INTERMEDIATE], Authentication::MlDsa65),
        (MLDSA_CA, MLDSA44, &[MLDSA_INTERMEDIATE], Authentication::MlDsa44),
        (MLDSA_CA, MLDSA87, &[MLDSA_INTERMEDIATE], Authentication::MlDsa87),
    ];
    for (root, leaf, chain, authentication) in cases {
        let mut pair = Pair::new(
            &client_config(root, Resumption::Off),
            server_config(leaf, chain, Resumption::Off),
            (Limits::DEFAULT, Limits::DEFAULT),
        );
        pair.run(at(0), Order::Sent);
        assert!(
            pair.client.is_confirmed() && pair.server().is_confirmed(),
            "{authentication:?}"
        );
        let evidence = pair.client.negotiated().expect("the handshake completed");
        assert_eq!(evidence.group, Group::X25519_MLKEM768);
        assert_eq!(evidence.protocol, Some(ALPN));
        assert_eq!(evidence.handshake, Handshake::Full);
        let peer = evidence.peer.expect("the server showed its chain");
        assert_eq!((peer.certificate, peer.authentication), (leaf.0, authentication));
        assert_eq!(pair.server().negotiated().expect("the handshake completed").peer, None);
        // Each end checked the connection IDs of the other in its transport parameters.
        let parameters = pair.client.peer_parameters().expect("the server sent its parameters");
        assert_eq!(parameters.idle_timeout, Limits::DEFAULT.idle_timeout);
    }
}

#[test]
fn a_handshake_message_in_two_datagrams_waits_for_its_rest_with_no_work() {
    let mut pair = Pair::new(
        &client_config(CA, Resumption::Off),
        server_config(SERVER, &[], Resumption::Off),
        (Limits::DEFAULT, Limits::DEFAULT),
    );
    // The ClientHello with its X25519MLKEM768 key share has more bytes than one datagram.
    let flight = Pair::send(&mut pair.client, at(0));
    assert!(flight.len() >= 2, "the ClientHello spans {} datagrams", flight.len());
    let mut flight = flight.into_iter();
    let first = pair.deliver(flight.next().unwrap(), at(0));
    assert_eq!(first, Progress::Blocked(rsnetwork::drive::Blocked::Input));
    assert_eq!(
        Pair::send(pair.server(), at(0)),
        Vec::<Vec<u8>>::new(),
        "the server waits"
    );
    for datagram in flight {
        pair.deliver(datagram, at(0));
    }
    pair.run(at(0), Order::Sent);
    assert!(pair.client.is_confirmed());
}

#[test]
fn a_chain_inside_the_crypto_bound_completes_out_of_order_and_one_past_it_refuses() {
    // Copies of the ML-DSA-65 intermediate, about 5.5 KB each, after the leaf. The server sends
    // its Handshake datagrams from the last one, so each CRYPTO frame waits ahead of the bytes
    // that rustls reads.
    let inside = [MLDSA_INTERMEDIATE; 9];
    assert!(inside.len() * MLDSA_INTERMEDIATE.len() + 2 * MLDSA65.0.len() < CRYPTO_BUFFER_BYTES_MAX);
    let mut pair = Pair::new(
        &client_config(MLDSA_CA, Resumption::Off),
        server_config(MLDSA65, &inside, Resumption::Off),
        (Limits::DEFAULT, Limits::DEFAULT),
    );
    pair.run(at(0), Order::HandshakeReversed);
    assert!(pair.client.is_confirmed(), "a chain inside the bound completes");

    let past = [MLDSA_INTERMEDIATE; 13];
    assert!(past.len() * MLDSA_INTERMEDIATE.len() > CRYPTO_BUFFER_BYTES_MAX);
    let mut pair = Pair::new(
        &client_config(MLDSA_CA, Resumption::Off),
        server_config(MLDSA65, &past, Resumption::Off),
        (Limits::DEFAULT, Limits::DEFAULT),
    );
    pair.run(at(0), Order::HandshakeReversed);
    let outcome = terminal(pair.client_outcome(at(0))).expect("the client ended");
    let error = outcome.unwrap_err();
    assert_eq!(
        (error.kind(), error.reason()),
        (
            Kind::Overload,
            "the CRYPTO data of the peer passed the buffer bound of its level"
        )
    );
    // The client closed with CRYPTO_BUFFER_EXCEEDED, which the server reads as an error.
    let server = terminal(pair.server().drive(at(0)).progress).expect("the close of the client ended the server");
    assert_eq!(
        server.unwrap_err().reason(),
        "the peer closed the QUIC connection with a transport error"
    );
}

#[test]
fn a_trust_failure_closes_with_its_tls_alert_and_the_peer_reads_it() {
    let mut pair = Pair::new(
        &client_config(OTHER_CA, Resumption::Off),
        server_config(SERVER, &[], Resumption::Off),
        (Limits::DEFAULT, Limits::DEFAULT),
    );
    pair.run(at(0), Order::Sent);
    let client = terminal(pair.client_outcome(at(0)))
        .expect("the client ended")
        .unwrap_err();
    assert_eq!(
        (client.kind(), client.reason()),
        (Kind::Trust, "the peer certificate chain reaches no trusted root")
    );
    // The alert went in the CRYPTO_ERROR range (RFC 9001, section 4.8).
    let server = terminal(pair.server().drive(at(0)).progress)
        .expect("the close ended the server")
        .unwrap_err();
    assert_eq!(
        (server.kind(), server.reason()),
        (Kind::Trust, "the peer refused the certificate of this end")
    );
}

#[test]
fn an_idle_connection_reaches_its_idle_deadline_with_no_peer_traffic() {
    let limits = Limits {
        idle_timeout: Some(Duration::from_secs(5)),
        handshake_timeout: Duration::from_secs(60),
        ..Limits::DEFAULT
    };
    // A client that hears nothing after its first datagram.
    let config = client_config(CA, Resumption::Off);
    let mut client = Connection::client(&config, "server.test", limits, &budget(), at(0)).unwrap();
    assert!(!Pair::send(&mut client, at(0)).is_empty());
    let turn = client.drive(at(4_999));
    assert_eq!(turn.progress, Progress::Blocked(rsnetwork::drive::Blocked::Input));
    assert_eq!(turn.deadline.map(|deadline| deadline.instant()), Some(at(5_000)));
    let idle = terminal(client.drive(at(5_000)).progress).expect("the idle deadline ended the client");
    assert_eq!(
        idle.unwrap_err().reason(),
        "the QUIC connection was idle past its timeout"
    );
    assert_eq!(
        client.transmit(&mut [0; 1500], at(5_000)),
        Ok(None),
        "an idle end sends nothing"
    );

    // Two ends with no traffic after the handshake.
    let mut pair = Pair::new(&config, server_config(SERVER, &[], Resumption::Off), (limits, limits));
    pair.run(at(0), Order::Sent);
    assert!(pair.client.is_confirmed());
    for connection in [&mut pair.client, pair.server.as_mut().unwrap()] {
        assert_eq!(terminal(connection.drive(at(4_999)).progress), None);
        let idle = terminal(connection.drive(at(5_000)).progress).expect("the idle deadline ended the end");
        assert_eq!(idle.unwrap_err().kind(), Kind::Deadline);
    }
}

#[test]
fn a_handshake_that_does_not_confirm_by_its_deadline_ends() {
    let limits = Limits {
        handshake_timeout: Duration::from_secs(2),
        ..Limits::DEFAULT
    };
    let config = client_config(CA, Resumption::Off);
    let mut client = Connection::client(&config, "server.test", limits, &budget(), at(0)).unwrap();
    Pair::send(&mut client, at(0));
    assert_eq!(
        client.drive(at(1_999)).deadline.map(|deadline| deadline.instant()),
        Some(at(2_000))
    );
    let late = terminal(client.drive(at(2_000)).progress).expect("the handshake deadline ended the client");
    let error = late.unwrap_err();
    assert_eq!(
        (error.kind(), error.reason()),
        (
            Kind::Deadline,
            "the QUIC handshake did not complete before its deadline"
        )
    );
}

#[test]
fn a_key_update_keeps_the_connection_and_the_crypto_stream_of_its_data_space() {
    let config = client_config(CA, SESSIONS);
    let server_limits = Limits {
        key_packets_max: 2,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(
        &config,
        server_config(SERVER, &[], SESSIONS),
        (Limits::DEFAULT, server_limits),
    );
    // The handshake, up to the first 1-RTT datagram of the server: it holds HANDSHAKE_DONE and
    // the session tickets, in phase 0.
    for _ in 0..16 {
        pair.to_server.extend(Pair::send(&mut pair.client, at(0)));
        while let Some(datagram) = pair.to_server.pop_front() {
            pair.deliver(datagram, at(0));
        }
        if pair.server().is_confirmed() {
            break;
        }
        for datagram in Pair::send(pair.server(), at(0)) {
            Pair::give(&mut pair.client, datagram, at(0));
        }
    }
    let late = Pair::send(pair.server(), at(0));
    assert!(!late.is_empty(), "the server sends HANDSHAKE_DONE and its tickets");
    assert_eq!(pair.server().key_phase(), Some(false));
    // Two PINGs reach the key limit of the server, which then updates its keys.
    for _ in 0..2 {
        pair.server().ping();
        let _ = Pair::send(pair.server(), at(0));
    }
    assert_eq!(pair.server().key_phase(), Some(true), "the server updated its keys");
    pair.server().ping();
    let updated = Pair::send(pair.server(), at(0));
    // The client reads the packet of phase 1 first: it follows the update. Then the late packets
    // of phase 0 open with the previous key, with HANDSHAKE_DONE and the tickets.
    for datagram in updated {
        Pair::give(&mut pair.client, datagram, at(0));
    }
    assert_eq!(pair.client.key_phase(), Some(true), "the client followed the update");
    assert!(!pair.client.is_confirmed());
    for datagram in late {
        Pair::give(&mut pair.client, datagram, at(0));
    }
    assert!(
        pair.client.is_confirmed(),
        "the late HANDSHAKE_DONE opened with the previous key"
    );
    // Both ends go on in the new phase.
    pair.client.ping();
    for datagram in Pair::send(&mut pair.client, at(0)) {
        assert_eq!(terminal(Pair::give(pair.server(), datagram, at(0))), None);
    }
    // The ticket of the late packet resumes the next connection.
    let mut next = Pair::new(&config, pair.config.clone(), (Limits::DEFAULT, Limits::DEFAULT));
    next.run(at(0), Order::Sent);
    assert_eq!(next.client.negotiated().unwrap().handshake, Handshake::Resumed);
}

#[test]
fn zero_rtt_is_refused_with_no_replay_contract() {
    let config = client_config(CA, SESSIONS);
    let server = server_config(SERVER, &[], SESSIONS);
    let mut first = Pair::new(&config, server.clone(), (Limits::DEFAULT, Limits::DEFAULT));
    first.run(at(0), Order::Sent);
    // A resumed client, which could send early data, sends no 0-RTT packet.
    let mut resumed = Pair::new(&config, server, (Limits::DEFAULT, Limits::DEFAULT));
    let flight = Pair::send(&mut resumed.client, at(0));
    let cid_bytes = resumed.client.local_cid().as_bytes().len();
    assert!(
        flight
            .iter()
            .all(|datagram| !kinds(datagram, cid_bytes).contains(&PacketKind::ZeroRtt))
    );
    // A server discards a 0-RTT packet: no key opens it, and the handshake goes on.
    let Ok(Header::Protected { dcid, scid, .. }) = Header::parse(&flight[0], 0) else {
        panic!("the first datagram has an Initial packet");
    };
    let keys = packet::initial_keys(&dcid, Side::Client);
    let mut zero_rtt = vec![0; 1200];
    let mut builder = Builder::new(
        &mut zero_rtt,
        Outgoing::ZeroRtt {
            dcid: &dcid,
            scid: &scid,
        },
        0,
        1,
    )
    .unwrap();
    builder.frame(&rsnetwork::quic::frame::Frame::Ping).unwrap();
    let len = builder.seal(&keys.local).unwrap();
    zero_rtt.truncate(len);
    for datagram in flight {
        resumed.deliver(datagram, at(0));
    }
    assert_eq!(terminal(resumed.deliver(zero_rtt, at(0))), None);
    resumed.run(at(0), Order::Sent);
    assert!(resumed.client.is_confirmed());
    assert_eq!(resumed.client.negotiated().unwrap().handshake, Handshake::Resumed);
}

#[test]
fn transport_parameters_write_and_parse_back_and_the_defaults_take_no_bytes() {
    assert_eq!(Parameters::default().encoded_len(), Some(0));
    let parameters = Parameters {
        original_destination_cid: ConnectionId::new(&[1; 8]),
        idle_timeout: Some(Duration::from_millis(30_000)),
        stateless_reset_token: Some([7; 16]),
        udp_payload_bytes_max: 1_472,
        data_bytes_initial: 1 << 20,
        stream_bytes_bidi_local_initial: 1 << 16,
        stream_bytes_bidi_remote_initial: 1 << 16,
        stream_bytes_uni_initial: 1 << 15,
        streams_bidi_initial: 100,
        streams_uni_initial: 3,
        ack_delay_exponent: 10,
        ack_delay_max: Duration::from_millis(40),
        migration: Migration::Disabled,
        preferred_address: Some(PreferredAddress {
            ipv4: ([192, 0, 2, 1], 443),
            ipv6: ([0; 16], 0),
            connection_id: ConnectionId::new(&[9; 4]).unwrap(),
            reset_token: [3; 16],
        }),
        connection_ids_active_max: 4,
        initial_source_cid: ConnectionId::new(&[2; 8]),
        retry_source_cid: ConnectionId::new(&[5; 8]),
        datagram_bytes_max: Some(1_200),
    };
    let mut bytes = vec![0; parameters.encoded_len().unwrap()];
    assert_eq!(parameters.write(&mut bytes), Some(bytes.len()));
    assert_eq!(Parameters::parse(&bytes, Sender::Server), Ok(parameters));
    // The idle timeout of RFC 9000, section 18.2: identifier 0x01, length 4, value 30000 ms.
    assert!(
        bytes
            .windows(6)
            .any(|window| window == [0x01, 0x04, 0x80, 0x00, 0x75, 0x30])
    );
}

#[test]
fn transport_parameters_that_break_a_rule_refuse_with_their_identifier() {
    let cases: [(&[u8], Sender, Option<u64>); 9] = [
        // A parameter two times.
        (&[0x01, 0x01, 0x05, 0x01, 0x01, 0x06], Sender::Client, Some(0x01)),
        // A UDP payload size below 1,200 bytes.
        (&[0x03, 0x02, 0x44, 0xaf], Sender::Client, Some(0x03)),
        // An ACK delay exponent above 20.
        (&[0x0a, 0x01, 0x15], Sender::Client, Some(0x0a)),
        // An ACK delay of 2^14 ms.
        (&[0x0b, 0x04, 0x80, 0x00, 0x40, 0x00], Sender::Client, Some(0x0b)),
        // An active connection ID limit below 2.
        (&[0x0e, 0x01, 0x01], Sender::Client, Some(0x0e)),
        // A stream limit above 2^60.
        (&[0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1], Sender::Client, Some(0x08)),
        // Parameters that only a server sends.
        (&[0x00, 0x01, 0x07], Sender::Client, Some(0x00)),
        (&[0x10, 0x01, 0x07], Sender::Client, Some(0x10)),
        // A value that ends past the parameters.
        (&[0x04, 0x02, 0x01], Sender::Server, Some(0x04)),
    ];
    for (bytes, sender, id) in cases {
        assert_eq!(
            Parameters::parse(bytes, sender),
            Err(ParameterError { id }),
            "{bytes:02x?}"
        );
    }
    // A reserved parameter of RFC 9000, section 18.1 (31 * 1 + 27 = 58) is ignored.
    assert_eq!(
        Parameters::parse(&[0x40, 0x3a, 0x02, 0xff, 0xff], Sender::Client),
        Ok(Parameters::default())
    );
}
