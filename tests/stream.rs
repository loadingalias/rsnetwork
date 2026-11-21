//! The TLS stream for a protocol other than HTTP. The test is the binding of both ends: it moves
//! the ciphertext between them. The rules: a clean close needs `close_notify`, a write that ends
//! early reports the bytes whose records went, and the evidence names the key exchange and the
//! authentication of the peer.

use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Kind, Received, TurnLimits};
use rsnetwork::host::Io as _;
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    Authentication, CertificateDer, ClientConfig, ClientOptions, Entropy, Group, Identity, Limits, Peer, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions, Stream, StreamLimits, TimeProvider, UnixTime,
};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
const CLIENT: (&[u8], &[u8]) = (include_bytes!("tls/client.der"), include_bytes!("tls/client.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

const LIMITS: StreamLimits = StreamLimits {
    tls: Limits {
        input_bytes: 32 * 1024,
        key_records_max: u64::MAX,
        turn: TurnLimits {
            bytes: 1 << 20,
            frames: 1 << 10,
        },
    },
    queue: NonZeroUsize::new(16).unwrap(),
    handshake_timeout: Some(Duration::from_secs(5)),
};

/// The content of a full TLS record: 2^14 bytes (RFC 8446, section 5.1).
const RECORD: usize = 1 << 14;

const ENDPOINT: Endpoint = Endpoint {
    peer: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 50_000),
    local: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 5432),
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

fn identity((chain, key): (&[u8], &[u8])) -> Identity {
    Identity {
        chain: vec![CertificateDer::from(chain.to_vec())],
        key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
    }
}

/// A client and a server stream. With `mutual`, the server asks for a client certificate, and the
/// client has one.
fn pair(mutual: bool) -> (Stream, Stream) {
    let roots = [CertificateDer::from(CA.to_vec())];
    let server = ServerConfig::new(ServerOptions {
        identity: identity(SERVER),
        client_roots: mutual.then_some(&roots[..]),
        protocols: &[b"postgresql"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let client = ClientConfig::new(ClientOptions {
        roots: &roots,
        identity: mutual.then(|| identity(CLIENT)),
        protocols: &[b"postgresql"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    (
        Stream::connect(&client, "server.test", LIMITS, clock(), &budget()).unwrap(),
        Stream::accept(&server, LIMITS, clock(), &budget()).unwrap(),
    )
}

/// The transport accepts each output of `from`, and gives it to `to`. Gives whether a byte moved.
fn carry(from: &mut Stream, to: &mut Stream) -> bool {
    let mut moved = false;
    while let Some(output) = from.output() {
        let received = Received {
            region: Lease::from(output.region.bytes().to_vec()),
            endpoint: ENDPOINT,
            capacity: 1 << 20,
        };
        assert!(to.receive(received).is_ok(), "the stream takes the bytes");
        from.ack(output.id, output.region.initialized()).unwrap();
        moved = true;
    }
    moved
}

/// Reads `stream` until it waits: the bytes that came, and the outcome when it ended.
fn read(stream: &mut Stream, bytes: &mut Vec<u8>) -> Option<Outcome> {
    loop {
        match stream.next(at(0)).unwrap() {
            Some(Part::Data(data)) => bytes.extend_from_slice(data.bytes()),
            Some(Part::End(outcome)) => return Some(outcome),
            None => return None,
        }
    }
}

/// The binding of both ends: drives the client, moves the ciphertext, and reads the server, until
/// no byte moves. Gives the bytes that the server read, and its outcome.
fn run(client: &mut Stream, server: &mut Stream) -> (Vec<u8>, Option<Outcome>) {
    let (mut bytes, mut outcome) = (Vec::new(), None);
    for _ in 0..16 {
        client.drive(at(0)).unwrap();
        let up = carry(client, server);
        outcome = outcome.or_else(|| read(server, &mut bytes));
        let down = carry(server, client);
        if !up && !down {
            return (bytes, outcome);
        }
    }
    panic!("the transport still moves bytes after 16 rounds");
}

#[test]
fn an_end_with_no_close_notify_ends_the_stream_truncated_and_close_notify_ends_it_complete() {
    let (mut client, mut server) = pair(false);
    client.write(&Lease::from(&b"hello"[..]), at(0)).unwrap();
    client.close(at(0)).unwrap();
    let (bytes, outcome) = run(&mut client, &mut server);
    assert_eq!(bytes, b"hello");
    assert_matches!(outcome, Some(Outcome::Complete(None)));
    assert_eq!(client.release(), Some(Ok(())));

    // The transport ends after the bytes, with no `close_notify`.
    let (mut client, mut server) = pair(false);
    client.write(&Lease::from(&b"hello"[..]), at(0)).unwrap();
    let (mut bytes, outcome) = run(&mut client, &mut server);
    assert!(outcome.is_none(), "the stream goes on until its end");
    server.end_input();
    let outcome = read(&mut server, &mut bytes);
    assert_eq!(bytes, b"hello");
    assert_matches!(outcome, Some(Outcome::Truncated));
}

#[test]
fn a_write_that_ends_early_reports_the_bytes_whose_records_went() {
    let (mut client, mut server) = pair(false);
    run(&mut client, &mut server);
    assert!(client.negotiated().is_some(), "the handshake completed");
    // 40,000 bytes are two full records and one record of 7,232 bytes.
    client.write(&Lease::from(vec![b'x'; 40_000]), at(0)).unwrap();
    let output = client.output().unwrap();
    let full = 5 + RECORD + 1 + 16;
    assert!(
        output.region.initialized() > 2 * full,
        "the three records are in one output"
    );
    // The transport accepts the first record and 100 bytes of the second.
    client.ack(output.id, full + 100).unwrap();
    assert_eq!(client.written(), 40_000);
    assert_eq!(client.sent(), RECORD as u64);
    client.reset();
    assert_eq!(client.sent(), RECORD as u64, "the progress stays after the failure");
}

#[test]
fn the_evidence_names_the_key_exchange_and_the_authentication_of_the_peer() {
    let (mut client, mut server) = pair(false);
    run(&mut client, &mut server);
    let evidence = client.negotiated().expect("the handshake completed");
    assert_eq!(evidence.group, Group::X25519_MLKEM768);
    assert_eq!(evidence.protocol, Some(&b"postgresql"[..]));
    assert_eq!(
        evidence.peer,
        Some(Peer {
            certificate: SERVER.0,
            authentication: Authentication::EcdsaP256
        })
    );
    assert_eq!(server.negotiated().expect("the handshake completed").peer, None);

    let (mut client, mut server) = pair(true);
    run(&mut client, &mut server);
    assert_eq!(
        server.negotiated().expect("the handshake completed").peer,
        Some(Peer {
            certificate: CLIENT.0,
            authentication: Authentication::EcdsaP256
        })
    );
}

#[test]
fn an_accepted_stream_ends_at_its_handshake_timeout() {
    let (_, mut server) = pair(false);
    assert!(server.next(at(0)).unwrap().is_none());
    assert!(server.next(at(4_999)).unwrap().is_none());
    assert!(server.release().is_none());
    assert_matches!(server.next(at(5_000)), Err(error) if error.kind() == Kind::Deadline);
    assert_matches!(server.release(), Some(Err(error)) if error.kind() == Kind::Deadline);
}

#[test]
fn a_write_that_crosses_the_end_of_a_region_of_the_host_goes_on_in_order_and_counts_whole_records() {
    let (mut client, mut server) = pair(false);
    run(&mut client, &mut server);
    // A region of 20,000 bytes takes one full record of 16,384 bytes and one record that fills
    // its rest: 20,000 - 16,406 - 22 = 3,572 bytes. The rest of the write goes into the output of
    // the engine.
    let region = rsnetwork::buffer::Backing::from(Vec::with_capacity(20_000));
    let address = region.as_ptr().addr();
    client.output_region(region).unwrap();
    let data: Vec<u8> = (0..40_000_u32).map(|index| (index % 251) as u8).collect();
    client.write(&Lease::from(data.clone()), at(0)).unwrap();
    let first = client.output().unwrap();
    assert_eq!(first.region.bytes().as_ptr().addr(), address);
    assert_eq!(first.region.initialized(), 20_000);
    let received = Received {
        region: Lease::from(first.region.bytes().to_vec()),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    server.receive(received).unwrap();
    client.ack(first.id, first.region.initialized()).unwrap();
    assert_eq!(client.sent(), RECORD as u64 + 3_572);
    let (mut bytes, outcome) = run(&mut client, &mut server);
    assert!(outcome.is_none());
    assert_eq!(client.sent(), 40_000);
    read(&mut server, &mut bytes);
    assert_eq!(bytes, data, "the bytes arrive in their order");
}

#[test]
fn a_received_region_larger_than_the_input_region_opens_in_turns() {
    let (mut client, mut server) = pair(false);
    run(&mut client, &mut server);
    let data: Vec<u8> = (0..40_000_u32).map(|index| (index % 251) as u8).collect();
    client.write(&Lease::from(data.clone()), at(0)).unwrap();
    // The transport gives the server all 40,000 bytes of records in one read-only region, more
    // than its input region of 32 KiB.
    let mut records = Vec::new();
    while let Some(output) = client.output() {
        records.extend_from_slice(output.region.bytes());
        client.ack(output.id, output.region.initialized()).unwrap();
    }
    assert!(records.len() > LIMITS.tls.input_bytes);
    let received = Received {
        region: Lease::from(records),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    server.receive(received).unwrap();
    let mut bytes = Vec::new();
    for _ in 0..8 {
        read(&mut server, &mut bytes);
    }
    assert_eq!(bytes, data);
}
