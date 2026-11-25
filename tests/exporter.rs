//! The exporter of an established TLS connection (N501), on the public API only. An integration
//! binds a proof of possession to one connection and one authentication instance, as a native
//! session profile does: the client derives the proof and sends it over the connection, and the
//! server derives the proof that it expects on its own end. The test is the binding of both ends.

use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::body::Part;
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Http1};
use rsnetwork::drive::{Ecn, Endpoint, Received, TurnLimits};
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::host::Io as _;
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, EXPORT_CONTEXT_MAX, EXPORT_LABEL_MAX, EXPORT_OUTPUT_MAX, Entropy,
    ExportError, Handshake, Identity, Limits, PrivateKeyDer, RESERVED_LABEL_PREFIX, Resumption, ServerConfig,
    ServerOptions, Stream, StreamLimits, TimeProvider, UnixTime,
};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

const LIMITS: StreamLimits = StreamLimits {
    tls: Limits {
        input_bytes: 32 * 1024,
        key_records_max: u64::MAX,
        turn: TurnLimits {
            bytes: 1 << 20,
            frames: 1 << 10,
            visits: 1 << 12,
        },
    },
    queue: NonZeroUsize::new(16).unwrap(),
    handshake_timeout: Some(Duration::from_secs(5)),
};

const ENDPOINT: Endpoint = Endpoint {
    peer: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 50_000),
    local: core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 5432),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The label of the proofs of possession of this integration.
const LABEL: &[u8] = b"EXPERIMENTAL-example-possession";

/// A proof of possession: 32 bytes of exporter material.
type Proof = [u8; 32];

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

fn now() -> Instant {
    Instant::new(clock(), 0)
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 24).unwrap())
}

/// The configurations of a client and of a server, with `resumption`.
fn configs(resumption: Resumption) -> (ClientConfig, ServerConfig) {
    let roots = [CertificateDer::from(CA.to_vec())];
    let client = ClientConfig::new(ClientOptions {
        roots: &roots,
        identity: None,
        protocols: &[b"example"],
        resumption,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let (chain, key) = SERVER;
    let server = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(chain.to_vec())],
            key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"example"],
        resumption,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    (client, server)
}

/// A connection from `client` to `server`, after its handshake.
fn connect((client, server): &(ClientConfig, ServerConfig)) -> (Stream, Stream) {
    let mut pair = (
        Stream::connect(client, "server.test", LIMITS, clock(), &budget()).unwrap(),
        Stream::accept(server, LIMITS, clock(), &budget()).unwrap(),
    );
    run(&mut pair);
    assert!(pair.0.negotiated().is_some(), "the handshake completed");
    pair
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

/// Drives both ends and moves their bytes until no byte moves.
fn run((client, server): &mut (Stream, Stream)) {
    for _ in 0..16 {
        client.drive(now()).unwrap();
        server.drive(now()).unwrap();
        if !carry(client, server) & !carry(server, client) {
            return;
        }
    }
    panic!("the transport still moves bytes after 16 rounds");
}

/// The context of one authentication instance, which the verifier names: its purpose and its
/// number. Each instance is fresh.
fn context(purpose: &[u8], instance: u64) -> Vec<u8> {
    [purpose, b" ", &instance.to_be_bytes()].concat()
}

/// The proof of possession of `stream` for `context`.
fn prove(stream: &Stream, context: &[u8]) -> Proof {
    let mut proof = [0; 32];
    stream.export(LABEL, context, &mut proof).unwrap();
    proof
}

/// The client sends `proof` over the connection, and the server reads it.
fn send(pair: &mut (Stream, Stream), proof: Proof) -> Vec<u8> {
    pair.0.write(&Lease::from(proof.to_vec()), now()).unwrap();
    run(pair);
    let mut received = Vec::new();
    while let Some(Part::Data(data)) = pair.1.next(now()).unwrap() {
        received.extend_from_slice(data.bytes());
    }
    received
}

#[test]
fn a_proof_binds_one_connection_and_one_authentication_instance() {
    let configs = configs(Resumption::Off);
    let mut first = connect(&configs);
    let initial = context(b"initial", 1);
    let proof = prove(&first.0, &initial);
    // The server derives the proof that it expects on its own end of the same connection.
    let received = send(&mut first, proof);
    assert_eq!(received, prove(&first.1, &initial));
    // A proof does not verify for another context, or for the renewal of the instance.
    assert_ne!(received, prove(&first.1, &context(b"other audience", 1)));
    assert_ne!(received, prove(&first.1, &context(b"renewal", 2)));
    // A second connection between the same client and the same server expects other bytes.
    let second = connect(&configs);
    assert_ne!(received, prove(&second.1, &initial));
    assert_eq!(prove(&second.0, &initial), prove(&second.1, &initial));
}

#[test]
fn a_resumed_connection_derives_from_its_own_regular_exporter() {
    let configs = configs(Resumption::Process(NonZeroUsize::new(4).unwrap()));
    let full = connect(&configs);
    let resumed = connect(&configs);
    assert_eq!(resumed.0.negotiated().unwrap().handshake, Handshake::Resumed);
    // 0-RTT is off, so the early exporter has no secret: both ends derive from the regular one.
    let initial = context(b"initial", 1);
    assert_eq!(prove(&resumed.0, &initial), prove(&resumed.1, &initial));
    assert_ne!(prove(&resumed.1, &initial), prove(&full.1, &initial));
}

#[test]
fn each_argument_outside_its_limit_refuses_with_its_name_and_leaves_zeros() {
    let (client, server) = connect(&configs(Resumption::Off));
    let long = vec![b'x'; EXPORT_LABEL_MAX + 1];
    let reserved = [RESERVED_LABEL_PREFIX, b"channel"].concat();
    let context = vec![0; EXPORT_CONTEXT_MAX + 1];
    let mut output = [0xff; 32];
    for (label, context, error) in [
        (&b""[..], &b""[..], ExportError::Label),
        (&long, b"", ExportError::Label),
        (&reserved, b"", ExportError::Label),
        (LABEL, &context, ExportError::Context),
    ] {
        assert_eq!(client.export(label, context, &mut output), Err(error));
        assert_eq!(output, [0; 32], "a refusal leaves no material");
    }
    assert_eq!(client.export(LABEL, b"", &mut []), Err(ExportError::Length));
    let mut longest = vec![0; EXPORT_OUTPUT_MAX + 1];
    assert_eq!(client.export(LABEL, b"", &mut longest), Err(ExportError::Length));
    // The limits themselves are inside the profile, and both ends agree at them.
    let label = vec![b'x'; EXPORT_LABEL_MAX];
    let context = vec![0; EXPORT_CONTEXT_MAX];
    let (mut near, mut far) = (vec![0; EXPORT_OUTPUT_MAX], vec![0; EXPORT_OUTPUT_MAX]);
    client.export(&label, &context, &mut near).unwrap();
    server.export(&label, &context, &mut far).unwrap();
    assert_eq!(near, far);
}

#[test]
fn a_derivation_refuses_before_the_handshake_after_the_end_and_with_no_tls() {
    let (client, server) = configs(Resumption::Off);
    let mut output = [0; 32];
    let early = Stream::connect(&client, "server.test", LIMITS, clock(), &budget()).unwrap();
    assert_eq!(early.export(LABEL, b"", &mut output), Err(ExportError::Handshake));

    // A close of this end, and a reset of the transport.
    let mut pair = connect(&(client, server));
    pair.0.close(now()).unwrap();
    assert_eq!(pair.0.export(LABEL, b"", &mut output), Err(ExportError::Closed));
    pair.1.reset();
    assert_eq!(pair.1.export(LABEL, b"", &mut output), Err(ExportError::Closed));

    // An HTTP connection over TCP has no TLS.
    let limits = client::Limits {
        head: h1::Limits {
            head_bytes: 1024,
            fields: 16,
            name_bytes: 64,
            value_bytes: 256,
        },
        h2: h2::Limits {
            settings: h2::Settings::INITIAL,
            work: 64 * 1024,
            encoder_table_bytes: 4096,
            connection_window: 1 << 20,
        },
        body: BodyLimits {
            body_bytes: 1 << 20,
            drain_bytes: 64,
            extension_bytes: 64,
            trailer_bytes: 256,
            trailer_fields: 4,
        },
        turn: LIMITS.tls.turn,
        queue: LIMITS.queue,
    };
    let plain = Http1::plain(limits, clock(), &budget()).unwrap();
    assert_matches!(plain.export(LABEL, b"", &mut output), Err(ExportError::Unavailable));
}
