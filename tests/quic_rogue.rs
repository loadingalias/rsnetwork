//! A server engine of the core against a client that breaks the rules of the streams: each
//! frame past a window, a limit, a final size, or the direction of a stream closes the connection
//! with its code of RFC 9000, section 20.1, and takes no memory (N305). The same client probes a
//! path that the connection does not use (N307).
//!
//! The client is a harness: rustls runs its handshake, and the packet layer of the core seals and
//! opens its packets. It sends each frame that a test gives it, on a path with no loss.

use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Kind, Progress};
use rsnetwork::quic::frame::{Direction, Frame};
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Keys, Kind as PacketKind, Outgoing, Side};
use rsnetwork::quic::params::Parameters;
use rsnetwork::quic::{CRYPTO_BUFFER_BYTES_MAX, Connection, ConnectionId, ErrorCode, Event, Limits, Path};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, Entropy, Identity, PrivateKeyDer, Resumption, ServerConfig, ServerOptions, TimeProvider, UnixTime,
};
use rustls::enums::ApplicationProtocol;
use rustls::pki_types::ServerName;
use rustls::quic::{ClientHandshake, KeyChange, QuicEvent, Version};
use rustls::{RootCertStore, TlsInputBuffer as _, VecInput};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
/// 2027-01-01, inside the validity of each certificate.
const VALID: u64 = 1_798_761_600;
/// The levels of the packets: Initial, Handshake, and 1-RTT.
const DATA: usize = 2;

/// A wall clock that stays at one time.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn now() -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), 0)
}

/// The path of the server to a client at the port `port`.
fn path(port: u16) -> Path {
    Path {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
        peer: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    }
}

/// A client that a test drives by hand.
struct Rogue {
    tls: Option<ClientHandshake>,
    events: Vec<QuicEvent>,
    keys: [Option<Keys>; 3],
    /// The CRYPTO bytes of the server at each level, in order, and their end.
    input: [VecInput; 3],
    received: [usize; 3],
    /// The CRYPTO bytes of the client at each level, and the bytes of them that went out.
    output: [Vec<u8>; 3],
    sent: [usize; 3],
    /// The next packet number of each level, and the next one that the client expects.
    numbers: [u64; 3],
    expected: [u64; 3],
    /// The level of the next messages of rustls, and the level that it reads.
    write: usize,
    read: usize,
    /// The connection ID of the server, which its first packet gives, and the one of the client.
    server_cid: ConnectionId,
    cid: ConnectionId,
    complete: bool,
    /// Each CONNECTION_CLOSE frame of the server: its code and the type of the frame that caused it.
    closes: Vec<(u64, Option<u64>)>,
    /// The data of each PATH_RESPONSE frame of the server.
    answers: Vec<[u8; 8]>,
}

impl Rogue {
    /// Starts a client that offers `parameters`, with its connection ID in them.
    fn new(mut parameters: Parameters) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(CA.to_vec())).unwrap();
        let mut config = rustls::ClientConfig::builder_with_details(
            Arc::new(rscrypto_rustls::default_provider()),
            Arc::new(At(VALID)),
        )
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth()
        .unwrap();
        config.alpn_protocols = vec![ApplicationProtocol::from(b"test".to_vec())];
        let (original, cid) = (
            ConnectionId::new(&[0xa5; 8]).unwrap(),
            ConnectionId::new(&[0x5a; 8]).unwrap(),
        );
        parameters.initial_source_cid = Some(cid);
        let mut encoded = vec![0; parameters.encoded_len().unwrap()];
        parameters.write(&mut encoded).unwrap();
        let mut events = Vec::new();
        let needs = Arc::new(config)
            .connect(ServerName::try_from("server.test").unwrap())
            .start_quic_handshake(Version::V1, encoded, &mut events)
            .unwrap();
        let mut rogue = Self {
            tls: Some(ClientHandshake::NeedsInput(needs)),
            events,
            keys: [Some(packet::initial_keys(&original, Side::Client)), None, None],
            input: [VecInput::default(), VecInput::default(), VecInput::default()],
            received: [0; 3],
            output: [Vec::new(), Vec::new(), Vec::new()],
            sent: [0; 3],
            numbers: [0; 3],
            expected: [0; 3],
            write: 0,
            read: 0,
            server_cid: original,
            cid,
            complete: false,
            closes: Vec::new(),
            answers: Vec::new(),
        };
        rogue.take_events();
        rogue
    }

    /// Takes the messages and the keys that rustls gave.
    fn take_events(&mut self) {
        for event in self.events.drain(..) {
            match event {
                QuicEvent::Message(message) => self.output[self.write].extend_from_slice(&message),
                QuicEvent::KeyChange(KeyChange::Handshake { keys }) => {
                    self.keys[1] = Some(keys);
                    (self.write, self.read) = (1, 1);
                }
                QuicEvent::KeyChange(KeyChange::OneRtt { keys, .. }) => {
                    self.keys[DATA] = Some(keys);
                    self.write = DATA;
                }
                _ => panic!("an event of rustls that the harness does not know"),
            }
        }
    }

    /// One packet of `level` with `frames`, in a datagram of its own.
    fn packet(&mut self, level: usize, frames: &[Frame<'_>]) -> Vec<u8> {
        let mut out = vec![0; 1500];
        let (dcid, scid) = (self.server_cid, self.cid);
        let header = match level {
            0 => Outgoing::Initial {
                dcid: &dcid,
                scid: &scid,
                token: &[],
            },
            1 => Outgoing::Handshake {
                dcid: &dcid,
                scid: &scid,
            },
            _ => Outgoing::OneRtt {
                dcid: &dcid,
                spin: false,
                key_phase: false,
            },
        };
        let mut builder = Builder::new(&mut out, header, self.numbers[level], 4).unwrap();
        self.numbers[level] += 1;
        for frame in frames {
            builder.frame(frame).unwrap();
        }
        if level == 0 {
            builder.pad_to(1200).unwrap();
        }
        let len = builder.seal(&self.keys[level].as_ref().unwrap().local).unwrap();
        out.truncate(len);
        out
    }

    /// The datagrams of the CRYPTO bytes that wait at `level`.
    fn crypto(&mut self, level: usize) -> Vec<Vec<u8>> {
        let mut datagrams = Vec::new();
        while self.sent[level] < self.output[level].len() {
            let end = self.output[level].len().min(self.sent[level] + 1000);
            let data = self.output[level][self.sent[level]..end].to_vec();
            let frame = Frame::Crypto {
                offset: self.sent[level] as u64,
                data: &data,
            };
            datagrams.push(self.packet(level, &[frame]));
            self.sent[level] = end;
        }
        datagrams
    }

    /// Opens the packets of `datagram` of the server, and runs rustls on their CRYPTO data.
    fn receive(&mut self, datagram: &[u8]) {
        let mut datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, self.cid.as_bytes().len());
        while let Some(Ok(packet)) = datagrams.next_packet() {
            let Header::Protected { kind, scid, .. } = *packet.header() else {
                continue;
            };
            let level = match kind {
                PacketKind::Initial => 0,
                PacketKind::Handshake => 1,
                _ => DATA,
            };
            let Some(keys) = &self.keys[level] else {
                continue;
            };
            let Ok(opened) = packet
                .unmask(&*keys.remote.header, self.expected[level])
                .and_then(|unmasked| unmasked.open(&*keys.remote.packet))
            else {
                continue;
            };
            self.expected[level] = self.expected[level].max(opened.number() + 1);
            if level == 0 {
                self.server_cid = scid;
            }
            let payload = opened.payload();
            let mut bytes = payload.bytes();
            while !bytes.is_empty() {
                let (frame, len) = Frame::parse(bytes).unwrap();
                bytes = &bytes[len..];
                match frame {
                    // The path has no loss and keeps the order, so each frame continues the bytes.
                    Frame::Crypto { offset, mut data } => {
                        assert_eq!(offset, self.received[level] as u64, "the CRYPTO data is in order");
                        self.received[level] += data.len();
                        while !data.is_empty() {
                            self.input[level].read(&mut data).unwrap();
                        }
                    }
                    Frame::ConnectionClose { code, frame_type, .. } => self.closes.push((code, frame_type)),
                    Frame::PathResponse { data } => self.answers.push(data),
                    _ => {}
                }
            }
            self.advance();
        }
    }

    /// Runs rustls while it makes progress. rustls reports what a call consumed by the next call
    /// at the latest, so it waits for input after two calls in a row with no progress.
    fn advance(&mut self) {
        let mut stalled = false;
        for _ in 0..64 {
            let before = (self.read, self.input[self.read].slice_mut().len());
            let (next, verified) = match self.tls.take() {
                Some(ClientHandshake::NeedsInput(needs)) => {
                    (needs.process(&mut self.input[self.read], &mut self.events), false)
                }
                Some(ClientHandshake::VerifyServerIdentity(verify)) => (verify.with_config(&mut self.events), true),
                Some(ClientHandshake::Complete(_)) | None => {
                    self.complete = true;
                    return;
                }
                Some(_) => panic!("a state of rustls that the harness does not know"),
            };
            self.tls = Some(next.unwrap());
            let progress = verified || !self.events.is_empty();
            self.take_events();
            if progress || (self.read, self.input[before.0].slice_mut().len()) != before {
                stalled = false;
            } else if core::mem::replace(&mut stalled, true) {
                return;
            }
        }
        panic!("rustls makes progress with no end");
    }

    /// A 1-RTT packet with `frames`.
    fn data(&mut self, frames: &[Frame<'_>]) -> Vec<u8> {
        self.packet(DATA, frames)
    }
}

/// Each datagram that `connection` sends now.
fn sent(connection: &mut Connection) -> Vec<Vec<u8>> {
    routed(connection).into_iter().map(|(_, datagram)| datagram).collect()
}

/// Each datagram that `connection` sends now, with its path.
fn routed(connection: &mut Connection) -> Vec<(Path, Vec<u8>)> {
    let mut datagrams = Vec::new();
    for _ in 0..64 {
        let mut out = vec![0; 1500];
        match connection.transmit(&mut out, now()).unwrap() {
            Some(sent) => {
                out.truncate(sent.len);
                datagrams.push((sent.path, out));
            }
            None => return datagrams,
        }
    }
    panic!("a server sends at most 64 datagrams at once");
}

/// Gives `datagram` to `connection` on its path, and gives the events of the call.
fn give(connection: &mut Connection, datagram: &[u8]) -> Vec<Event> {
    let path = connection.path();
    give_on(connection, path, datagram)
}

/// Gives `datagram` to `connection` as a datagram that arrived on `path`.
fn give_on(connection: &mut Connection, path: Path, datagram: &[u8]) -> Vec<Event> {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, len);
    let mut events = Vec::new();
    for _ in 0..64 {
        match connection.receive(&mut datagrams, path, now()) {
            (Some(event), _) => events.push(event),
            (None, turn) if turn.progress == Progress::Pending => {}
            (None, _) => return events,
        }
    }
    panic!("a datagram gives at most 64 events");
}

/// A server with `limits`, and the hostile client. With `complete`, the client sends its
/// Finished message, so the handshake completes at both ends.
fn pair(limits: Limits, complete: bool) -> (Connection, Rogue) {
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let config = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(SERVER.0.to_vec())],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"test"],
        resumption: Resumption::Off,
        budget: &budget,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap();
    let mut rogue = Rogue::new(Parameters {
        data_bytes_initial: 1 << 20,
        ..Parameters::default()
    });
    let hello = rogue.crypto(0);
    let header = Header::parse(&hello[0], 0).unwrap();
    let mut server = Connection::server(&config, &header, path(4301), limits, &budget, now()).unwrap();
    for datagram in &hello {
        assert!(give(&mut server, datagram).is_empty());
    }
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    assert!(rogue.keys[DATA].is_some(), "the client has its 1-RTT keys");
    if complete {
        for datagram in rogue.crypto(1) {
            assert!(give(&mut server, &datagram).is_empty());
        }
        assert!(server.is_confirmed() && rogue.closes.is_empty());
        for datagram in sent(&mut server) {
            rogue.receive(&datagram);
        }
    }
    (server, rogue)
}

/// Gives the 1-RTT packet with `frames` to the server, and gives the events of the server.
fn attack(server: &mut Connection, rogue: &mut Rogue, frames: &[Frame<'_>]) -> Vec<Event> {
    let datagram = rogue.data(frames);
    give(server, &datagram)
}

/// Gives the 1-RTT packet with `frames`, which breaks a rule, to the server. Checks that the
/// server ends for its application at once, closes with `code` for a frame of type `frame`, and
/// gives its terminal outcome at the end of its closing period.
fn refused(server: &mut Connection, rogue: &mut Rogue, frames: &[Frame<'_>], code: ErrorCode, frame: u64) {
    let events = attack(server, rogue, frames);
    assert_matches!(&events[..], [Event::Closed(Err(error))] if error.kind() == Kind::Malformed);
    for datagram in sent(server) {
        rogue.receive(&datagram);
    }
    assert_eq!(rogue.closes, [(code.0, Some(frame))]);
    let turn = server.drive(now()).1;
    assert_eq!(turn.progress, Progress::Blocked(Blocked::Input));
    let end = turn.deadline.expect("a closing period has its end").instant();
    assert_matches!(server.drive(end).1.progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Malformed);
}

fn stream(stream: u64, offset: u64, data: &[u8], fin: bool) -> Frame<'_> {
    Frame::Stream {
        stream,
        offset,
        data,
        fin,
    }
}

#[test]
fn data_past_the_window_of_a_stream_or_of_the_connection_closes_with_flow_control_error() {
    let limits = Limits {
        stream_bytes_max: 1000,
        data_bytes_max: 1500,
        ..Limits::DEFAULT
    };
    let bytes = [7; 1001];
    // One byte past the window of the stream, in order.
    let (mut server, mut rogue) = pair(limits, true);
    refused(
        &mut server,
        &mut rogue,
        &[stream(0, 0, &bytes, false)],
        ErrorCode::FLOW_CONTROL_ERROR,
        0x08,
    );

    // One byte past it far out of order: the offset alone breaks the rule, and no page holds it.
    let (mut server, mut rogue) = pair(limits, true);
    refused(
        &mut server,
        &mut rogue,
        &[stream(0, 1000, &bytes[..1], false)],
        ErrorCode::FLOW_CONTROL_ERROR,
        0x08,
    );

    // Each stream inside its window, and the second one byte past the window of the connection.
    let (mut server, mut rogue) = pair(limits, true);
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, &bytes[..1000], false)]);
    assert_matches!(&events[..], [Event::Stream { data, end: false, .. }] if data.bytes() == &bytes[..1000]);
    refused(
        &mut server,
        &mut rogue,
        &[stream(4, 0, &bytes[..501], false)],
        ErrorCode::FLOW_CONTROL_ERROR,
        0x08,
    );

    // A reset counts its final size, also for the bytes that never arrived.
    let (mut server, mut rogue) = pair(limits, true);
    let reset = Frame::ResetStream {
        stream: 0,
        code: 1,
        final_size: 1001,
    };
    refused(&mut server, &mut rogue, &[reset], ErrorCode::FLOW_CONTROL_ERROR, 0x04);
}

#[test]
fn a_stream_past_the_stream_limit_closes_and_a_stream_opens_each_stream_below_it_with_no_state() {
    let limits = Limits {
        streams_bidi_max: 10,
        ..Limits::DEFAULT
    };
    // The client opens its last stream first: the nine streams below it open with it.
    let (mut server, mut rogue) = pair(limits, true);
    let events = attack(&mut server, &mut rogue, &[stream(36, 0, b"last", true)]);
    assert_matches!(&events[..], [Event::Stream { stream, end: true, .. }] if stream.get() == 36);
    // A stream below it carries data, and the server can send on it.
    let events = attack(&mut server, &mut rogue, &[stream(8, 0, b"low", false)]);
    assert_matches!(&events[..], [Event::Stream { stream, data, .. }] if stream.get() == 8 && data.bytes() == b"low");
    // The next stream is past the limit.
    refused(
        &mut server,
        &mut rogue,
        &[stream(40, 0, b"x", false)],
        ErrorCode::STREAM_LIMIT_ERROR,
        0x08,
    );
}

#[test]
fn a_frame_that_changes_a_final_size_closes_with_final_size_error() {
    // Data after the end of the stream.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, b"0123456789", true)]);
    assert_matches!(&events[..], [Event::Stream { end: true, .. }]);
    refused(
        &mut server,
        &mut rogue,
        &[stream(0, 10, b"x", false)],
        ErrorCode::FINAL_SIZE_ERROR,
        0x08,
    );

    // An end before the bytes that arrived.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    assert!(attack(&mut server, &mut rogue, &[stream(0, 5, b"56789", false)]).is_empty());
    refused(
        &mut server,
        &mut rogue,
        &[stream(0, 0, b"0123", true)],
        ErrorCode::FINAL_SIZE_ERROR,
        0x08,
    );

    // A reset with a final size below the bytes that arrived.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    assert_eq!(
        attack(&mut server, &mut rogue, &[stream(0, 0, b"0123456789", false)]).len(),
        1
    );
    let reset = Frame::ResetStream {
        stream: 0,
        code: 1,
        final_size: 9,
    };
    refused(&mut server, &mut rogue, &[reset], ErrorCode::FINAL_SIZE_ERROR, 0x04);
}

#[test]
fn a_frame_on_a_stream_that_cannot_carry_it_closes_with_stream_state_error() {
    // Data on a unidirectional stream of the server, and on a stream that the server did not open.
    for id in [3, 1] {
        let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
        refused(
            &mut server,
            &mut rogue,
            &[stream(id, 0, b"x", false)],
            ErrorCode::STREAM_STATE_ERROR,
            0x08,
        );
    }
    // Credit and a stop for a stream that the server only receives.
    let frames = [
        (Frame::MaxStreamData { stream: 2, max: 100 }, 0x11),
        (Frame::StopSending { stream: 2, code: 0 }, 0x05),
    ];
    for (frame, kind) in frames {
        let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
        refused(&mut server, &mut rogue, &[frame], ErrorCode::STREAM_STATE_ERROR, kind);
    }
    // The server opens its own stream: then the client can send on it.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    assert_eq!(
        server.open(Direction::Bidirectional).unwrap(),
        None,
        "the client gave no stream credit"
    );
    let credit = Frame::MaxStreams {
        direction: Direction::Bidirectional,
        max: 1,
    };
    assert_matches!(
        attack(&mut server, &mut rogue, &[credit])[..],
        [Event::Openable(Direction::Bidirectional)]
    );
    let opened = server
        .open(Direction::Bidirectional)
        .unwrap()
        .expect("the credit of the client");
    assert_eq!(opened.get(), 1);
    assert_eq!(attack(&mut server, &mut rogue, &[stream(1, 0, b"x", false)]).len(), 1);
}

#[test]
fn an_unreliable_datagram_that_the_server_did_not_offer_to_take_closes_the_connection() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    refused(
        &mut server,
        &mut rogue,
        &[Frame::Datagram { data: b"x" }],
        ErrorCode::PROTOCOL_VIOLATION,
        0x30,
    );
}

#[test]
fn a_server_reads_no_1_rtt_packet_before_its_handshake_completes() {
    // The client has its 1-RTT keys, and the server did not see its Finished message.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, false);
    assert!(!server.is_confirmed());
    assert!(attack(&mut server, &mut rogue, &[stream(0, 0, b"early", false)]).is_empty());
    for datagram in rogue.crypto(1) {
        assert!(give(&mut server, &datagram).is_empty());
    }
    assert!(server.is_confirmed());
    // The data that the server did not read arrives again.
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, b"early", false)]);
    assert_matches!(&events[..], [Event::Stream { data, .. }] if data.bytes() == b"early");
}

#[test]
fn crypto_data_past_the_buffer_bound_of_its_level_closes_with_crypto_buffer_exceeded() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, false);
    // One byte at the first offset past the bound: no memory holds the bytes before it.
    let far = Frame::Crypto {
        offset: CRYPTO_BUFFER_BYTES_MAX as u64,
        data: b"x",
    };
    let datagram = rogue.packet(1, &[far]);
    assert!(give(&mut server, &datagram).is_empty());
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    let close = (ErrorCode::CRYPTO_BUFFER_EXCEEDED.0, Some(0x06));
    assert!(!rogue.closes.is_empty() && rogue.closes.iter().all(|sent| *sent == close));
    // The handshake is not confirmed, so the server ends at once.
    assert_matches!(
        server.drive(now()).1.progress,
        Progress::Terminal(Err(error))
            if (error.kind(), error.reason())
                == (Kind::Overload, "the CRYPTO data of the peer passed the buffer bound of its level")
    );
}

/// The datagrams that `server` sends now to the path `to`. Its acknowledgements go to the path of
/// the connection.
fn answers_to(server: &mut Connection, to: Path) -> Vec<Vec<u8>> {
    let sent = routed(server);
    sent.into_iter()
        .filter(|(path, _)| *path == to)
        .map(|(_, datagram)| datagram)
        .collect()
}

#[test]
fn a_probe_from_another_path_gets_its_answer_there_within_the_limit_and_moves_no_connection() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let (home, other) = (server.path(), path(4400));
    // A probe of 1,200 bytes: the answer has the same data, on the path of the probe, in a datagram
    // of 1,200 bytes (RFC 9000, section 8.2.2).
    let probe = rogue.data(&[Frame::PathChallenge { data: [7; 8] }, Frame::Padding { len: 1200 }]);
    assert!(probe.len() >= 1200);
    assert!(give_on(&mut server, other, &probe).is_empty());
    let answers = answers_to(&mut server, other);
    assert_eq!(answers.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    rogue.receive(&answers[0]);
    assert_eq!(rogue.answers, [[7; 8]]);
    // A probe is no move: the connection stays on its path (RFC 9000, section 9.1).
    assert_eq!(server.path(), home);
    assert!(server.address_validated());

    // A small probe: its answer has at most three times its bytes.
    let small = rogue.data(&[Frame::PathChallenge { data: [9; 8] }]);
    assert!(give_on(&mut server, other, &small).is_empty());
    let answers = answers_to(&mut server, other);
    assert_eq!(answers.len(), 1);
    assert!(answers[0].len() <= 3 * small.len());
    rogue.receive(&answers[0]);
    assert_eq!(rogue.answers, [[7; 8], [9; 8]]);
    assert_eq!(server.path(), home);
    // The server still serves the client on its path.
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, b"after", false)]);
    assert_matches!(&events[..], [Event::Stream { data, .. }] if data.bytes() == b"after");
}
