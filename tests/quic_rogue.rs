//! A server engine of the core against a client that breaks the rules of the streams: each
//! frame past a window, a limit, a final size, or the direction of a stream closes the connection
//! with its code of RFC 9000, section 20.1, and takes no memory (N305). A stop after the client
//! acknowledged each byte of a stream and its end changes nothing. Data out of order keeps
//! the counts of its stream when the reassembly bound refuses a part of it, and a gap between its
//! pieces costs no memory. The same client probes a path that the connection does not use, and
//! moves between its frames (N307). It also gives a listener a connection ID whose reset token
//! the test knows (N304).
//!
//! The client is a harness: rustls runs its handshake, and the packet layer of the core seals and
//! opens its packets. It sends each frame that a test gives it, on a path with no loss.

use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Kind, Progress, TurnLimits};
use rsnetwork::quic::frame::{Direction, Frame};
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Keys, Kind as PacketKind, Outgoing, Side};
use rsnetwork::quic::params::Parameters;
use rsnetwork::quic::{
    CRYPTO_BUFFER_BYTES_MAX, Connection, ConnectionId, Endpoint, EndpointKeys, EndpointLimits, ErrorCode, Event,
    Handle, Limits, Path, REDEEMED_BYTES_DEFAULT, Route,
};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, Entropy, Identity, PrivateKeyDer, Resumption, ServerConfig, ServerOptions, TimeProvider, UnixTime,
};
use rustls::enums::ApplicationProtocol;
use rustls::pki_types::ServerName;
use rustls::quic::{ClientHandshake, KeyChange, PacketKeySet, QuicEvent, Secrets, Version};
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
    /// The secrets of the 1-RTT phases after the first one.
    next: Option<Secrets>,
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
    /// The data of each PATH_CHALLENGE frame of the server.
    challenges: Vec<[u8; 8]>,
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
            next: None,
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
            challenges: Vec::new(),
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
                QuicEvent::KeyChange(KeyChange::OneRtt { keys, next }) => {
                    self.keys[DATA] = Some(keys);
                    self.next = Some(next);
                    self.write = DATA;
                }
                _ => panic!("an event of rustls that the harness does not know"),
            }
        }
    }

    /// One packet of `level` with `frames`, in a datagram of its own.
    fn packet(&mut self, level: usize, frames: &[Frame<'_>]) -> Vec<u8> {
        let number = self.numbers[level];
        self.numbers[level] += 1;
        self.packet_at(level, number, None, frames)
    }

    /// One packet of `level` with the number `number` and `frames`. With `phase`, a 1-RTT packet
    /// has the key phase 1, and the packet key of that phase seals it.
    fn packet_at(
        &mut self,
        level: usize,
        number: u64,
        phase: Option<&mut PacketKeySet>,
        frames: &[Frame<'_>],
    ) -> Vec<u8> {
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
                key_phase: phase.is_some(),
            },
        };
        let mut builder = Builder::new(&mut out, header, number, 4).unwrap();
        for frame in frames {
            builder.frame(frame).unwrap();
        }
        if level == 0 {
            builder.pad_to(1200).unwrap();
        }
        let keys = self.keys[level].as_mut().unwrap();
        if let Some(next) = phase {
            core::mem::swap(&mut keys.local.packet, &mut next.local);
            let len = builder.seal(&keys.local).unwrap();
            core::mem::swap(&mut keys.local.packet, &mut next.local);
            out.truncate(len);
        } else {
            let len = builder.seal(&keys.local).unwrap();
            out.truncate(len);
        }
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
                    Frame::PathChallenge { data } => self.challenges.push(data),
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
    give_at(connection, path, datagram, now())
}

/// Gives `datagram` to `connection` as a datagram that arrived on `path` at the time `at`.
fn give_at(connection: &mut Connection, path: Path, datagram: &[u8], at: Instant) -> Vec<Event> {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, len);
    let mut events = Vec::new();
    for _ in 0..64 {
        match connection.receive(&mut datagrams, path, at) {
            (Some(event), _) => events.push(event),
            (None, turn) if turn.progress == Progress::Pending => {}
            (None, _) => return events,
        }
    }
    panic!("a datagram gives at most 64 events");
}

fn server_config(budget: &Budget) -> ServerConfig {
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(SERVER.0.to_vec())],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"test"],
        resumption: Resumption::Off,
        budget,
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

/// A server with `limits`, and the hostile client. With `complete`, the client sends its
/// Finished message, so the handshake completes at both ends.
fn pair(limits: Limits, complete: bool) -> (Connection, Rogue) {
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let config = server_config(&budget);
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

/// The bytes of each [`Event::Stream`] in `events`, in order.
fn stream_bytes(events: &[Event]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for event in events {
        let Event::Stream { data, .. } = event else {
            panic!("an event that is not stream data: {event:?}");
        };
        bytes.extend_from_slice(data.bytes());
    }
    bytes
}

#[test]
fn a_frame_whose_second_page_the_reassembly_bound_refuses_counts_its_bytes_and_its_stream_can_stop() {
    // The bound holds one page: a frame across two pages keeps its first page and is refused.
    let limits = Limits {
        reassembly_bytes_max: 4096,
        ..Limits::DEFAULT
    };
    let (mut server, mut rogue) = pair(limits, true);
    let bytes: Vec<u8> = (0..=u8::MAX).cycle().take(4200).collect();
    assert!(attack(&mut server, &mut rogue, &[stream(0, 4000, &bytes[4000..], false)]).is_empty());
    assert_eq!(server.reassembly_refused(), 1);
    // The bytes before the gap arrive, and the kept page goes up after them.
    let mut events = Vec::new();
    for offset in (0..4000).step_by(1000) {
        let frame = stream(0, offset as u64, &bytes[offset..offset + 1000], false);
        events.extend(attack(&mut server, &mut rogue, &[frame]));
    }
    assert_eq!(stream_bytes(&events), bytes[..4096]);
    let Event::Stream { stream: id, .. } = events[0] else {
        panic!("the events are stream data");
    };
    // The application stops the stream: the bytes that did not go up drop.
    server.stop(id, 7).unwrap();
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    assert!(rogue.closes.is_empty(), "the connection stays open");
}

#[test]
fn two_pieces_far_apart_on_a_stream_cost_only_their_pages_and_go_up_when_the_gap_before_them_fills() {
    // A gap of 64 GiB, whose cost for each page would pass the budget of 16 MiB.
    let far = 1 << 36;
    let limits = Limits {
        stream_bytes_max: far + 1,
        data_bytes_max: far + 1,
        ..Limits::DEFAULT
    };
    let (mut server, mut rogue) = pair(limits, true);
    assert!(attack(&mut server, &mut rogue, &[stream(0, 1, b"b", false)]).is_empty());
    assert!(attack(&mut server, &mut rogue, &[stream(0, far, b"z", false)]).is_empty());
    assert_eq!(server.reassembly_refused(), 0);
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, b"a", false)]);
    assert_eq!(stream_bytes(&events), b"ab");
}

#[test]
fn a_packet_with_newer_keys_below_a_packet_with_older_keys_closes_with_key_update_error() {
    // Two packets of the first phase, with a gap between their numbers.
    let start = |server: &mut Connection, rogue: &mut Rogue| {
        let base = rogue.numbers[DATA];
        for number in [base, base + 2] {
            let datagram = rogue.packet_at(DATA, number, None, &[Frame::Ping]);
            assert!(give(server, &datagram).is_empty());
        }
        rogue.numbers[DATA] = base + 3;
        (base, rogue.next.as_mut().unwrap().next_packet_keys())
    };
    // A packet of the next phase above each packet of the first phase updates the keys.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let (base, mut next) = start(&mut server, &mut rogue);
    let datagram = rogue.packet_at(DATA, base + 3, Some(&mut next), &[Frame::Ping]);
    assert!(give(&mut server, &datagram).is_empty());
    let after = rogue.packet_at(DATA, base + 4, Some(&mut next), &[Frame::Ping]);
    assert!(give(&mut server, &after).is_empty(), "the connection stays open");
    // A packet of the next phase in the gap is an inversion.
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let (base, mut next) = start(&mut server, &mut rogue);
    let datagram = rogue.packet_at(DATA, base + 1, Some(&mut next), &[Frame::Ping]);
    let events = give(&mut server, &datagram);
    assert_matches!(&events[..], [Event::Closed(Err(error))] if error.kind() == Kind::Malformed);
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    assert_eq!(rogue.closes, [(ErrorCode::KEY_UPDATE_ERROR.0, Some(0))]);
}

#[test]
fn a_part_of_a_client_hello_waits_for_input_also_with_one_frame_for_each_turn() {
    let limits = Limits {
        turn: TurnLimits {
            frames: 1,
            ..Limits::DEFAULT.turn
        },
        ..Limits::DEFAULT
    };
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let config = server_config(&budget);
    let mut rogue = Rogue::new(Parameters::default());
    let hello = rogue.crypto(0);
    assert_eq!(hello.len(), 2, "the ClientHello takes two datagrams");
    let header = Header::parse(&hello[0], 0).unwrap();
    let mut server = Connection::server(&config, &header, path(4301), limits, &budget, now()).unwrap();
    // rustls cannot take a part of a message: the server waits for the rest, and reports no work.
    assert!(give(&mut server, &hello[0]).is_empty());
    assert_matches!(server.drive(now()).1.progress, Progress::Blocked(Blocked::Input));
    // The rest arrives, and the handshake goes on.
    assert!(give(&mut server, &hello[1]).is_empty());
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    assert!(rogue.keys[DATA].is_some(), "the client has its 1-RTT keys");
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
fn a_stop_after_the_peer_acknowledged_each_byte_and_the_end_keeps_the_complete_delivery() {
    // The client acknowledges both packets of a stream, or only the packet with its end. In the
    // same packet, it stops the stream (RFC 9000, section 3.1).
    for each in [true, false] {
        let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
        assert_eq!(server.open(Direction::Unidirectional).unwrap(), None);
        let credit = Frame::MaxStreams {
            direction: Direction::Unidirectional,
            max: 1,
        };
        assert_matches!(
            attack(&mut server, &mut rogue, &[credit])[..],
            [Event::Openable(Direction::Unidirectional)]
        );
        let stream = server.open(Direction::Unidirectional).unwrap().unwrap();
        let window = Frame::MaxStreamData {
            stream: stream.get(),
            max: 20,
        };
        assert!(attack(&mut server, &mut rogue, &[window]).is_empty());
        let mut numbers = [0; 2];
        for (number, (byte, end)) in numbers.iter_mut().zip([(1, false), (2, true)]) {
            server.send(stream, Lease::from(vec![byte; 10]), end).unwrap();
            for datagram in sent(&mut server) {
                rogue.receive(&datagram);
            }
            *number = rogue.expected[DATA] - 1;
        }
        let low = if each { numbers[0] } else { numbers[1] };
        let wire = [
            0x02,
            u8::try_from(numbers[1]).unwrap(),
            0,
            0,
            u8::try_from(numbers[1] - low).unwrap(),
        ];
        let ack = Frame::parse(&wire).unwrap().0;
        let stop = Frame::StopSending {
            stream: stream.get(),
            code: 5,
        };
        let events = attack(&mut server, &mut rogue, &[ack, stop]);
        if each {
            assert_matches!(events[..], [Event::Sent { .. }, Event::Acknowledged { stream: id, offset: 20, end: true }] if id == stream);
            assert_matches!(server.reset(stream, 6).map_err(|error| error.kind()), Err(Kind::Misuse));
        } else {
            // The first bytes still wait for an ACK: the stop resets the stream.
            assert_matches!(events[..], [.., Event::Stopped { stream: id, code: 5 }] if id == stream);
        }
    }
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
    // A Handshake flight with no first byte: the server keeps each byte after the gap, up to the
    // bound, and rustls reads none of them.
    let data = [0x16; 1000];
    let mut offset = 1;
    while offset < CRYPTO_BUFFER_BYTES_MAX {
        let len = data.len().min(CRYPTO_BUFFER_BYTES_MAX - offset);
        let piece = Frame::Crypto {
            offset: offset as u64,
            data: &data[..len],
        };
        let datagram = rogue.packet(1, &[piece]);
        assert!(give(&mut server, &datagram).is_empty());
        offset += len;
    }
    for datagram in sent(&mut server) {
        rogue.receive(&datagram);
    }
    assert!(rogue.closes.is_empty(), "the bytes inside the bound wait for the gap");
    // The next byte passes the bound.
    let past = Frame::Crypto {
        offset: CRYPTO_BUFFER_BYTES_MAX as u64,
        data: b"x",
    };
    let datagram = rogue.packet(1, &[past]);
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
    // A datagram that no key opens, from a third address, changes nothing for the probe.
    let mut forged = vec![0x40];
    forged.extend_from_slice(rogue.server_cid.as_bytes());
    forged.extend_from_slice(&[0x5c; 40]);
    assert!(give_on(&mut server, path(4700), &forged).is_empty());
    let answers = answers_to(&mut server, other);
    assert_eq!(answers.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    rogue.receive(&answers[0]);
    assert_eq!(rogue.answers, [[7; 8]]);
    // A probe is no move: the connection stays on its path (RFC 9000, section 9.1).
    assert_eq!(server.path(), home);
    assert!(server.address_validated());

    // A small probe from an address that sent nothing before: its answer has at most three times
    // its bytes.
    let third = path(4500);
    let small = rogue.data(&[Frame::PathChallenge { data: [9; 8] }]);
    assert!(give_on(&mut server, third, &small).is_empty());
    let answers = answers_to(&mut server, third);
    assert_eq!(answers.len(), 1);
    assert!(answers[0].len() <= 3 * small.len());
    rogue.receive(&answers[0]);
    assert_eq!(rogue.answers, [[7; 8], [9; 8]]);
    assert_eq!(server.path(), home);
    // The server still serves the client on its path.
    let events = attack(&mut server, &mut rogue, &[stream(0, 0, b"after", false)]);
    assert_matches!(&events[..], [Event::Stream { data, .. }] if data.bytes() == b"after");
}

#[test]
fn a_datagram_from_a_new_address_pays_for_three_times_its_bytes_one_time() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let moved = path(4400);
    // One datagram from a new address: a probe of the path, and then data. The data gives an
    // event, so the host can send before the server reads the end of the packet.
    let datagram = rogue.data(&[Frame::PathChallenge { data: [7; 8] }, stream(0, 0, b"data", false)]);
    let len = server.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram.clone()), None, len);
    assert_matches!(
        server.receive(&mut datagrams, moved, now()).0,
        Some(Event::Stream { .. })
    );
    let bytes = |sent: Vec<Vec<u8>>| sent.iter().map(Vec::len).sum::<usize>();
    let answer = bytes(answers_to(&mut server, moved));
    assert!(answer > 0, "the answer to the probe goes to its path");
    // The packet was not a probe: at its end the server follows the client to the new address.
    for _ in 0..64 {
        let (event, turn) = server.receive(&mut datagrams, moved, now());
        if event.is_none() && turn.progress != Progress::Pending {
            break;
        }
    }
    assert_eq!(server.path(), moved);
    assert!(!server.address_validated());
    // The answer had no padding, because 1,200 bytes are past the limit (RFC 9000, section
    // 8.2.2). Thus the credit still pays for the challenge of the server.
    let challenge = bytes(answers_to(&mut server, moved));
    assert!(challenge > 0, "the answer of {answer} bytes left no credit");
    let to_new = answer + challenge;
    assert!(
        to_new <= 3 * datagram.len(),
        "{to_new} bytes after {} bytes",
        datagram.len()
    );
}

/// A listener, its connection with the hostile client after the handshake, and the client.
fn listened() -> (Endpoint, Handle, Rogue) {
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let config = server_config(&budget);
    let keys = Arc::new(EndpointKeys::generate(&config, 0, REDEEMED_BYTES_DEFAULT).unwrap());
    let limits = EndpointLimits {
        connections_max: 4,
        handshakes_max: 2,
        retry_at: 2,
        ..EndpointLimits::default()
    };
    let mut endpoint = Endpoint::new(&config, keys, 1, limits, Limits::DEFAULT, &budget).unwrap();
    let mut rogue = Rogue::new(Parameters {
        data_bytes_initial: 1 << 20,
        ..Parameters::default()
    });
    let hello = rogue.crypto(0);
    let mut reply = [0; 1200];
    let Route::Accepted(handle) = endpoint.route(path(4301), &hello[0], &mut reply, now()).unwrap() else {
        panic!("the listener takes the first Initial packet")
    };
    for flight in [hello, Vec::new()] {
        for datagram in &flight {
            endpoint.with_connection(handle, |server| give(server, datagram));
        }
        for datagram in endpoint.with_connection(handle, sent).unwrap() {
            rogue.receive(&datagram);
        }
        if rogue.sent[1] == 0 {
            for datagram in rogue.crypto(1) {
                endpoint.with_connection(handle, |server| give(server, &datagram));
            }
        }
    }
    assert_eq!(
        endpoint.with_connection(handle, |server| server.is_confirmed()),
        Some(true)
    );
    (endpoint, handle, rogue)
}

#[test]
fn a_stateless_reset_routes_from_each_address_that_the_connection_sent_to_with_its_token() {
    let (mut endpoint, handle, mut rogue) = listened();
    let (second, third, probed) = (path(4400), path(4500), path(4600));
    // The client gives a second connection ID, with its reset token.
    let token = [0xc3; 16];
    let spare = Frame::NewConnectionId {
        sequence: 1,
        retire_prior_to: 0,
        id: ConnectionId::new(&[0x6b; 8]).unwrap(),
        reset_token: token,
    };
    let datagram = rogue.data(&[spare]);
    endpoint.with_connection(handle, |server| give(server, &datagram));
    // The client moves, and the server sends to the second address with that connection ID.
    let datagram = rogue.data(&[Frame::Ping]);
    let to_second = endpoint.with_connection(handle, |server| {
        give_on(server, second, &datagram);
        answers_to(server, second)
    });
    assert!(to_second.is_some_and(|sent| !sent.is_empty()));
    // The client moves again. The server sent nothing to the third address, so a reset from
    // there is not valid. A reset from the second address is (RFC 9000, section 10.3.1).
    let datagram = rogue.data(&[Frame::Ping]);
    endpoint.with_connection(handle, |server| give_on(server, third, &datagram));
    let mut reset = [0x41; 43];
    reset[27..].copy_from_slice(&token);
    let mut reply = [0; 1200];
    assert_ne!(
        endpoint.route(third, &reset, &mut reply, now()).unwrap(),
        Route::Reset(handle)
    );
    // The answer to a probe of another path also uses the connection ID at that address.
    let probe = rogue.data(&[Frame::PathChallenge { data: [7; 8] }, Frame::Padding { len: 1200 }]);
    let to_probed = endpoint.with_connection(handle, |server| {
        give_on(server, probed, &probe);
        answers_to(server, probed)
    });
    assert!(to_probed.is_some_and(|sent| !sent.is_empty()));
    for from in [probed, second] {
        assert_eq!(
            endpoint.route(from, &reset, &mut reply, now()).unwrap(),
            Route::Reset(handle)
        );
    }
}

/// The destination connection ID of each datagram of `datagrams`. The IDs of the client have 8 bytes.
fn destinations(datagrams: &[Vec<u8>]) -> Vec<ConnectionId> {
    let destination = |datagram: &Vec<u8>| match Header::parse(datagram, 8) {
        Ok(Header::Protected { dcid, .. }) => dcid,
        _ => panic!("a 1-RTT packet"),
    };
    datagrams.iter().map(destination).collect()
}

/// The connection ID of the client with each byte `byte`.
fn id(byte: u8) -> ConnectionId {
    ConnectionId::new(&[byte; 8]).unwrap()
}

/// The NEW_CONNECTION_ID frame of the client for the ID `id(byte)`.
fn issue(sequence: u64, retire_prior_to: u64, byte: u8) -> Frame<'static> {
    Frame::NewConnectionId {
        sequence,
        retire_prior_to,
        id: id(byte),
        reset_token: [byte; 16],
    }
}

/// A path to another address of the server, so that each path has its own local address.
fn away() -> Path {
    Path {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)),
        peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 4400)),
    }
}

#[test]
fn a_path_whose_connection_id_the_peer_retires_takes_one_that_no_path_uses() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let (home, away) = (server.path(), away());
    let datagram = rogue.data(&[issue(1, 0, 0x6b)]);
    assert!(give(&mut server, &datagram).is_empty());
    let datagram = rogue.data(&[Frame::Ping, Frame::Padding { len: 1200 }]);
    assert!(give_on(&mut server, away, &datagram).is_empty());
    assert_eq!(server.path(), away);
    let sent = answers_to(&mut server, away);
    assert!(!sent.is_empty() && destinations(&sent).iter().all(|used| *used == id(0x6b)));

    // The client probes the path that the connection left. Before the answer goes out, it
    // retires the connection ID of that path, and gives a new one.
    let probe = rogue.data(&[Frame::PathChallenge { data: [9; 8] }, Frame::Padding { len: 1200 }]);
    assert!(give_on(&mut server, home, &probe).is_empty());
    let datagram = rogue.data(&[issue(2, 1, 0x7c)]);
    assert!(give_on(&mut server, away, &datagram).is_empty());
    // The answer has the new ID: not the retired one, and not the one of the other local address
    // (RFC 9000, section 9.5).
    let answers = answers_to(&mut server, home);
    assert_eq!(destinations(&answers), [id(0x7c)]);

    // The client returns to the first path. The server sends there with the new ID.
    let datagram = rogue.data(&[Frame::Ping]);
    assert!(give_on(&mut server, home, &datagram).is_empty());
    assert_eq!(server.path(), home);
    let sent = answers_to(&mut server, home);
    assert!(!sent.is_empty() && destinations(&sent).iter().all(|used| *used == id(0x7c)));
}

/// A server that followed the client to another of its addresses, and the client. The client
/// then retired the connection ID of each path, and gave one new ID, which the active path took.
/// The path that the connection left has another local address, so it has no ID (RFC 9000,
/// section 9.5).
fn stranded() -> (Connection, Rogue) {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let away = away();
    let datagram = rogue.data(&[issue(1, 0, 0x6b)]);
    assert!(give(&mut server, &datagram).is_empty());
    let datagram = rogue.data(&[Frame::Ping, Frame::Padding { len: 1200 }]);
    assert!(give_on(&mut server, away, &datagram).is_empty());
    assert_eq!(server.path(), away);
    routed(&mut server);
    let datagram = rogue.data(&[issue(2, 2, 0x7c)]);
    assert!(give_on(&mut server, away, &datagram).is_empty());
    (server, rogue)
}

#[test]
fn a_path_with_no_connection_id_gets_no_datagram_until_the_peer_gives_one() {
    let (mut server, mut rogue) = stranded();
    let (home, away) = (path(4301), away());
    // The client sends from the first path again. The server cannot answer there, and stays.
    let datagram = rogue.data(&[Frame::Ping]);
    assert!(give_on(&mut server, home, &datagram).is_empty());
    assert_eq!(server.path(), away);
    let sent = routed(&mut server);
    assert!(!sent.is_empty() && sent.iter().all(|(to, _)| *to == away));
    let to_away: Vec<Vec<u8>> = sent.into_iter().map(|(_, datagram)| datagram).collect();
    assert!(destinations(&to_away).iter().all(|used| *used == id(0x7c)));

    // The next ID is for the first path, and the server follows the client back with it.
    let datagram = rogue.data(&[issue(3, 2, 0x8d)]);
    assert!(give_on(&mut server, away, &datagram).is_empty());
    let datagram = rogue.data(&[Frame::Ping]);
    assert!(give_on(&mut server, home, &datagram).is_empty());
    assert_eq!(server.path(), home);
    let sent = answers_to(&mut server, home);
    assert!(!sent.is_empty() && destinations(&sent).iter().all(|used| *used == id(0x8d)));
}

#[test]
fn a_validation_that_ends_with_no_connection_id_for_the_path_before_it_ends_the_connection() {
    let (mut server, _rogue) = stranded();
    // The new path gives no answer. At the end of the validation the server cannot return, and
    // it does not send the ID of one local address from another one. Three probe timeouts of a
    // path with no round-trip sample are 3,072 ms.
    assert_eq!(server.drive(ms(3071)).1.progress, Progress::Blocked(Blocked::Input));
    assert_matches!(
        server.drive(ms(3072)).1.progress,
        Progress::Terminal(Err(error)) if error.kind() == Kind::Deadline
    );
}

#[test]
fn the_newest_packet_that_is_no_probe_moves_the_connection_also_after_a_probe_with_a_higher_number() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let (home, moved) = (server.path(), path(4400));
    let late = rogue.data(&[Frame::Ping]);
    let data = rogue.data(&[Frame::Ping]);
    let probe = rogue.data(&[Frame::PathChallenge { data: [7; 8] }, Frame::Padding { len: 1200 }]);
    // The probe has the highest number, and arrives first. A probe is no move.
    assert!(give_on(&mut server, moved, &probe).is_empty());
    assert_eq!(server.path(), home);
    // The packet before it is the newest one that is no probe: the client moved (RFC 9000,
    // section 9.3).
    assert!(give_on(&mut server, moved, &data).is_empty());
    assert_eq!(server.path(), moved);
    // An older packet from the old address arrives late, and brings no connection back.
    assert!(give_on(&mut server, home, &late).is_empty());
    assert_eq!(server.path(), moved);
}

fn ms(value: u64) -> Instant {
    now().checked_add(Duration::from_millis(value)).unwrap()
}

/// Each datagram that `server` sends at `at` to the path `to`.
fn sent_to_at(server: &mut Connection, to: Path, at: Instant) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    let mut out = vec![0; 1500];
    for _ in 0..64 {
        match server.transmit(&mut out, at).unwrap() {
            Some(sent) if sent.path == to => datagrams.push(out[..sent.len].to_vec()),
            Some(_) => {}
            None => return datagrams,
        }
    }
    panic!("a server sends at most 64 datagrams at once");
}

#[test]
fn a_validation_lasts_three_probe_timeouts_of_a_path_with_no_sample_also_for_a_new_port() {
    // Three probe timeouts of a path with no round-trip sample (RFC 9000, section 8.2.4). One
    // has 333 ms, four times the half of them, and the 25 ms that the peer can delay an
    // acknowledgement (RFC 9002, section 6.2).
    const PERIOD_MS: u64 = 3 * (999 + 25);
    for padded in [true, false] {
        let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
        let (home, moved) = (server.path(), path(4400));
        // The first path has a round trip of 10 ms: the client acknowledges each packet of the
        // server.
        let start = ms(10);
        let largest = u8::try_from(rogue.expected[DATA] - 1).unwrap();
        let bytes = [2, largest, 0, 0, largest];
        let (ack, _) = Frame::parse(&bytes).unwrap();
        let datagram = rogue.data(&[ack]);
        assert!(give_at(&mut server, home, &datagram, start).is_empty());
        // Only the port of the client changes, so the new path starts with that short estimate.
        let frames = [Frame::Ping, Frame::Padding { len: 1200 }];
        let datagram = rogue.data(&frames[..if padded { 2 } else { 1 }]);
        assert!(give_at(&mut server, moved, &datagram, start).is_empty());
        for datagram in sent_to_at(&mut server, moved, start) {
            rogue.receive(&datagram);
        }
        assert_eq!(rogue.challenges.len(), 1);
        if !padded {
            // The datagram of the challenge was small. Its answer shows the address, and a
            // challenge of 1,200 bytes follows, with its own period (RFC 9000, section 8.2.1).
            let answer = rogue.data(&[Frame::PathResponse {
                data: rogue.challenges[0],
            }]);
            assert!(give_at(&mut server, moved, &answer, start).is_empty());
            assert!(server.address_validated());
        }
        // No answer comes. The server stays for the full period, and then returns.
        server.drive(ms(10 + PERIOD_MS - 1));
        assert_eq!(server.path(), moved, "padded: {padded}");
        server.drive(ms(10 + PERIOD_MS));
        assert_eq!(server.path(), home, "padded: {padded}");
    }
}

#[test]
fn each_challenge_has_new_data_and_the_answer_to_an_earlier_one_validates_the_path() {
    let (mut server, mut rogue) = pair(Limits::DEFAULT, true);
    let moved = path(4400);
    let datagram = rogue.data(&[Frame::Ping, Frame::Padding { len: 1200 }]);
    assert!(give_on(&mut server, moved, &datagram).is_empty());
    // The server sends its challenge again at each probe timeout.
    let mut at = now();
    for _ in 0..8 {
        for datagram in sent_to_at(&mut server, moved, at) {
            rogue.receive(&datagram);
        }
        if rogue.challenges.len() >= 2 {
            break;
        }
        at = server.drive(at).1.deadline.expect("a probe timeout").instant();
        server.drive(at);
    }
    let [first, second] = rogue.challenges[..] else {
        panic!("two challenges, not {}", rogue.challenges.len())
    };
    assert_ne!(first, second, "each PATH_CHALLENGE frame has its own data");
    // The path is slow: the answer to the first challenge comes after the second one went out.
    let answer = rogue.data(&[Frame::PathResponse { data: first }]);
    let len = server.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(answer), None, len);
    assert!(server.receive(&mut datagrams, moved, at).0.is_none());
    assert!(server.address_validated());
    assert_eq!(server.path(), moved);
}

#[test]
fn a_server_that_closes_before_its_handshake_completes_sends_its_close_when_a_datagram_pays_for_it() {
    // The deadlines leave the time for the probes that spend the credit.
    let limits = Limits {
        idle_timeout: None,
        handshake_timeout: Duration::from_secs(600),
        ..Limits::DEFAULT
    };
    let (mut server, mut rogue) = pair(limits, false);
    let home = server.path();
    // The client gets nothing more: the probes of the server spend its amplification credit.
    let mut at = now();
    for _ in 0..8 {
        if server.recovery().amplification_blocked_round_trips > 0 {
            break;
        }
        at = server.drive(at).1.deadline.expect("a probe timer").instant();
        server.drive(at);
        sent_to_at(&mut server, home, at);
    }
    assert!(server.recovery().amplification_blocked_round_trips > 0);
    server.close(7, at).unwrap();
    assert!(
        sent_to_at(&mut server, home, at).is_empty(),
        "the Initial close needs 1,200 bytes"
    );
    assert_eq!(server.drive(at).1.progress, Progress::Blocked(Blocked::Input));
    // A datagram of the client pays for the close (RFC 9000, section 10.2.3), and the server ends
    // when it is out, because the handshake is not confirmed.
    let ping = rogue.packet(0, &[Frame::Ping]);
    assert!(give_at(&mut server, home, &ping, at).is_empty());
    for datagram in sent_to_at(&mut server, home, at) {
        rogue.receive(&datagram);
    }
    let shown = (ErrorCode::APPLICATION_ERROR.0, Some(0));
    assert_eq!(rogue.closes, [shown, shown, (7, None)]);
    assert_eq!(server.drive(at).1.progress, Progress::Terminal(Ok(())));
}
