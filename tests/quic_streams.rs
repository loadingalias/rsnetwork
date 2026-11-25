//! The streams of a QUIC connection between two engines of the core: flow control that follows
//! the consumer, data out of order under its bound, the outcomes of a stream, the send order, the
//! stream credit, and unreliable datagrams (N305; RFC 9000, sections 2 to 4, and RFC 9221). Then
//! the delivery of packets (N306, N320), and the paths and the close of a connection (N307; RFC
//! 9000, sections 8.2, 9, 10.2, and 14, and RFC 8899).

use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use core::time::Duration;
use std::assert_matches;
use std::collections::BTreeMap;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Kind, Progress};
use rsnetwork::quic::frame::{Ack, Direction, Frame};
use rsnetwork::quic::packet::{Datagrams, Header};
use rsnetwork::quic::{
    CongestionControl, Connection, EcnState, Event, Limits, Path, PeerClose, Priority, STREAM_REGIONS_MAX, StreamId,
};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Entropy, Identity, PrivateKeyDer, Resumption, ServerConfig,
    ServerOptions, TimeProvider, UnixTime,
};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));
/// 2027-01-01, inside the validity of each certificate.
const VALID: u64 = 1_798_761_600;
/// The bytes of one page of the store of data out of order.
const PAGE: u64 = 4096;

/// A wall clock that stays at one time.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 26).unwrap())
}

fn now() -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), 0)
}

fn ms(value: u64) -> Instant {
    now().checked_add(Duration::from_millis(value)).unwrap()
}

/// The byte at `offset` of the data of each test stream, so a byte at a wrong place shows.
fn byte(offset: usize) -> u8 {
    u8::try_from(offset % 251).unwrap()
}

/// The `len` bytes of a test stream from `offset`, as a region.
fn region(offset: usize, len: usize) -> Lease {
    Lease::from((offset..offset + len).map(byte).collect::<Vec<u8>>())
}

/// The address of the server, and the address of a client at the port `port`.
const SERVER_ADDRESS: SocketAddr = SocketAddr::new(core::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);

fn client_address(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), port))
}

/// The path of the server to a client at `peer`.
fn from_server(peer: SocketAddr) -> Path {
    Path {
        local: SERVER_ADDRESS,
        peer,
    }
}

/// Each datagram that `connection` sends now.
fn sent(connection: &mut Connection) -> Vec<Vec<u8>> {
    sent_at(connection, now())
}

fn sent_at(connection: &mut Connection, at: Instant) -> Vec<Vec<u8>> {
    routed_at(connection, at)
        .into_iter()
        .map(|(_, datagram)| datagram)
        .collect()
}

/// Each datagram that `connection` sends at `at`, with its path. The output has room for the
/// largest datagram limit of a test.
fn routed_at(connection: &mut Connection, at: Instant) -> Vec<(Path, Vec<u8>)> {
    let mut datagrams = Vec::new();
    let mut out = vec![0; 16_384];
    for _ in 0..8192 {
        match connection.transmit(&mut out, at).unwrap() {
            Some(sent) => datagrams.push((sent.path, out[..sent.len].to_vec())),
            None => return datagrams,
        }
    }
    panic!("a connection sends at most 8,192 datagrams at once");
}

/// Gives `datagram` to `connection` in a region of its own, and gives the events of the call.
fn give(connection: &mut Connection, datagram: &[u8]) -> Vec<Event> {
    give_at(connection, datagram, now())
}

fn give_at(connection: &mut Connection, datagram: &[u8], at: Instant) -> Vec<Event> {
    give_marked(connection, datagram, at, Ecn::NotEct)
}

fn give_marked(connection: &mut Connection, datagram: &[u8], at: Instant, mark: Ecn) -> Vec<Event> {
    let path = connection.path();
    give_on(connection, path, datagram, at, mark)
}

/// Gives `datagram` to `connection` as a datagram that arrived on `path`.
fn give_on(connection: &mut Connection, path: Path, datagram: &[u8], at: Instant, mark: Ecn) -> Vec<Event> {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, len).with_ecn(mark);
    let mut events = Vec::new();
    for _ in 0..8192 {
        match connection.receive(&mut datagrams, path, at) {
            (Some(event), _) => events.push(event),
            (None, turn) if turn.progress == Progress::Pending => {}
            (None, _) => return events,
        }
    }
    panic!("a datagram gives at most 8,192 events");
}

/// The events that wait in `connection` after its last datagram went out.
fn driven_at(connection: &mut Connection, at: Instant) -> Vec<Event> {
    let mut events = Vec::new();
    for _ in 0..8192 {
        match connection.drive(at) {
            (Some(event), _) => events.push(event),
            (None, turn) if turn.progress == Progress::Pending => {}
            (None, _) => return events,
        }
    }
    panic!("a drive gives at most 8,192 events");
}

/// The bytes of each stream that an end received, in the order of their events, and whether the
/// stream gave its end.
#[derive(Default)]
struct Received {
    streams: BTreeMap<u64, (Vec<u8>, bool)>,
    /// The stream of each event with bytes, in the order of the events.
    order: Vec<u64>,
    other: Vec<Event>,
}

impl Received {
    /// Takes `events` of `connection`, and releases the bytes of each stream for which `releases`
    /// gives `true`.
    fn take(&mut self, connection: &mut Connection, events: Vec<Event>, releases: impl Fn(StreamId) -> bool) {
        for event in events {
            match event {
                Event::Stream { stream, data, end } => {
                    let entry = self.streams.entry(stream.get()).or_default();
                    assert!(!entry.1, "no byte comes after the end of a stream");
                    entry.0.extend_from_slice(data.bytes());
                    entry.1 = end;
                    if data.initialized() > 0 {
                        self.order.push(stream.get());
                    }
                    if releases(stream) {
                        connection.release(stream, data.initialized() as u64).unwrap();
                    }
                }
                other => self.other.push(other),
            }
        }
    }

    fn bytes(&self, stream: StreamId) -> usize {
        self.streams.get(&stream.get()).map_or(0, |(bytes, _)| bytes.len())
    }

    /// Whether `stream` gave its end after exactly the `len` bytes of its test data.
    fn complete(&self, stream: StreamId, len: usize) -> bool {
        self.streams.get(&stream.get()).is_some_and(|(bytes, end)| {
            *end && bytes.len() == len && bytes.iter().enumerate().all(|(at, b)| *b == byte(at))
        })
    }
}

/// A client and a server after their handshake.
struct Pair {
    client: Connection,
    server: Connection,
    at_client: Received,
    at_server: Received,
    /// The address that the network gives the client. The server gets each datagram of the client
    /// from it, and the client gets only the datagrams that the server sends to it.
    seen: SocketAddr,
    /// The datagrams that the server sent to another address.
    elsewhere: Vec<(Path, Vec<u8>)>,
    /// The largest datagram that the path carries: it drops each larger one, and keeps it.
    path_bytes: usize,
    dropped: Vec<Vec<u8>>,
    /// The largest datagram of the client that the path carried.
    largest: usize,
}

impl Pair {
    fn new(client: Limits, server: Limits) -> Self {
        Self::on_path(client, server, usize::MAX)
    }

    /// A client and a server after their handshake, on a path that carries datagrams of at most
    /// `path_bytes` bytes.
    fn on_path(client: Limits, server: Limits, path_bytes: usize) -> Self {
        let client_config = ClientConfig::new(ClientOptions {
            roots: &[CertificateDer::from(CA.to_vec())],
            identity: None,
            protocols: &[b"test"],
            resumption: Resumption::Off,
            budget: &budget(),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::System,
        })
        .unwrap();
        let server_config = ServerConfig::new(ServerOptions {
            identity: Identity {
                chain: vec![CertificateDer::from(SERVER.0.to_vec())],
                key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
            },
            client_roots: None,
            protocols: &[b"test"],
            resumption: Resumption::Off,
            budget: &budget(),
            clock: Arc::new(At(VALID)),
            entropy: Entropy::System,
        })
        .unwrap();
        let route = Path {
            local: client_address(4301),
            peer: SERVER_ADDRESS,
        };
        let mut client_end =
            Connection::client(&client_config, "server.test", route, client, &budget(), now()).unwrap();
        let first = sent(&mut client_end);
        let header = Header::parse(&first[0], 0).unwrap();
        let route = from_server(client_address(4301));
        let mut server_end = Connection::server(&server_config, &header, route, server, &budget(), now()).unwrap();
        for datagram in &first {
            assert!(give(&mut server_end, datagram).is_empty());
        }
        let mut pair = Self {
            client: client_end,
            server: server_end,
            at_client: Received::default(),
            at_server: Received::default(),
            seen: client_address(4301),
            elsewhere: Vec::new(),
            path_bytes,
            dropped: Vec::new(),
            largest: 0,
        };
        pair.run(|_| true);
        assert!(pair.client.is_confirmed() && pair.server.is_confirmed());
        pair
    }

    /// Moves the datagrams of both ends until no datagram and no event moves. Each end releases
    /// the bytes of each stream for which `releases` gives `true`.
    fn run(&mut self, releases: impl Fn(StreamId) -> bool) {
        self.run_at(now(), releases);
    }

    fn run_at(&mut self, at: Instant, releases: impl Fn(StreamId) -> bool) {
        for _ in 0..4096 {
            let events = driven_at(&mut self.client, at);
            let to_server = sent_at(&mut self.client, at);
            let mut quiet = to_server.is_empty() && events.is_empty();
            self.at_client.take(&mut self.client, events, &releases);
            for datagram in &to_server {
                if datagram.len() > self.path_bytes {
                    self.dropped.push(datagram.clone());
                    continue;
                }
                self.largest = self.largest.max(datagram.len());
                let events = give_on(&mut self.server, from_server(self.seen), datagram, at, Ecn::NotEct);
                self.at_server.take(&mut self.server, events, &releases);
            }
            let events = driven_at(&mut self.server, at);
            let to_client = routed_at(&mut self.server, at);
            quiet &= to_client.is_empty() && events.is_empty();
            self.at_server.take(&mut self.server, events, &releases);
            for (path, datagram) in to_client {
                if path.peer != self.seen {
                    self.elsewhere.push((path, datagram));
                } else if datagram.len() <= self.path_bytes {
                    let events = give_at(&mut self.client, &datagram, at);
                    self.at_client.take(&mut self.client, events, &releases);
                }
            }
            if quiet {
                return;
            }
        }
        panic!("the connection is not quiet after 4,096 rounds");
    }

    /// Runs the connection, and moves the clock to the next deadline of an end, until `done`.
    /// Gives the time.
    fn run_until(&mut self, mut at: Instant, done: impl Fn(&Self) -> bool) -> Instant {
        for _ in 0..512 {
            self.run_at(at, |_| true);
            if done(self) {
                return at;
            }
            at = [self.client.drive(at).1.deadline, self.server.drive(at).1.deadline]
                .into_iter()
                .flatten()
                .map(|deadline| deadline.instant())
                .min_by_key(|instant| instant.as_nanos())
                .expect("an end that waits has a deadline");
        }
        panic!("the connection does not reach its state after 512 deadlines");
    }

    /// The server sends `len` bytes of the test data on a new stream of the client, from the
    /// time `at`. Gives the stream.
    fn download(&mut self, at: Instant, len: usize) -> StreamId {
        let stream = self.open(Direction::Bidirectional);
        self.client.send(stream, region(0, 1), true).unwrap();
        let mut offset = 0;
        for _ in 0..4096 {
            self.run_at(at, |_| true);
            if self.at_client.complete(stream, len) {
                return stream;
            }
            offset = feed(&mut self.server, stream, offset, len, 16 * 1024);
        }
        panic!("the download does not end");
    }

    /// Opens a stream of the client.
    fn open(&mut self, direction: Direction) -> StreamId {
        self.client
            .open(direction)
            .unwrap()
            .expect("the limit of the server allows the stream")
    }
}

/// Gives the `len` bytes of the test data to `stream` of `connection` from `offset`, in regions of
/// `piece` bytes, as many as the stream takes, with the end after the last byte. Gives the new
/// offset.
fn feed(connection: &mut Connection, stream: StreamId, mut offset: usize, len: usize, piece: usize) -> usize {
    for _ in 0..STREAM_REGIONS_MAX {
        if offset == len {
            break;
        }
        let part = piece.min(len - offset);
        if connection
            .send(stream, region(offset, part), offset + part == len)
            .is_err()
        {
            break;
        }
        offset += part;
    }
    offset
}

/// Sends the test data of each stream of `streams`, from the offset with it up to `len` bytes,
/// from the client to the server, with each datagram in the order that the client sent it. It
/// stops when no stream takes a region more, and keeps the offset of each stream.
fn transfer(pair: &mut Pair, streams: &mut [(StreamId, usize)], len: usize, releases: impl Fn(StreamId) -> bool) {
    for _ in 0..4096 {
        let before: Vec<usize> = streams.iter().map(|(_, offset)| *offset).collect();
        for (stream, offset) in streams.iter_mut() {
            *offset = feed(&mut pair.client, *stream, *offset, len, 16 * 1024);
        }
        pair.run(&releases);
        if streams.iter().map(|(_, offset)| *offset).eq(before) {
            return;
        }
    }
    panic!("the transfer does not end");
}

#[test]
fn a_slow_consumer_limits_the_credit_of_its_own_stream_and_of_no_other() {
    const WINDOW: usize = 64 * 1024;
    const LEN: usize = 5 * WINDOW;
    let server = Limits {
        stream_bytes_max: WINDOW as u64,
        data_bytes_max: 4 * WINDOW as u64,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, server);
    let (slow, fast) = (pair.open(Direction::Bidirectional), pair.open(Direction::Bidirectional));
    // The consumer of `slow` releases nothing, and the consumer of `fast` releases each byte.
    let mut streams = [(slow, 0), (fast, 0)];
    transfer(&mut pair, &mut streams, LEN, |stream| stream == fast);
    // The peer got credit for `slow` only up to the capacity that its consumer admitted.
    assert_eq!(pair.at_server.bytes(slow), WINDOW);
    assert!(pair.at_server.complete(fast, LEN), "the other stream is complete");
    // The bytes that the slow consumer releases give its stream the next credit, and no more.
    pair.server.release(slow, WINDOW as u64).unwrap();
    pair.run(|stream| stream == fast);
    assert_eq!(pair.at_server.bytes(slow), 2 * WINDOW);
    assert_matches!(
        pair.server
            .release(slow, WINDOW as u64 + 1)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    pair.server.release(slow, WINDOW as u64).unwrap();
    transfer(&mut pair, &mut streams, LEN, |_| true);
    assert!(pair.at_server.complete(slow, LEN));
}

#[test]
fn a_stream_window_as_large_as_the_connection_window_lets_a_slow_consumer_hold_each_stream() {
    // The contract of the limits: one consumer can hold the whole window of the connection.
    const WINDOW: usize = 32 * 1024;
    let server = Limits {
        stream_bytes_max: WINDOW as u64,
        data_bytes_max: WINDOW as u64,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, server);
    let (slow, other) = (
        pair.open(Direction::Unidirectional),
        pair.open(Direction::Unidirectional),
    );
    let mut streams = [(slow, 0), (other, 0)];
    transfer(&mut pair, &mut streams[..1], 2 * WINDOW, |_| false);
    transfer(&mut pair, &mut streams[1..], WINDOW, |_| true);
    assert_eq!((pair.at_server.bytes(slow), pair.at_server.bytes(other)), (WINDOW, 0));
    // The release gives the credit of the connection to the stream that waits for it.
    pair.server.release(slow, WINDOW as u64).unwrap();
    transfer(&mut pair, &mut streams[1..], WINDOW, |_| true);
    assert!(pair.at_server.complete(other, WINDOW));
    transfer(&mut pair, &mut streams[..1], 2 * WINDOW, |_| true);
    assert!(pair.at_server.complete(slow, 2 * WINDOW));
}

/// The datagrams of a transfer of `len` bytes on one new stream of the client, not delivered.
fn flight(pair: &mut Pair, len: usize) -> (StreamId, Vec<Vec<u8>>) {
    // An earlier transfer grows the congestion window enough to put this flight on the path.
    let warm = pair.open(Direction::Unidirectional);
    pair.client.send(warm, region(0, 3 * len), true).unwrap();
    pair.run(|_| true);
    assert!(pair.at_server.complete(warm, 3 * len));
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, len), true).unwrap();
    let datagrams = sent(&mut pair.client);
    assert_matches!(driven_at(&mut pair.client, now())[..], [Event::Sent { stream: id }] if id == stream);
    (stream, datagrams)
}

/// Delivers `datagrams` to the server of `pair`, which releases each byte.
fn deliver<'a>(pair: &mut Pair, datagrams: impl IntoIterator<Item = &'a Vec<u8>>) {
    for datagram in datagrams {
        let events = give(&mut pair.server, datagram);
        pair.at_server.take(&mut pair.server, events, |_| true);
    }
}

#[test]
fn data_out_of_order_past_its_bound_is_refused_and_counted_and_the_stream_completes() {
    const LEN: usize = 60 * 1024;
    let server = Limits {
        reassembly_bytes_max: 4 * PAGE,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, server);
    let (stream, datagrams) = flight(&mut pair, LEN);
    // The first datagram is late: each other one is out of order, and only 4 pages hold them.
    deliver(&mut pair, &datagrams[1..]);
    let refused = pair.server.reassembly_refused();
    assert!(refused > 0, "the data past the bound is refused");
    assert_eq!(pair.at_server.bytes(stream), 0);
    assert_matches!(pair.server.drive(now()).1.progress, Progress::Blocked(_));
    // The first datagram arrives: the bytes that the pages hold go up after it.
    deliver(&mut pair, &datagrams[..1]);
    let held = pair.at_server.bytes(stream);
    assert!((12 * 1024..20 * 1024).contains(&held), "{held} bytes: about 4 pages");
    // The packets that the server did not take got no acknowledgement, so the client sends their
    // data again: now it is in order, and needs no page.
    pair.run(|_| true);
    pair.run_at(now().checked_add(Duration::from_millis(26)).unwrap(), |_| true);
    assert!(pair.at_server.complete(stream, LEN));
    assert_eq!(pair.server.reassembly_refused(), refused);
}

#[test]
fn a_transfer_with_many_gaps_completes_and_pieces_with_no_neighbor_reach_the_bound_first() {
    const LEN: usize = 200 * 1024;
    // Each second datagram arrives late. A second flight arrives in reverse order.
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let (stream, datagrams) = flight(&mut pair, LEN);
    deliver(&mut pair, datagrams.iter().skip(1).step_by(2));
    deliver(&mut pair, datagrams.iter().step_by(2));
    pair.run(|_| true);
    assert!(pair.at_server.complete(stream, LEN));
    let (stream, datagrams) = flight(&mut pair, LEN);
    deliver(&mut pair, datagrams.iter().rev());
    assert!(pair.at_server.complete(stream, LEN));
    assert_eq!(pair.server.reassembly_refused(), 0);

    // A flood of gaps: only each fourth datagram arrives, so each piece has a page of its own.
    // The bound counts the pages, so it refuses while the pieces hold few bytes.
    let bound = 8 * PAGE;
    let server = Limits {
        reassembly_bytes_max: bound,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, server);
    let (stream, datagrams) = flight(&mut pair, LEN);
    let mut taken = 0;
    for datagram in datagrams.iter().skip(3).step_by(4) {
        deliver(&mut pair, [datagram]);
        if pair.server.reassembly_refused() > 0 {
            break;
        }
        taken += datagram.len() as u64;
    }
    assert!(pair.server.reassembly_refused() > 0, "the flood reaches the bound");
    assert!(taken * 3 < bound, "{taken} bytes in pieces reach a bound of {bound}");
    // The connection stays open, and the stream completes when its data arrives in order.
    deliver(&mut pair, &datagrams);
    assert!(pair.at_server.complete(stream, LEN));
}

#[test]
fn a_reset_with_a_code_and_a_stop_give_distinct_outcomes() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let (reset, stopped) = (pair.open(Direction::Bidirectional), pair.open(Direction::Bidirectional));
    for stream in [reset, stopped] {
        pair.client.send(stream, region(0, 10), false).unwrap();
    }
    pair.run(|_| true);
    assert_eq!((pair.at_server.bytes(reset), pair.at_server.bytes(stopped)), (10, 10));

    // The client resets one stream with code 7, and the server stops the other with code 9.
    pair.client.reset(reset, 7).unwrap();
    pair.server.stop(stopped, 9).unwrap();
    pair.run(|_| true);
    assert_matches!(pair.at_server.other[..], [Event::Reset { stream, code: 7 }] if stream == reset);
    assert_matches!(pair.at_client.other[..], [.., Event::Stopped { stream, code: 9 }] if stream == stopped);
    // No stream gave a clean end, and a stopped stream takes no more data.
    assert!(pair.at_server.streams.values().all(|(_, end)| !end));
    assert_matches!(
        pair.client
            .send(stopped, region(10, 10), true)
            .map_err(|error| error.kind()),
        Err(Kind::Cancelled)
    );
    assert_matches!(
        pair.client.reset(reset, 8).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    assert_matches!(
        pair.server.stop(stopped, 8).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
}

#[test]
fn the_peer_gets_the_credit_for_a_new_stream_only_after_the_application_closes_one() {
    let server = Limits {
        streams_bidi_max: 2,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, server);
    let streams = [pair.open(Direction::Bidirectional), pair.open(Direction::Bidirectional)];
    assert_eq!(pair.client.open(Direction::Bidirectional).unwrap(), None);
    // The client resets its streams at once: the server still works on both of them.
    for stream in streams {
        pair.client.send(stream, region(0, 100), false).unwrap();
        pair.client.reset(stream, 1).unwrap();
        pair.client.stop(stream, 1).unwrap();
    }
    pair.run(|_| true);
    assert_eq!(pair.client.open(Direction::Bidirectional).unwrap(), None);
    assert!(
        !pair
            .at_client
            .other
            .iter()
            .any(|event| matches!(event, Event::Openable(_)))
    );
    // A stream with an open direction does not close.
    let open = pair.open(Direction::Unidirectional);
    assert_matches!(
        pair.client.close_stream(open).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    // The server is done with one stream: the client can open one more, and not two.
    pair.server.close_stream(streams[0]).unwrap();
    pair.run(|_| true);
    assert_matches!(
        pair.at_client.other[..],
        [.., Event::Openable(Direction::Bidirectional)]
    );
    let next = pair.open(Direction::Bidirectional);
    assert_eq!(next.get(), 8);
    assert_eq!(pair.client.open(Direction::Bidirectional).unwrap(), None);
    // A closed stream takes no call, and the new stream carries data.
    assert_matches!(
        pair.server.release(streams[0], 0).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    transfer(&mut pair, &mut [(next, 0)], 1000, |_| true);
    assert!(pair.at_server.complete(next, 1000));
}

#[test]
fn the_scheduler_sends_by_urgency_then_in_order_and_shares_among_incremental_streams() {
    const LEN: usize = 40 * 1024;
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let streams: Vec<StreamId> = (0..6).map(|_| pair.open(Direction::Unidirectional)).collect();
    let priorities = [(9, false), (9, false), (5, true), (5, true), (2, false), (9, true)];
    // The data goes in from the last stream, so the order of the calls is not the send order.
    for (stream, (urgency, incremental)) in streams.iter().zip(priorities).rev() {
        pair.client
            .set_priority(*stream, Priority { urgency, incremental })
            .unwrap();
        pair.client.send(*stream, region(0, LEN), true).unwrap();
    }
    pair.run(|_| true);
    assert!(streams.iter().all(|stream| pair.at_server.complete(*stream, LEN)));
    let order = &pair.at_server.order;
    let first = |stream: StreamId| order.iter().position(|id| *id == stream.get()).unwrap();
    let last = |stream: StreamId| order.iter().rposition(|id| *id == stream.get()).unwrap();
    // Urgency 2 goes before urgency 5, and urgency 5 before urgency 9.
    assert!(last(streams[4]) < first(streams[2]).min(first(streams[3])));
    assert!(last(streams[2]).max(last(streams[3])) < first(streams[0]));
    // Inside urgency 5, the two incremental streams take turns.
    assert!(first(streams[3]) < last(streams[2]) && first(streams[2]) < last(streams[3]));
    // Inside urgency 9, the streams that are not incremental go in the order of their
    // identifiers, and the incremental stream goes after them.
    assert!(last(streams[0]) < first(streams[1]) && last(streams[1]) < first(streams[5]));
}

#[test]
fn an_unreliable_datagram_goes_only_to_a_peer_that_takes_it_and_a_full_queue_refuses() {
    let on = Limits {
        unreliable_bytes_max: Some(2000),
        ..Limits::DEFAULT
    };
    // The server did not negotiate unreliable datagrams.
    let mut pair = Pair::new(on, Limits::DEFAULT);
    assert_eq!(pair.client.unreliable_room(), None);
    assert_matches!(
        pair.client.send_unreliable(region(0, 10)).map_err(|error| error.kind()),
        Err(Kind::Unsupported)
    );

    let mut pair = Pair::new(on, on);
    let room = pair
        .client
        .unreliable_room()
        .expect("the server takes unreliable datagrams");
    assert!((1100..1200).contains(&room), "{room} bytes in a datagram of 1,200");
    // One datagram past the room, and one past the bytes of the queue.
    assert_matches!(
        pair.client
            .send_unreliable(region(0, room + 1))
            .map_err(|error| error.kind()),
        Err(Kind::Overload)
    );
    for len in [room, 500, 0] {
        pair.client.send_unreliable(region(len, len)).unwrap();
    }
    assert_matches!(
        pair.client
            .send_unreliable(region(0, 2000 - room - 499))
            .map_err(|error| error.kind()),
        Err(Kind::Overload)
    );
    pair.run(|_| true);
    // Each datagram arrives whole, in its order, and the queue has room again.
    let lens: Vec<usize> = pair
        .at_server
        .other
        .iter()
        .map(|event| match event {
            Event::Unreliable(data) => {
                assert!(
                    data.bytes()
                        .iter()
                        .enumerate()
                        .all(|(at, b)| *b == byte(data.initialized() + at))
                );
                data.initialized()
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(lens, [room, 500, 0]);
    pair.client.send_unreliable(region(0, room)).unwrap();
}

#[test]
fn a_stream_takes_its_regions_up_to_its_bound_and_refuses_what_its_state_forbids() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let stream = pair.open(Direction::Unidirectional);
    assert_matches!(
        pair.client
            .send(stream, region(0, 0), false)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    for at in 0..STREAM_REGIONS_MAX {
        pair.client.send(stream, region(at * 10, 10), false).unwrap();
    }
    assert_matches!(
        pair.client
            .send(stream, region(40, 10), true)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    // The regions are in a packet: the stream takes the next one, and then its end with no byte.
    pair.run(|_| true);
    assert_matches!(pair.at_client.other[..], [Event::Sent { stream: sent }, Event::Acknowledged { stream: acked, offset: 40, end: false }] if sent == stream && acked == stream);
    pair.client.send(stream, region(40, 10), false).unwrap();
    pair.run(|_| true);
    pair.client.send(stream, region(50, 0), true).unwrap();
    assert_matches!(
        pair.client
            .send(stream, region(50, 1), false)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    pair.run(|_| true);
    assert!(pair.at_server.complete(stream, 50));
    // A stream of the client that only sends has no data to stop, and the server cannot send on it.
    assert_matches!(
        pair.client.stop(stream, 0).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    assert_matches!(
        pair.server
            .send(stream, region(0, 1), true)
            .map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
    // Both ends are done with the stream.
    pair.client.close_stream(stream).unwrap();
    pair.server.close_stream(stream).unwrap();
    assert_matches!(
        pair.client.close_stream(stream).map_err(|error| error.kind()),
        Err(Kind::Misuse)
    );
}

/// Collects a window of full packets at the deadlines of the pacer.
fn paced_flight(connection: &mut Connection, mut at: Instant, count: usize) -> Vec<Vec<u8>> {
    let mut flight = Vec::new();
    for _ in 0..=count {
        flight.extend(sent_at(connection, at));
        if flight.len() == count {
            return flight;
        }
        let next = connection.drive(at).1.deadline.unwrap().instant();
        assert!(next.as_nanos() > at.as_nanos());
        at = next;
    }
    panic!("the pacer did not release the requested flight");
}

#[test]
fn newreno_grows_on_delivery_and_halves_once_for_packet_and_time_threshold_losses() {
    let mut pair = Pair::new(
        Limits {
            congestion_control: CongestionControl::NewReno,
            ..Limits::DEFAULT
        },
        Limits::DEFAULT,
    );
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, 128 * 1024), true).unwrap();
    assert_eq!(pair.client.recovery().congestion_window, 12_000);
    let first = sent_at(&mut pair.client, ms(10));
    assert_eq!(first.iter().map(Vec::len).collect::<Vec<_>>(), [1200; 10]);
    for packet in first {
        give_at(&mut pair.server, &packet, ms(14));
    }
    for ack in sent_at(&mut pair.server, ms(16)) {
        give_at(&mut pair.client, &ack, ms(20));
    }
    let path = pair.client.recovery();
    assert_eq!((path.congestion_window, path.bytes_in_flight), (24_000, 0));
    assert_eq!(path.latest_rtt, Some(Duration::from_millis(10)));
    // The handshake took zero ticks. The first data sample is 10 ms less 2 ms of ACK delay.
    assert_eq!(path.smoothed_rtt, Some(Duration::from_millis(1)));

    let second = paced_flight(&mut pair.client, ms(30), 20);
    assert_eq!(second.len(), 20);
    give_at(&mut pair.server, &second[3], ms(34));
    for ack in sent_at(&mut pair.server, ms(35)) {
        give_at(&mut pair.client, &ack, ms(40));
    }
    let path = pair.client.recovery();
    assert_eq!(
        (path.packets_lost, path.congestion_window, path.bytes_in_flight),
        (1, 12_000, 21_600)
    );
    let threshold = now().checked_add(Duration::from_micros(41_250)).unwrap();
    let turn = pair.client.drive(ms(41)).1;
    assert_eq!(turn.deadline.map(|d| d.instant()), Some(threshold));
    assert_eq!(pair.client.recovery().packets_lost, 1);
    pair.client.drive(threshold);
    let path = pair.client.recovery();
    assert_eq!(
        (path.packets_lost, path.congestion_window, path.bytes_in_flight),
        (3, 12_000, 19_200)
    );

    for packet in &second[4..] {
        give_at(&mut pair.server, packet, ms(42));
    }
    for ack in sent_at(&mut pair.server, ms(42)) {
        give_at(&mut pair.client, &ack, ms(45));
    }
    assert_eq!(pair.client.recovery().congestion_window, 12_000);
    let third = paced_flight(&mut pair.client, ms(46), 10);
    assert_eq!(third.iter().map(Vec::len).sum::<usize>(), 12_000);
    for packet in third {
        give_at(&mut pair.server, &packet, ms(50));
    }
    for ack in sent_at(&mut pair.server, ms(50)) {
        give_at(&mut pair.client, &ack, ms(55));
    }
    assert_eq!(
        pair.client.recovery().congestion_window,
        13_200,
        "one datagram per acknowledged window"
    );
}

#[test]
fn a_probe_backs_off_without_declaring_loss_and_an_ack_releases_the_retained_region() {
    let limits = Limits {
        send_bytes_max: 4000,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, Limits::DEFAULT);
    let stream = pair.open(Direction::Unidirectional);
    let owner: Arc<[u8]> = (0..4000).map(byte).collect();
    let backing = Arc::downgrade(&owner);
    pair.client.send(stream, Lease::from_owner(owner, 4000), false).unwrap();
    let lost = sent_at(&mut pair.client, ms(1));
    let in_flight = lost.iter().map(|d| d.len() as u64).sum::<u64>();
    assert!(lost.len() > 1);
    assert_matches!(driven_at(&mut pair.client, ms(1))[..], [Event::Sent { stream: id }] if id == stream);
    assert!(backing.upgrade().is_some(), "the packet needs the region for recovery");
    assert_eq!(
        pair.client.send(stream, region(4000, 1), true).unwrap_err().kind(),
        Kind::Overload
    );
    let deadline = |connection: &mut Connection, time| connection.drive(time).1.deadline.map(|d| d.instant());
    assert_eq!(deadline(&mut pair.client, ms(26)), Some(ms(27)));
    pair.client.drive(ms(27));
    let first_probe = sent_at(&mut pair.client, ms(27));
    assert_eq!(first_probe.len(), 1);
    let path = pair.client.recovery();
    assert_eq!(
        (path.packets_lost, path.probes_sent, path.congestion_window),
        (0, 1, 12_000)
    );
    assert_eq!(path.bytes_in_flight, in_flight + first_probe[0].len() as u64);
    assert_eq!(deadline(&mut pair.client, ms(78)), Some(ms(79)));
    pair.client.drive(ms(79));
    let probe = sent_at(&mut pair.client, ms(79));
    assert_eq!(probe.len(), 1);
    give_at(&mut pair.server, &probe[0], ms(80));
    for ack in sent_at(&mut pair.server, ms(80)) {
        give_at(&mut pair.client, &ack, ms(81));
    }
    assert_eq!(pair.client.recovery().packets_lost, lost.len() as u64 + 1);
    pair.run_at(ms(82), |_| true);
    assert_eq!(pair.at_server.bytes(stream), 4000);
    assert!(
        backing.upgrade().is_none(),
        "the transport released its acknowledged region"
    );
    assert_matches!(pair.at_client.other[..], [Event::Acknowledged { stream: id, offset: 4000, end: false }] if id == stream);
    pair.client.send(stream, region(4000, 1), true).unwrap();
    pair.run_at(ms(83), |_| true);
    assert!(pair.at_server.complete(stream, 4001));
}

#[test]
fn a_full_congestion_window_admits_one_probe_and_counts_its_bytes() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, 24_000), true).unwrap();
    assert_eq!(sent_at(&mut pair.client, ms(1)).len(), 10);
    let time = pair.client.drive(ms(1)).1.deadline.unwrap().instant();
    pair.client.drive(time);
    let probe = sent_at(&mut pair.client, time);
    assert_eq!(probe.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    let path = pair.client.recovery();
    assert_eq!(
        (path.bytes_in_flight, path.congestion_window, path.packets_lost),
        (13_200, 12_000, 0)
    );
}

#[test]
fn an_ack_covering_a_ping_and_a_later_bare_ack_samples_the_later_send_time() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    pair.client.ping();
    let ping = sent_at(&mut pair.client, ms(10));
    pair.server.ping();
    for packet in sent_at(&mut pair.server, ms(12)) {
        give_at(&mut pair.client, &packet, ms(13));
    }
    let bare = sent_at(&mut pair.client, ms(15));
    assert_eq!((ping.len(), bare.len()), (1, 1));
    give_at(&mut pair.server, &ping[0], ms(16));
    give_at(&mut pair.server, &bare[0], ms(20));
    for ack in sent_at(&mut pair.server, ms(22)) {
        give_at(&mut pair.client, &ack, ms(25));
    }
    assert_eq!(pair.client.recovery().latest_rtt, Some(Duration::from_millis(10)));
    assert_eq!(pair.client.recovery().bytes_in_flight, 0);
}

#[test]
fn lost_stream_credit_and_a_lost_reset_after_close_reach_the_peer() {
    let limits = Limits {
        stream_bytes_max: 4,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, limits);
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, 8), true).unwrap();
    let packets = sent_at(&mut pair.client, ms(10));
    for packet in packets {
        let events = give_at(&mut pair.server, &packet, ms(11));
        pair.at_server.take(&mut pair.server, events, |_| true);
    }
    assert_eq!(pair.at_server.bytes(stream), 4);
    assert!(
        !sent_at(&mut pair.server, ms(11)).is_empty(),
        "the first credit update is lost"
    );
    pair.server.ping();
    for ping in sent_at(&mut pair.server, ms(12)) {
        give_at(&mut pair.client, &ping, ms(13));
    }
    for ack in sent_at(&mut pair.client, ms(14)) {
        give_at(&mut pair.server, &ack, ms(16));
    }
    pair.run_at(ms(17), |_| true);
    assert!(pair.at_server.complete(stream, 8), "the current credit goes out again");

    let reset = pair.open(Direction::Unidirectional);
    pair.client.reset(reset, 7).unwrap();
    pair.client.close_stream(reset).unwrap();
    assert_eq!(sent_at(&mut pair.client, ms(20)).len(), 1);
    let timeout = pair.client.drive(ms(20)).1.deadline.unwrap().instant();
    pair.run_at(timeout, |_| true);
    assert!(
        pair.at_server
            .other
            .iter()
            .any(|e| matches!(e, Event::Reset { stream, code: 7 } if *stream == reset))
    );
}

#[test]
fn the_declared_reordering_interval_preserves_goodput_and_delivers_each_datagram_once() {
    use std::collections::VecDeque;

    // At 100,000 packets/s, each tick is 10 us. Delay 20 of every 100 packets by exactly 100 ms.
    // Count payload bytes in the second 100 ms, after the path fills.
    const INTERVAL: usize = 10_000;
    let measure = |limits: Limits, reorder: bool| {
        let mut pair = Pair::new(limits, limits);
        let mut late = VecDeque::new();
        let mut seen = vec![false; 2 * INTERVAL];
        let mut delivered = 0;
        let mut out = [0; 1200];
        for tick in 0..2 * INTERVAL {
            let at = now().checked_add(Duration::from_micros(tick as u64 * 10)).unwrap();
            pair.client
                .send_unreliable(Lease::from(u32::try_from(tick).unwrap().to_be_bytes().to_vec()))
                .unwrap();
            let len = pair
                .client
                .transmit(&mut out, at)
                .unwrap()
                .expect("the offered packet fits the path")
                .len;
            let mut arrive = |packet: &[u8]| {
                for event in give_at(&mut pair.server, packet, at) {
                    let Event::Unreliable(data) = event else {
                        panic!("an unreliable datagram")
                    };
                    let id = u32::from_be_bytes(data.bytes().try_into().unwrap()) as usize;
                    assert!(!core::mem::replace(&mut seen[id], true), "one delivery per packet");
                    if tick >= INTERVAL {
                        delivered += data.initialized();
                    }
                }
            };
            if reorder && tick % 100 < 20 {
                late.push_back(out[..len].to_vec());
                if tick >= INTERVAL {
                    arrive(&late.pop_front().unwrap());
                }
            } else {
                arrive(&out[..len]);
                if tick % 100 == 50 {
                    arrive(&out[..len]);
                }
            }
            for ack in sent_at(&mut pair.server, at) {
                give_at(&mut pair.client, &ack, at);
            }
        }
        delivered
    };
    let limits = Limits {
        unreliable_bytes_max: Some(1200),
        ..Limits::DEFAULT
    };
    let clean = measure(limits, false);
    assert_eq!(clean, 40_000);
    assert_eq!(
        measure(limits, true),
        clean,
        "zero tolerated loss of goodput inside the declared interval"
    );
    let short = Limits {
        reordering_time: Duration::from_millis(10),
        ..limits
    };
    assert_eq!(
        measure(short, true),
        32_000,
        "the late fifth is outside a 10 ms interval"
    );
}

/// An authenticated side ACK uses the same packet-range and ECN fields as a QUIC ACK.
fn feedback(bytes: &[u8]) -> Ack<'_> {
    let (Frame::Ack(ack), len) = Frame::parse(bytes).unwrap() else {
        panic!("expected an ACK")
    };
    assert_eq!(len, bytes.len());
    ack
}

#[test]
fn side_datagrams_share_the_parent_window_and_release_it_on_ack_or_close() {
    let limits = Limits {
        side_flows_max: 2,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, Limits::DEFAULT);
    let first = pair.client.open_side_flow().unwrap();
    let second = pair.client.open_side_flow().unwrap();
    for number in 0..9 {
        assert_eq!(
            pair.client.admit_side(first, 1200, ms(1)).unwrap().unwrap().number,
            number
        );
    }
    assert_eq!(pair.client.admit_side(second, 1200, ms(1)).unwrap().unwrap().number, 0);
    assert_eq!(pair.client.recovery().bytes_in_flight, 12_000);
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, 2400), true).unwrap();
    assert!(sent_at(&mut pair.client, ms(1)).is_empty());
    pair.client
        .acknowledge_side(first, &feedback(&[3, 8, 0, 0, 8, 9, 0, 0]), ms(2))
        .unwrap();
    assert_eq!(pair.client.recovery().bytes_in_flight, 1200);
    assert_eq!(pair.client.recovery().ecn, EcnState::Capable);
    pair.client.close_side_flow(second).unwrap();
    assert_eq!(pair.client.recovery().bytes_in_flight, 0);
    assert!(!sent_at(&mut pair.client, ms(3)).is_empty());
}

#[test]
fn a_valid_ce_mark_reduces_cubic_once_and_a_cleared_mark_disables_ecn() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let mut out = [0; 1200];
    for (sent, observed, window, state) in [
        (10, Ecn::Ect0, 12_000, EcnState::Capable),
        (20, Ecn::Ce, 8400, EcnState::Capable),
        (30, Ecn::NotEct, 8400, EcnState::Failed),
    ] {
        pair.client.ping();
        let packet = pair.client.transmit_ecn(&mut out, ms(sent)).unwrap().unwrap();
        assert_eq!(packet.ecn, Ecn::Ect0);
        give_marked(&mut pair.server, &out[..packet.len], ms(sent + 1), observed);
        for ack in sent_at(&mut pair.server, ms(sent + 1)) {
            give_at(&mut pair.client, &ack, ms(sent + 2));
            give_at(&mut pair.client, &ack, ms(sent + 3));
        }
        let path = pair.client.recovery();
        assert_eq!((path.ecn, path.congestion_window), (state, window));
    }
    assert_eq!(pair.client.recovery().ecn_counts.ce, 1);
    pair.client.ping();
    assert_eq!(
        pair.client.transmit_ecn(&mut out, ms(40)).unwrap().unwrap().ecn,
        Ecn::NotEct
    );
}

#[test]
fn each_datagram_in_a_full_window_leaves_at_its_pacing_deadline() {
    let mut pair = Pair::new(
        Limits {
            side_flows_max: 1,
            ..Limits::DEFAULT
        },
        Limits::DEFAULT,
    );
    let side = pair.client.open_side_flow().unwrap();
    pair.client.ping();
    let ping = sent_at(&mut pair.client, ms(10));
    give_at(&mut pair.server, &ping[0], ms(410));
    for ack in sent_at(&mut pair.server, ms(410)) {
        give_at(&mut pair.client, &ack, ms(810));
    }
    // The 800 ms sample after a zero-tick handshake gives a 100 ms smoothed RTT.
    assert_eq!(pair.client.recovery().smoothed_rtt, Some(Duration::from_millis(100)));
    let stream = pair.open(Direction::Unidirectional);
    pair.client.send(stream, region(0, 18_000), true).unwrap();
    let mut at = ms(900);
    for index in 0..10 {
        if index == 0 {
            pair.client.admit_side(side, 1200, at).unwrap().unwrap();
            assert!(sent_at(&mut pair.client, at).is_empty());
        } else {
            let packets = sent_at(&mut pair.client, at);
            assert_eq!(packets.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
        }
        if index < 9 {
            let deadline = pair.client.drive(at).1.deadline.unwrap().instant();
            // One full packet every 10 ms, with at most 1 ms of batching.
            assert_eq!(deadline, ms(900 + (index + 1) * 10 - 1));
            let early = Instant::new(deadline.domain(), deadline.as_nanos() - 1);
            assert!(sent_at(&mut pair.client, early).is_empty());
            at = deadline;
        }
    }
    assert_eq!(pair.client.recovery().bytes_in_flight, 12_000);
}

#[test]
fn persistent_congestion_spans_side_flows_and_a_delivered_parent_packet_breaks_the_run() {
    for delivered in [false, true] {
        let limits = Limits {
            side_flows_max: 2,
            ..Limits::DEFAULT
        };
        let mut pair = Pair::new(limits, Limits::DEFAULT);
        let first = pair.client.open_side_flow().unwrap();
        let second = pair.client.open_side_flow().unwrap();
        pair.client.admit_side(first, 1200, ms(1)).unwrap().unwrap();
        if delivered {
            pair.client.ping();
            let ping = sent_at(&mut pair.client, ms(40));
            give_at(&mut pair.server, &ping[0], ms(40));
            for ack in sent_at(&mut pair.server, ms(40)) {
                give_at(&mut pair.client, &ack, ms(40));
            }
        }
        pair.client.admit_side(second, 1200, ms(100)).unwrap().unwrap();
        for space in [second, first] {
            for _ in 0..3 {
                pair.client.admit_side(space, 1200, ms(101)).unwrap().unwrap();
            }
        }
        let ack = feedback(&[2, 3, 0, 0, 2]);
        for space in [second, first] {
            pair.client.acknowledge_side(space, &ack, ms(102)).unwrap();
        }
        let path = pair.client.recovery();
        assert_eq!(path.packets_lost, 2);
        assert_eq!(path.congestion_window, if delivered { 8400 } else { 2400 });
    }
}

#[test]
fn a_full_side_window_uses_a_parent_probe_and_reordered_feedback_keeps_validated_ecn() {
    let mut pair = Pair::new(
        Limits {
            side_flows_max: 1,
            ..Limits::DEFAULT
        },
        Limits::DEFAULT,
    );
    let flow = pair.client.open_side_flow().unwrap();
    pair.client.admit_side(flow, 1200, ms(0)).unwrap().unwrap();
    pair.client
        .acknowledge_side(flow, &feedback(&[3, 0, 0, 0, 0, 1, 0, 0]), ms(0))
        .unwrap();
    for _ in 0..10 {
        pair.client.admit_side(flow, 1200, ms(1)).unwrap().unwrap();
    }
    assert!(pair.client.admit_side(flow, 1200, ms(1)).unwrap().is_none());
    let at = pair.client.drive(ms(1)).1.deadline.unwrap().instant();
    assert_eq!(at, ms(27));
    assert_matches!(pair.client.drive(at).0, Some(Event::SideProbe(id)) if id == flow);
    assert!(pair.client.admit_side(flow, 1200, at).unwrap().is_none());
    let probe = sent_at(&mut pair.client, at);
    assert_eq!(probe.len(), 1);
    let flight = 12_000 + probe[0].len() as u64;
    assert_eq!(pair.client.recovery().bytes_in_flight, flight);
    assert_eq!(pair.client.recovery().packets_lost, 0);
    give_at(&mut pair.server, &probe[0], at);
    for ack in sent_at(&mut pair.server, at) {
        give_at(&mut pair.client, &ack, at);
    }
    // A parent ACK proves path reachability. The side bytes still need their own ACK.
    assert_eq!(pair.client.recovery().bytes_in_flight, 12_000);
    assert_eq!(pair.client.recovery().probes_sent, 1);
    assert!(pair.client.drive(at).1.deadline.unwrap().instant().as_nanos() > at.as_nanos());
    // Side feedback for packet 10 arrives before earlier feedback for packet 8.
    pair.client
        .acknowledge_side(flow, &feedback(&[3, 10, 0, 0, 0, 3, 0, 0]), ms(300))
        .unwrap();
    pair.client
        .acknowledge_side(flow, &feedback(&[3, 8, 0, 0, 0, 2, 0, 0]), ms(300))
        .unwrap();
    assert!(pair.client.recovery().packets_lost > 0);
    assert_eq!(pair.client.recovery().ecn_counts.ect0, 3);
    assert_eq!(pair.client.recovery().ecn, EcnState::Capable);
    assert_eq!(pair.client.recovery().bytes_in_flight, 1200);
}

/// The window of a path with datagrams of 1,200 bytes and no acknowledgement: ten datagrams (RFC
/// 9002, section 7.2).
const INITIAL_WINDOW: u64 = 12_000;
/// The probe timeout of a path with no round-trip sample: 333 ms, four times 166.5 ms, and the
/// 25 ms that the peer can delay an acknowledgement (RFC 9002, sections 6.2.1 and 6.2.2).
const FIRST_TIMEOUT_MS: u64 = 1_024;

fn moved_address() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 4301))
}

#[test]
fn a_rebound_client_keeps_its_connection_after_path_validation() {
    // A new port is the same network, so the window stays. A new address starts from the initial
    // window (RFC 9000, section 9.4).
    for (rebound, window) in [(client_address(4302), None), (moved_address(), Some(INITIAL_WINDOW))] {
        let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
        pair.download(now(), 60_000);
        let before = pair.server.recovery().congestion_window;
        assert!(before > INITIAL_WINDOW);
        // The client does not know that its address changed.
        pair.client.ping();
        for datagram in sent(&mut pair.client) {
            give_on(&mut pair.server, from_server(rebound), &datagram, now(), Ecn::NotEct);
        }
        assert_eq!(pair.server.path(), from_server(rebound));
        assert!(!pair.server.address_validated());
        assert_eq!(pair.server.recovery().congestion_window, window.unwrap_or(before));
        // The client answers the challenge of the server. The server also asks the old address,
        // one time, in a full datagram (RFC 9000, section 9.3.3).
        pair.seen = rebound;
        pair.run(|_| true);
        assert!(pair.server.address_validated());
        let old: Vec<(SocketAddr, usize)> = pair.elsewhere.iter().map(|(to, d)| (to.peer, d.len())).collect();
        assert_eq!(old, [(client_address(4301), 1200)]);
        // The connection goes on at the new address.
        pair.download(now(), 60_000);
        assert_eq!(pair.server.path(), from_server(rebound));
        assert_eq!(pair.elsewhere.len(), 1);
    }
}

#[test]
fn data_to_a_new_peer_address_stays_within_three_times_its_received_bytes_until_validation() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let stream = pair.open(Direction::Bidirectional);
    pair.client.send(stream, region(0, 1), true).unwrap();
    pair.run(|_| true);
    // The server has 64 KB to send when the client moves.
    assert_eq!(feed(&mut pair.server, stream, 0, 64_000, 16_000), 64_000);
    // Each datagram of the client from the new address raises the limit by three times its bytes.
    // No datagram of the server reaches the client, so the address gets no validation.
    let (mut received, mut to_new) = (0, 0);
    for _ in 0..3 {
        pair.client.ping();
        for datagram in sent(&mut pair.client) {
            received += datagram.len();
            give_on(
                &mut pair.server,
                from_server(moved_address()),
                &datagram,
                now(),
                Ecn::NotEct,
            );
        }
        for (path, datagram) in routed_at(&mut pair.server, now()) {
            if path.peer == moved_address() {
                to_new += datagram.len();
            }
        }
        assert_eq!(pair.server.path(), from_server(moved_address()));
        assert!(!pair.server.address_validated());
        assert!(
            to_new > 0 && to_new <= 3 * received,
            "{to_new} bytes after {received} bytes"
        );
    }
    // The client hears the server again, and answers its challenge: the limit ends, and the data
    // arrives.
    pair.seen = moved_address();
    pair.run_until(now(), |pair| pair.at_client.complete(stream, 64_000));
    assert!(pair.server.address_validated());
    assert_eq!(pair.server.path(), from_server(moved_address()));
}

#[test]
fn a_client_with_no_spare_connection_id_stays_on_its_path_and_only_a_client_moves() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let home = pair.client.path();
    // This server gave no second connection ID, and one ID goes out from one local address only
    // (RFC 9000, section 9.5).
    let other = Path {
        local: client_address(4400),
        ..home
    };
    assert_eq!(pair.client.migrate(other, now()), Ok(false));
    assert_eq!(pair.client.path(), home);
    // A client moves to no other address of the server, and a server does not move.
    let elsewhere = Path {
        peer: moved_address(),
        ..home
    };
    assert_eq!(pair.client.migrate(elsewhere, now()).unwrap_err().kind(), Kind::Misuse);
    let server = Path {
        local: moved_address(),
        ..pair.server.path()
    };
    assert_eq!(pair.server.migrate(server, now()).unwrap_err().kind(), Kind::Misuse);
}

#[test]
fn a_side_datagram_counts_against_the_limit_of_a_path_with_no_validation() {
    let side = Limits {
        side_flows_max: 1,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(Limits::DEFAULT, side);
    let flow = pair.server.open_side_flow().unwrap();
    // The client moves, and no datagram of the server reaches it.
    pair.client.ping();
    let mut received = 0;
    for datagram in sent(&mut pair.client) {
        received += datagram.len();
        give_on(
            &mut pair.server,
            from_server(moved_address()),
            &datagram,
            now(),
            Ecn::NotEct,
        );
    }
    // The connection sends its challenge first, and the side flow has what the limit leaves.
    let parent: usize = routed_at(&mut pair.server, now())
        .iter()
        .filter(|(path, _)| path.peer == moved_address())
        .map(|(_, datagram)| datagram.len())
        .sum();
    let left = 3 * received - parent;
    assert!(parent > 0 && left > 0, "{parent} bytes of {received} times three");
    // One byte past the limit waits. A datagram inside it goes, and then the limit is reached.
    assert_eq!(pair.server.admit_side(flow, left + 1, now()).unwrap(), None);
    assert!(pair.server.admit_side(flow, left, now()).unwrap().is_some());
    assert_eq!(pair.server.admit_side(flow, 1, now()).unwrap(), None);
    // After the validation of the address, the side flow has no such limit.
    pair.seen = moved_address();
    let at = pair.run_until(now(), |pair| pair.server.address_validated());
    assert!(pair.server.admit_side(flow, 1200, at).unwrap().is_some());
}

#[test]
fn an_unreliable_datagram_that_waits_drops_with_its_count_when_the_path_returns_to_1200_bytes() {
    let limits = Limits {
        datagram_bytes_max: 1452,
        unreliable_bytes_max: Some(64_000),
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, limits);
    assert!(pair.client.unreliable_room().is_some_and(|room| room >= 1300));
    // The path now drops each datagram above 1,200 bytes. The client queues more datagrams of
    // 1,300 bytes than its window sends, and data of a stream after them.
    pair.path_bytes = 1200;
    for _ in 0..30 {
        pair.client.send_unreliable(region(0, 1300)).unwrap();
    }
    let stream = pair.open(Direction::Bidirectional);
    pair.client.send(stream, region(0, 5000), true).unwrap();
    pair.run_until(now(), |pair| pair.at_server.complete(stream, 5000));
    // The datagrams that waited do not fit a path of 1,200 bytes. They dropped, so the stream
    // went on, and a new one of this size refuses.
    assert!(pair.client.unreliable_room().is_some_and(|room| room < 1200));
    assert_matches!(
        pair.client
            .send_unreliable(region(0, 1300))
            .map_err(|error| error.kind()),
        Err(Kind::Overload)
    );
    assert!(
        pair.at_server.other.is_empty(),
        "the path carried no datagram of 1,300 bytes"
    );
    // The server opens the packets that the path dropped. Each datagram that did not leave the
    // client is in the count.
    let mut left = 0;
    for datagram in &pair.dropped {
        for event in give(&mut pair.server, datagram) {
            assert_matches!(event, Event::Unreliable(data) if data.bytes() == region(0, 1300).bytes());
            left += 1;
        }
    }
    assert!(left > 0, "the client sent datagrams before the path changed");
    assert_eq!(pair.client.unreliable_dropped(), 30 - left);
}

/// A server with a window above the initial one, which an attacker moves: a copy of a datagram
/// of the client arrives from the address of the attacker, and the datagram itself is lost. Gives
/// the window before the move, that address, and the bytes of the copy.
fn forwarded(pair: &mut Pair) -> (u64, SocketAddr, usize) {
    pair.download(now(), 60_000);
    let window = pair.server.recovery().congestion_window;
    assert!(window > INITIAL_WINDOW);
    pair.client.ping();
    let copy = sent(&mut pair.client).remove(0);
    let attacker = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 66), 9));
    give_on(&mut pair.server, from_server(attacker), &copy, now(), Ecn::NotEct);
    assert_eq!(pair.server.path(), from_server(attacker));
    assert_eq!(pair.server.recovery().congestion_window, INITIAL_WINDOW);
    (window, attacker, copy.len())
}

#[test]
fn the_validation_of_an_address_that_never_answers_ends_at_its_timer_and_the_old_path_keeps_its_window() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let (window, attacker, copied) = forwarded(&mut pair);
    let home = from_server(client_address(4301));
    // Nothing answers, and the server follows its deadlines.
    let (mut at, mut to_attacker) = (now(), 0);
    for _ in 0..64 {
        for (path, datagram) in routed_at(&mut pair.server, at) {
            if path.peer == attacker {
                to_attacker += datagram.len();
            }
        }
        if pair.server.path() == home {
            break;
        }
        at = pair
            .server
            .drive(at)
            .1
            .deadline
            .expect("a validation has its end")
            .instant();
        driven_at(&mut pair.server, at);
    }
    // The validation ends after three probe timeouts of the new path, which are longer than the
    // ones of the old path (RFC 9000, section 8.2.4).
    assert_eq!(at, ms(3 * FIRST_TIMEOUT_MS));
    assert_eq!(pair.server.path(), home);
    assert!(pair.server.address_validated());
    assert_eq!(pair.server.recovery().congestion_window, window);
    assert!(to_attacker <= 3 * copied, "{to_attacker} bytes after {copied} bytes");
    // The client, which heard nothing of this, still has its connection.
    pair.download(at, 20_000);
    assert_eq!(pair.server.path(), home);
}

#[test]
fn a_client_that_did_not_move_answers_on_its_path_and_the_server_returns_at_once() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let (window, _, _) = forwarded(&mut pair);
    let home = from_server(client_address(4301));
    // The server asks the path that the client seemed to leave, in a full datagram.
    let asked: Vec<Vec<u8>> = routed_at(&mut pair.server, now())
        .into_iter()
        .filter(|(path, _)| *path == home)
        .map(|(_, datagram)| datagram)
        .collect();
    assert_eq!(asked.iter().map(Vec::len).collect::<Vec<_>>(), [1200]);
    // The answer of the client is a packet that is not a probe. It is the newest packet of the
    // client, and it comes from the address of the client (RFC 9000, section 9.3.3).
    give(&mut pair.client, &asked[0]);
    for datagram in sent(&mut pair.client) {
        give_on(&mut pair.server, home, &datagram, now(), Ecn::NotEct);
    }
    assert_eq!(pair.server.path(), home);
    assert!(pair.server.address_validated());
    assert_eq!(pair.server.recovery().congestion_window, window);
}

#[test]
fn the_search_finds_the_datagram_size_of_the_path_and_a_lost_probe_is_no_congestion() {
    // The client can send datagrams of 1,452 bytes, and the path carries 1,300.
    let limits = Limits {
        datagram_bytes_max: 1452,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::on_path(limits, Limits::DEFAULT, 1300);
    // The search runs with no data. It ends before the idle timeout is the only deadline.
    let mut at = now();
    for _ in 0..512 {
        pair.run_at(at, |_| true);
        let next = pair.client.drive(at).1.deadline.expect("the idle deadline").instant();
        if next.as_nanos() >= ms(20_000).as_nanos() {
            break;
        }
        at = next;
    }
    // At most three probes of each size, and at most six sizes: the top, and then each half of
    // the 252 bytes above 1,200 down to a step of 20 bytes.
    let lost = pair.dropped.len();
    assert!((1..=18).contains(&lost), "{lost} probes were lost");
    let recovery = pair.client.recovery();
    assert_eq!(recovery.packets_lost, 0);
    assert!(recovery.congestion_window >= INITIAL_WINDOW);
    // The data then goes in datagrams of the size that the search found: at most 20 bytes below
    // the size that the path carries.
    let stream = pair.open(Direction::Bidirectional);
    let mut offset = 0;
    for _ in 0..64 {
        offset = feed(&mut pair.client, stream, offset, 100_000, 16_000);
        pair.run_at(at, |_| true);
    }
    assert!(pair.at_server.complete(stream, 100_000));
    assert!(
        (1281..=1300).contains(&pair.largest),
        "datagrams of {} bytes",
        pair.largest
    );
    assert_eq!(pair.client.recovery().packets_lost, 0);
}

#[test]
fn a_path_that_starts_to_drop_large_datagrams_returns_to_1200_bytes_in_three_probe_timeouts() {
    let limits = Limits {
        datagram_bytes_max: 1452,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, Limits::DEFAULT);
    // The path carries each size, so the first probe finds the top of the search.
    let stream = pair.open(Direction::Bidirectional);
    let mut offset = feed(&mut pair.client, stream, 0, 60_000, 5_000);
    pair.run(|_| true);
    assert_eq!((offset, pair.largest), (20_000, 1452));
    let probes = pair.client.recovery().probes_sent;
    // The path now drops each datagram above 1,200 bytes.
    (pair.path_bytes, pair.largest) = (1200, 0);
    let mut at = now();
    for _ in 0..64 {
        offset = feed(&mut pair.client, stream, offset, 60_000, 5_000);
        at = pair.run_until(at, |pair| pair.client.recovery().bytes_in_flight == 0);
        if pair.at_server.complete(stream, 60_000) {
            break;
        }
    }
    assert!(pair.at_server.complete(stream, 60_000));
    assert_eq!(pair.client.recovery().probes_sent - probes, 3);
    assert_eq!(pair.largest, 1200);
}

#[test]
fn a_close_sends_its_code_at_once_then_at_a_bounded_rate_and_each_end_releases_after_its_period() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
    let stream = pair.open(Direction::Bidirectional);
    // Eight datagrams of the server, which arrive after the client closes.
    let late: Vec<Vec<u8>> = (0..8)
        .flat_map(|_| {
            pair.server.ping();
            sent(&mut pair.server)
        })
        .collect();
    assert_eq!(late.len(), 8);
    pair.client.close(0x2a, now()).unwrap();
    assert_eq!(
        pair.client.send(stream, region(0, 1), false).unwrap_err().kind(),
        Kind::Cancelled
    );
    let first = sent(&mut pair.client);
    assert_eq!(
        first.len(),
        1,
        "the frame goes out one time with no datagram of the peer"
    );
    // A copy answers datagram 1, 2, 4, and 8 of the peer.
    let copies: Vec<Vec<Vec<u8>>> = late
        .iter()
        .map(|datagram| {
            assert!(give(&mut pair.client, datagram).is_empty());
            sent(&mut pair.client)
        })
        .collect();
    assert_eq!(
        copies.iter().map(Vec::len).collect::<Vec<_>>(),
        [1, 1, 0, 1, 0, 0, 0, 1]
    );
    // Each copy is the datagram that went out first: the key seals the frame one time (RFC 9000,
    // section 10.2.1).
    assert!(copies.iter().flatten().all(|copy| *copy == first[0]));
    // The first frame is lost, and a copy reaches the server: it ends for its application at
    // once, and sends nothing more.
    let events = give(&mut pair.server, &copies[7][0]);
    assert_matches!(&events[..], [Event::Closed(Ok(()))]);
    assert_eq!(pair.server.peer_close(), Some(PeerClose::Application(0x2a)));
    assert_eq!(
        pair.server.open(Direction::Bidirectional).unwrap_err().kind(),
        Kind::Cancelled
    );
    assert!(sent(&mut pair.server).is_empty());
    // Each end gives its terminal outcome after three probe timeouts, not before. With no round
    // trip time, a probe timeout is the 1 ms of the timer and the 25 ms of the peer.
    for end in [&mut pair.client, &mut pair.server] {
        let turn = end.drive(ms(77)).1;
        assert_eq!(turn.progress, Progress::Blocked(rsnetwork::drive::Blocked::Input));
        assert_eq!(turn.deadline.map(|deadline| deadline.instant()), Some(ms(78)));
        assert_eq!(end.drive(ms(78)).1.progress, Progress::Terminal(Ok(())));
    }
}

#[test]
fn a_key_that_cannot_update_seals_its_close_inside_its_limit_and_no_packet_after_it() {
    const KEY_PACKETS: usize = 8;
    let limits = Limits {
        key_packets_max: KEY_PACKETS as u64,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, Limits::DEFAULT);
    let late: Vec<Vec<u8>> = (0..4)
        .flat_map(|_| {
            pair.server.ping();
            sent(&mut pair.server)
        })
        .collect();
    // No datagram of the client arrives, so the server acknowledges no packet of a new key phase.
    // The client updates its keys one time, and cannot update them again (RFC 9001, section 6.1).
    let mut sealed: Vec<(Option<bool>, Vec<u8>)> = Vec::new();
    for _ in 0..3 * KEY_PACKETS {
        pair.client.ping();
        for datagram in sent(&mut pair.client) {
            sealed.push((pair.client.key_phase(), datagram));
        }
    }
    assert_matches!(
        &driven_at(&mut pair.client, now())[..],
        [Event::Closed(Err(error))] if error.kind() == Kind::Overload
    );
    // The datagrams of the server that still arrive get the datagram of the close again.
    for datagram in &late {
        give(&mut pair.client, datagram);
        for copy in sent(&mut pair.client) {
            sealed.push((pair.client.key_phase(), copy));
        }
    }
    // The packets of the last key: at most its limit, with the close as the last of them (RFC
    // 9001, section 6.6).
    let (phase, close) = sealed.last().cloned().expect("the client sent its close");
    let mut last_key: Vec<&Vec<u8>> = sealed
        .iter()
        .rev()
        .take_while(|(of, _)| *of == phase)
        .map(|(_, datagram)| datagram)
        .collect();
    last_key.sort();
    last_key.dedup();
    assert!(last_key.len() <= KEY_PACKETS, "{} packets with one key", last_key.len());
    give(&mut pair.server, &close);
    assert_matches!(
        pair.server.peer_close(),
        Some(PeerClose::Transport { code, .. }) if code == rsnetwork::quic::ErrorCode::AEAD_LIMIT_REACHED
    );
}

#[test]
fn the_search_starts_on_an_idle_path_whose_limit_is_above_the_window() {
    // The limit of the client is above the first window of ten datagrams of 1,200 bytes, and the
    // path carries each size.
    let limits = Limits {
        datagram_bytes_max: 13_000,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, Limits::DEFAULT);
    let mut at = now();
    for _ in 0..512 {
        pair.run_at(at, |_| true);
        let next = pair.client.drive(at).1.deadline.expect("the idle deadline").instant();
        if next.as_nanos() >= ms(20_000).as_nanos() {
            break;
        }
        at = next;
    }
    // Each probe has at most two datagrams of the size before it, which each window holds. Thus
    // the search reaches the limit, and loses no probe.
    assert_eq!((pair.largest, pair.dropped.len()), (13_000, 0));
}
