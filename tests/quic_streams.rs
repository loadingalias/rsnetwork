//! The streams of a QUIC connection between two engines of the core: flow control that follows
//! the consumer, data out of order under its bound, the outcomes of a stream, the send order, the
//! stream credit, and unreliable datagrams (N305; RFC 9000, sections 2 to 4, and RFC 9221).

use core::num::NonZeroU64;
use core::time::Duration;
use std::assert_matches;
use std::collections::BTreeMap;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Kind, Progress};
use rsnetwork::quic::frame::Direction;
use rsnetwork::quic::packet::{Datagrams, Header};
use rsnetwork::quic::{Connection, Event, Limits, Priority, STREAM_REGIONS_MAX, StreamId};
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

/// Each datagram that `connection` sends now.
fn sent(connection: &mut Connection) -> Vec<Vec<u8>> {
    sent_at(connection, now())
}

fn sent_at(connection: &mut Connection, at: Instant) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    for _ in 0..8192 {
        let mut out = vec![0; 1500];
        match connection.transmit(&mut out, at).unwrap() {
            Some(len) => {
                out.truncate(len);
                datagrams.push(out);
            }
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
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, len);
    let mut events = Vec::new();
    for _ in 0..8192 {
        match connection.receive(&mut datagrams, at) {
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
}

impl Pair {
    fn new(client: Limits, server: Limits) -> Self {
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
        let mut client_end = Connection::client(&client_config, "server.test", client, &budget(), now()).unwrap();
        let first = sent(&mut client_end);
        let header = Header::parse(&first[0], 0).unwrap();
        let mut server_end = Connection::server(&server_config, &header, server, &budget(), now()).unwrap();
        for datagram in &first {
            assert!(give(&mut server_end, datagram).is_empty());
        }
        let mut pair = Self {
            client: client_end,
            server: server_end,
            at_client: Received::default(),
            at_server: Received::default(),
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
                let events = give_at(&mut self.server, datagram, at);
                self.at_server.take(&mut self.server, events, &releases);
            }
            let events = driven_at(&mut self.server, at);
            let to_client = sent_at(&mut self.server, at);
            quiet &= to_client.is_empty() && events.is_empty();
            self.at_server.take(&mut self.server, events, &releases);
            for datagram in &to_client {
                let events = give_at(&mut self.client, datagram, at);
                self.at_client.take(&mut self.client, events, &releases);
            }
            if quiet {
                return;
            }
        }
        panic!("the connection is not quiet after 4,096 rounds");
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

#[test]
fn newreno_grows_on_delivery_and_halves_once_for_packet_and_time_threshold_losses() {
    let mut pair = Pair::new(Limits::DEFAULT, Limits::DEFAULT);
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

    let second = sent_at(&mut pair.client, ms(30));
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
    let third = sent_at(&mut pair.client, ms(46));
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
                .expect("the offered packet fits the path");
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
