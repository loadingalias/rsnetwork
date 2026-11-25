//! The deterministic in-memory path of the QUIC tests (N306, N307, N320, and the N310 cells): a
//! client and a server engine of the core, and a path that the test controls. A [`Pair`] moves
//! the datagrams of both ends through one [`Link`] in each direction. The default link delivers
//! each datagram at once and unchanged. A link can delay, jitter, drop, and reorder datagrams,
//! clear their ECN marks, and pass them through a [`Bottleneck`] with a fixed rate and queue,
//! which several pairs can share. [`Pair::path_bytes`] drops each datagram above the size of the
//! path, and [`Pair::seen`] is the address that the network gives the client.
//!
//! With a seed, each end draws its entropy from its own child of the seed, and each fault of the
//! path draws from another child. The clock is the time that the test gives each call. So a run
//! with the same seed sends the same bytes at the same times, and its [`Transcript`] is the same.
//!
//! The path tests of `tests/quic_streams.rs` and the cells of `tests/quic_conformance.rs` use
//! this module. A binding includes it with `#[path]`, as the Tokio tests include the HTTP/1.1
//! suite.

use core::cell::Cell;
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Progress};
use rsnetwork::quic::frame::Direction;
use rsnetwork::quic::packet::{Datagrams, Header};
use rsnetwork::quic::{Connection, Event, Limits, Path, STREAM_REGIONS_MAX, StreamId};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ChaCha20Rng, ClientConfig, ClientOptions, Entropy, Identity, PrivateKeyDer, Resumption,
    ServerConfig, ServerOptions, TimeProvider, UnixTime,
};

/// The steps of one run: each step is a time at which an end has a deadline or a datagram arrives.
const STEPS_MAX: usize = 1 << 20;

pub(crate) const CA: &[u8] = include_bytes!("../tls/ca.der");
pub(crate) const SERVER: (&[u8], &[u8]) = (
    include_bytes!("../tls/server.der"),
    include_bytes!("../tls/server.key.der"),
);
/// 2027-01-01, inside the validity of each certificate.
pub(crate) const VALID: u64 = 1_798_761_600;

/// A wall clock that stays at one time.
#[derive(Debug)]
pub(crate) struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

pub(crate) fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 26).unwrap())
}

pub(crate) fn now() -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), 0)
}

pub(crate) fn ms(value: u64) -> Instant {
    now().checked_add(Duration::from_millis(value)).unwrap()
}

/// The byte at `offset` of the data of each test stream, so a byte at a wrong place shows.
pub(crate) fn byte(offset: usize) -> u8 {
    u8::try_from(offset % 251).unwrap()
}

/// The `len` bytes of a test stream from `offset`, as a region.
pub(crate) fn region(offset: usize, len: usize) -> Lease {
    Lease::from((offset..offset + len).map(byte).collect::<Vec<u8>>())
}

/// The address of the server, and the address of a client at the port `port`.
pub(crate) const SERVER_ADDRESS: SocketAddr = SocketAddr::new(core::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);

pub(crate) fn client_address(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), port))
}

/// The path of the server to a client at `peer`.
pub(crate) fn from_server(peer: SocketAddr) -> Path {
    Path {
        local: SERVER_ADDRESS,
        peer,
    }
}

/// Each datagram that `connection` sends now.
pub(crate) fn sent(connection: &mut Connection) -> Vec<Vec<u8>> {
    sent_at(connection, now())
}

pub(crate) fn sent_at(connection: &mut Connection, at: Instant) -> Vec<Vec<u8>> {
    routed_at(connection, at)
        .into_iter()
        .map(|(_, datagram)| datagram)
        .collect()
}

/// The segments of one send with segmentation offload on Linux (GSO).
pub(crate) const SEGMENTS: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Each datagram that `connection` sends at `at`, with its path, from batches of at most
/// [`SEGMENTS`] datagrams in 64 KB, as a host with segmentation offload sends them.
pub(crate) fn routed_at(connection: &mut Connection, at: Instant) -> Vec<(Path, Vec<u8>)> {
    let sent = batches(connection, at, Marking::Off);
    sent.into_iter().map(|(path, datagram, _)| (path, datagram)).collect()
}

/// Whether an end sets the ECN mark of its datagrams.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Marking {
    /// [`Connection::transmit`]: each datagram is Not-ECT.
    #[default]
    Off,
    /// [`Connection::transmit_ecn`].
    Ecn,
}

/// Each datagram that `connection` sends at `at`, with its path and its mark, in batches as
/// [`routed_at`] sends them.
fn batches(connection: &mut Connection, at: Instant, marking: Marking) -> Vec<(Path, Vec<u8>, Ecn)> {
    let mut datagrams = Vec::new();
    let mut out = vec![0; 65_536];
    for _ in 0..8192 {
        let sent = match marking {
            Marking::Off => connection.transmit(&mut out, SEGMENTS, at),
            Marking::Ecn => connection.transmit_ecn(&mut out, SEGMENTS, at),
        };
        let Some(sent) = sent.unwrap() else {
            return datagrams;
        };
        let batch = out[..sent.len].chunks(sent.segment_bytes);
        datagrams.extend(batch.map(|datagram| (sent.path, datagram.to_vec(), sent.ecn)));
    }
    panic!("a connection sends at most 8,192 batches at once");
}

/// Gives `datagram` to `connection` in a region of its own, and gives the events of the call.
pub(crate) fn give(connection: &mut Connection, datagram: &[u8]) -> Vec<Event> {
    give_at(connection, datagram, now())
}

pub(crate) fn give_at(connection: &mut Connection, datagram: &[u8], at: Instant) -> Vec<Event> {
    give_marked(connection, datagram, at, Ecn::NotEct)
}

pub(crate) fn give_marked(connection: &mut Connection, datagram: &[u8], at: Instant, mark: Ecn) -> Vec<Event> {
    let path = connection.path();
    give_on(connection, path, datagram, at, mark)
}

/// Gives `datagram` to `connection` as a datagram that arrived on `path`.
pub(crate) fn give_on(connection: &mut Connection, path: Path, datagram: &[u8], at: Instant, mark: Ecn) -> Vec<Event> {
    let len = connection.local_cid().as_bytes().len();
    let datagrams = Datagrams::new(Backing::from(datagram.to_vec()), None, len).with_ecn(mark);
    receive(connection, path, datagrams, at)
}

pub(crate) fn receive(connection: &mut Connection, path: Path, mut datagrams: Datagrams, at: Instant) -> Vec<Event> {
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
pub(crate) fn driven_at(connection: &mut Connection, at: Instant) -> Vec<Event> {
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
pub(crate) struct Received {
    pub(crate) streams: BTreeMap<u64, (Vec<u8>, bool)>,
    /// The stream of each event with bytes, in the order of the events.
    pub(crate) order: Vec<u64>,
    pub(crate) other: Vec<Event>,
}

impl Received {
    /// Takes `events` of `connection`, and releases the bytes of each stream for which `releases`
    /// gives `true`.
    pub(crate) fn take(
        &mut self,
        connection: &mut Connection,
        events: Vec<Event>,
        releases: impl Fn(StreamId) -> bool,
    ) {
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

    pub(crate) fn bytes(&self, stream: StreamId) -> usize {
        self.streams.get(&stream.get()).map_or(0, |(bytes, _)| bytes.len())
    }

    /// Whether `stream` gave its end after exactly the `len` bytes of its test data.
    pub(crate) fn complete(&self, stream: StreamId, len: usize) -> bool {
        self.streams.get(&stream.get()).is_some_and(|(bytes, end)| {
            *end && bytes.len() == len && bytes.iter().enumerate().all(|(at, b)| *b == byte(at))
        })
    }
}

/// The root generator of the run with `seed`.
pub(crate) fn root(seed: u64) -> ChaCha20Rng {
    let mut bytes = [0; ChaCha20Rng::SEED_SIZE];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    ChaCha20Rng::from_seed(bytes)
}

/// The configurations of a client and a server: with the entropy of the system, or each one with
/// its own child of the root of `seed`.
pub(crate) fn configs(seed: Option<u64>) -> (ClientConfig, ServerConfig) {
    let entropy = |label: &[u8; 8]| seed.map_or(Entropy::System, |seed| Entropy::Seeded(root(seed).child(label, 0)));
    let client = ClientConfig::new(ClientOptions {
        roots: &[CertificateDer::from(CA.to_vec())],
        identity: None,
        protocols: &[b"test"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: entropy(b"client\0\0"),
    })
    .unwrap();
    let server = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(SERVER.0.to_vec())],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"test"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: entropy(b"server\0\0"),
    })
    .unwrap();
    (client, server)
}

/// The clock nanoseconds of `duration`.
fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap()
}

/// One direction of the path: what it does to each datagram that enters it. The default link
/// delivers each datagram at once and unchanged, and draws nothing from the seed. Each fault
/// that is on draws from the seed of the pair for each datagram.
#[derive(Clone, Debug, Default)]
pub(crate) struct Link {
    /// The time from the entry of a datagram, or from its exit from the bottleneck, to its arrival.
    pub(crate) delay: Duration,
    /// The most extra delay of a datagram.
    pub(crate) jitter: Duration,
    /// The datagrams of each 1,000 that the link drops.
    pub(crate) loss_per_mille: u32,
    /// The datagrams of each 1,000 that arrive [`late`](Self::late) after their time, so that
    /// later datagrams pass them.
    pub(crate) late_per_mille: u32,
    pub(crate) late: Duration,
    pub(crate) marks: Marks,
    pub(crate) bottleneck: Option<Bottleneck>,
}

/// What a link does with the ECN mark of a datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Marks {
    #[default]
    Keep,
    /// Each datagram arrives Not-ECT, as on a path that clears the mark.
    Clear,
}

/// A queue that sends `bytes_per_second` and holds at most `queue_bytes`: a datagram that does
/// not fit drops (drop-tail). The clones of a link share its queue, so several pairs can share
/// one bottleneck.
#[derive(Clone, Debug)]
pub(crate) struct Bottleneck {
    bytes_per_second: u64,
    queue_bytes: u64,
    /// The clock nanoseconds at which the queue sends its last byte.
    free: Rc<Cell<u64>>,
}

impl Bottleneck {
    pub(crate) fn new(bytes_per_second: u64, queue_bytes: u64) -> Self {
        Self {
            bytes_per_second,
            queue_bytes,
            free: Rc::new(Cell::new(0)),
        }
    }

    /// The clock nanoseconds at which the last byte of `len` bytes that enter at `at` leaves, or
    /// `None` when they do not fit in the queue.
    fn pass(&self, at: u64, len: usize) -> Option<u64> {
        let rate = u128::from(self.bytes_per_second);
        let start = self.free.get().max(at);
        let queued = u128::from(start - at) * rate / 1_000_000_000;
        if queued + len as u128 > u128::from(self.queue_bytes) {
            return None;
        }
        let end = start + u64::try_from(len as u128 * 1_000_000_000 / rate).unwrap();
        self.free.set(end);
        Some(end)
    }
}

impl Link {
    /// The arrival of a datagram of `len` bytes with `mark` that enters at `at` clock nanoseconds,
    /// and the mark that it arrives with, or `None` when the link drops it.
    pub(crate) fn pass(&self, at: u64, len: usize, mark: Ecn, seed: &mut ChaCha20Rng) -> Option<(u64, Ecn)> {
        if self.loss_per_mille > 0 && seed.next_u32() % 1000 < self.loss_per_mille {
            return None;
        }
        let leave = match &self.bottleneck {
            Some(bottleneck) => bottleneck.pass(at, len)?,
            None => at,
        };
        let mut delay = nanos(self.delay);
        if !self.jitter.is_zero() {
            delay += seed.next_u64() % (nanos(self.jitter) + 1);
        }
        if self.late_per_mille > 0 && seed.next_u32() % 1000 < self.late_per_mille {
            delay += nanos(self.late);
        }
        let mark = if self.marks == Marks::Clear { Ecn::NotEct } else { mark };
        Some((leave + delay, mark))
    }
}

/// An end of a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    Client,
    Server,
}

/// A datagram on its way to `to`: its arrival in clock nanoseconds, the path that the receiver
/// gets it on, its bytes, and its mark.
pub(crate) struct Flight {
    pub(crate) at: u64,
    order: u64,
    pub(crate) to: End,
    pub(crate) path: Path,
    pub(crate) bytes: Vec<u8>,
    pub(crate) mark: Ecn,
}

/// The datagrams on their way through the links of a path. A datagram arrives after each one
/// with an earlier arrival, and after each one with the same arrival that entered before it.
#[derive(Default)]
pub(crate) struct Wire {
    flights: Vec<Flight>,
    entered: u64,
}

impl Wire {
    /// Puts a datagram for `to` that arrives at `at` clock nanoseconds.
    pub(crate) fn push(&mut self, at: u64, to: End, path: Path, bytes: Vec<u8>, mark: Ecn) {
        let order = self.entered;
        self.entered += 1;
        let place = self
            .flights
            .partition_point(|flight| (flight.at, flight.order) < (at, order));
        let flight = Flight {
            at,
            order,
            to,
            path,
            bytes,
            mark,
        };
        self.flights.insert(place, flight);
    }

    /// Takes the first datagram for `to` that arrives by `at` clock nanoseconds.
    pub(crate) fn pop(&mut self, to: End, at: u64) -> Option<Flight> {
        let index = self
            .flights
            .iter()
            .position(|flight| flight.to == to && flight.at <= at)?;
        Some(self.flights.remove(index))
    }

    /// The first arrival, in clock nanoseconds.
    pub(crate) fn next(&self) -> Option<u64> {
        self.flights.first().map(|flight| flight.at)
    }
}

/// The datagrams that an end sent: the clock nanoseconds of each one, its sender, its path, and
/// its bytes.
pub(crate) type Transcript = Vec<(u64, End, Path, Vec<u8>)>;

/// The limits of the ends of a pair, its seed, and the path after the handshake.
#[derive(Clone, Debug, Default)]
pub(crate) struct Setup {
    pub(crate) client: Limits,
    pub(crate) server: Limits,
    /// The seed of each end and of the faults of the path, or `None` for the entropy of the
    /// system and a path with no fault that draws.
    pub(crate) seed: Option<u64>,
    /// The link from the client to the server.
    pub(crate) up: Link,
    /// The link from the server to the client.
    pub(crate) down: Link,
    pub(crate) marking: Marking,
}

/// A client and a server after their handshake.
pub(crate) struct Pair {
    pub(crate) client: Connection,
    pub(crate) server: Connection,
    pub(crate) at_client: Received,
    pub(crate) at_server: Received,
    /// The address that the network gives the client. The server gets each datagram of the client
    /// from it, and the client gets only the datagrams that the server sends to it.
    pub(crate) seen: SocketAddr,
    /// The datagrams that the server sent to another address.
    pub(crate) elsewhere: Vec<(Path, Vec<u8>)>,
    /// The largest datagram that the path carries: it drops each larger one, and keeps it.
    pub(crate) path_bytes: usize,
    pub(crate) dropped: Vec<Vec<u8>>,
    /// The largest datagram of the client that the path carried.
    pub(crate) largest: usize,
    /// The budget of the client connection.
    pub(crate) client_budget: Budget,
    pub(crate) up: Link,
    pub(crate) down: Link,
    marking: Marking,
    /// The source of the faults of the path.
    faults: ChaCha20Rng,
    wire: Wire,
    /// Each datagram that an end sent, in a seeded pair.
    pub(crate) transcript: Option<Transcript>,
}

impl Pair {
    pub(crate) fn new(client: Limits, server: Limits) -> Self {
        Self::on_path(client, server, usize::MAX)
    }

    /// A client and a server after their handshake, on a path that carries datagrams of at most
    /// `path_bytes` bytes.
    pub(crate) fn on_path(client: Limits, server: Limits, path_bytes: usize) -> Self {
        let setup = Setup {
            client,
            server,
            ..Setup::default()
        };
        Self::build(setup, path_bytes)
    }

    /// A client and a server after their handshake on a path with no delay and no fault, which
    /// then take the links of `setup`.
    pub(crate) fn with(setup: Setup) -> Self {
        Self::build(setup, usize::MAX)
    }

    fn build(setup: Setup, path_bytes: usize) -> Self {
        let (client_config, server_config) = configs(setup.seed);
        let route = Path {
            local: client_address(4301),
            peer: SERVER_ADDRESS,
        };
        let client_budget = budget();
        let mut client_end = Connection::client(
            &client_config,
            "server.test",
            route,
            setup.client,
            &client_budget,
            now(),
        )
        .unwrap();
        let first = sent(&mut client_end);
        let header = Header::parse(&first[0], 0).unwrap();
        let route = from_server(client_address(4301));
        let mut server_end =
            Connection::server(&server_config, &header, route, setup.server, &budget(), now()).unwrap();
        for datagram in &first {
            assert!(give(&mut server_end, datagram).is_empty());
        }
        let faults = root(setup.seed.unwrap_or(0)).child(b"path\0\0\0\0", 0);
        let client_end_path = client_end.path();
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
            client_budget,
            up: Link::default(),
            down: Link::default(),
            marking: setup.marking,
            faults,
            wire: Wire::default(),
            transcript: setup.seed.map(|_| {
                let path = client_end_path;
                first
                    .iter()
                    .map(|datagram| (0, End::Client, path, datagram.clone()))
                    .collect()
            }),
        };
        pair.run(|_| true);
        assert!(pair.client.is_confirmed() && pair.server.is_confirmed());
        (pair.up, pair.down) = (setup.up, setup.down);
        pair
    }

    /// Moves the datagrams of both ends until no datagram and no event moves. Each end releases
    /// the bytes of each stream for which `releases` gives `true`.
    pub(crate) fn run(&mut self, releases: impl Fn(StreamId) -> bool) {
        self.run_at(now(), releases);
    }

    /// Moves the datagrams of both ends at `at` until no datagram that arrives by then and no
    /// event moves.
    pub(crate) fn run_at(&mut self, at: Instant, releases: impl Fn(StreamId) -> bool) {
        for _ in 0..4096 {
            let events = driven_at(&mut self.client, at);
            let mut quiet = events.is_empty();
            self.at_client.take(&mut self.client, events, &releases);
            for (path, datagram, mark) in batches(&mut self.client, at, self.marking) {
                quiet = false;
                self.enter(End::Client, path, datagram, mark, at);
            }
            quiet &= !self.arrive(End::Server, at, &releases);
            let events = driven_at(&mut self.server, at);
            quiet &= events.is_empty();
            self.at_server.take(&mut self.server, events, &releases);
            for (path, datagram, mark) in batches(&mut self.server, at, self.marking) {
                quiet = false;
                if path.peer == self.seen {
                    self.enter(End::Server, path, datagram, mark, at);
                } else {
                    self.elsewhere.push((path, datagram));
                }
            }
            quiet &= !self.arrive(End::Client, at, &releases);
            if quiet {
                return;
            }
        }
        panic!("the connection is not quiet after 4,096 rounds");
    }

    /// Puts a datagram that `from` sent at `at` on its link.
    fn enter(&mut self, from: End, path: Path, datagram: Vec<u8>, mark: Ecn, at: Instant) {
        if let Some(transcript) = &mut self.transcript {
            transcript.push((at.as_nanos(), from, path, datagram.clone()));
        }
        if datagram.len() > self.path_bytes {
            if from == End::Client {
                self.dropped.push(datagram);
            }
            return;
        }
        let (to, link, path) = match from {
            End::Client => (End::Server, &self.up, from_server(self.seen)),
            End::Server => (End::Client, &self.down, self.client.path()),
        };
        if let Some((arrival, mark)) = link.pass(at.as_nanos(), datagram.len(), mark, &mut self.faults) {
            self.wire.push(arrival, to, path, datagram, mark);
        }
    }

    /// Gives `to` each datagram that arrives by `at`, in the order of arrival. Gives whether one
    /// arrived.
    fn arrive(&mut self, to: End, at: Instant, releases: impl Fn(StreamId) -> bool) -> bool {
        let mut arrived = false;
        while let Some(flight) = self.wire.pop(to, at.as_nanos()) {
            arrived = true;
            match to {
                End::Server => {
                    self.largest = self.largest.max(flight.bytes.len());
                    let events = give_on(&mut self.server, flight.path, &flight.bytes, at, flight.mark);
                    self.at_server.take(&mut self.server, events, &releases);
                }
                End::Client => {
                    let events = give_on(&mut self.client, flight.path, &flight.bytes, at, flight.mark);
                    self.at_client.take(&mut self.client, events, &releases);
                }
            }
        }
        arrived
    }

    /// The next time at which an end has a deadline or a datagram arrives.
    pub(crate) fn next(&mut self, at: Instant) -> Option<Instant> {
        let arrival = self.wire.next().map(|nanos| Instant::new(at.domain(), nanos));
        [self.client.drive(at).1.deadline, self.server.drive(at).1.deadline]
            .into_iter()
            .flatten()
            .map(|deadline| deadline.instant())
            .chain(arrival)
            .min_by_key(|instant| instant.as_nanos())
    }

    /// Runs the connection, and moves the clock to the next deadline of an end or the next
    /// arrival, until `done`. Gives the time.
    pub(crate) fn run_until(&mut self, mut at: Instant, done: impl Fn(&Self) -> bool) -> Instant {
        for _ in 0..STEPS_MAX {
            self.run_at(at, |_| true);
            if done(self) {
                return at;
            }
            at = self.next(at).expect("an end that waits has a deadline");
        }
        panic!("the connection does not reach its state after {STEPS_MAX} steps");
    }

    /// Opens a stream of the client.
    pub(crate) fn open(&mut self, direction: Direction) -> StreamId {
        self.client
            .open(direction)
            .unwrap()
            .expect("the limit of the server allows the stream")
    }
}

/// Runs `pairs` together from `at` until `until`. Each pair moves its datagrams only at its own
/// deadlines and arrivals, as a host of its own does, so that no pair sends at the time of another
/// one. Gives the time of the last step.
pub(crate) fn run_together(pairs: &mut [Pair], at: Instant, until: Instant) -> Instant {
    let mut times: Vec<Option<Instant>> = vec![Some(at); pairs.len()];
    let mut last = at;
    for _ in 0..STEPS_MAX {
        let Some(at) = times.iter().flatten().copied().min_by_key(|instant| instant.as_nanos()) else {
            return last;
        };
        if at.as_nanos() > until.as_nanos() {
            return last;
        }
        for (pair, time) in pairs.iter_mut().zip(&mut times) {
            if time.is_some_and(|time| time.as_nanos() <= at.as_nanos()) {
                pair.run_at(at, |_| true);
                *time = pair.next(at);
            }
        }
        last = at;
    }
    panic!("the pairs do not reach {until:?} after {STEPS_MAX} steps");
}

/// Gives the `len` bytes of the test data to `stream` of `connection` from `offset`, in regions of
/// `piece` bytes, as many as the stream takes, with the end after the last byte. Gives the new
/// offset.
pub(crate) fn feed(
    connection: &mut Connection,
    stream: StreamId,
    mut offset: usize,
    len: usize,
    piece: usize,
) -> usize {
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
