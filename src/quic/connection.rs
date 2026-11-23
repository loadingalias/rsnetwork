//! The connection engine of version 1: the TLS 1.3 handshake on rustls's QUIC API, the packet
//! number spaces and their keys, the transport parameters, key updates, and the idle and
//! handshake timeouts (RFC 9000 and RFC 9001).
//!
//! A host drives a [`Connection`] in calls: [`Connection::receive`] with each received region,
//! [`Connection::drive`] at its deadline, and then [`Connection::transmit`] until it gives no
//! datagram. Each call returns at once: the engine does no I/O and keeps no thread.
//!
//! This engine has the handshake. Acknowledgements and loss recovery come with N306, streams and
//! datagrams with N305, address validation and connection IDs with N304, and the close periods
//! with N307. Until then a lost packet is not sent again, the engine ignores the frames of those
//! parts, and a close ends the connection at once.

use core::cmp::Ordering;
use core::fmt;
use core::mem::size_of;
use core::time::Duration;
use std::sync::Arc;

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Credit};
use rstypes::time::{Deadline, Instant};
use rustls::error::AlertDescription;
use rustls::pki_types::ServerName;
use rustls::quic::{
    ClientHandshake, DirectionalKeys, KeyChange, PacketKey, PacketKeySet, QuicEvent, Secrets, ServerHandshake,
    Version as TlsVersion,
};
use rustls::{ClientSide, ServerSide};

use super::crypto::{self, Refused};
use super::frame::Frame;
use super::packet::{self, Builder, Datagrams, Header, Kind as PacketKind, OpenError, Outgoing, Side};
use super::params::{Parameters, Sender};
use super::{ConnectionId, ErrorCode};
use crate::drive::{Blocked, Error, Kind, Progress, Turn, TurnLimits, Work};
use crate::tls::memory::{self, ClientStore, Cost, Held, Owns};
use crate::tls::{self, Facts, Negotiated};

/// The limits of a QUIC connection, which the caller sets. [`Limits::DEFAULT`] has the default of
/// each one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The time with no activity after which the connection ends, or `None` for no limit of this
    /// end. The connection uses the smaller of this time and the time of the peer, and at least
    /// three probe timeouts (RFC 9000, section 10.1).
    pub idle_timeout: Option<Duration>,
    /// The time from the start of the connection to a confirmed handshake. At this deadline the
    /// connection ends with [`Kind::Deadline`].
    pub handshake_timeout: Duration,
    /// The largest datagram that this end sends: 1,200 to 65,527 bytes. A datagram that carries an
    /// Initial packet has at least 1,200 bytes (RFC 9000, section 14.1).
    pub datagram_bytes_max: usize,
    /// The bytes of the connection ID that this end chooses for itself: 0 to 20.
    pub cid_bytes: usize,
    /// The most packets that one 1-RTT key seals, at least 2. Then this end updates its keys
    /// (RFC 9001, section 6). The connection uses the smaller of this limit and the
    /// confidentiality limit of its suite, so `u64::MAX` gives the limit of the suite.
    pub key_packets_max: u64,
    /// The work of one call: the received bytes and the frames that it reads, and the rustls
    /// calls that it makes, each counted as a frame.
    pub turn: TurnLimits,
}

impl Limits {
    /// An idle timeout of 30 s, a handshake timeout of 10 s, datagrams of at most 1,200 bytes,
    /// connection IDs of 8 bytes, the key limit of the suite, and 1 MiB and 4,096 frames for each
    /// call.
    pub const DEFAULT: Self = Self {
        idle_timeout: Some(Duration::from_secs(30)),
        handshake_timeout: Duration::from_secs(10),
        datagram_bytes_max: DATAGRAM_MIN,
        cid_bytes: 8,
        key_packets_max: u64::MAX,
        turn: TurnLimits {
            bytes: 1 << 20,
            frames: 4096,
        },
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The smallest datagram that carries an Initial packet (RFC 9000, section 14.1).
const DATAGRAM_MIN: usize = 1_200;
/// The largest UDP payload (RFC 9000, section 18.2).
const DATAGRAM_MAX: usize = 65_527;
/// The bytes of the destination connection ID of the first Initial packet of a client: at least
/// 8 (RFC 9000, section 7.2).
const ORIGINAL_CID_BYTES: usize = 8;
/// The probe timeout before the first round-trip sample: the initial RTT of 333 ms and four times
/// its half as variation (RFC 9002, sections 6.2.2 and 6.2.4).
const PTO_INITIAL: Duration = Duration::from_millis(999);
/// The code of the CRYPTO_ERROR range: the TLS alert follows it (RFC 9001, section 4.8).
const CRYPTO_ERROR: u64 = 0x100;
/// The bytes of a CRYPTO frame besides its data: its type, an offset of up to 8 bytes, and a
/// length of up to 2 bytes for the data of one packet.
const CRYPTO_FRAME_HEAD: usize = 1 + 8 + 2;
/// The memory of the keys of one level: two packet keys and two header keys of the provider.
const KEYS_BYTES: u64 = 2 * memory::RECORD_KEY + 2 * memory::HEADER_KEY;
/// The events of one rustls call that the engine keeps room for: a flight of the server, its key
/// changes, and its session tickets.
const EVENTS: usize = 16;

/// The packet number spaces, and the levels of their keys (RFC 9000, section 12.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

impl Level {
    const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::Data];

    const fn of(kind: PacketKind) -> Option<Self> {
        match kind {
            PacketKind::Initial => Some(Self::Initial),
            PacketKind::Handshake => Some(Self::Handshake),
            PacketKind::OneRtt => Some(Self::Data),
            // 0-RTT is off: no level reads it.
            PacketKind::ZeroRtt => None,
        }
    }
}

/// One packet number space: its keys, its CRYPTO streams, and its packet numbers.
struct Space {
    /// The keys of an Initial or Handshake space. The data space keeps its keys in [`OneRtt`].
    keys: Option<rustls::quic::Keys>,
    receive: crypto::Receive,
    send: crypto::Send,
    /// The end of the CRYPTO data that arrived at this level.
    received: u64,
    /// The number of the next packet that this end sends.
    next: u64,
    /// The largest number of a packet of the peer that opened.
    largest: Option<u64>,
    /// The keys are gone: each later packet of the space drops.
    discarded: bool,
    credit: Credit,
}

impl Space {
    fn new(budget: &Budget) -> Self {
        Self {
            keys: None,
            receive: crypto::Receive::new(budget),
            send: crypto::Send::new(budget),
            received: 0,
            next: 0,
            largest: None,
            discarded: false,
            credit: budget.credit(0),
        }
    }

    /// Installs the keys that `keys` makes, after their charge, so a refusal allocates nothing.
    fn install(&mut self, keys: impl FnOnce() -> rustls::quic::Keys) -> Result<(), Error> {
        self.credit.charge(KEYS_BYTES).map_err(|_| KEYS_REFUSED)?;
        self.keys = Some(keys());
        Ok(())
    }

    /// Drops the keys and the CRYPTO streams of the space (RFC 9001, section 4.9).
    fn discard(&mut self, budget: &Budget) {
        *self = Self {
            discarded: true,
            next: self.next,
            largest: self.largest,
            ..Self::new(budget)
        };
    }
}

/// The 1-RTT keys of the connection, and their updates (RFC 9001, section 6).
struct OneRtt {
    local: DirectionalKeys,
    remote: DirectionalKeys,
    /// The packet key of the peer before its last update, until the deadline.
    previous: Option<(Box<dyn PacketKey>, Instant)>,
    /// The keys of the next phase, made before the peer uses them, so their cost does not show
    /// when a packet of the next phase arrives.
    next: PacketKeySet,
    /// The secrets of the phase after the next one.
    secrets: Secrets,
    /// The key phase of `local` and `remote`.
    phase: bool,
    /// The packets that `local` sealed.
    sealed: u64,
    /// The number of the first packet that this end sealed in this phase.
    first_sent: Option<u64>,
    /// The number of the first packet of the peer that opened in this phase.
    first_received: Option<u64>,
    /// The peer acknowledged a packet of this phase, so a later update is allowed.
    acknowledged: bool,
    /// A key update happened: each later one needs an acknowledgement of the current phase.
    updated: bool,
    /// The most packets that one key seals.
    limit: u64,
    /// The charge of the keys, which returns when they drop.
    _charge: Credit,
}

impl fmt::Debug for OneRtt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneRtt")
            .field("phase", &self.phase)
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}

impl OneRtt {
    fn new(keys: rustls::quic::Keys, mut secrets: Secrets, limit: u64, budget: &Budget) -> Result<Self, Error> {
        let mut credit = budget.credit(0);
        // The keys of this phase, the keys of the next one, the secrets, and a previous key.
        credit.charge(3 * KEYS_BYTES).map_err(|_| KEYS_REFUSED)?;
        let limit = limit.min(keys.local.packet.confidentiality_limit());
        Ok(Self {
            local: keys.local,
            remote: keys.remote,
            previous: None,
            next: secrets.next_packet_keys(),
            secrets,
            phase: false,
            sealed: 0,
            first_sent: None,
            first_received: None,
            acknowledged: false,
            updated: false,
            limit,
            _charge: credit,
        })
    }

    /// Moves both directions to the next phase. The old packet key of the peer stays until
    /// `until`, for its packets that arrive late.
    fn update(&mut self, until: Instant) {
        let next = core::mem::replace(&mut self.next, self.secrets.next_packet_keys());
        let old = core::mem::replace(&mut self.remote.packet, next.remote);
        self.local.packet = next.local;
        self.previous = Some((old, until));
        self.phase = !self.phase;
        self.sealed = 0;
        self.first_sent = None;
        self.first_received = None;
        self.acknowledged = false;
        self.updated = true;
    }
}

/// The rustls state of the handshake.
enum Tls {
    Client(ClientHandshake),
    Server(ServerHandshake),
    /// The completed handshake: rustls reads the CRYPTO data of the data space, such as session
    /// tickets.
    ClientDone(rustls::Connection<ClientSide, rustls::quic::Quic>),
    ServerDone(rustls::Connection<ServerSide, rustls::quic::Quic>),
    /// A rustls call failed, and took the state.
    Failed,
}

/// The end of a client or a server: its configuration.
enum End {
    Client {
        tickets: Option<Arc<ClientStore>>,
    },
    Server {
        config: Arc<rustls::ServerConfig>,
        /// The encoded transport parameters, until rustls takes them.
        parameters: Option<Vec<u8>>,
    },
}

/// A CONNECTION_CLOSE frame that waits to go out, and the error that ends the connection.
#[derive(Clone, Copy, Debug)]
struct Close {
    code: u64,
    frame_type: u64,
    error: Error,
}

/// One QUIC connection of version 1, client or server, with no I/O.
pub struct Connection {
    end: End,
    tls: Tls,
    /// The stream of each draw of the connection, or `None` for the system.
    stream: Option<rscrypto_rustls::replay::Stream>,
    /// The charge of the memory of rustls.
    held: Held,
    cost: Cost,
    own: Arc<Owns>,
    /// The charge of what one rustls call can write.
    output: Credit,
    /// The charge of the parts that rustls keeps: the transport parameters of each end.
    kept: Credit,
    /// The transport parameters of the peer are charged.
    parameters_kept: bool,
    events: Vec<QuicEvent>,
    spaces: [Space; 3],
    one_rtt: Option<OneRtt>,
    /// The level of the next messages of rustls.
    write: Level,
    /// The level whose CRYPTO data rustls reads next.
    read: Level,
    /// The connection ID of this end: the destination of the packets of the peer.
    local_cid: ConnectionId,
    /// The connection ID of the peer: the destination of the packets of this end.
    remote_cid: ConnectionId,
    /// The destination connection ID of the first Initial packet of the client.
    original_cid: ConnectionId,
    /// A client took the connection ID of the server from its first Initial packet.
    remote_known: bool,
    facts: Option<Facts>,
    peer: Option<Parameters>,
    limits: Limits,
    budget: Budget,
    /// The idle timeout of the connection, or `None` for none.
    idle: Option<Duration>,
    idle_deadline: Option<Instant>,
    handshake_deadline: Option<Instant>,
    /// A packet of the peer opened after the last ack-eliciting packet of this end.
    received: bool,
    /// The handshake is confirmed (RFC 9001, section 4.1.2).
    confirmed: bool,
    /// A server owes a HANDSHAKE_DONE frame.
    handshake_done: bool,
    /// A PING frame waits for the next 1-RTT packet.
    ping: bool,
    close: Option<Close>,
    outcome: Option<Result<(), Error>>,
    /// The packets of the peer that failed authentication, across each key.
    failures: u64,
    /// The capacity that the next rustls call waits for.
    wait: Option<u64>,
    /// Work waits for the next call: a limit of a turn stopped it.
    more: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("client", &matches!(self.end, End::Client { .. }))
            .field("confirmed", &self.confirmed)
            .field("one_rtt", &self.one_rtt)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

const KEYS_REFUSED: Error = Error::new(Kind::Overload, "the budget refused the keys of a QUIC level");
const OUTPUT_REFUSED: Error = Error::new(Kind::Overload, "the budget refused the QUIC handshake output");
const CLOCK: Error = Error::new(
    Kind::Misuse,
    "the time of the call is not on the clock of the QUIC connection",
);
const IDLE: Error = Error::new(Kind::Deadline, "the QUIC connection was idle past its timeout");
const HANDSHAKE_LATE: Error = Error::new(
    Kind::Deadline,
    "the QUIC handshake did not complete before its deadline",
);
const VIOLATION: Error = Error::new(Kind::Malformed, "the peer broke a rule of QUIC version 1");
const PARAMETERS: Error = Error::new(
    Kind::Malformed,
    "the QUIC transport parameters of the peer are not valid",
);

/// The instant `duration` after `now`.
fn after(now: Instant, duration: Duration) -> Result<Instant, Error> {
    now.checked_add(duration).map_err(|_| CLOCK)
}

/// Whether `deadline` is at or before `now`.
fn reached(deadline: Option<Instant>, now: Instant) -> Result<bool, Error> {
    deadline.map_or(Ok(false), |deadline| {
        now.compare(deadline)
            .map(|order| order != Ordering::Less)
            .map_err(|_| CLOCK)
    })
}

/// The earlier of two instants of one clock.
fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.compare(a) == Ok(Ordering::Less) { b } else { a }),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Checks the limits that the caller set.
fn check(limits: &Limits) -> Result<(), Error> {
    if !(DATAGRAM_MIN..=DATAGRAM_MAX).contains(&limits.datagram_bytes_max)
        || limits.cid_bytes > ConnectionId::MAX
        || limits.key_packets_max < 2
        || limits.handshake_timeout.is_zero()
        || limits.idle_timeout.is_some_and(|timeout| timeout.is_zero())
    {
        return Err(Error::new(Kind::Misuse, "the QUIC limits cannot work"));
    }
    Ok(())
}

/// A connection ID of `len` random bytes from the source of the connection.
fn random_cid(random: &dyn rustls::crypto::SecureRandom, len: usize) -> Result<ConnectionId, Error> {
    let mut bytes = [0; ConnectionId::MAX];
    let bytes = &mut bytes[..len];
    random
        .fill(bytes)
        .map_err(|_| Error::new(Kind::Unsupported, "the entropy source failed"))?;
    ConnectionId::new(bytes).ok_or(Error::new(Kind::Misuse, "a QUIC connection ID has more than 20 bytes"))
}

/// The encoding of `parameters` in a vector of its exact size, charged to `credit`.
fn encode(parameters: &Parameters, credit: &mut Credit) -> Result<Vec<u8>, Error> {
    let len = parameters.encoded_len().ok_or(Error::new(
        Kind::Misuse,
        "a QUIC transport parameter does not fit its field",
    ))?;
    credit.charge(len as u64).map_err(|_| OUTPUT_REFUSED)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| OUTPUT_REFUSED)?;
    bytes.resize(len, 0);
    let written = parameters.write(&mut bytes);
    assert_eq!(written, Some(len), "the parameters write the bytes of their length");
    Ok(bytes)
}

impl Connection {
    /// Makes the client end of a connection to the server `name`, a DNS name or an IP address.
    /// The first Initial packet waits for [`transmit`](Self::transmit).
    ///
    /// Refuses with [`Kind::Misuse`] when `name` is not valid, `config` offers no ALPN name
    /// (RFC 9001, section 8.1), or `limits` cannot work, and with [`Kind::Overload`] when
    /// `budget` cannot pay.
    pub fn client(
        config: &tls::ClientConfig,
        name: &str,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        check(&limits)?;
        if config.protocols == 0 {
            return Err(Error::new(Kind::Misuse, "a QUIC client offers no ALPN name"));
        }
        let name = ServerName::try_from(name)
            .map_err(|_| Error::new(Kind::Misuse, "the server name is not a DNS name or an IP address"))?;
        let name_bytes = match &name {
            ServerName::DnsName(dns) => dns.as_ref().len(),
            _ => 0,
        };
        let stream = config.entropy.stream(QUIC);
        let random = config.config.provider().secure_random;
        let (original_cid, local_cid) = tls::scoped(stream.as_ref(), || {
            Ok::<_, Error>((
                random_cid(random, ORIGINAL_CID_BYTES)?,
                random_cid(random, limits.cid_bytes)?,
            ))
        })?;
        let own = config.own.get();
        let held = Held::new(budget, &config.cost, 2 * name_bytes as u64, &own)?;
        let mut connection = Self::new(
            (
                End::Client {
                    tickets: config.store.clone(),
                },
                Tls::Failed,
            ),
            (stream, held, config.cost, Arc::clone(&config.own)),
            (local_cid, original_cid, original_cid),
            limits,
            budget,
            now,
        )?;
        connection.spaces[Level::Initial as usize].install(|| packet::initial_keys(&original_cid, Side::Client))?;
        let parameters = encode(&connection.parameters(), &mut connection.kept)?;
        // The connection keeps the name after the charges, and the ClientHello carries it.
        let name = name.to_owned();
        let started = connection.call(|events| {
            config
                .config
                .connect(name)
                .start_quic_handshake(TlsVersion::V1, parameters, events)
                .map(|needs| Tls::Client(ClientHandshake::NeedsInput(needs)))
        });
        connection.tls = started.map_err(|failure| failure.error)?;
        Ok(connection)
    }

    /// Makes the server end of the connection that the client starts with the Initial packet of
    /// `initial`, the header of its first packet. Give that packet to
    /// [`receive`](Self::receive) next.
    ///
    /// Refuses with [`Kind::Misuse`] when `initial` is not the header of an Initial packet,
    /// `config` accepts no ALPN name, or `limits` cannot work, and with [`Kind::Overload`] when
    /// `budget` cannot pay.
    pub fn server(
        config: &tls::ServerConfig,
        initial: &Header,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        check(&limits)?;
        let Header::Protected {
            kind: PacketKind::Initial,
            dcid,
            scid,
            ..
        } = *initial
        else {
            return Err(Error::new(
                Kind::Misuse,
                "the first packet of a QUIC client is not an Initial packet",
            ));
        };
        if config.config.alpn_protocols.is_empty() {
            return Err(Error::new(Kind::Misuse, "a QUIC server accepts no ALPN name"));
        }
        let stream = config.entropy.stream(QUIC);
        let random = config.config.provider().secure_random;
        let local_cid = tls::scoped(stream.as_ref(), || random_cid(random, limits.cid_bytes))?;
        let own = config.own.get();
        let held = Held::new(budget, &config.cost, 0, &own)?;
        let mut connection = Self::new(
            (
                End::Server {
                    config: Arc::clone(&config.config),
                    parameters: None,
                },
                Tls::Server(ServerHandshake::NeedsInput(ServerHandshake::start(TlsVersion::V1))),
            ),
            (stream, held, config.cost, Arc::clone(&config.own)),
            (local_cid, scid, dcid),
            limits,
            budget,
            now,
        )?;
        connection.remote_known = true;
        connection.spaces[Level::Initial as usize].install(|| packet::initial_keys(&dcid, Side::Server))?;
        let parameters = encode(&connection.parameters(), &mut connection.kept)?;
        if let End::Server { parameters: slot, .. } = &mut connection.end {
            *slot = Some(parameters);
        }
        Ok(connection)
    }

    fn new(
        (end, tls): (End, Tls),
        (stream, held, cost, own): (Option<rscrypto_rustls::replay::Stream>, Held, Cost, Arc<Owns>),
        (local_cid, remote_cid, original_cid): (ConnectionId, ConnectionId, ConnectionId),
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        let mut output = budget.credit(0);
        output
            .charge((EVENTS * size_of::<QuicEvent>()) as u64)
            .map_err(|_| OUTPUT_REFUSED)?;
        let mut events = Vec::new();
        events.try_reserve_exact(EVENTS).map_err(|_| OUTPUT_REFUSED)?;
        let idle = limits.idle_timeout.map(|timeout| timeout.max(3 * PTO_INITIAL));
        Ok(Self {
            end,
            tls,
            stream,
            held,
            cost,
            own,
            output,
            kept: budget.credit(0),
            parameters_kept: false,
            events,
            spaces: [Space::new(budget), Space::new(budget), Space::new(budget)],
            one_rtt: None,
            write: Level::Initial,
            read: Level::Initial,
            local_cid,
            remote_cid,
            original_cid,
            remote_known: false,
            facts: None,
            peer: None,
            limits,
            budget: budget.clone(),
            idle,
            idle_deadline: idle.map(|idle| after(now, idle)).transpose()?,
            handshake_deadline: Some(after(now, limits.handshake_timeout)?),
            received: false,
            confirmed: false,
            handshake_done: false,
            ping: false,
            close: None,
            outcome: None,
            failures: 0,
            wait: None,
            more: false,
        })
    }

    /// The transport parameters of this end.
    fn parameters(&self) -> Parameters {
        let server = matches!(self.end, End::Server { .. });
        Parameters {
            original_destination_cid: server.then_some(self.original_cid),
            idle_timeout: self.limits.idle_timeout,
            initial_source_cid: Some(self.local_cid),
            ..Parameters::default()
        }
    }

    /// The connection ID of this end, which the packets of the peer carry: route them to this
    /// connection, and read their short headers with its length.
    pub const fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// What the handshake negotiated, or `None` before it completed.
    pub fn negotiated(&self) -> Option<Negotiated<'_>> {
        self.facts.as_ref().map(Facts::negotiated)
    }

    /// Whether the handshake is confirmed: a server completed it, or a client received
    /// HANDSHAKE_DONE (RFC 9001, section 4.1.2).
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// The transport parameters of the peer, after the handshake completed.
    pub const fn peer_parameters(&self) -> Option<&Parameters> {
        self.peer.as_ref()
    }

    /// The 1-RTT key phase of this end, after the handshake completed.
    pub fn key_phase(&self) -> Option<bool> {
        self.one_rtt.as_ref().map(|keys| keys.phase)
    }

    /// Sends a PING frame in the next 1-RTT packet: the peer acknowledges it, and it counts as
    /// activity for the idle timeout of the peer. Before the 1-RTT keys, the PING waits for them.
    pub fn ping(&mut self) {
        self.ping = true;
    }

    /// Opens the packets of `datagrams`, the received region, and runs the handshake on their
    /// CRYPTO data. A packet that this end cannot open is discarded. Stops at a limit of the
    /// turn: then call again with the same region.
    pub fn receive(&mut self, datagrams: &mut Datagrams, now: Instant) -> Turn {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now) {
            self.outcome = Some(Err(error));
        }
        while self.outcome.is_none() && self.close.is_none() {
            if work.reached(&self.limits.turn) {
                self.more = true;
                break;
            }
            let Some(next) = datagrams.next_packet() else {
                break;
            };
            let Ok(packet) = next else {
                continue;
            };
            if let Err(failure) = self.packet(packet, &mut work, now) {
                self.fail(failure);
            }
            if let Err(failure) = self.advance(&mut work) {
                self.fail(failure);
            }
        }
        self.turn()
    }

    /// Runs the timers at `now`, and the handshake work that a limit of a turn or the budget
    /// stopped. Call it at the deadline of the last turn, when capacity is free, and after a
    /// [`Progress::Pending`].
    pub fn drive(&mut self, now: Instant) -> Turn {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now) {
            self.outcome = Some(Err(error));
        }
        if self.outcome.is_none()
            && self.close.is_none()
            && let Err(failure) = self.advance(&mut work)
        {
            self.fail(failure);
        }
        self.turn()
    }

    /// The result of a call.
    fn turn(&self) -> Turn {
        let progress = match (self.outcome, self.wait) {
            (Some(outcome), _) => Progress::Terminal(outcome),
            (None, Some(units)) => Progress::Blocked(Blocked::Capacity(units)),
            (None, None) if self.more => Progress::Pending,
            (None, None) => Progress::Blocked(Blocked::Input),
        };
        Turn {
            progress,
            deadline: self.deadline().map(Deadline::at),
        }
    }

    /// The earliest timer of the connection.
    fn deadline(&self) -> Option<Instant> {
        if self.outcome.is_some() {
            return None;
        }
        let previous = self
            .one_rtt
            .as_ref()
            .and_then(|keys| keys.previous.as_ref().map(|(_, until)| *until));
        let handshake = if self.confirmed { None } else { self.handshake_deadline };
        earlier(earlier(self.idle_deadline, handshake), previous)
    }

    /// Ends the connection at its idle or handshake deadline, with no packet (RFC 9000, section
    /// 10.1), and drops the old key of the peer at its deadline.
    fn timers(&mut self, now: Instant) -> Result<(), Error> {
        if self.outcome.is_some() {
            return Ok(());
        }
        if reached(self.idle_deadline, now)? {
            return Err(IDLE);
        }
        if !self.confirmed && reached(self.handshake_deadline, now)? {
            return Err(HANDSHAKE_LATE);
        }
        if let Some(keys) = &mut self.one_rtt
            && reached(keys.previous.as_ref().map(|(_, until)| *until), now)?
        {
            keys.previous = None;
        }
        Ok(())
    }

    /// Opens one packet and reads its frames.
    fn packet(&mut self, packet: packet::Protected<'_>, work: &mut Work, now: Instant) -> Result<(), Failure> {
        let Header::Protected { kind, dcid, scid, .. } = *packet.header() else {
            // A Retry, a Version Negotiation, or another version: the endpoint (N304) reads them.
            return Ok(());
        };
        work.add(packet.header().end(), 0);
        let server = matches!(self.end, End::Server { .. });
        let ours = dcid == self.local_cid
            || (server && kind == PacketKind::Initial && dcid == self.original_cid && !self.spaces[0].discarded);
        let Some(level) = Level::of(kind).filter(|_| ours) else {
            return Ok(());
        };
        // A client takes the connection ID of the server from its first Initial packet, and drops
        // each later packet with another one (RFC 9000, section 7.2).
        if level != Level::Data && self.remote_known && scid != self.remote_cid {
            return Ok(());
        }
        let space = &self.spaces[level as usize];
        let expected = space.largest.map_or(0, |largest| largest + 1);
        let opened = match level {
            Level::Data => {
                let Some(keys) = &mut self.one_rtt else {
                    return Ok(());
                };
                let unmasked = match packet.unmask(&*keys.remote.header, expected) {
                    Ok(unmasked) => unmasked,
                    Err(_) => return Ok(()),
                };
                // A packet of the other phase is of the previous phase while the old key stays and
                // no packet of this phase came before it, and else of the next phase (RFC 9001,
                // section 6.3).
                let number = unmasked.number();
                let old = keys.first_received.is_none_or(|first| number < first);
                match (unmasked.key_phase() == keys.phase, &keys.previous) {
                    (true, _) => unmasked.open(&*keys.remote.packet).map(|packet| (packet, false)),
                    (false, Some((previous, _))) if old => unmasked.open(&**previous).map(|packet| (packet, false)),
                    (false, _) => unmasked.open(&*keys.next.remote).map(|packet| (packet, true)),
                }
            }
            _ => {
                let Some(keys) = &space.keys else {
                    return Ok(());
                };
                packet
                    .unmask(&*keys.remote.header, expected)
                    .and_then(|unmasked| unmasked.open(&*keys.remote.packet))
                    .map(|packet| (packet, false))
            }
        };
        let (packet, updated) = match opened {
            Ok(opened) => opened,
            Err(OpenError::Authentication) => return self.authentication_failed(),
            Err(OpenError::Short) => return Ok(()),
            Err(OpenError::Violation) => return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0, VIOLATION)),
        };
        let number = packet.number();
        if updated {
            // The peer updated its keys: this end follows in its next packet (RFC 9001, section
            // 6.2).
            let until = after(now, 3 * self.pto())?;
            if let Some(keys) = &mut self.one_rtt {
                keys.update(until);
            }
        }
        if level == Level::Data
            && let Some(keys) = &mut self.one_rtt
        {
            keys.first_received.get_or_insert(number);
        }
        let space = &mut self.spaces[level as usize];
        space.largest = Some(space.largest.map_or(number, |largest| largest.max(number)));
        if !server && level == Level::Initial && !self.remote_known {
            self.remote_cid = scid;
            self.remote_known = true;
        }
        // A server drops the Initial keys when a Handshake packet of the client opens (RFC 9001,
        // section 4.9.1).
        if server && level == Level::Handshake && !self.spaces[0].discarded {
            self.spaces[0].discard(&self.budget);
        }
        self.received = true;
        self.idle_deadline = self.idle.map(|idle| after(now, idle)).transpose()?;
        self.frames(level, &packet.payload(), work)
    }

    /// Counts a packet that failed authentication, and ends the connection at the integrity
    /// limit of its suite (RFC 9001, section 6.6).
    fn authentication_failed(&mut self) -> Result<(), Failure> {
        self.failures = self.failures.saturating_add(1);
        let limit = self
            .one_rtt
            .as_ref()
            .map_or(u64::MAX, |keys| keys.remote.packet.integrity_limit());
        if self.failures > limit {
            return Err(Failure::transport(
                ErrorCode::AEAD_LIMIT_REACHED,
                0,
                Error::new(
                    Kind::Malformed,
                    "the QUIC packets that failed authentication reached their limit",
                ),
            ));
        }
        Ok(())
    }

    /// Reads the frames of an opened packet of `level`.
    fn frames(&mut self, level: Level, payload: &Lease, work: &mut Work) -> Result<(), Failure> {
        let mut bytes = payload.bytes();
        let server = matches!(self.end, End::Server { .. });
        while !bytes.is_empty() {
            let (frame, len) =
                Frame::parse(bytes).map_err(|error| Failure::transport(error.code, error.frame_type, VIOLATION))?;
            bytes = &bytes[len..];
            work.add(0, 1);
            let handshake_level = level != Level::Data;
            match frame {
                Frame::Padding { .. } | Frame::Ping => {}
                Frame::Ack(ack) => {
                    let space = &self.spaces[level as usize];
                    if ack.largest >= space.next {
                        return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x02, VIOLATION));
                    }
                    if level == Level::Data
                        && let Some(keys) = &mut self.one_rtt
                        && keys.first_sent.is_some_and(|first| ack.largest >= first)
                    {
                        keys.acknowledged = true;
                    }
                }
                Frame::Crypto { offset, data } => self.crypto(level, offset, data)?,
                // A close of the application is only in 1-RTT packets (RFC 9000, section 12.4).
                Frame::ConnectionClose { frame_type: None, .. } if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1d, VIOLATION));
                }
                Frame::ConnectionClose { code, frame_type, .. } => {
                    self.outcome = Some(closed(code, frame_type));
                    return Ok(());
                }
                Frame::HandshakeDone if !server && !handshake_level => self.confirm(),
                Frame::HandshakeDone | Frame::NewToken { .. } if server || handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1e, VIOLATION));
                }
                // Only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE are in Initial and
                // Handshake packets (RFC 9000, section 12.4).
                _ if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0, VIOLATION));
                }
                // The frames of streams, datagrams, paths, and connection IDs come with N304,
                // N305, and N307.
                _ => {}
            }
        }
        Ok(())
    }

    /// Takes the CRYPTO data of a frame of `level`. Data at a level below the one that rustls
    /// reads must not pass the data that arrived there (RFC 9001, section 4.1.3).
    fn crypto(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), Failure> {
        let end = offset.saturating_add(data.len() as u64);
        let space = &mut self.spaces[level as usize];
        if (level as usize) < (self.read as usize) && end > space.received {
            return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x06, VIOLATION));
        }
        space.received = space.received.max(end);
        space.receive.insert(offset, data).map_err(|refused| {
            Failure::transport(
                refused.code(),
                0x06,
                match refused {
                    Refused::Bound => Error::new(
                        Kind::Overload,
                        "the CRYPTO data of the peer passed the buffer bound of its level",
                    ),
                    Refused::Budget => Error::new(Kind::Overload, "the budget refused the CRYPTO data of the peer"),
                },
            )
        })
    }

    /// Confirms the handshake: the handshake keys and the handshake deadline go.
    fn confirm(&mut self) {
        if self.confirmed {
            return;
        }
        self.confirmed = true;
        self.handshake_deadline = None;
        self.spaces[Level::Handshake as usize].discard(&self.budget);
    }

    /// The probe timeout before a round-trip sample, with the ACK delay of the peer.
    fn pto(&self) -> Duration {
        PTO_INITIAL + self.peer.map_or(Duration::ZERO, |peer| peer.ack_delay_max)
    }

    /// Runs rustls on the CRYPTO data in order, one level at a time, until it needs more, a limit
    /// of the turn stops it, or the budget cannot pay for the next call.
    fn advance(&mut self, work: &mut Work) -> Result<(), Failure> {
        self.wait = None;
        let mut stalled = false;
        loop {
            if matches!(self.tls, Tls::Failed) || self.close.is_some() || self.outcome.is_some() {
                return Ok(());
            }
            let level = self.read;
            let visible = self.spaces[level as usize].receive.ordered();
            let ready = matches!(
                self.tls,
                Tls::Client(ClientHandshake::VerifyServerIdentity(_))
                    | Tls::Server(ServerHandshake::Accepted(_) | ServerHandshake::VerifyClientIdentity(_))
            );
            if !ready && visible == 0 {
                return Ok(());
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                return Ok(());
            }
            let own = self.own.get();
            if let Err(units) = self.held.charge(own.work(self.cost.read, visible)) {
                self.wait = Some(units);
                return Ok(());
            }
            if let Err(units) = self.output.charge(own.flight() as u64).map_err(|_| own.flight() as u64) {
                self.held.after(0, &own);
                self.wait = Some(units);
                return Ok(());
            }
            work.add(visible, 1);
            let consumed = self.spaces[level as usize].receive.consumed();
            let ticket = self.ticket(level, visible);
            let tls = core::mem::replace(&mut self.tls, Tls::Failed);
            let input = &mut self.spaces[level as usize].receive;
            let config = match &mut self.end {
                End::Server { config, parameters } => Some((Arc::clone(config), parameters)),
                End::Client { .. } => None,
            };
            let step = Self::step(tls, input, config, &mut self.events);
            let (held, output, stream) = (&mut self.held, &mut self.output, self.stream.as_ref());
            // A read that can give a session ticket runs with the charge of the ticket; each other
            // call with the charges of the handshake. One call context runs at a time.
            let next = match ticket {
                Some(ticket) => memory::ticket(ticket, || tls::scoped(stream, step)),
                None => memory::handshake(held, output, || tls::scoped(stream, step)),
            };
            // The messages and the keys of the call are charged before the reservations of the
            // call return, so each byte that rustls gave stays charged.
            let events = self.events.len();
            let taken = self.take_events();
            self.settle_output()?;
            self.held.after(visible, &own);
            self.tls = next.map_err(|error| Failure::tls(&error))?;
            taken?;
            self.keep_parameters()?;
            self.completed()?;
            // rustls reports what a call consumed by the next call at the latest, so a stall is two
            // calls in a row that consume nothing, give no event, and keep the level: then the
            // engine waits for the rest of a message.
            let progress =
                ready || events > 0 || self.read != level || self.spaces[level as usize].receive.consumed() != consumed;
            if progress {
                stalled = false;
            } else if core::mem::replace(&mut stalled, true) {
                return Ok(());
            }
            // A level that rustls left must hold no more data (RFC 9001, section 4.1.3).
            for lower in Level::ALL.iter().take(self.read as usize) {
                if self.spaces[*lower as usize].receive.ordered() > 0 {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x06, VIOLATION));
                }
            }
        }
    }

    /// The charge of a session ticket that a client can read in `visible` bytes of the data
    /// space, for the store of its configuration, or `None`.
    fn ticket(&self, level: Level, visible: usize) -> Option<memory::Ticket> {
        let (End::Client { tickets: Some(store) }, Level::Data) = (&self.end, level) else {
            return None;
        };
        let chain = match &self.tls {
            Tls::ClientDone(connection) => memory::chain_bytes(connection.peer_identity()),
            _ => 0,
        };
        store.charge(visible, chain)
    }

    /// One rustls call on `input` in the state `tls`, which gives the next state.
    fn step<'a>(
        tls: Tls,
        input: &'a mut crypto::Receive,
        config: Option<(Arc<rustls::ServerConfig>, &'a mut Option<Vec<u8>>)>,
        events: &'a mut Vec<QuicEvent>,
    ) -> impl FnOnce() -> Result<Tls, rustls::Error> + 'a {
        move || match tls {
            Tls::Client(ClientHandshake::NeedsInput(needs)) => needs.process(input, events).map(client),
            Tls::Client(ClientHandshake::VerifyServerIdentity(verify)) => verify.with_config(events).map(client),
            Tls::Server(ServerHandshake::NeedsInput(needs)) => needs.process(input, events).map(server),
            Tls::Server(ServerHandshake::Accepted(accepted)) => {
                let (config, parameters) = config.expect("a server has its configuration");
                let parameters = parameters.take().unwrap_or_default();
                accepted.choose_config(config, parameters, events).map(server)
            }
            Tls::Server(ServerHandshake::VerifyClientIdentity(verify)) => verify.with_config(events).map(server),
            Tls::ClientDone(mut connection) => {
                let read = connection.read_hs(input);
                events.extend(connection.events());
                read.map(|()| Tls::ClientDone(connection))
            }
            Tls::ServerDone(mut connection) => {
                let read = connection.read_hs(input);
                events.extend(connection.events());
                read.map(|()| Tls::ServerDone(connection))
            }
            // A completed state and a failed one wait for no call; the others are not in this
            // version of rustls.
            other => Ok(other),
        }
    }

    /// Runs `f`, the first rustls call of a client, under the charges of the connection.
    fn call(&mut self, f: impl FnOnce(&mut Vec<QuicEvent>) -> Result<Tls, rustls::Error>) -> Result<Tls, Failure> {
        let own = self.own.get();
        self.output
            .charge(own.flight() as u64)
            .map_err(|_| Failure::local(OUTPUT_REFUSED))?;
        let (held, output, stream, events) = (&mut self.held, &mut self.output, self.stream.as_ref(), &mut self.events);
        let started = memory::handshake(held, output, || tls::scoped(stream, || f(events)));
        let taken = self.take_events();
        self.settle_output()?;
        self.held.after(0, &own);
        let started = started.map_err(|error| Failure::tls(&error))?;
        taken.map(|()| started)
    }

    /// Gives back the charge of the output of a call: each message that it wrote is charged to
    /// the CRYPTO stream that sends it.
    fn settle_output(&mut self) -> Result<(), Failure> {
        let charged = self
            .output
            .charged()
            .saturating_sub((EVENTS * size_of::<QuicEvent>()) as u64);
        let refunded = self.output.refund(charged);
        assert!(refunded.is_ok(), "a credit refunds at most its charged units");
        if self.events.capacity() > EVENTS {
            return Err(Failure::local(Error::new(
                Kind::Unsupported,
                "rustls gave more QUIC events in one call than the engine keeps room for",
            )));
        }
        Ok(())
    }

    /// Takes the events of the last rustls call: each message goes to the CRYPTO stream of its
    /// level, and each key change installs its keys.
    fn take_events(&mut self) -> Result<(), Failure> {
        for event in self.events.drain(..) {
            match event {
                QuicEvent::Message(message) => self.spaces[self.write as usize]
                    .send
                    .push(message)
                    .map_err(|_| Failure::local(OUTPUT_REFUSED))?,
                QuicEvent::KeyChange(KeyChange::Handshake { keys }) => {
                    self.spaces[Level::Handshake as usize]
                        .install(|| keys)
                        .map_err(Failure::local)?;
                    self.write = Level::Handshake;
                    self.read = Level::Handshake;
                }
                QuicEvent::KeyChange(KeyChange::OneRtt { keys, next }) => {
                    self.one_rtt = Some(
                        OneRtt::new(keys, next, self.limits.key_packets_max, &self.budget).map_err(Failure::local)?,
                    );
                    self.write = Level::Data;
                }
                _ => {
                    return Err(Failure::local(Error::new(
                        Kind::Unsupported,
                        "rustls gave a QUIC event that the engine does not know",
                    )));
                }
            }
        }
        Ok(())
    }

    /// Charges the transport parameters of the peer, which rustls keeps, when they arrive.
    fn keep_parameters(&mut self) -> Result<(), Failure> {
        if self.parameters_kept {
            return Ok(());
        }
        let len = match &self.tls {
            Tls::Client(ClientHandshake::NeedsInput(needs)) => needs.quic_transport_parameters().map(<[u8]>::len),
            Tls::Server(ServerHandshake::NeedsInput(needs)) => needs.quic_transport_parameters().map(<[u8]>::len),
            Tls::ClientDone(connection) => connection.quic_transport_parameters().map(<[u8]>::len),
            Tls::ServerDone(connection) => connection.quic_transport_parameters().map(<[u8]>::len),
            _ => None,
        };
        if let Some(len) = len {
            self.kept.charge(len as u64).map_err(|_| {
                Failure::local(Error::new(
                    Kind::Overload,
                    "the budget refused the transport parameters of the peer",
                ))
            })?;
            self.parameters_kept = true;
        }
        Ok(())
    }

    /// When rustls completed the handshake: the facts, the parameters of the peer, and on a
    /// server the confirmation and its HANDSHAKE_DONE.
    fn completed(&mut self) -> Result<(), Failure> {
        self.tls = match core::mem::replace(&mut self.tls, Tls::Failed) {
            Tls::Client(ClientHandshake::Complete(connection)) => Tls::ClientDone(connection),
            Tls::Server(ServerHandshake::Complete(connection)) => Tls::ServerDone(connection),
            other => other,
        };
        if self.facts.is_some() {
            return Ok(());
        }
        let (common, parameters, sender): (&rustls::CommonState, _, _) = match &self.tls {
            Tls::ClientDone(connection) => (&**connection, connection.quic_transport_parameters(), Sender::Server),
            Tls::ServerDone(connection) => (&**connection, connection.quic_transport_parameters(), Sender::Client),
            _ => return Ok(()),
        };
        let invalid = || Failure::transport(ErrorCode::TRANSPORT_PARAMETER_ERROR, 0, PARAMETERS);
        let parameters = Parameters::parse(parameters.ok_or_else(invalid)?, sender).map_err(|_| invalid())?;
        let identity = common.peer_identity();
        let (peer, evidence) = (memory::chain_bytes(identity), memory::end_entity_bytes(identity));
        let facts = Facts::of(common)
            .map_err(Failure::local)?
            .ok_or(Failure::local(Error::new(
                Kind::Unsupported,
                "rustls did not give the facts of the QUIC handshake",
            )))?;
        self.facts = Some(facts);
        self.held.finished(peer, evidence, &self.own.get());
        self.validate(&parameters)?;
        self.peer = Some(parameters);
        self.idle = match (self.limits.idle_timeout, parameters.idle_timeout) {
            (Some(local), Some(remote)) => Some(local.min(remote)),
            (local, remote) => local.or(remote),
        }
        .map(|idle| idle.max(3 * self.pto()));
        self.read = Level::Data;
        if sender == Sender::Client {
            self.handshake_done = true;
            self.confirm();
        }
        Ok(())
    }

    /// Checks the connection IDs that the peer names in its parameters against the ones of its
    /// packets (RFC 9000, section 7.3).
    fn validate(&self, parameters: &Parameters) -> Result<(), Failure> {
        let invalid = || Failure::transport(ErrorCode::TRANSPORT_PARAMETER_ERROR, 0, PARAMETERS);
        if parameters.initial_source_cid != Some(self.remote_cid) {
            return Err(invalid());
        }
        if matches!(self.end, End::Client { .. })
            && (parameters.original_destination_cid != Some(self.original_cid) || parameters.retry_source_cid.is_some())
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Ends the connection with `failure`: its CONNECTION_CLOSE waits for
    /// [`transmit`](Self::transmit) when this end has keys to send it.
    fn fail(&mut self, failure: Failure) {
        if self.outcome.is_some() || self.close.is_some() {
            return;
        }
        let keys = self.spaces.iter().any(|space| space.keys.is_some()) || self.one_rtt.is_some();
        match failure.code {
            Some((code, frame_type)) if keys => {
                self.close = Some(Close {
                    code,
                    frame_type,
                    error: failure.error,
                });
            }
            _ => self.outcome = Some(Err(failure.error)),
        }
    }

    /// Builds the next datagram at the start of `out`, and gives its length, or `None` when this
    /// end has nothing to send. Call it until it gives `None`. The datagram has at most
    /// [`Limits::datagram_bytes_max`] bytes, and at least 1,200 when it carries an Initial packet.
    ///
    /// Refuses with [`Kind::Misuse`] when `out` has fewer than 1,200 bytes.
    pub fn transmit(&mut self, out: &mut [u8], now: Instant) -> Result<Option<usize>, Error> {
        if out.len() < DATAGRAM_MIN {
            return Err(Error::new(
                Kind::Misuse,
                "a QUIC datagram needs an output of 1,200 bytes or more",
            ));
        }
        if self.outcome.is_some() {
            return Ok(None);
        }
        let peer = self.peer.map_or(usize::MAX, |peer| {
            usize::try_from(peer.udp_payload_bytes_max).unwrap_or(usize::MAX)
        });
        let size = self.limits.datagram_bytes_max.min(peer).min(out.len());
        let out = &mut out[..size];
        let built = match self.close {
            Some(close) => self.closing(out, close, now),
            None => self.datagram(out, now),
        };
        let Err(failure) = built else {
            return Ok(built.unwrap_or_default());
        };
        self.fail(failure);
        match self.close {
            Some(close) => Ok(self.closing(out, close, now).unwrap_or_default()),
            None => Ok(None),
        }
    }

    /// Whether this end has something to send at `level`.
    fn wants(&self, level: Level) -> bool {
        let space = &self.spaces[level as usize];
        match level {
            Level::Data => self.one_rtt.is_some() && (space.send.pending() || self.handshake_done || self.ping),
            _ => space.keys.is_some() && space.send.pending(),
        }
    }

    /// Builds a datagram of the packets that wait, at most one for each level.
    fn datagram(&mut self, out: &mut [u8], now: Instant) -> Result<Option<usize>, Failure> {
        let wanted = Level::ALL.map(|level| self.wants(level));
        let Some(last) = wanted.iter().rposition(|&wanted| wanted) else {
            return Ok(None);
        };
        let initial = wanted[0];
        let mut at = 0;
        let mut handshake_sent = false;
        for level in Level::ALL {
            if !wanted[level as usize] {
                continue;
            }
            let pad = (initial && level as usize == last).then_some(DATAGRAM_MIN.saturating_sub(at));
            let Some(len) = self.packet_out(level, &mut out[at..], pad, (None, now))? else {
                break;
            };
            at += len;
            handshake_sent |= level == Level::Handshake;
        }
        if at == 0 {
            return Ok(None);
        }
        // A client drops its Initial keys when it first sends a Handshake packet (RFC 9001,
        // section 4.9.1).
        if handshake_sent && matches!(self.end, End::Client { .. }) && !self.spaces[0].discarded {
            self.spaces[0].discard(&self.budget);
        }
        // The first ack-eliciting packet after a received one restarts the idle timer (RFC 9000,
        // section 10.1).
        if self.received {
            self.received = false;
            self.idle_deadline = self.idle.map(|idle| after(now, idle)).transpose()?;
        }
        Ok(Some(at))
    }

    /// Builds a datagram with a CONNECTION_CLOSE frame in each level that has keys, and then ends
    /// the connection.
    fn closing(&mut self, out: &mut [u8], close: Close, now: Instant) -> Result<Option<usize>, Failure> {
        let keyed = Level::ALL.map(|level| match level {
            Level::Data => self.one_rtt.is_some(),
            _ => self.spaces[level as usize].keys.is_some(),
        });
        let last = keyed.iter().rposition(|&keyed| keyed);
        let mut at = 0;
        for level in Level::ALL {
            if !keyed[level as usize] {
                continue;
            }
            let pad = (keyed[0] && Some(level as usize) == last).then_some(DATAGRAM_MIN.saturating_sub(at));
            match self.packet_out(level, &mut out[at..], pad, (Some(close), now)) {
                Ok(Some(len)) => at += len,
                _ => break,
            }
        }
        self.close = None;
        self.outcome = Some(Err(close.error));
        Ok((at > 0).then_some(at))
    }

    /// Builds one packet of `level` at the start of `out`: a CONNECTION_CLOSE frame for `close`,
    /// or the HANDSHAKE_DONE and CRYPTO frames that wait. Pads it to `pad` bytes. Gives its
    /// length, or `None` when `out` has no room for a packet with a frame.
    fn packet_out(
        &mut self,
        level: Level,
        out: &mut [u8],
        pad: Option<usize>,
        (close, now): (Option<Close>, Instant),
    ) -> Result<Option<usize>, Failure> {
        let space = &self.spaces[level as usize];
        let number = space.next;
        let number_len = packet::number_len(number, None).ok_or(Failure::local(Error::new(
            Kind::Overload,
            "the packet numbers of a QUIC space passed their limit",
        )))?;
        if level == Level::Data && close.is_none() {
            self.key_limit(now)?;
        }
        let (dcid, scid) = (self.remote_cid, self.local_cid);
        let header = match level {
            Level::Initial => Outgoing::Initial {
                dcid: &dcid,
                scid: &scid,
                token: &[],
            },
            Level::Handshake => Outgoing::Handshake {
                dcid: &dcid,
                scid: &scid,
            },
            Level::Data => Outgoing::OneRtt {
                dcid: &dcid,
                spin: false,
                key_phase: self.one_rtt.as_ref().is_some_and(|keys| keys.phase),
            },
        };
        let Ok(mut builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let full = |_: packet::BuildError| {
            Failure::local(Error::new(Kind::Unsupported, "a QUIC frame did not fit its packet"))
        };
        // A packet with no room for a frame waits for the next datagram.
        let control = level == Level::Data && (self.handshake_done || self.ping);
        if close.is_none() && !control && builder.room() <= CRYPTO_FRAME_HEAD {
            return Ok(None);
        }
        if let Some(close) = close {
            let frame = Frame::ConnectionClose {
                code: close.code,
                frame_type: Some(close.frame_type),
                reason: &[],
            };
            if builder.frame(&frame).is_err() {
                return Ok(None);
            }
        } else {
            if level == Level::Data && self.handshake_done {
                builder.frame(&Frame::HandshakeDone).map_err(full)?;
                self.handshake_done = false;
            }
            if level == Level::Data && self.ping {
                builder.frame(&Frame::Ping).map_err(full)?;
                self.ping = false;
            }
            let send = &mut self.spaces[level as usize].send;
            while builder.room() > CRYPTO_FRAME_HEAD
                && let Some((offset, data)) = send.next(builder.room() - CRYPTO_FRAME_HEAD)
            {
                let len = data.len();
                builder.frame(&Frame::Crypto { offset, data }).map_err(full)?;
                send.sent(len);
            }
        }
        if let Some(pad) = pad {
            builder.pad_to(pad).map_err(full)?;
        }
        let keys = match level {
            Level::Data => self.one_rtt.as_ref().map(|keys| &keys.local),
            _ => self.spaces[level as usize].keys.as_ref().map(|keys| &keys.local),
        };
        let keys = keys.ok_or(Failure::local(Error::new(
            Kind::Unsupported,
            "a QUIC level has no keys for its packet",
        )))?;
        let len = builder.seal(keys).map_err(|_| {
            Failure::local(Error::new(
                Kind::Unsupported,
                "the packet key refused to seal a QUIC packet",
            ))
        })?;
        self.spaces[level as usize].next = number + 1;
        if level == Level::Data
            && let Some(keys) = &mut self.one_rtt
        {
            keys.sealed += 1;
            keys.first_sent.get_or_insert(number);
        }
        Ok(Some(len))
    }

    /// Updates the 1-RTT keys of this end before the key seals more packets than its limit
    /// (RFC 9001, sections 6 and 6.6). A key update needs a confirmed handshake, and after the
    /// first one an acknowledgement of a packet of the current phase: without them the connection
    /// ends with AEAD_LIMIT_REACHED.
    fn key_limit(&mut self, now: Instant) -> Result<(), Failure> {
        let (confirmed, until) = (self.confirmed, after(now, 3 * self.pto())?);
        let Some(keys) = &mut self.one_rtt else {
            return Ok(());
        };
        if keys.sealed < keys.limit {
            return Ok(());
        }
        if confirmed && (!keys.updated || keys.acknowledged) {
            keys.update(until);
            return Ok(());
        }
        Err(Failure::transport(
            ErrorCode::AEAD_LIMIT_REACHED,
            0,
            Error::new(
                Kind::Overload,
                "the QUIC packet key reached its limit, and the peer did not acknowledge the last key update",
            ),
        ))
    }
}

/// The label of the stream of each QUIC connection.
const QUIC: &[u8; 8] = b"quic-con";

/// A failure of the connection: the error, and the code of its CONNECTION_CLOSE frame with the
/// type of the frame that caused it, or `None` for a failure that sends no frame.
#[derive(Clone, Copy, Debug)]
struct Failure {
    error: Error,
    code: Option<(u64, u64)>,
}

impl Failure {
    const fn local(error: Error) -> Self {
        Self {
            error,
            code: Some((ErrorCode::INTERNAL_ERROR.0, 0)),
        }
    }

    const fn transport(code: ErrorCode, frame_type: u64, error: Error) -> Self {
        Self {
            error,
            code: Some((code.0, frame_type)),
        }
    }

    /// A failure of rustls: its alert goes in the CRYPTO_ERROR range (RFC 9001, section 4.8).
    fn tls(error: &rustls::Error) -> Self {
        let code = AlertDescription::try_from(error)
            .map_or(ErrorCode::INTERNAL_ERROR.0, |alert| CRYPTO_ERROR + u64::from(alert.0));
        Self {
            error: tls::refused(error),
            code: Some((code, 0x06)),
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::local(error)
    }
}

/// The outcome of a CONNECTION_CLOSE frame of the peer with `code`.
fn closed(code: u64, frame_type: Option<u64>) -> Result<(), Error> {
    match (code, frame_type) {
        // A close of the application, or of the transport with no error.
        (_, None) | (0, Some(_)) => Ok(()),
        (CRYPTO_ERROR..=0x1ff, Some(_)) => {
            let alert = AlertDescription(u8::try_from(code - CRYPTO_ERROR).unwrap_or(u8::MAX));
            Err(tls::refused(&rustls::Error::AlertReceived(alert)))
        }
        _ => Err(Error::new(
            Kind::Malformed,
            "the peer closed the QUIC connection with a transport error",
        )),
    }
}

fn client(handshake: ClientHandshake) -> Tls {
    Tls::Client(handshake)
}

fn server(handshake: ServerHandshake) -> Tls {
    Tls::Server(handshake)
}
