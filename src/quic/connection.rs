//! The connection engine of version 1: the TLS 1.3 handshake on rustls's QUIC API, the packet
//! number spaces and their keys, the transport parameters, key updates, and the idle and
//! handshake timeouts (RFC 9000 and RFC 9001).
//!
//! A host drives a [`Connection`] in calls: [`Connection::receive`] with each received region,
//! [`Connection::drive`] at its deadline, and then [`Connection::transmit`] until it gives no
//! datagram. Each call returns at once: the engine does no I/O and keeps no thread.
//!
//! After the handshake, the application opens streams, gives them regions to send, and takes the
//! [`Event`]s of the peer: `receive` and `drive` give one event for each call, so call them again
//! while they give one. Also call `drive` after the last `transmit`: it gives the events of the
//! packets that went out, and the next deadline.
//!
//! Each packet number space keeps its received ranges and outstanding packets. The spaces share
//! the round-trip estimate, congestion window, and pacer of the path.

use core::cmp::Ordering;
use core::fmt;
use core::mem::size_of;
use core::time::Duration;
use std::collections::VecDeque;
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
use super::frame::{Ack, Direction, Frame, STREAMS_MAX};
use super::packet::{self, Builder, Datagrams, Header, Kind as PacketKind, OpenError, Outgoing, Side};
use super::params::{Parameters, Sender};
use super::recovery::{self, DataRange, History, Output, Path, Received, Record, RecoveryStats, Sent};
use super::stream::{self, Event, Priority, Stop, StreamId, Streams};
use super::{CongestionControl, ConnectionId, ErrorCode, VARINT_MAX};
use crate::drive::{Blocked, Ecn, Error, Kind, Progress, Turn, TurnLimits, Work};
use crate::tls::memory::{self, ClientStore, Cost, Held, Owns};
use crate::tls::{self, Facts, Negotiated};

/// The limits of a QUIC connection, which the caller sets. [`Limits::DEFAULT`] has the default of
/// each one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The controller of the path. Both controllers pace the admitted bytes.
    pub congestion_control: CongestionControl,
    /// The maximum number of separate side-flow packet number spaces. Zero disables side-flow admission.
    pub side_flows_max: u16,
    /// The time with no activity after which the connection ends, or `None` for no limit of this
    /// end. The connection uses the smaller of this time and the time of the peer, and at least
    /// three probe timeouts (RFC 9000, section 10.1).
    pub idle_timeout: Option<Duration>,
    /// The time from the start of the connection to a confirmed handshake. At this deadline the
    /// connection ends with [`Kind::Deadline`].
    pub handshake_timeout: Duration,
    /// The largest datagram that this end sends: 1,200 to 65,527 bytes. A datagram that carries an
    /// ack-eliciting Initial packet or a client Initial has at least 1,200 bytes (RFC 9000, section 14.1).
    pub datagram_bytes_max: usize,
    /// The bytes of the connection ID that this end chooses for itself: 0 to 20.
    pub cid_bytes: usize,
    /// The most packets that one 1-RTT key seals, at least 2. Then this end updates its keys
    /// (RFC 9001, section 6). The connection uses the smaller of this limit and the
    /// confidentiality limit of its suite, so `u64::MAX` gives the limit of the suite.
    pub key_packets_max: u64,
    /// The stream bytes, of each stream together, that the consumers of this end hold at one
    /// time: the flow-control window of the connection. The peer gets more credit only for the
    /// bytes that [`Connection::release`] gives back.
    pub data_bytes_max: u64,
    /// The bytes of one stream that its consumer holds at one time: the flow-control window of
    /// each stream. A consumer that does not release holds back only its own stream, while this
    /// window is smaller than the window of the connection.
    pub stream_bytes_max: u64,
    /// The bidirectional streams that the peer has open at one time. A stream stays open until
    /// [`Connection::close_stream`].
    pub streams_bidi_max: u64,
    /// The unidirectional streams that the peer has open at one time.
    pub streams_uni_max: u64,
    /// The bytes of the pages that hold stream data that arrived out of order, for each stream
    /// together. A page has 4 KiB and covers a fixed range of its stream, so a piece with no
    /// neighbor counts as one page. The engine does not take a packet whose data needs more: it
    /// sends no acknowledgement for it, the peer sends its data again, and
    /// [`Connection::reassembly_refused`] counts it. A bound of the window of the connection and
    /// two pages for each stream refuses nothing that the windows admit.
    pub reassembly_bytes_max: u64,
    /// The bytes of unreliable datagrams (RFC 9221) that wait to go out at one time, or `None`
    /// for a connection that sends and takes none.
    pub unreliable_bytes_max: Option<u32>,
    /// The sum of the lengths of stream regions this end can retain for sending and retransmission.
    /// An ACK of the whole region or a stream reset returns its allowance.
    pub send_bytes_max: u64,
    /// The packet rate used to size duplicate detection, in packets per second.
    pub packets_per_second: u32,
    /// The time a packet can arrive out of order at that rate.
    pub reordering_time: Duration,
    /// The work of one call: the received bytes and the frames that it reads, and the rustls
    /// calls that it makes, each counted as a frame.
    pub turn: TurnLimits,
}

impl Limits {
    /// An idle timeout of 30 s, a handshake timeout of 10 s, datagrams of at most 1,200 bytes,
    /// connection IDs of 8 bytes, the key limit of the suite, and 1 MiB and 4,096 frames for each
    /// call. A window of 4 MiB for the connection and of 1 MiB for each stream, 100 streams of the
    /// peer in each direction, 6 MiB for data out of order, which the windows never reach, and no
    /// unreliable datagrams. The path uses CUBIC. Side-flow admission is off. Send regions share 4 MiB. Duplicate detection covers 100,000 packets/s for 100 ms.
    pub const DEFAULT: Self = Self {
        congestion_control: CongestionControl::Cubic,
        side_flows_max: 0,
        idle_timeout: Some(Duration::from_secs(30)),
        handshake_timeout: Duration::from_secs(10),
        datagram_bytes_max: DATAGRAM_MIN,
        cid_bytes: 8,
        key_packets_max: u64::MAX,
        data_bytes_max: 4 << 20,
        stream_bytes_max: 1 << 20,
        streams_bidi_max: 100,
        streams_uni_max: 100,
        reassembly_bytes_max: 6 << 20,
        send_bytes_max: 4 << 20,
        packets_per_second: 100_000,
        reordering_time: Duration::from_millis(100),
        unreliable_bytes_max: None,
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
/// length of up to 4 bytes for the data of one packet.
const CRYPTO_FRAME_HEAD: usize = 1 + 8 + 4;
/// A Handshake header with two maximum-length IDs, the tag, and a transport close with an empty reason.
const COALESCED_ROOM: usize = 1 + 4 + 2 * (1 + ConnectionId::MAX) + 4 + 4 + packet::TAG + 1 + 8 + 8 + 1;
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

#[derive(Clone, Copy)]
enum Alarm {
    Loss(Level),
    Probe(Level),
    SideLoss,
    SideProbe(super::SideFlow),
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
    ranges: Received,
    history: History,
    /// Lost stream and CRYPTO ranges that still need a packet.
    retry: VecDeque<DataRange>,
    probe: bool,
    /// The keys are gone: each later packet of the space drops.
    discarded: bool,
    credit: Credit,
}

impl Space {
    fn new(budget: &Budget, window: u64) -> Self {
        Self {
            keys: None,
            receive: crypto::Receive::new(budget),
            send: crypto::Send::new(budget),
            received: 0,
            next: 0,
            ranges: Received::new(window, budget),
            history: History::new(),
            retry: VecDeque::new(),
            probe: false,
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
    fn discard(&mut self, budget: &Budget, window: u64) {
        *self = Self {
            discarded: true,
            next: self.next,
            ..Self::new(budget, window)
        };
    }

    /// Repackages lost ranges. A shorter packet can carry a prefix and leave the rest queued.
    fn resend(&mut self, streams: &Streams, out: &mut Output<'_, '_>) {
        while let Some(record) = self.retry.front_mut() {
            let (offset, remaining, count) = match *record {
                DataRange::Crypto { offset, len } => {
                    let room = stream::fit(
                        out.room().saturating_sub(1 + super::varint_len(offset).unwrap_or(8)),
                        len,
                    );
                    if room == 0 {
                        break;
                    }
                    let data = self
                        .send
                        .retained(offset, room)
                        .expect("an outstanding CRYPTO range owns its message");
                    if out
                        .track(
                            &Frame::Crypto { offset, data },
                            Record::Range(DataRange::Crypto {
                                offset,
                                len: data.len(),
                            }),
                        )
                        .is_err()
                    {
                        break;
                    }
                    (offset, len, data.len())
                }
                DataRange::Stream {
                    id,
                    region,
                    offset,
                    len,
                    fin,
                } => {
                    let Some(bytes) = streams.retained(id, region, offset, len) else {
                        self.retry.pop_front();
                        continue;
                    };
                    let header = 1
                        + super::varint_len(id.get()).unwrap_or(8)
                        + if offset == 0 {
                            0
                        } else {
                            super::varint_len(offset).unwrap_or(8)
                        };
                    let count = stream::fit(out.room().saturating_sub(header), len);
                    if count == 0 {
                        break;
                    }
                    let fin = fin && count == len;
                    let frame = Frame::Stream {
                        stream: id.get(),
                        offset,
                        data: &bytes[..count],
                        fin,
                    };
                    if out
                        .track(
                            &frame,
                            Record::Range(DataRange::Stream {
                                id,
                                region,
                                offset,
                                len: count,
                                fin,
                            }),
                        )
                        .is_err()
                    {
                        break;
                    }
                    (offset, len, count)
                }
            };
            if count == remaining {
                self.retry.pop_front();
            } else {
                let (DataRange::Stream { offset: start, len, .. } | DataRange::Crypto { offset: start, len }) = record;
                *start = offset + count as u64;
                *len -= count;
                break;
            }
        }
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

/// The code from an authenticated CONNECTION_CLOSE frame of the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClose {
    /// The application protocol supplied this code.
    Application(u64),
    /// The peer closed the QUIC transport.
    Transport {
        /// The transport error code.
        code: ErrorCode,
        /// The frame type that triggered the close, or zero when the peer gave none.
        frame_type: u64,
    },
}

impl PeerClose {
    fn outcome(self) -> Result<(), Error> {
        match self {
            Self::Application(_)
            | Self::Transport {
                code: ErrorCode::NO_ERROR,
                ..
            } => Ok(()),
            Self::Transport {
                code: ErrorCode(code @ CRYPTO_ERROR..=0x1ff),
                ..
            } => {
                let alert = AlertDescription(u8::try_from(code - CRYPTO_ERROR).expect("a TLS alert fits one byte"));
                Err(tls::refused(&rustls::Error::AlertReceived(alert)))
            }
            Self::Transport { .. } => Err(Error::new(
                Kind::Malformed,
                "the peer closed the QUIC connection with a transport error",
            )),
        }
    }
}

/// The length and IP ECN codepoint of one outgoing UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmission {
    /// The initialized prefix of the output buffer.
    pub len: usize,
    /// The codepoint for the host to apply to this datagram.
    pub ecn: Ecn,
}

#[derive(Clone, Copy)]
struct SendAt {
    now: Instant,
    mark: Ecn,
    admitted: bool,
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
    path: Path,
    sides: super::side::Flows,
    window: u64,
    /// Start of the client probe timer when address validation still needs a packet.
    validation_at: Instant,
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
    last_activity: Instant,
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
    peer_close: Option<PeerClose>,
    outcome: Option<Result<(), Error>>,
    /// The packets of the peer that failed authentication, across each key.
    failures: u64,
    /// The capacity that the next rustls call waits for.
    wait: Option<u64>,
    /// Work waits for the next call: a limit of a turn stopped it, or the call gave an event.
    more: bool,
    streams: Streams,
    /// The opened packet whose frames the engine reads, after a frame that gave an event.
    reading: Option<Reading>,
    /// The packets that the engine did not take: it had no room for their stream data.
    refused: u64,
}

/// The frames of an opened packet: its payload, and the offset of the next frame.
struct Reading {
    level: Level,
    payload: Lease,
    at: usize,
    number: u64,
    received_at: Instant,
    ecn: Ecn,
    eliciting: bool,
    first_datagram: Option<usize>,
    accepted: bool,
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
pub(super) const CLOCK: Error = Error::new(
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

/// A packet can be as late as the declared rate times the reordering time. Include the newest packet.
fn receive_window(limits: &Limits) -> Result<u64, Error> {
    let packets = (u128::from(limits.packets_per_second) * limits.reordering_time.as_nanos()).div_ceil(1_000_000_000);
    u64::try_from(packets)
        .ok()
        .filter(|n| (1..(1 << 31) - 1).contains(n))
        .map(|n| n + 1)
        .ok_or(Error::new(
            Kind::Misuse,
            "the QUIC reordering interval must fit a packet number of four bytes",
        ))
}

/// Checks the limits that the caller set.
fn check(limits: &Limits) -> Result<(), Error> {
    if !(DATAGRAM_MIN..=DATAGRAM_MAX).contains(&limits.datagram_bytes_max)
        || limits.cid_bytes > ConnectionId::MAX
        || limits.key_packets_max < 2
        || limits.handshake_timeout.is_zero()
        || limits.turn.bytes == 0
        || limits.turn.frames == 0
        || limits.idle_timeout.is_some_and(|timeout| timeout.is_zero())
        || limits.data_bytes_max.max(limits.stream_bytes_max) > VARINT_MAX
        || limits.streams_bidi_max.max(limits.streams_uni_max) > STREAMS_MAX
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
        let window = receive_window(&limits)?;
        let mut output = budget.credit(0);
        output
            .charge((EVENTS * size_of::<QuicEvent>()) as u64)
            .map_err(|_| OUTPUT_REFUSED)?;
        let mut events = Vec::new();
        events.try_reserve_exact(EVENTS).map_err(|_| OUTPUT_REFUSED)?;
        let idle = limits.idle_timeout;
        if let Some(timeout) = idle {
            after(now, timeout.max(3 * PTO_INITIAL))?;
        }
        let side = if matches!(end, End::Client { .. }) {
            Side::Client
        } else {
            Side::Server
        };
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
            spaces: core::array::from_fn(|_| Space::new(budget, window)),
            path: Path::new(limits.datagram_bytes_max, limits.congestion_control, budget),
            sides: super::side::Flows::new(budget, limits.side_flows_max),
            window,
            validation_at: now,
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
            last_activity: now,
            handshake_deadline: Some(after(now, limits.handshake_timeout)?),
            received: false,
            confirmed: false,
            handshake_done: false,
            ping: false,
            close: None,
            peer_close: None,
            outcome: None,
            failures: 0,
            wait: None,
            more: false,
            streams: Streams::new(
                side,
                stream::Config {
                    data_bytes: limits.data_bytes_max,
                    stream_bytes: limits.stream_bytes_max,
                    streams: [limits.streams_bidi_max, limits.streams_uni_max],
                    reassembly_bytes: limits.reassembly_bytes_max,
                    send_bytes: limits.send_bytes_max,
                    unreliable_bytes: limits.unreliable_bytes_max.map(u64::from),
                },
                budget,
            ),
            reading: None,
            refused: 0,
        })
    }

    /// The transport parameters of this end.
    fn parameters(&self) -> Parameters {
        let server = matches!(self.end, End::Server { .. });
        Parameters {
            original_destination_cid: server.then_some(self.original_cid),
            idle_timeout: self.limits.idle_timeout,
            initial_source_cid: Some(self.local_cid),
            data_bytes_initial: self.limits.data_bytes_max,
            stream_bytes_bidi_local_initial: self.limits.stream_bytes_max,
            stream_bytes_bidi_remote_initial: self.limits.stream_bytes_max,
            stream_bytes_uni_initial: self.limits.stream_bytes_max,
            streams_bidi_initial: self.limits.streams_bidi_max,
            streams_uni_initial: self.limits.streams_uni_max,
            datagram_bytes_max: self
                .limits
                .unreliable_bytes_max
                .map(|_| stream::UNRELIABLE_FRAME_BYTES_MAX),
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

    /// The code the peer sent to close the connection, if its CONNECTION_CLOSE frame arrived.
    pub const fn peer_close(&self) -> Option<PeerClose> {
        self.peer_close
    }

    /// Whether the handshake is confirmed: a server completed it, or a client received
    /// HANDSHAKE_DONE (RFC 9001, section 4.1.2).
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// The round-trip estimate, congestion window, and recovery counters of the current path.
    pub fn recovery(&self) -> RecoveryStats {
        self.path.stats()
    }

    /// Opens a recovery space for a negotiated side flow. The extension owns the wire protocol.
    /// The parent must have confirmed its handshake. Set [`Limits::side_flows_max`] before creating the connection.
    /// A full table or a refused memory charge returns [`Kind::Overload`].
    pub fn open_side_flow(&mut self) -> Result<super::SideFlow, Error> {
        self.live()?;
        if !self.confirmed {
            return Err(Error::new(Kind::Misuse, "a QUIC side flow needs a confirmed parent"));
        }
        self.sides.open()
    }

    /// Admits one complete side datagram for immediate transmission, including headers and its tag.
    /// Apply its returned ECN codepoint. A full window, a pacing deadline, or waiting parent control gives `None`.
    /// Drive the parent at its deadline. [`Event::SideProbe`] identifies a flow that needs fresh feedback from the peer.
    pub fn admit_side(
        &mut self,
        flow: super::SideFlow,
        bytes: usize,
        now: Instant,
    ) -> Result<Option<super::SideDatagram>, Error> {
        self.live()?;
        if bytes == 0 || bytes > self.datagram_bytes() {
            return Err(Error::new(
                Kind::Misuse,
                "the QUIC side datagram length is outside the path limit",
            ));
        }
        self.check_clock(now)?;
        let control = self.spaces.iter().any(|space| space.probe || space.ranges.due)
            || (self.path.room() >= self.datagram_bytes() as u64
                && (self.ping
                    || self.handshake_done
                    || self.streams.control_pending()
                    || self.spaces.iter().any(|space| space.send.pending())));
        self.sides.admit(flow, &mut self.path, bytes as u64, now, control)
    }

    /// Applies the packet ranges and ECN counts from an authenticated side acknowledgement.
    /// The delay uses the parent's ACK delay exponent. An invalid packet range ends this side flow with [`Kind::Malformed`].
    /// The extension keeps the payload and acknowledges its consumer separately.
    pub fn acknowledge_side(&mut self, flow: super::SideFlow, ack: &Ack<'_>, now: Instant) -> Result<(), Error> {
        self.live()?;
        self.check_clock(now)?;
        let limited = self.limited();
        let delay = self.ack_delay(ack.delay);
        self.sides.acknowledge(flow, &mut self.path, ack, delay, now, limited)
    }

    /// Releases the recovery state and outstanding flight of an ended side flow.
    pub fn close_side_flow(&mut self, flow: super::SideFlow) -> Result<(), Error> {
        self.sides.close(flow, &mut self.path)
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

    fn check_clock(&self, now: Instant) -> Result<(), Error> {
        if now.domain() == self.last_activity.domain() {
            Ok(())
        } else {
            Err(CLOCK)
        }
    }

    /// Refuses a call of the application after the connection ended.
    fn live(&self) -> Result<(), Error> {
        match (self.outcome, &self.close) {
            (Some(Err(error)), _) => Err(error),
            (Some(Ok(())), _) => Err(Error::new(Kind::Cancelled, "the QUIC connection closed")),
            (None, Some(close)) => Err(close.error),
            (None, None) => Ok(()),
        }
    }

    /// Opens the next stream of `direction` of this end. Gives `None` when the stream limit of
    /// the peer allows no new stream: [`Event::Openable`] tells when it does.
    ///
    /// Refuses with [`Kind::Misuse`] before the handshake completes, with [`Kind::Overload`] when
    /// the budget cannot pay for the stream, and with the error of a connection that ended.
    pub fn open(&mut self, direction: Direction) -> Result<Option<StreamId>, Error> {
        self.live()?;
        self.streams.open(direction)
    }

    /// Queues `data` without a copy. With `end`, the region ends the stream and can be empty.
    /// Each stream accepts up to [`STREAM_REGIONS_MAX`](super::STREAM_REGIONS_MAX) unsent regions.
    /// [`Event::Sent`] permits the next batch. The engine retains each region until the peer
    /// acknowledges its bytes or the stream resets. [`Event::Acknowledged`] reports the acknowledged prefix.
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open, only receives, sent its end, or
    /// holds its most regions, and when `data` is empty with no `end`. Refuses with
    /// [`Kind::Cancelled`] after the peer stopped the stream, and with [`Kind::Overload`] when
    /// the budget or [`Limits::send_bytes_max`] cannot admit the region.
    pub fn send(&mut self, stream: StreamId, data: Lease, end: bool) -> Result<(), Error> {
        self.live()?;
        self.streams.send(stream, data, end)
    }

    /// Ends the send direction of `stream` early, with the error code `code` of the application
    /// protocol: the regions that wait drop, and the peer gets a RESET_STREAM frame.
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open, only receives, or was reset
    /// before, and when `code` is above 2^62 - 1.
    pub fn reset(&mut self, stream: StreamId, code: u64) -> Result<(), Error> {
        self.live()?;
        self.streams.reset(stream, code)
    }

    /// Ends the receive direction of `stream` early, with the error code `code` of the
    /// application protocol: the bytes that did not go up drop, each later byte drops, and the
    /// peer gets a STOP_SENDING frame.
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open, only sends, or ended its data
    /// before, and when `code` is above 2^62 - 1.
    pub fn stop(&mut self, stream: StreamId, code: u64) -> Result<(), Error> {
        self.live()?;
        self.streams.stop(stream, code)
    }

    /// Releases `bytes` bytes of `stream` that the consumer is done with: bytes of
    /// [`Event::Stream`] that it copied out or dropped. The peer gets their credit back, for the
    /// stream and for the connection, when the free credit reaches the credit that it still has.
    /// No other credit goes to the peer, so it can send at most the windows of the [`Limits`].
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open or only sends, and when its
    /// consumer holds fewer bytes.
    pub fn release(&mut self, stream: StreamId, bytes: u64) -> Result<(), Error> {
        self.live()?;
        self.streams.release(stream, bytes)
    }

    /// Ends the use of `stream` by the application. Each direction of the stream ended before:
    /// the data went up or was given with its end, or the direction was reset or stopped. The
    /// bytes that the consumer still holds count as released. The peer gets the credit for a new
    /// stream only after this call, so the streams that the application works on never pass
    /// [`Limits::streams_bidi_max`] and [`Limits::streams_uni_max`].
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open, or a direction of it is.
    pub fn close_stream(&mut self, stream: StreamId) -> Result<(), Error> {
        self.live()?;
        self.streams.close(stream)
    }

    /// Sets the send priority of `stream`. A new stream has [`Priority::DEFAULT`].
    ///
    /// Refuses with [`Kind::Misuse`] when the stream is not open or only receives, and with
    /// [`Kind::Overload`] when the budget cannot pay for a new urgency.
    pub fn set_priority(&mut self, stream: StreamId, priority: Priority) -> Result<(), Error> {
        self.live()?;
        self.streams.set_priority(stream, priority)
    }

    /// The bytes that a 1-RTT packet of the largest datagram has for its frames: after its
    /// header, with the longest packet number, and before its tag.
    fn frame_room(&self) -> usize {
        self.datagram_bytes()
            .saturating_sub(1 + self.remote_cid.as_bytes().len() + 4 + packet::TAG)
    }

    /// The bytes of the largest unreliable datagram (RFC 9221) that goes out now, or `None` when
    /// the peer takes none or [`Limits::unreliable_bytes_max`] has them off.
    pub fn unreliable_room(&self) -> Option<usize> {
        self.streams.unreliable_room(self.frame_room())
    }

    /// Queues `data` as one unreliable datagram (RFC 9221), with no copy. It goes out one time, in
    /// one packet, before the data of the streams, and no loss sends it again.
    ///
    /// Refuses with [`Kind::Unsupported`] when the peer takes no unreliable datagram or this end
    /// has them off, and with [`Kind::Overload`] when `data` is larger than
    /// [`unreliable_room`](Self::unreliable_room), when the queue holds
    /// [`Limits::unreliable_bytes_max`] bytes, and when the budget cannot pay. A refusal queues
    /// nothing: no datagram drops with no report.
    pub fn send_unreliable(&mut self, data: Lease) -> Result<(), Error> {
        self.live()?;
        self.streams.unreliable(data, self.frame_room())
    }

    /// The packets that this end did not take, because their stream data found no room in
    /// [`Limits::reassembly_bytes_max`] or the budget. Each of them got no acknowledgement, so the
    /// peer sends its frames again.
    pub const fn reassembly_refused(&self) -> u64 {
        self.refused
    }

    /// Opens the packets of `datagrams`, the received region, runs the handshake on their CRYPTO
    /// data, and reads the frames of the streams. A packet that this end cannot open is
    /// discarded. Gives the next event, and stops there: call again with the same region while
    /// the call gives an event or [`Progress::Pending`].
    pub fn receive(&mut self, datagrams: &mut Datagrams, now: Instant) -> (Option<Event>, Turn) {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now) {
            self.outcome = Some(Err(error));
        }
        loop {
            if let Some(event) = self.next_event(&mut work) {
                return (Some(event), self.turn());
            }
            if self.outcome.is_some() || self.close.is_some() {
                break;
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                break;
            }
            let ecn = datagrams.ecn;
            let Some(next) = datagrams.next_packet() else {
                break;
            };
            let Ok(packet) = next else {
                continue;
            };
            if let Err(failure) = self.packet(packet, &mut work, now, ecn) {
                self.fail(failure);
            }
        }
        (None, self.turn())
    }

    /// Runs the timers at `now`, and the work that waits: the events of the streams, the frames
    /// after an event, and the handshake work that a limit of a turn or the budget stopped. Gives
    /// the next event. Call it at the deadline of the last turn, when capacity is free, after the
    /// last [`transmit`](Self::transmit), and again while it gives an event or
    /// [`Progress::Pending`].
    pub fn drive(&mut self, now: Instant) -> (Option<Event>, Turn) {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now) {
            self.outcome = Some(Err(error));
        }
        let event = self.next_event(&mut work);
        (event, self.turn())
    }

    /// Gives the next event of the streams, from the events that wait and then from the frames of
    /// the packet that the engine reads, and else runs the handshake.
    fn next_event(&mut self, work: &mut Work) -> Option<Event> {
        for _ in 0..2 {
            if self.outcome.is_some() || self.close.is_some() {
                return None;
            }
            if let Some(flow) = self.sides.notify_probe.take() {
                self.more = true;
                return Some(Event::SideProbe(flow));
            }
            let event = self
                .streams
                .event()
                .map_or_else(|| self.frames(work), |event| Ok(Some(event)));
            match event {
                Ok(Some(event)) => {
                    self.more = true;
                    return Some(event);
                }
                Ok(None) => {}
                Err(failure) => self.fail(failure),
            }
        }
        if self.outcome.is_none()
            && self.close.is_none()
            && let Err(failure) = self.advance(work)
        {
            self.fail(failure);
        }
        None
    }

    /// The result of a call.
    fn turn(&mut self) -> Turn {
        let deadline = match self.deadline() {
            Ok(at) => at.map(Deadline::at),
            Err(error) => {
                self.outcome = Some(Err(error));
                None
            }
        };
        let progress = match (self.outcome, self.wait) {
            (Some(outcome), _) => Progress::Terminal(outcome),
            (None, Some(units)) => Progress::Blocked(Blocked::Capacity(units)),
            (None, None) if self.more => Progress::Pending,
            (None, None) => Progress::Blocked(Blocked::Input),
        };
        Turn { progress, deadline }
    }

    /// The earliest timer of the connection.
    fn deadline(&self) -> Result<Option<Instant>, Error> {
        if self.outcome.is_some() {
            return Ok(None);
        }
        let previous = self
            .one_rtt
            .as_ref()
            .and_then(|keys| keys.previous.as_ref().map(|(_, until)| *until));
        let handshake = if self.confirmed { None } else { self.handshake_deadline };
        Ok(earlier(
            earlier(self.idle_deadline()?, handshake),
            earlier(
                earlier(previous, self.recovery_timer().map(|(at, _)| at)),
                self.path.pacing_wait,
            ),
        ))
    }

    fn idle_deadline(&self) -> Result<Option<Instant>, Error> {
        self.idle
            .map(|idle| after(self.last_activity, idle.max(3 * self.pto())))
            .transpose()
    }

    /// The loss timer takes priority over a probe in any space (RFC 9002, section 6).
    fn recovery_timer(&self) -> Option<(Instant, Alarm)> {
        let loss = Level::ALL
            .into_iter()
            .filter_map(|l| self.spaces[l as usize].history.loss_time.map(|at| (at, Alarm::Loss(l))))
            .chain(self.sides.deadline().map(|at| (at, Alarm::SideLoss)))
            .min_by_key(|(at, _)| at.as_nanos());
        if loss.is_some() || self.spaces.iter().any(|space| space.probe) {
            return loss;
        }
        let delay = |base: Instant, pto: Duration| {
            let nanos = pto
                .as_nanos()
                .checked_mul(1u128.checked_shl(self.path.backoff)?)?
                .try_into()
                .ok()?;
            base.checked_add(Duration::from_nanos(nanos)).ok()
        };
        let parent = |base, level| {
            let pto = if level == Level::Data {
                self.pto()
            } else {
                self.path.pto(Duration::ZERO)
            };
            delay(base, pto).map(|at| (at, Alarm::Probe(level)))
        };
        Level::ALL
            .into_iter()
            .filter_map(|level| {
                self.spaces[level as usize]
                    .history
                    .pto_start()
                    .filter(|_| level != Level::Data || self.confirmed)
                    .and_then(|base| parent(base, level))
            })
            .chain(
                self.sides
                    .probe_start()
                    .and_then(|(base, flow)| delay(base, self.pto()).map(|at| (at, Alarm::SideProbe(flow)))),
            )
            .min_by_key(|(at, _)| at.as_nanos())
            .or_else(|| {
                if self.validated() {
                    return None;
                }
                let level = if self.spaces[Level::Handshake as usize].keys.is_some() {
                    Level::Handshake
                } else {
                    Level::Initial
                };
                parent(self.validation_at, level)
            })
    }

    fn validated(&self) -> bool {
        self.confirmed
            || matches!(self.end, End::Server { .. })
            || self.spaces[Level::Handshake as usize].history.largest.is_some()
    }

    /// Ends the connection at its idle or handshake deadline, with no packet (RFC 9000, section
    /// 10.1), and drops the old key of the peer at its deadline.
    fn timers(&mut self, now: Instant) -> Result<(), Error> {
        if self.outcome.is_some() {
            return Ok(());
        }
        self.check_clock(now)?;
        if reached(self.path.pacing_wait, now)? {
            self.path.pacing_wait = None;
        }
        if reached(self.idle_deadline()?, now)? {
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
        if let Some((at, alarm)) = self.recovery_timer()
            && reached(Some(at), now)?
        {
            match alarm {
                Alarm::Loss(level) => {
                    self.detect_loss(level, now)?;
                }
                Alarm::SideLoss => self.sides.timers(&mut self.path, now)?,
                Alarm::Probe(level) => {
                    self.spaces[level as usize].probe = true;
                    self.path.backoff = self.path.backoff.saturating_add(1);
                }
                Alarm::SideProbe(flow) => {
                    self.sides.probe(flow, now);
                    self.spaces[Level::Data as usize].probe = true;
                    self.path.backoff = self.path.backoff.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    fn limited(&self) -> bool {
        self.path.room() < self.datagram_bytes() as u64
            || self.sides.waiting()
            || Level::ALL.into_iter().any(|l| self.has_data(l))
    }

    fn ack_delay(&self, encoded: u64) -> Duration {
        self.peer.map_or(Duration::ZERO, |peer| {
            let delay = Duration::from_micros(encoded.saturating_mul(1 << peer.ack_delay_exponent));
            if self.confirmed {
                delay.min(peer.ack_delay_max)
            } else {
                delay
            }
        })
    }

    fn acknowledge(&mut self, level: Level, ack: &Ack<'_>, now: Instant) -> Result<(), Failure> {
        let space = &self.spaces[level as usize];
        if ack.largest >= space.next {
            return Err(Failure::transport(
                ErrorCode::PROTOCOL_VIOLATION,
                if ack.ecn.is_some() { 3 } else { 2 },
                VIOLATION,
            ));
        }
        let mut delay = Duration::ZERO;
        if level == Level::Data {
            if let Some(keys) = &mut self.one_rtt
                && keys.first_sent.is_some_and(|first| ack.largest >= first)
            {
                keys.acknowledged = true;
            }
            delay = self.ack_delay(ack.delay);
        }
        let limited = self.limited();
        self.path.controller.limited(now, limited);
        let space = &mut self.spaces[level as usize];
        let acked = space
            .history
            .ack(ack, &mut self.path, now, delay, |record| match record {
                Record::Range(DataRange::Crypto { offset, len }) => space.send.acknowledged(offset, len),
                other => self.streams.acknowledged(other),
            })?;
        if acked.eliciting {
            space.probe = false;
            self.validation_at = now;
            if self.validated() {
                self.path.backoff = 0;
            }
        }
        let congestion = self.detect_loss(level, now)?;
        self.path.acknowledged(acked, now, limited && !congestion);
        Ok(())
    }

    fn detect_loss(&mut self, level: Level, now: Instant) -> Result<bool, Error> {
        let space = &mut self.spaces[level as usize];
        space.history.detect(&mut self.path, now, |record| {
            match record {
                Record::HandshakeDone => self.handshake_done = true,
                Record::Limit(_) | Record::Control(_, _) => self.streams.lost_control(record),
                Record::Range(range) => {
                    let retry = &mut space.retry;
                    super::reassembly::grow(
                        (retry.len(), retry.capacity(), size_of::<DataRange>()),
                        &mut space.credit,
                        |n| retry.try_reserve_exact(n).is_ok(),
                    )
                    .map_err(|_| recovery::NO_ROOM)?;
                    retry.push_back(range);
                }
            }
            Ok(())
        })
    }

    /// Opens one packet and reads its frames.
    fn packet(
        &mut self,
        packet: packet::Protected<'_>,
        work: &mut Work,
        now: Instant,
        ecn: Ecn,
    ) -> Result<(), Failure> {
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
        let expected = space.ranges.largest().map_or(0, |largest| largest + 1);
        let opened = match level {
            Level::Data => {
                // No 1-RTT packet is read before the handshake completes (RFC 9001, section
                // 5.7): the parameters of the peer, which the frames need, come with it.
                let Some(keys) = self.one_rtt.as_mut().filter(|_| self.peer.is_some()) else {
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
        if self.spaces[level as usize].ranges.seen(number) {
            return Ok(());
        }
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
            && keys.phase == packet.key_phase()
        {
            keys.first_received = Some(keys.first_received.map_or(number, |first| first.min(number)));
        }
        if !server && level == Level::Initial && !self.remote_known {
            self.remote_cid = scid;
            self.remote_known = true;
        }
        // A server drops the Initial keys when a Handshake packet of the client opens (RFC 9001,
        // section 4.9.1).
        if server && level == Level::Handshake && !self.spaces[0].discarded {
            self.discard(Level::Initial);
        }
        self.received = true;
        self.last_activity = now;
        self.reading = Some(Reading {
            level,
            payload: packet.payload(),
            at: 0,
            number,
            received_at: now,
            ecn,
            eliciting: false,
            first_datagram: None,
            accepted: false,
        });
        Ok(())
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

    /// Reads the frames of the opened packet, up to a frame that gives an event: the rest waits
    /// for the next call. A frame whose stream data or state finds no room ends the packet, which
    /// is then not received.
    fn frames(&mut self, work: &mut Work) -> Result<Option<Event>, Failure> {
        let Some(mut reading) = self.reading.take() else {
            return Ok(None);
        };
        let server = matches!(self.end, End::Server { .. });
        let (level, handshake_level) = (reading.level, reading.level != Level::Data);
        loop {
            let bytes = reading.payload.bytes().get(reading.at..).unwrap_or_default();
            if bytes.is_empty() {
                if !reading.accepted && !self.spaces[level as usize].discarded {
                    self.spaces[level as usize].ranges.accept(
                        reading.number,
                        reading.received_at,
                        reading.eliciting,
                        reading.ecn,
                    )?;
                    if let Some(at) = reading.first_datagram {
                        reading.at = at;
                        reading.accepted = true;
                        continue;
                    }
                }
                return Ok(None);
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                self.reading = Some(reading);
                return Ok(None);
            }
            let start = reading.at;
            let (frame, len) =
                Frame::parse(bytes).map_err(|error| Failure::transport(error.code, error.frame_type, VIOLATION))?;
            reading.at += len;
            work.add(0, 1);
            // The data of a STREAM or DATAGRAM frame is the end of its frame.
            let data = |data: &[u8]| reading.at - data.len()..reading.at;
            if reading.accepted && !matches!(frame, Frame::Datagram { .. }) {
                continue;
            }
            reading.eliciting |= !matches!(
                frame,
                Frame::Padding { .. } | Frame::Ack(_) | Frame::ConnectionClose { .. }
            );
            let taken = match frame {
                Frame::Padding { .. } | Frame::Ping => Ok(None),
                Frame::Ack(ack) => {
                    self.acknowledge(level, &ack, reading.received_at)?;
                    Ok(None)
                }
                Frame::Crypto { offset, data } => {
                    self.crypto(level, offset, data)?;
                    Ok(None)
                }
                // A close of the application is only in 1-RTT packets (RFC 9000, section 12.4).
                Frame::ConnectionClose { frame_type: None, .. } if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1d, VIOLATION));
                }
                Frame::ConnectionClose { code, frame_type, .. } => {
                    let close = match frame_type {
                        Some(frame_type) => PeerClose::Transport {
                            code: ErrorCode(code),
                            frame_type,
                        },
                        None => PeerClose::Application(code),
                    };
                    self.peer_close = Some(close);
                    self.outcome = Some(close.outcome());
                    return Ok(None);
                }
                Frame::HandshakeDone if !server && !handshake_level => {
                    self.confirm();
                    Ok(None)
                }
                Frame::HandshakeDone | Frame::NewToken { .. } if server || handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1e, VIOLATION));
                }
                // Only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE are in Initial and
                // Handshake packets (RFC 9000, section 12.4).
                _ if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0, VIOLATION));
                }
                Frame::Stream {
                    stream,
                    offset,
                    data: bytes,
                    fin,
                } => self
                    .streams
                    .stream_in(stream, (offset, fin), data(bytes), &reading.payload),
                Frame::ResetStream {
                    stream,
                    code,
                    final_size,
                } => self.streams.reset_in(stream, code, final_size).map(|()| None),
                Frame::StopSending { stream, code } => self.streams.stop_in(stream, code).map(|()| None),
                Frame::MaxData { max } => {
                    self.streams.max_data_in(max);
                    Ok(None)
                }
                Frame::MaxStreamData { stream, max } => self.streams.max_stream_data_in(stream, max).map(|()| None),
                Frame::MaxStreams { direction, max } => {
                    self.streams.max_streams_in(direction, max);
                    Ok(None)
                }
                Frame::StreamDataBlocked { stream, .. } => self.streams.blocked_in(stream).map(|()| None),
                Frame::Datagram { data: bytes } => {
                    self.streams
                        .unreliable_in(len, data(bytes), &reading.payload)
                        .map(|event| {
                            if reading.accepted {
                                event
                            } else {
                                reading.first_datagram.get_or_insert(start);
                                None
                            }
                        })
                }
                // The frames of paths and connection IDs come with N304 and N307. The other
                // BLOCKED frames and a NEW_TOKEN frame change nothing.
                _ => Ok(None),
            };
            match taken {
                Ok(None) => {}
                Ok(Some(event)) => {
                    self.reading = Some(reading);
                    return Ok(Some(event));
                }
                Err(Stop::Violation(code, frame_type)) => {
                    return Err(Failure::transport(code, frame_type, VIOLATION));
                }
                Err(Stop::Refused(_)) => {
                    self.refused = self.refused.saturating_add(1);
                    return Ok(None);
                }
            }
        }
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
        self.discard(Level::Handshake);
    }

    fn discard(&mut self, level: Level) {
        let space = &mut self.spaces[level as usize];
        space.history.discard(&mut self.path);
        self.path.backoff = 0;
        space.discard(&self.budget, self.window);
    }

    /// The probe timeout of the data space, including the peer's maximum ACK delay.
    fn pto(&self) -> Duration {
        self.path.pto(
            self.peer
                .filter(|_| self.confirmed)
                .map_or(Duration::ZERO, |peer| peer.ack_delay_max),
        )
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
        self.streams.peer(&parameters);
        self.path.ack_delay_max = parameters.ack_delay_max;
        self.path.datagram_limit(self.datagram_bytes());
        self.idle = match (self.limits.idle_timeout, parameters.idle_timeout) {
            (Some(local), Some(remote)) => Some(local.min(remote)),
            (local, remote) => local.or(remote),
        };
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
        self.reading = None;
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

    /// Builds an unmarked datagram at the start of `out`. Gives its length, or `None` when no datagram can leave now. Call it until it gives `None`. The datagram has at most
    /// [`Limits::datagram_bytes_max`] bytes. A client Initial or an ack-eliciting server Initial needs at least 1,200.
    ///
    /// Refuses with [`Kind::Misuse`] when `out` has fewer bytes than
    /// [`Limits::datagram_bytes_max`].
    pub fn transmit(&mut self, out: &mut [u8], now: Instant) -> Result<Option<usize>, Error> {
        self.transmit_mark(out, now, Ecn::NotEct)
    }

    /// Builds a datagram for a host that can set its IP ECN codepoint. Apply the returned mark to that datagram.
    /// Supply the received mark with [`Datagrams::with_ecn`]. A host without send metadata uses [`transmit`](Self::transmit).
    /// After `None`, call [`drive`](Self::drive) to get the next deadline.
    pub fn transmit_ecn(&mut self, out: &mut [u8], now: Instant) -> Result<Option<Transmission>, Error> {
        self.check_clock(now)?;
        let ecn = self.path.mark(now);
        let len = self.transmit_mark(out, now, ecn)?;
        if len.is_some() {
            self.path.marked(ecn, now);
        }
        Ok(len.map(|len| Transmission { len, ecn }))
    }

    fn transmit_mark(&mut self, out: &mut [u8], now: Instant, mark: Ecn) -> Result<Option<usize>, Error> {
        self.check_clock(now)?;
        if out.len() < self.limits.datagram_bytes_max {
            return Err(Error::new(
                Kind::Misuse,
                "a QUIC datagram needs an output of the bytes of its limit",
            ));
        }
        if self.outcome.is_some() {
            return Ok(None);
        }
        let out = &mut out[..self.datagram_bytes()];
        let built = match self.close {
            Some(close) => self.closing(out, close, now, mark),
            None => self.datagram(out, now, mark),
        };
        let Err(failure) = built else {
            return Ok(built.unwrap_or_default());
        };
        self.fail(failure);
        match self.close {
            Some(close) => Ok(self.closing(out, close, now, mark).unwrap_or_default()),
            None => Ok(None),
        }
    }

    /// The bytes of the largest datagram that this end sends: its limit, and the limit of the
    /// peer.
    fn datagram_bytes(&self) -> usize {
        let peer = self.peer.map_or(usize::MAX, |peer| {
            usize::try_from(peer.udp_payload_bytes_max).unwrap_or(usize::MAX)
        });
        self.limits.datagram_bytes_max.min(peer)
    }

    /// Whether an ack-eliciting frame waits at this level.
    fn has_data(&self, level: Level) -> bool {
        let space = &self.spaces[level as usize];
        space.send.pending()
            || !space.retry.is_empty()
            || (level == Level::Data && (self.handshake_done || self.ping || self.streams.pending()))
    }

    fn wants(&self, level: Level, admitted: bool) -> bool {
        let space = &self.spaces[level as usize];
        let keyed = if level == Level::Data {
            self.one_rtt.is_some()
        } else {
            space.keys.is_some()
        };
        keyed && (space.ranges.due || space.probe || (self.has_data(level) && admitted))
    }

    /// Builds a datagram of the packets that wait, at most one for each level.
    fn datagram(&mut self, out: &mut [u8], now: Instant, mark: Ecn) -> Result<Option<usize>, Failure> {
        let data = Level::ALL.into_iter().any(|level| self.has_data(level));
        let admitted = data && self.path.paced(out.len() as u64, now)?;
        self.path
            .controller
            .limited(now, data || self.sides.waiting() || self.path.room() < out.len() as u64);
        let send = SendAt { now, mark, admitted };
        let wanted = Level::ALL.map(|level| self.wants(level, admitted));
        let Some(last) = wanted.iter().rposition(|&wanted| wanted) else {
            return Ok(None);
        };
        let initial = wanted[0]
            && (matches!(self.end, End::Client { .. }) || self.has_data(Level::Initial) || self.spaces[0].probe);
        let mut at = 0;
        let mut handshake_sent = false;
        for level in Level::ALL {
            if !wanted[level as usize] {
                continue;
            }
            let pad = initial.then_some((DATAGRAM_MIN.saturating_sub(at), Level::ALL[last]));
            let Some(len) = self.packet_out(level, &mut out[at..], pad, None, send)? else {
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
            self.discard(Level::Initial);
        }
        Ok(Some(at))
    }

    /// Builds a datagram with a CONNECTION_CLOSE frame in each level that has keys, and then ends
    /// the connection.
    fn closing(&mut self, out: &mut [u8], close: Close, now: Instant, mark: Ecn) -> Result<Option<usize>, Failure> {
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
            let pad = last
                .filter(|_| keyed[0])
                .map(|i| (DATAGRAM_MIN.saturating_sub(at), Level::ALL[i]));
            match self.packet_out(
                level,
                &mut out[at..],
                pad,
                Some(close),
                SendAt {
                    now,
                    mark,
                    admitted: false,
                },
            ) {
                Ok(Some(len)) => at += len,
                _ => break,
            }
        }
        self.close = None;
        self.outcome = Some(Err(close.error));
        Ok((at > 0).then_some(at))
    }

    /// Builds one packet of `level` at the start of `out`: a CONNECTION_CLOSE frame for `close`,
    /// or the HANDSHAKE_DONE and CRYPTO frames and the frames of the streams that wait. Pads it
    /// to `pad` bytes. Gives its length, or `None` when `out` has no room for a packet with a
    /// frame.
    fn packet_out(
        &mut self,
        level: Level,
        out: &mut [u8],
        pad: Option<(usize, Level)>,
        close: Option<Close>,
        SendAt { now, mark, admitted }: SendAt,
    ) -> Result<Option<usize>, Failure> {
        let space = &self.spaces[level as usize];
        let number = space.next;
        let number_len = packet::number_len(number, space.history.largest)
            .filter(|_| number <= VARINT_MAX)
            .ok_or(Failure::local(Error::new(
                Kind::Overload,
                "the packet numbers of a QUIC space passed their limit",
            )))?;
        let number_len = if level == Level::Data {
            number_len.max(packet::number_len(self.window - 1, None).unwrap_or(4))
        } else {
            number_len
        };
        let admitted = space.probe || (admitted && self.path.room() >= out.len() as u64);
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
        let Ok(builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let full = |_: packet::BuildError| {
            Failure::local(Error::new(Kind::Unsupported, "a QUIC frame did not fit its packet"))
        };
        let mut output = Output::new(builder, &self.budget);
        let room = output.room();
        let mut eliciting = false;
        if let Some(close) = close {
            let frame = Frame::ConnectionClose {
                code: close.code,
                frame_type: Some(close.frame_type),
                reason: &[],
            };
            if output.builder.frame(&frame).is_err() {
                return Ok(None);
            }
        } else {
            let space = &mut self.spaces[level as usize];
            space.ranges.write(&mut output.builder, now)?;
            let after_ack = output.room();
            if admitted {
                if level == Level::Data
                    && self.handshake_done
                    && output.track(&Frame::HandshakeDone, Record::HandshakeDone).is_ok()
                {
                    self.handshake_done = false;
                }
                if level == Level::Data && self.ping && output.builder.frame(&Frame::Ping).is_ok() {
                    self.ping = false;
                }
                space.resend(&self.streams, &mut output);
                let send = &mut space.send;
                while output.room() > CRYPTO_FRAME_HEAD
                    && let Some((offset, data)) = send.next(output.room() - CRYPTO_FRAME_HEAD)
                {
                    let len = data.len();
                    output
                        .track(
                            &Frame::Crypto { offset, data },
                            Record::Range(DataRange::Crypto { offset, len }),
                        )
                        .map_err(full)?;
                    send.sent(len);
                }
                if level == Level::Data {
                    self.streams.write(&mut output);
                }
                if space.probe && output.room() == after_ack {
                    let _fits = output.builder.frame(&Frame::Ping);
                }
            }
            eliciting = after_ack != output.room();
            if output.refused {
                return Err(Failure::local(recovery::NO_ROOM));
            }
            // A packet that took no frame, because none fits, waits for the next datagram.
            if output.room() == room && pad.is_none_or(|(min, last)| min == 0 || level != last) {
                return Ok(None);
            }
        }
        let mut builder = output.builder;
        let before_pad = builder.room();
        if let Some((minimum, last)) = pad
            && (level == last || before_pad < COALESCED_ROOM)
        {
            builder.pad_to(minimum).map_err(full)?;
        }
        let in_flight = eliciting || builder.room() < before_pad;
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
        self.spaces[level as usize].history.ect_sent += u64::from(mark == Ecn::Ect0);
        // A later bare ACK can be the largest number in an ACK that also covers a live elicitor.
        if close.is_none() && (in_flight || self.spaces[level as usize].history.pto_start().is_some()) {
            let bytes = if in_flight { len as u64 } else { 0 };
            let space = &mut self.spaces[level as usize];
            space.history.insert(
                &mut self.path,
                Sent {
                    mark,
                    number,
                    time: now,
                    bytes,
                    eliciting,
                    records: output.records,
                },
            )?;
            if eliciting {
                if core::mem::take(&mut space.probe) {
                    self.path.probes = self.path.probes.saturating_add(1);
                }
                if core::mem::take(&mut self.received) {
                    self.last_activity = now;
                }
            }
        } else {
            self.path.untracked();
        }
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
        let Some(keys) = &self.one_rtt else {
            return Ok(());
        };
        if keys.sealed < keys.limit {
            return Ok(());
        }
        if self.confirmed && (!keys.updated || keys.acknowledged) {
            let until = after(now, 3 * self.pto())?;
            self.one_rtt.as_mut().expect("this space has 1-RTT keys").update(until);
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

fn client(handshake: ClientHandshake) -> Tls {
    Tls::Client(handshake)
}

fn server(handshake: ServerHandshake) -> Tls {
    Tls::Server(handshake)
}
