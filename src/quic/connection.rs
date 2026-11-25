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
//!
//! The host gives the [`Path`] of each received region, and sends each datagram on the path that
//! its [`Transmission`] names. A server follows a peer that moves to a new address, and validates
//! that address before it sends more than three times the bytes that came from it. A client moves
//! with [`Connection::migrate`]. [`Connection::close`] ends the connection with a code of the
//! application. An end that closes, or that reads the close of its peer, gives [`Event::Closed`]
//! at once and its terminal outcome three probe timeouts later (RFC 9000, section 10.2).

use core::cmp::Ordering;
use core::fmt;
use core::mem::size_of;
use core::net::SocketAddr;
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Credit, Permit};
use rstypes::time::{Deadline, Instant};
use rustls::error::AlertDescription;
use rustls::pki_types::ServerName;
use rustls::quic::{
    ClientHandshake, DirectionalKeys, KeyChange, PacketKey, PacketKeySet, QuicEvent, Secrets, ServerHandshake,
    Version as TlsVersion,
};
use rustls::{ClientSide, ServerSide};

use super::cid::{Id, Ids};
use super::crypto::{self, Refused};
use super::endpoint::{self, Issuer};
use super::frame::{Ack, Direction, Frame, STREAMS_MAX};
use super::packet::{self, Builder, Datagrams, Header, Kind as PacketKind, OpenError, Outgoing, Side};
use super::params::{Migration, Parameters, Sender};
use super::path::{Path, Validation};
use super::recovery::{self, DataRange, History, Output, PathState, Paths, Received, Record, RecoveryStats, Sent};
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
    /// The largest datagram that this end sends: 1,200 to 65,527 bytes. Each path starts at 1,200
    /// bytes. Above 1,200, the connection searches each validated path for the largest size that
    /// the path carries, up to this limit and the limit of the peer (RFC 8899). The search sends at
    /// most three probes of each size, and the loss of a probe is no sign of congestion. A probe
    /// has at most two times the bytes that the path carried before it. After three probe
    /// timeouts in a row that lose only datagrams above 1,200 bytes, the path returns to 1,200
    /// bytes. Set a limit above 1,200 only on a host that forbids the fragmentation of its
    /// datagrams. A datagram that carries an ack-eliciting Initial packet or a client Initial has
    /// at least 1,200 bytes (RFC 9000, section 14.1).
    pub datagram_bytes_max: usize,
    /// The bytes of the connection ID that this end chooses for itself: 0 to 20.
    pub cid_bytes: usize,
    /// The most packets that one 1-RTT key seals, at least 2. The last of them is kept for a
    /// CONNECTION_CLOSE frame. Thus this end updates its keys one packet before the limit (RFC
    /// 9001, sections 6 and 6.6). The connection uses the smaller of this limit and the
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
    /// An idle timeout of 30 s, a handshake timeout of 10 s, datagrams of 1,200 bytes with no search,
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

/// The smallest datagram that carries an Initial packet, and the size that each path carries with
/// no search (RFC 9000, section 14).
pub(super) const DATAGRAM_MIN: usize = 1_200;
/// A token of this size leaves room for a CRYPTO frame in a minimum-sized Initial.
const CLIENT_TOKEN_MAX: usize = 1024;
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
/// The addresses of the peer that a stateless reset can come from, each with the connection ID
/// that this end sent to it. They are the active path, the path that the connection left, and one
/// path that the peer probes.
pub(super) const RESET_ROUTES: usize = 3;
/// The bytes of the datagram of a close that has a closing period: one 1-RTT packet. It has the
/// longest connection ID and packet number, a CONNECTION_CLOSE frame of the transport with an
/// empty reason, and the tag.
const CLOSE_BYTES_MAX: usize = 1 + ConnectionId::MAX + 4 + (1 + 8 + 8 + 1) + packet::TAG;

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
        service: [u8; 32],
    },
    Server {
        config: Arc<rustls::ServerConfig>,
        /// The encoded transport parameters, until rustls takes them.
        parameters: Option<Vec<u8>>,
    },
}

/// The CONNECTION_CLOSE frame of an end that closes.
#[derive(Clone, Copy, Debug)]
struct Close {
    code: u64,
    /// The type of the frame that caused a close of the transport, or `None` for a close of the
    /// application.
    frame_type: Option<u64>,
}

impl Close {
    /// The frame for a packet of `level`. A close of the application shows its code only in a
    /// 1-RTT packet (RFC 9000, section 10.2.3).
    const fn frame(self, level: Level) -> Frame<'static> {
        let (code, frame_type) = match (self.frame_type, level) {
            (None, Level::Initial | Level::Handshake) => (ErrorCode::APPLICATION_ERROR.0, Some(0)),
            (frame_type, _) => (self.code, frame_type),
        };
        Frame::ConnectionClose {
            code,
            frame_type,
            reason: &[],
        }
    }
}

/// The end of a connection, before its terminal outcome (RFC 9000, section 10.2): a closing end
/// sends its CONNECTION_CLOSE frame, and a draining end sends nothing.
#[derive(Clone, Copy, Debug)]
struct Ending {
    /// The terminal outcome of the connection.
    outcome: Result<(), Error>,
    /// The frame of a closing end. `None` for a draining end.
    close: Option<Close>,
    /// A copy of the frame waits to go out.
    send: bool,
    /// The datagrams of the peer since the end. A copy of the frame answers datagram 1, 2, 4, 8,
    /// and so on, so a peer that lost the frame gets it again at a bounded rate.
    heard: u64,
    /// The application did not take [`Event::Closed`].
    notify: bool,
    /// The end of the closing or draining period. `None` before the handshake is confirmed: the
    /// connection then ends when its frame is out, so its handshake slot is free at once.
    until: Option<Instant>,
    /// The protected datagram of the frame, and its bytes, after it went out. Each copy is this
    /// datagram, so no key seals the frame again (RFC 9000, section 10.2.1).
    sealed: Option<([u8; CLOSE_BYTES_MAX], usize)>,
}

/// The answer to a PATH_CHALLENGE frame, which waits to go out on the path of the challenge
/// (RFC 9000, section 8.2.2).
#[derive(Clone, Copy)]
struct Answer {
    path: Path,
    data: [u8; 8],
    /// The address of the peer on that path had its validation when the challenge came, and an
    /// address keeps it. Else the credit of the path pays for the datagram of the answer when it
    /// goes out.
    validated: bool,
}

/// The code from an authenticated CONNECTION_CLOSE frame of the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClose {
    /// A stateless reset matched the token for a destination this connection used.
    StatelessReset,
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
            Self::StatelessReset => Err(Error::new(Kind::Uncertain, "the peer reset the QUIC connection")),
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

/// The length, the IP ECN codepoint, and the path of one outgoing UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmission {
    /// The initialized prefix of the output buffer.
    pub len: usize,
    /// The codepoint for the host to apply to this datagram.
    pub ecn: Ecn,
    /// Send the datagram from `path.local` to `path.peer`.
    pub path: Path,
}

#[derive(Clone, Copy)]
struct SendAt {
    now: Instant,
    mark: Ecn,
    admitted: bool,
}

/// The caller consumes this address proof on its next connection to the same service.
pub struct AddressToken {
    bytes: Vec<u8>,
    service: [u8; 32],
    _storage: Permit,
}

impl fmt::Debug for AddressToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressToken").finish_non_exhaustive()
    }
}

impl AddressToken {
    fn copy(bytes: &[u8], service: [u8; 32], budget: &Budget) -> Result<Self, Error> {
        let storage = budget.reserve(bytes.len() as u64).map_err(|_| endpoint::NO_ROOM)?;
        let mut data = Vec::new();
        data.try_reserve_exact(bytes.len()).map_err(|_| endpoint::NO_ROOM)?;
        data.extend_from_slice(bytes);
        Ok(Self {
            bytes: data,
            service,
            _storage: storage,
        })
    }
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
    paths: Paths,
    /// The answers to the PATH_CHALLENGE frames of the peer that wait to go out: one for a
    /// challenge on the path of the connection, and one for a challenge on another path. A later
    /// challenge of the same kind replaces the answer, and the peer then sends its challenge again.
    answers: [Option<Answer>; 2],
    /// The room for frames that the queue of unreliable datagrams follows.
    fitted: usize,
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
    initial_local: ConnectionId,
    /// The destination connection ID of the first Initial packet of the client.
    original_cid: ConnectionId,
    retry_cid: Option<ConnectionId>,
    initial_token: Option<AddressToken>,
    future_token: Option<AddressToken>,
    pub(super) ids: Ids,
    issuer: Option<Issuer>,
    random: &'static dyn rustls::crypto::SecureRandom,
    reset_mask: rscrypto::SecretBytes<32>,
    /// The address and the connection ID of the peer of the newest datagrams of this end, the
    /// newest first. A stateless reset from one of these addresses is valid with the token of its
    /// connection ID (RFC 9000, section 10.3.1).
    used: [Option<(SocketAddr, ConnectionId)>; RESET_ROUTES],
    /// The peer source ID in Initial and Handshake packets. Rotation only affects the data path.
    initial_peer: Option<ConnectionId>,
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
    /// The largest number of a 1-RTT packet of the peer that was not a probe. Only a packet above
    /// it shows that the peer moved (RFC 9000, section 9.3).
    non_probing: Option<u64>,
    /// The handshake is confirmed (RFC 9001, section 4.1.2).
    confirmed: bool,
    /// A server owes a HANDSHAKE_DONE frame.
    handshake_done: bool,
    /// A PING frame waits for the next 1-RTT packet.
    ping: bool,
    ending: Option<Ending>,
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
    destination: ConnectionId,
    /// The path of the datagram of the packet.
    path: Path,
    /// Each frame so far only probes a path (RFC 9000, section 9.1).
    probing: bool,
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
const NO_PATH: Error = Error::new(
    Kind::Deadline,
    "the QUIC path gave no answer, and the peer gave no connection ID for the path before it",
);
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
pub(super) fn check(limits: &Limits) -> Result<(), Error> {
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

/// The data of a PATH_CHALLENGE frame, from the source of a connection. Each frame has its own
/// data (RFC 9000, section 8.2.1).
fn challenge(
    stream: Option<&rscrypto_rustls::replay::Stream>,
    random: &dyn rustls::crypto::SecureRandom,
) -> Result<[u8; 8], Error> {
    let mut data = [0; 8];
    tls::scoped(stream, || random.fill(&mut data)).map_err(|_| endpoint::RANDOM)?;
    Ok(data)
}

impl Connection {
    /// Makes the client end of a connection to the server `name`, a DNS name or an IP address, on
    /// `path`. The first Initial packet waits for [`transmit`](Self::transmit).
    ///
    /// Refuses with [`Kind::Misuse`] when `name` is not valid, `config` offers no ALPN name
    /// (RFC 9001, section 8.1), or `limits` cannot work, and with [`Kind::Overload`] when
    /// `budget` cannot pay.
    pub fn client(
        config: &tls::ClientConfig,
        name: &str,
        path: Path,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        check(&limits)?;
        if config.protocols == 0 {
            return Err(Error::new(Kind::Misuse, "a QUIC client offers no ALPN name"));
        }
        let input_name = name;
        let name = ServerName::try_from(input_name)
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
                    service: rscrypto::Sha256::digest(input_name.as_bytes()),
                },
                Tls::Failed,
            ),
            (stream, random, held, config.cost, Arc::clone(&config.own)),
            (local_cid, original_cid, original_cid),
            path,
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

    /// Makes the server end of the connection that the client starts on `path` with the Initial
    /// packet of `initial`, the header of its first packet. Give that packet to
    /// [`receive`](Self::receive) next. Use [`super::Endpoint`] for a listener with shared routing,
    /// address proofs, stateless reset, and handshake admission. This constructor serves one externally routed connection.
    ///
    /// Refuses with [`Kind::Misuse`] when `initial` is not the header of an Initial packet,
    /// `config` accepts no ALPN name, or `limits` cannot work, and with [`Kind::Overload`] when
    /// `budget` cannot pay.
    pub fn server(
        config: &tls::ServerConfig,
        initial: &Header,
        path: Path,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        Self::server_admitted(config, initial, None, path, limits, budget, now)
    }

    pub(super) fn server_admitted(
        config: &tls::ServerConfig,
        initial: &Header,
        admission: Option<(Issuer, Option<endpoint::Proof>)>,
        path: Path,
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
        let local_cid = tls::scoped(stream.as_ref(), || match &admission {
            Some((issuer, _)) => issuer.issue(random),
            None => random_cid(random, limits.cid_bytes),
        })?;
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
            (stream, random, held, config.cost, Arc::clone(&config.own)),
            (local_cid, scid, dcid),
            path,
            limits,
            budget,
            now,
        )?;
        if let Some((issuer, proof)) = admission {
            connection.issuer = Some(issuer);
            if proof.is_some() {
                connection.paths.active.amplification_credit = None;
            }
            if let Some(endpoint::Proof::Retry { original, retry }) = proof {
                connection.original_cid = original;
                connection.retry_cid = Some(retry);
            }
        }
        connection.initial_peer = Some(scid);
        connection.spaces[Level::Initial as usize].install(|| packet::initial_keys(&dcid, Side::Server))?;
        let parameters = encode(&connection.parameters(), &mut connection.kept)?;
        if let End::Server { parameters: slot, .. } = &mut connection.end {
            *slot = Some(parameters);
        }
        Ok(connection)
    }

    fn new(
        (end, tls): (End, Tls),
        (stream, random, held, cost, own): (
            Option<rscrypto_rustls::replay::Stream>,
            &'static dyn rustls::crypto::SecureRandom,
            Held,
            Cost,
            Arc<Owns>,
        ),
        (local_cid, remote_cid, original_cid): (ConnectionId, ConnectionId, ConnectionId),
        path: Path,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        let window = receive_window(&limits)?;
        let reset_mask = tls::scoped(stream.as_ref(), || {
            rscrypto::SecretBytes::try_fill_with(|b| random.fill(b))
        })
        .map_err(|_| endpoint::RANDOM)?;
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
        let mut active = PathState::new(path, remote_cid, limits.datagram_bytes_max, limits.congestion_control);
        active.amplification_credit = (side == Side::Server).then_some(0);
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
            paths: Paths::new(active, budget),
            answers: [None; 2],
            fitted: usize::MAX,
            sides: super::side::Flows::new(budget, limits.side_flows_max),
            window,
            validation_at: now,
            one_rtt: None,
            write: Level::Initial,
            read: Level::Initial,
            local_cid,
            original_cid,
            retry_cid: None,
            initial_token: None,
            future_token: None,
            ids: Ids::new(local_cid),
            issuer: None,
            random,
            reset_mask,
            used: [None; RESET_ROUTES],
            initial_local: local_cid,
            initial_peer: None,
            facts: None,
            peer: None,
            limits,
            budget: budget.clone(),
            idle,
            last_activity: now,
            handshake_deadline: Some(after(now, limits.handshake_timeout)?),
            received: false,
            non_probing: None,
            confirmed: false,
            handshake_done: false,
            ping: false,
            ending: None,
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
            retry_source_cid: self.retry_cid,
            stateless_reset_token: self.issuer.as_ref().map(|issuer| issuer.reset(&self.local_cid)),
            idle_timeout: self.limits.idle_timeout,
            initial_source_cid: Some(self.initial_local),
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

    /// Gives the live local destination IDs. An endpoint routes each of these to this connection.
    pub fn local_ids(&self) -> [Option<ConnectionId>; 2] {
        self.ids.issued()
    }

    /// The path that carries the connection: the destination of its datagrams, but for the
    /// probes of other paths.
    pub const fn path(&self) -> Path {
        self.paths.active.addresses
    }

    /// Whether this end can send beyond three times the bytes it received on this path.
    pub fn address_validated(&self) -> bool {
        self.paths.active.amplification_credit.is_none()
    }

    /// Takes the latest unused NEW_TOKEN. Keep it only for a future connection to the same service.
    pub fn take_address_token(&mut self) -> Option<AddressToken> {
        self.future_token.take()
    }

    /// Gives a client an address token from this service before its first Initial leaves.
    pub fn use_address_token(&mut self, token: AddressToken) -> Result<(), Error> {
        if !matches!(self.end, End::Client { service, .. } if token.service == service) || self.spaces[0].next != 0 {
            return Err(Error::new(
                Kind::Misuse,
                "use the same server name before sending the first client Initial",
            ));
        }
        self.initial_token = Some(token);
        Ok(())
    }

    fn copy_token(&self, bytes: &[u8]) -> Result<AddressToken, Error> {
        let End::Client { service, .. } = self.end else {
            return Err(Error::new(
                Kind::Misuse,
                "only a QUIC client retains a received address token",
            ));
        };
        AddressToken::copy(bytes, service, &self.budget)
    }

    /// Switches to a spare destination ID and retires the old ID. Returns false if no spare has
    /// arrived, and while the validation of a path keeps the old ID for the path before it.
    pub fn rotate_peer_id(&mut self) -> Result<bool, Error> {
        self.live()?;
        let current = self.paths.active.remote_cid;
        let Some(spare) = self.spare().filter(|_| self.paths.validation.is_none()) else {
            return Ok(false);
        };
        let old = self.ids.peer(current).expect("a spare accompanies a current ID");
        self.ids.rotate(old.sequence).map_err(|_| endpoint::NO_ROOM)?;
        self.paths.active.remote_cid = spare.id;
        Ok(true)
    }

    /// A connection ID of the peer that no path uses: not the active path, and not the path that
    /// the connection left.
    fn spare(&self) -> Option<Id> {
        let active = self.paths.active.remote_cid;
        let fallback = self.paths.validation.as_ref();
        self.ids
            .spare([active, fallback.map_or(active, |left| left.fallback.remote_cid)])
    }

    /// The connection ID of the peer for a datagram to `path`, which is not the active path. An
    /// ID goes out from one local address only (RFC 9000, section 9.5). The path that the
    /// connection left keeps its ID while the peer did not retire it. Else, and for each other
    /// path, the ID is one that no path uses. With none, a path with the local address of the
    /// active path takes the ID of the active path: the peer changed its address. Else the peer
    /// gave no ID for `path`, and no datagram goes there.
    fn cid_for(&self, path: Path) -> Option<ConnectionId> {
        let active = &self.paths.active;
        // A peer with a connection ID of no bytes has no other one.
        if active.remote_cid.as_bytes().is_empty() {
            return Some(active.remote_cid);
        }
        let one_local = path.local == active.addresses.local;
        let fallback = self.paths.validation.as_ref().map(|left| &left.fallback);
        let own = fallback
            .filter(|fallback| fallback.addresses == path)
            .map(|own| own.remote_cid);
        own.filter(|own| self.ids.peer(*own).is_some() && (*own != active.remote_cid || one_local))
            .or_else(|| self.spare().map(|spare| spare.id))
            .or_else(|| one_local.then_some(active.remote_cid))
    }

    /// Moves a client to `path`, a new local address with the same address of the server (RFC
    /// 9000, section 9.2). The next packets leave on `path` with a spare connection ID of the
    /// server, and the client validates the path. If the path gives no answer in three probe
    /// timeouts, the client returns to the path that it left. Returns false when the server gave
    /// no connection ID that the client can use on `path`: the client then stays on its path.
    ///
    /// Refuses with [`Kind::Misuse`] on a server, before the handshake is confirmed, and for
    /// another address of the server. Refuses with [`Kind::Unsupported`] when the server
    /// disabled migration.
    pub fn migrate(&mut self, path: Path, now: Instant) -> Result<bool, Error> {
        self.live()?;
        self.check_clock(now)?;
        let active = &self.paths.active;
        if matches!(self.end, End::Server { .. }) || !self.confirmed || path.peer != active.addresses.peer {
            return Err(Error::new(
                Kind::Misuse,
                "only a confirmed QUIC client moves, and to the same server address",
            ));
        }
        if path == active.addresses {
            return Ok(true);
        }
        if self.peer.is_some_and(|peer| peer.migration == Migration::Disabled) {
            return Err(Error::new(Kind::Unsupported, "the QUIC server disabled migration"));
        }
        if !self.moved(path, now)? {
            return Ok(false);
        }
        // A packet that is not a probe shows the server the new path (RFC 9000, section 9.2).
        self.ping = true;
        Ok(true)
    }

    /// Makes `path` the active path: the path of the newest packet of a peer that moved, or the
    /// path that a client selected (RFC 9000, section 9.3). A server sends at most three times the
    /// bytes that came from an address with no validation. Thus the path starts with the credit
    /// that its datagrams left. Gives false when the peer gave no connection ID for `path`: the
    /// connection then stays on its path.
    fn moved(&mut self, path: Path, now: Instant) -> Result<bool, Error> {
        let Some(remote_cid) = self.cid_for(path) else {
            return Ok(false);
        };
        // A return to the last validated path ends the validation of the path that the connection
        // leaves, and restores the delivery state of the path (RFC 9000, section 9.3.2).
        if let Some(mut validation) = self
            .paths
            .validation
            .take_if(|validation| validation.fallback.addresses == path)
        {
            validation.fallback.remote_cid = remote_cid;
            self.paths.activate(validation.fallback);
            return Ok(true);
        }
        let server = matches!(self.end, End::Server { .. });
        let old = &self.paths.active;
        let mut next = old.next(path, remote_cid, self.datagram_top(), self.limits.congestion_control);
        next.amplification_credit = server.then(|| self.paths.take_credit(path));
        let until = self.validation_end(now)?;
        let old = self.paths.switch(next);
        match &mut self.paths.validation {
            // The path that the connection leaves had no validation: the fallback path stays.
            Some(validation) => validation.restart(until),
            // A server also asks the path that the peer left, so a peer that did not move answers
            // there and brings the connection back (RFC 9000, section 9.3.3).
            None => self.paths.validation = Some(Validation::new(old, until, server)),
        }
        Ok(true)
    }

    /// The end of a validation that starts at `now`: three probe timeouts later (RFC 9000,
    /// section 8.2.4). The probe timeout is the larger one of the path that the connection came
    /// from, and of a path with no round-trip sample. The estimate of the new path is no measure.
    /// The new path can have a longer round trip, and its estimate can come from the path before it.
    fn validation_end(&self, now: Instant) -> Result<Instant, Error> {
        let validation = self.paths.validation.as_ref();
        let from = validation.map_or(&self.paths.active, |validation| &validation.fallback);
        let ack_delay = self.ack_delay_max();
        after(now, 3 * from.pto(ack_delay).max(PTO_INITIAL + ack_delay))
    }

    /// Takes a PATH_RESPONSE frame. The data of a challenge of the active path shows that the
    /// peer is at its address. When the datagram of that challenge had 1,200 bytes, it also shows
    /// that the path carries QUIC, and the validation is complete. Else a challenge of 1,200 bytes
    /// follows, with its own period (RFC 9000, section 8.2.1).
    fn responded(&mut self, data: [u8; 8], now: Instant) -> Result<(), Failure> {
        let validation = self.paths.validation.as_ref();
        let Some(padded) = validation.and_then(|validation| validation.answered(data)) else {
            return Ok(());
        };
        let active = &mut self.paths.active;
        active.amplification_credit = None;
        active.amplification_blocked = false;
        if !padded {
            let until = self.validation_end(now)?;
            if let Some(validation) = &mut self.paths.validation {
                validation.restart(until);
            }
            return Ok(());
        }
        // The connection ID of the path that the connection left is not used again.
        if let Some(validation) = self.paths.validation.take()
            && validation.fallback.remote_cid != self.paths.active.remote_cid
            && let Some(old) = self.ids.peer(validation.fallback.remote_cid)
        {
            self.ids
                .rotate(old.sequence)
                .map_err(|code| Failure::transport(code, 0x1b, VIOLATION))?;
        }
        Ok(())
    }

    /// Ends the connection with the error code `code` of the application protocol. The next
    /// [`transmit`](Self::transmit) gives the CONNECTION_CLOSE frame, and each later call of the
    /// application refuses with [`Kind::Cancelled`]. After the handshake is confirmed, the
    /// connection sends the frame again when datagrams of the peer still arrive, and gives its
    /// terminal outcome, `Ok`, three probe timeouts later (RFC 9000, section 10.2.1). Before that,
    /// it ends when the frame is out, and the frame of an Initial or Handshake packet shows only
    /// that the application closed. A server that waits for the credit of its amplification limit
    /// takes it from each datagram of the peer, and ends at the handshake deadline at the latest.
    ///
    /// Refuses with [`Kind::Misuse`] when `code` is above 2^62 - 1, and with the error of a
    /// connection that ended.
    pub fn close(&mut self, code: u64, now: Instant) -> Result<(), Error> {
        self.live()?;
        self.check_clock(now)?;
        if code > VARINT_MAX {
            return Err(Error::new(
                Kind::Misuse,
                "the error code of a QUIC close is above 2^62 - 1",
            ));
        }
        let close = Close { code, frame_type: None };
        self.end_with(Ok(()), Some(close), now);
        if let Some(ending) = &mut self.ending {
            ending.notify = false;
        }
        Ok(())
    }

    /// Ends the connection for the application: `close` is the frame of a closing end, and `None`
    /// starts the draining period of an end that read the close of its peer. The terminal outcome
    /// follows three probe timeouts later (RFC 9000, section 10.2).
    fn end_with(&mut self, outcome: Result<(), Error>, close: Option<Close>, now: Instant) {
        self.reading = None;
        let until = if self.confirmed {
            after(now, 3 * self.pto()).ok()
        } else {
            None
        };
        if until.is_none() && close.is_none() {
            self.outcome = Some(outcome);
            return;
        }
        self.ending = Some(Ending {
            outcome,
            close,
            send: close.is_some(),
            heard: 0,
            notify: until.is_some(),
            until,
            sealed: None,
        });
    }

    fn issue_id(&mut self) -> Result<(), Error> {
        let (id, reset) = tls::scoped(self.stream.as_ref(), || -> Result<_, Error> {
            if let Some(issuer) = &self.issuer {
                let id = issuer.issue(self.random)?;
                return Ok((id, issuer.reset(&id)));
            }
            let id = random_cid(self.random, self.limits.cid_bytes)?;
            let mut reset = [0; 16];
            self.random.fill(&mut reset).map_err(|_| endpoint::RANDOM)?;
            Ok((id, reset))
        })?;
        self.ids.issue(id, reset).map_err(|_| endpoint::NO_ROOM)
    }

    /// Records a datagram to the address `peer` with the connection ID `dcid` of the peer, as the
    /// newest pair. A pair of a retired connection ID leaves, and then the oldest pair.
    fn sent_to(&mut self, peer: SocketAddr, dcid: ConnectionId) {
        let newest = Some((peer, dcid));
        if self.used[0] == newest {
            return;
        }
        let mut used = [None; RESET_ROUTES];
        used[0] = newest;
        let older = self
            .used
            .into_iter()
            .flatten()
            .filter(|old| Some(*old) != newest && self.ids.peer(old.1).is_some());
        for (slot, old) in used[1..].iter_mut().zip(older) {
            *slot = Some(old);
        }
        self.used = used;
    }

    /// Each stateless reset that is valid for this connection. It has an address of the peer that
    /// this end sent to, and the token of the connection ID that this end used there. A retired
    /// connection ID has no token (RFC 9000, section 10.3.1).
    pub(super) fn resets(&self) -> [Option<(SocketAddr, [u8; 16])>; RESET_ROUTES] {
        self.used.map(|used| {
            let (peer, id) = used?;
            Some((peer, self.ids.peer(id)?.reset?))
        })
    }

    fn matches_reset(&self, tail: &[u8; 16], from: SocketAddr) -> bool {
        let key = self.reset_mask.as_bytes();
        let mut tokens = self.resets().into_iter().flatten().filter(|(peer, _)| *peer == from);
        tokens.any(|(_, expected)| {
            let expected = rscrypto::HmacSha256::mac(key, &expected);
            rscrypto::HmacSha256::verify_tag(key, tail, &expected).is_ok()
        })
    }

    /// Starts the draining period of a connection that the peer reset (RFC 9000, section 10.3.1).
    /// A closing end sends no more copies of its frame, and keeps the outcome of its close.
    pub(super) fn stateless_reset(&mut self, now: Instant) -> Result<(), Error> {
        self.check_clock(now)?;
        if let Some(ending) = &mut self.ending {
            ending.close = None;
            ending.send = false;
            // An end with no closing period waited only for its frame.
            if ending.until.is_none() {
                self.outcome = Some(ending.outcome);
            }
        } else if self.outcome.is_none() {
            self.peer_close = Some(PeerClose::StatelessReset);
            self.end_with(PeerClose::StatelessReset.outcome(), None, now);
        }
        Ok(())
    }

    pub(super) fn ended(&self) -> bool {
        self.outcome.is_some()
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
        self.paths.active.stats()
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
            || (self.paths.active.room() >= self.datagram_bytes() as u64
                && (self.ping
                    || self.handshake_done
                    || self.path_frames()
                    || self.streams.control_pending()
                    || self.spaces.iter().any(|space| space.send.pending())));
        self.sides.admit(flow, &mut self.paths, bytes as u64, now, control)
    }

    /// Applies the packet ranges and ECN counts from an authenticated side acknowledgement.
    /// The delay uses the parent's ACK delay exponent. An invalid packet range ends this side flow with [`Kind::Malformed`].
    /// The extension keeps the payload and acknowledges its consumer separately.
    pub fn acknowledge_side(&mut self, flow: super::SideFlow, ack: &Ack<'_>, now: Instant) -> Result<(), Error> {
        self.live()?;
        self.check_clock(now)?;
        let limited = self.limited();
        let delay = self.ack_delay(ack.delay);
        self.sides.acknowledge(flow, &mut self.paths, ack, delay, now, limited)
    }

    /// Releases the recovery state and outstanding flight of an ended side flow.
    pub fn close_side_flow(&mut self, flow: super::SideFlow) -> Result<(), Error> {
        self.sides.close(flow, &mut self.paths)
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
        match self.outcome.or_else(|| self.ending.map(|ending| ending.outcome)) {
            Some(Err(error)) => Err(error),
            Some(Ok(())) => Err(Error::new(Kind::Cancelled, "the QUIC connection closed")),
            None => Ok(()),
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
            .saturating_sub(1 + self.paths.active.remote_cid.as_bytes().len() + 4 + packet::TAG)
    }

    /// Applies the datagram size of the active path: the controller counts its window in
    /// datagrams of this size, and an unreliable datagram that waits and no longer fits drops
    /// with its count.
    fn fit(&mut self) {
        let bytes = self.datagram_bytes() as u64;
        self.paths.active.controller.datagram_limit(bytes);
        let room = self.frame_room();
        if room < core::mem::replace(&mut self.fitted, room) {
            self.streams.resize_unreliable(room);
        }
    }

    /// The bytes of the largest unreliable datagram (RFC 9221) that goes out now, or `None` when
    /// the peer takes none or [`Limits::unreliable_bytes_max`] has them off.
    pub fn unreliable_room(&self) -> Option<usize> {
        self.streams.unreliable_room(self.frame_room())
    }

    /// Queued unreliable datagrams dropped because a longer destination ID or a smaller datagram
    /// size of the path left too little space.
    pub const fn unreliable_dropped(&self) -> u64 {
        self.streams.unreliable_dropped
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

    /// Opens the packets of `datagrams`, the received region, which arrived on `path`. Runs the
    /// handshake on their CRYPTO data, and reads the frames of the streams. A packet that this end
    /// cannot open is discarded. Gives the next event, and stops there: call again with the same
    /// region and path while the call gives an event or [`Progress::Pending`].
    ///
    /// A server takes the packets of each path, and follows its peer to the path of its newest
    /// packet. A client takes only the packets of its path, and of the path that it left.
    pub fn receive(&mut self, datagrams: &mut Datagrams, path: Path, now: Instant) -> (Option<Event>, Turn) {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now) {
            self.outcome = Some(Err(error));
        }
        loop {
            if let Some(event) = self.next_event(&mut work, now) {
                return (Some(event), self.turn());
            }
            if self.outcome.is_some() {
                break;
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                break;
            }
            let ecn = datagrams.ecn;
            let suffix = datagrams.next_datagram().and_then(endpoint::reset_suffix).copied();
            let Some(next) = datagrams.next_packet() else {
                break;
            };
            match next {
                Ok(packet) if self.ending.is_some() => self.heard(&packet, path, &mut work),
                Ok(packet) => {
                    if let Err(failure) = self.packet(packet, path, &mut work, now, ecn) {
                        self.fail(failure, now);
                    }
                }
                Err(_) => work.add(1, 1),
            }
            if self.reading.is_none()
                && suffix.is_some_and(|tail| self.matches_reset(&tail, path.peer))
                && let Err(error) = self.stateless_reset(now)
            {
                self.outcome = Some(Err(error));
            }
        }
        (None, self.turn())
    }

    /// Counts a datagram of the peer for a closing end, which reads no packet. A copy of the
    /// CONNECTION_CLOSE frame answers datagram 1, 2, 4, 8, and so on (RFC 9000, section 10.2.1).
    /// The datagram also pays for the frame on a path with no validation, so a server that waits
    /// for its credit sends the frame (RFC 9000, section 10.2.3).
    fn heard(&mut self, packet: &packet::Protected<'_>, path: Path, work: &mut Work) {
        work.add(packet.header().end(), 0);
        let (bytes, first) = packet.datagram();
        let Header::Protected { kind, dcid, .. } = *packet.header() else {
            return;
        };
        if !first || !self.ours(kind, dcid) {
            return;
        }
        // A client path has no amplification limit, so this counts only for a server.
        if path == self.paths.active.addresses {
            self.paths.received(path, bytes as u64);
        }
        if let Some(ending) = &mut self.ending {
            ending.heard = ending.heard.saturating_add(1);
            ending.send |= ending.close.is_some() && ending.heard.is_power_of_two();
        }
    }

    /// Whether a packet of `kind` to `dcid` is for this connection: its destination is a
    /// connection ID that this end issued, or the first destination of the client while the
    /// server has its Initial keys.
    fn ours(&self, kind: PacketKind, dcid: ConnectionId) -> bool {
        self.ids.issued().contains(&Some(dcid))
            || (matches!(self.end, End::Server { .. })
                && kind == PacketKind::Initial
                && dcid == self.retry_cid.unwrap_or(self.original_cid)
                && !self.spaces[0].discarded)
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
        let event = self.next_event(&mut work, now);
        (event, self.turn())
    }

    /// Gives the next event: the end of the connection, then the events of the streams that wait,
    /// and then the events of the frames of the packet that the engine reads. Else runs the
    /// handshake.
    fn next_event(&mut self, work: &mut Work, now: Instant) -> Option<Event> {
        for _ in 0..2 {
            if let Some(ending) = &mut self.ending
                && self.outcome.is_none()
                && core::mem::take(&mut ending.notify)
            {
                self.more = true;
                return Some(Event::Closed(ending.outcome));
            }
            if self.outcome.is_some() || self.ending.is_some() {
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
                Err(failure) => self.fail(failure, now),
            }
        }
        if self.outcome.is_none()
            && self.ending.is_none()
            && let Err(failure) = self.advance(work)
        {
            self.fail(failure, now);
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
        if let Some(ending) = &self.ending {
            return Ok(ending.until.or(self.handshake_deadline));
        }
        let previous = self
            .one_rtt
            .as_ref()
            .and_then(|keys| keys.previous.as_ref().map(|(_, until)| *until));
        let handshake = if self.confirmed { None } else { self.handshake_deadline };
        let validation = self.paths.validation.as_ref().map(|validation| validation.until);
        Ok(earlier(
            earlier(earlier(self.idle_deadline()?, handshake), validation),
            earlier(
                earlier(previous, self.recovery_timer().map(|(at, _)| at)),
                self.paths.active.pacing_wait,
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
        if loss.is_some()
            || self.paths.active.amplification_credit == Some(0)
            || self.paths.active.amplification_blocked
            || self.spaces.iter().any(|space| space.probe)
        {
            return loss;
        }
        let delay = |base: Instant, pto: Duration| {
            let nanos = pto
                .as_nanos()
                .checked_mul(1u128.checked_shl(self.paths.active.backoff)?)?
                .try_into()
                .ok()?;
            base.checked_add(Duration::from_nanos(nanos)).ok()
        };
        let parent = |base, level| {
            let pto = if level == Level::Data {
                self.pto()
            } else {
                self.paths.active.pto(Duration::ZERO)
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
    /// 10.1), and at the end of its closing or draining period. Drops the old key of the peer at
    /// its deadline, and leaves a path that gave no answer in the time of its validation. When the
    /// peer gave no connection ID for the path before that one, the connection ends there.
    fn timers(&mut self, now: Instant) -> Result<(), Error> {
        if self.outcome.is_some() {
            return Ok(());
        }
        self.check_clock(now)?;
        if let Some(ending) = self.ending {
            // An end with no period ends when its frame is out, and at the handshake deadline at
            // the latest.
            if reached(ending.until.or(self.handshake_deadline), now)? {
                self.outcome = Some(ending.outcome);
            }
            return Ok(());
        }
        if reached(self.paths.active.pacing_wait, now)? {
            self.paths.active.pacing_wait = None;
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
        // The connection returns to its last validated path, with the delivery state of that path
        // (RFC 9000, sections 8.2.4 and 9.3.2). A connection that cannot return has no path.
        let validation = self.paths.validation.as_ref();
        let ended = validation.filter(|validation| validation.until.as_nanos() <= now.as_nanos());
        if let Some(fallback) = ended.map(|validation| validation.fallback.addresses)
            && !self.moved(fallback, now)?
        {
            return Err(NO_PATH);
        }
        if let Some((at, alarm)) = self.recovery_timer()
            && reached(Some(at), now)?
        {
            match alarm {
                Alarm::Loss(level) => {
                    self.detect_loss(level, now)?;
                }
                Alarm::SideLoss => self.sides.timers(&mut self.paths, now)?,
                Alarm::Probe(level) => self.probe(level),
                Alarm::SideProbe(flow) => {
                    self.sides.probe(flow, now);
                    self.probe(Level::Data);
                }
            }
        }
        Ok(())
    }

    /// A probe timeout of `level` ended: its next packet is a probe (RFC 9002, section 6.2.4).
    fn probe(&mut self, level: Level) {
        self.spaces[level as usize].probe = true;
        let path = &mut self.paths.active;
        path.backoff = path.backoff.saturating_add(1);
        path.mtu.timed_out();
        // The probe also carries the challenge of a path that waits for its validation.
        if let Some(validation) = &mut self.paths.validation {
            validation.send = true;
        }
    }

    fn limited(&self) -> bool {
        self.paths.active.room() < self.datagram_bytes() as u64
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
        self.paths.active.controller.limited(now, limited);
        let space = &mut self.spaces[level as usize];
        let acked = space
            .history
            .ack(ack, &mut self.paths, now, delay, |record| match record {
                Record::Range(DataRange::Crypto { offset, len }) => space.send.acknowledged(offset, len),
                record @ (Record::RetireId(_) | Record::NewToken) => self.ids.acknowledged(record),
                other => self.streams.acknowledged(other),
            })?;
        if acked.eliciting {
            space.probe = false;
            self.validation_at = now;
            if self.validated() {
                self.paths.active.backoff = 0;
            }
        }
        let congestion = self.detect_loss(level, now)?;
        self.paths.active.acknowledged(acked, now, limited && !congestion);
        Ok(())
    }

    fn detect_loss(&mut self, level: Level, now: Instant) -> Result<bool, Error> {
        let space = &mut self.spaces[level as usize];
        space.history.detect(&mut self.paths, now, |record| {
            match record {
                record @ (Record::IssueId(_) | Record::RetireId(_) | Record::NewToken) => self.ids.lost(record),
                // The recovery layer takes these records.
                Record::Mtu(_) | Record::Challenge => {}
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

    /// Opens one packet, which arrived on `path`, and reads its frames.
    fn packet(
        &mut self,
        packet: packet::Protected<'_>,
        path: Path,
        work: &mut Work,
        now: Instant,
        ecn: Ecn,
    ) -> Result<(), Failure> {
        work.add(packet.header().end(), 0);
        let active = path == self.paths.active.addresses;
        let Header::Protected { kind, dcid, scid, .. } = *packet.header() else {
            if !active {
                return Ok(());
            }
            if matches!(self.end, End::Client { .. })
                && matches!(packet.header(), Header::Negotiation { .. })
                && packet::Negotiation::of(
                    (packet.bytes(), packet.header()),
                    (&self.original_cid, &self.local_cid, super::Version::V1),
                    self.initial_peer.is_some() || self.retry_cid.is_some(),
                ) == packet::Negotiation::Abandon
            {
                self.outcome = Some(Err(Error::new(
                    Kind::Unsupported,
                    "the peer offered no supported QUIC version",
                )));
                return Ok(());
            }
            if let Header::Retry { dcid, scid, token, .. } = packet.header()
                && matches!(self.end, End::Client { .. })
                && self.retry_cid.is_none()
                && self.initial_peer.is_none()
                && self.local_cid == *dcid
                && *scid != self.original_cid
                && !token.is_empty()
                && token.len() <= CLIENT_TOKEN_MAX
                && packet::retry_is_valid(packet.bytes(), &self.original_cid)
            {
                let token = self.copy_token(&packet.bytes()[token.clone()])?;
                let space = &mut self.spaces[0];
                space.history.discard(&mut self.paths);
                space.retry.clear();
                space.keys = None;
                space.keys = Some(packet::initial_keys(scid, Side::Client));
                space.send.rewind();
                space.probe = false;
                // The connection starts again, with the connection ID of the Retry packet.
                self.paths.switch(PathState::new(
                    path,
                    *scid,
                    self.limits.datagram_bytes_max,
                    self.limits.congestion_control,
                ));
                self.initial_token = Some(token);
                self.retry_cid = Some(*scid);
                self.validation_at = now;
            }
            return Ok(());
        };
        let server = matches!(self.end, End::Server { .. });
        let ours = self.ours(kind, dcid);
        let (bytes, first) = packet.datagram();
        // Each datagram counts one time, for the address that it came from. The active path counts
        // each datagram of the connection, also one that this end then discards (RFC 9000, section
        // 8.1).
        if server && first && ours && active {
            self.paths.received(path, bytes as u64);
        }
        if server && kind == PacketKind::Initial && bytes < DATAGRAM_MIN {
            return Ok(());
        }
        let Some(level) = Level::of(kind).filter(|_| ours) else {
            return Ok(());
        };
        // Another path carries only 1-RTT packets, after the handshake is confirmed. A server takes
        // each path. A client takes only the path that it left, and no other address of the
        // server (RFC 9000, section 9).
        let known = self
            .paths
            .validation
            .as_ref()
            .is_some_and(|validation| validation.fallback.addresses == path);
        if !active && !(level == Level::Data && self.confirmed && (server || known)) {
            return Ok(());
        }
        // A client takes the connection ID of the server from its first Initial packet, and drops
        // each later packet with another one (RFC 9000, section 7.2).
        if level != Level::Data && self.initial_peer.is_some_and(|first| first != scid) {
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
        // Another address counts only a datagram whose first packet opens, so no forged datagram
        // changes its credit.
        if server && first && !active {
            self.paths.received(path, bytes as u64);
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
        if !server && level == Level::Initial && self.initial_peer.is_none() {
            self.paths.active.remote_cid = scid;
            self.initial_peer = Some(scid);
        }
        // A server drops the Initial keys when a Handshake packet of the client opens (RFC 9001,
        // section 4.9.1).
        if server && level == Level::Handshake && !self.spaces[0].discarded {
            self.paths.active.amplification_credit = None;
            self.paths.active.amplification_blocked = false;
            self.discard(Level::Initial);
        }
        self.received = true;
        self.last_activity = now;
        self.reading = Some(Reading {
            destination: dcid,
            path,
            probing: true,
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
                    let ranges = &mut self.spaces[level as usize].ranges;
                    ranges.accept(reading.number, reading.received_at, reading.eliciting, reading.ecn)?;
                    // The peer moved: its newest packet that is not a probe came on another path.
                    // A probe with a higher number can arrive before it (RFC 9000, section 9.3).
                    if level == Level::Data
                        && !reading.probing
                        && self.non_probing.is_none_or(|largest| reading.number > largest)
                    {
                        self.non_probing = Some(reading.number);
                        if server && reading.path != self.paths.active.addresses {
                            self.moved(reading.path, reading.received_at)?;
                        }
                    }
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
            reading.probing &= matches!(
                frame,
                Frame::Padding { .. }
                    | Frame::PathChallenge { .. }
                    | Frame::PathResponse { .. }
                    | Frame::NewConnectionId { .. }
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
                    self.end_with(close.outcome(), None, reading.received_at);
                    return Ok(None);
                }
                Frame::HandshakeDone if !server && !handshake_level => {
                    self.confirm();
                    Ok(None)
                }
                Frame::HandshakeDone => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1e, VIOLATION));
                }
                Frame::NewToken { token } => {
                    if server || handshake_level {
                        return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 7, VIOLATION));
                    }
                    if token.len() <= CLIENT_TOKEN_MAX
                        && let Ok(token) = self.copy_token(token)
                    {
                        self.future_token = Some(token);
                    }
                    Ok(None)
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
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token,
                } => {
                    let id = Id {
                        sequence,
                        id,
                        reset: Some(reset_token),
                    };
                    let active = self.paths.active.remote_cid;
                    let kept = self
                        .ids
                        .receive(id, retire_prior_to, active)
                        .map_err(|code| Failure::transport(code, 0x18, VIOLATION))?;
                    // A path keeps its connection ID while the peer did not retire it. Else it
                    // takes one that no path uses, when the peer gave one (RFC 9000, section 9.5).
                    if kept != active {
                        self.paths.active.remote_cid = self.spare().map_or(kept, |spare| spare.id);
                    }
                    let left = self.paths.validation.as_ref();
                    let fallback = left.map(|validation| validation.fallback.addresses);
                    if let Some(cid) = fallback.and_then(|path| self.cid_for(path))
                        && let Some(validation) = &mut self.paths.validation
                    {
                        validation.fallback.remote_cid = cid;
                    }
                    Ok(None)
                }
                Frame::RetireConnectionId { sequence } => {
                    if self.local_cid.as_bytes().is_empty() {
                        return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x19, VIOLATION));
                    }
                    if self
                        .ids
                        .retire_local(sequence, reading.destination)
                        .map_err(|code| Failure::transport(code, 0x19, VIOLATION))?
                    {
                        self.issue_id()?;
                        if !self.ids.issued().contains(&Some(self.local_cid)) {
                            self.local_cid = reading.destination;
                        }
                    }
                    Ok(None)
                }
                Frame::PathChallenge { data } => {
                    let active = &self.paths.active;
                    let on_active = reading.path == active.addresses;
                    let fallback = self.paths.validation.as_ref().map(|validation| &validation.fallback);
                    let validated = if on_active {
                        active.amplification_credit.is_none()
                    } else {
                        fallback.is_some_and(|fallback| fallback.addresses == reading.path)
                    };
                    self.answers[usize::from(!on_active)] = Some(Answer {
                        path: reading.path,
                        data,
                        validated,
                    });
                    // The answer on the active path goes in a packet that is not a probe, so a
                    // peer that did not move brings the connection back (RFC 9000, section 9.3.3).
                    self.ping |= on_active;
                    Ok(None)
                }
                Frame::PathResponse { data } => {
                    self.responded(data, reading.received_at)?;
                    Ok(None)
                }
                // The credit of the peer follows the consumer of this end: these frames change
                // nothing.
                Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => Ok(None),
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
        if level == Level::Initial {
            self.initial_token = None;
        }
        let space = &mut self.spaces[level as usize];
        space.history.discard(&mut self.paths);
        self.paths.active.backoff = 0;
        space.discard(&self.budget, self.window);
    }

    /// The longest time that the peer delays an acknowledgement, after the handshake is confirmed.
    fn ack_delay_max(&self) -> Duration {
        self.peer
            .filter(|_| self.confirmed)
            .map_or(Duration::ZERO, |peer| peer.ack_delay_max)
    }

    /// The probe timeout of the data space, including the peer's maximum ACK delay.
    fn pto(&self) -> Duration {
        self.paths.active.pto(self.ack_delay_max())
    }

    /// Runs rustls on the CRYPTO data in order, one level at a time, until it needs more, a limit
    /// of the turn stops it, or the budget cannot pay for the next call.
    fn advance(&mut self, work: &mut Work) -> Result<(), Failure> {
        self.wait = None;
        let mut stalled = false;
        loop {
            if matches!(self.tls, Tls::Failed) || self.ending.is_some() || self.outcome.is_some() {
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
        let (
            End::Client {
                tickets: Some(store), ..
            },
            Level::Data,
        ) = (&self.end, level)
        else {
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
        self.ids
            .first_peer(self.paths.active.remote_cid, parameters.stateless_reset_token);
        self.peer = Some(parameters);
        self.streams.peer(&parameters);
        self.paths.active.ack_delay_max = parameters.ack_delay_max;
        self.paths.active.mtu.limit(parameters.udp_payload_bytes_max);
        self.idle = match (self.limits.idle_timeout, parameters.idle_timeout) {
            (Some(local), Some(remote)) => Some(local.min(remote)),
            (local, remote) => local.or(remote),
        };
        self.read = Level::Data;
        if !self.local_cid.as_bytes().is_empty()
            && (self.issuer.is_some() || parameters.stateless_reset_token.is_some())
        {
            self.issue_id()?;
        }
        if sender == Sender::Client {
            self.handshake_done = true;
            if let (Some(issuer), End::Server { config, .. }) = (&self.issuer, &self.end) {
                let now = config.time_provider.current_time().ok_or(endpoint::TIME)?.as_secs();
                self.ids.token = Some(tls::scoped(self.stream.as_ref(), || {
                    issuer.repeat(now, self.random, &self.budget)
                })?);
                self.ids.send_token = true;
            }
            self.confirm();
        }
        Ok(())
    }

    /// Checks the connection IDs that the peer names in its parameters against the ones of its
    /// packets (RFC 9000, section 7.3).
    fn validate(&self, parameters: &Parameters) -> Result<(), Failure> {
        let invalid = || Failure::transport(ErrorCode::TRANSPORT_PARAMETER_ERROR, 0, PARAMETERS);
        if parameters.initial_source_cid != self.initial_peer
            || (parameters.stateless_reset_token.is_some() && self.paths.active.remote_cid.as_bytes().is_empty())
        {
            return Err(invalid());
        }
        if matches!(self.end, End::Client { .. })
            && (parameters.original_destination_cid != Some(self.original_cid)
                || parameters.retry_source_cid != self.retry_cid)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Ends the connection with `failure`: its CONNECTION_CLOSE waits for
    /// [`transmit`](Self::transmit) when this end has keys to send it.
    fn fail(&mut self, failure: Failure, now: Instant) {
        if self.outcome.is_some() || self.ending.is_some() {
            return;
        }
        self.reading = None;
        let keys = self.spaces.iter().any(|space| space.keys.is_some()) || self.one_rtt.is_some();
        match failure.code {
            Some((code, frame_type)) if keys => {
                let close = Close {
                    code,
                    frame_type: Some(frame_type),
                };
                self.end_with(Err(failure.error), Some(close), now);
            }
            _ => self.outcome = Some(Err(failure.error)),
        }
    }

    /// Builds an unmarked datagram at the start of `out`. Gives its length and its path, or `None`
    /// when no datagram can leave now. Call it until it gives `None`. The datagram has at most
    /// [`Limits::datagram_bytes_max`] bytes. A client Initial or an ack-eliciting server Initial
    /// needs at least 1,200.
    ///
    /// Refuses with [`Kind::Misuse`] when `out` has fewer bytes than
    /// [`Limits::datagram_bytes_max`].
    pub fn transmit(&mut self, out: &mut [u8], now: Instant) -> Result<Option<Transmission>, Error> {
        self.transmit_mark(out, now, Ecn::NotEct)
    }

    /// Builds a datagram for a host that can set its IP ECN codepoint. Apply the returned mark to that datagram.
    /// Supply the received mark with [`Datagrams::with_ecn`]. A host without send metadata uses [`transmit`](Self::transmit).
    /// After `None`, call [`drive`](Self::drive) to get the next deadline.
    pub fn transmit_ecn(&mut self, out: &mut [u8], now: Instant) -> Result<Option<Transmission>, Error> {
        self.check_clock(now)?;
        let ecn = self.paths.active.mark(now);
        let sent = self.transmit_mark(out, now, ecn)?;
        if let Some(sent) = sent {
            self.paths.active.marked(sent.ecn, now);
        }
        Ok(sent)
    }

    fn transmit_mark(&mut self, out: &mut [u8], now: Instant, mark: Ecn) -> Result<Option<Transmission>, Error> {
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
        let send = SendAt {
            now,
            mark,
            admitted: false,
        };
        if self.ending.is_none() {
            self.fit();
            match self.build(out, send) {
                Ok(sent) => return Ok(sent),
                Err(failure) => self.fail(failure, now),
            }
        }
        Ok(self.closing(out, send))
    }

    /// Builds the next datagram of a live connection: for a path that does not carry the
    /// connection, then a probe of the datagram size, and then the packets that wait.
    fn build(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<Transmission>, Failure> {
        if let Some((len, path)) = self.off_path(out, send)? {
            let ecn = Ecn::NotEct;
            return Ok(Some(Transmission { len, ecn, path }));
        }
        let (path, ecn) = (self.paths.active.addresses, send.mark);
        if let Some(len) = self.size_probe(out, send)? {
            return Ok(Some(Transmission { len, ecn, path }));
        }
        let room = self.room();
        let pad = self.spaces[0].keys.is_some() && (self.spaces[0].probe || self.has_data(Level::Initial));
        if self.paths.active.amplification_credit.is_some() && (room == 0 || (pad && room < DATAGRAM_MIN)) {
            self.amplification_blocked();
            return Ok(None);
        }
        let Some(len) = self.datagram(&mut out[..room], send.now, send.mark)? else {
            let active = &self.paths.active;
            if room < DATAGRAM_MIN && active.pacing_wait.is_none() && active.room() >= room as u64 {
                self.amplification_blocked();
            }
            return Ok(None);
        };
        self.paths.active.charge(len as u64);
        Ok(Some(Transmission { len, ecn, path }))
    }

    /// The bytes of the next datagram to the active path: its datagram size, and what the
    /// amplification limit leaves. After a probe timeout, at most 1,200 bytes, so a path that now
    /// drops larger datagrams still carries the probe.
    fn room(&self) -> usize {
        let path = &self.paths.active;
        let size = if self.spaces.iter().any(|space| space.probe) {
            DATAGRAM_MIN
        } else {
            path.mtu.size()
        };
        path.amplification_credit
            .map_or(size, |credit| size.min(usize::try_from(credit).unwrap_or(usize::MAX)))
    }

    fn amplification_blocked(&mut self) {
        let pending = self.ending.is_some() || Level::ALL.into_iter().any(|level| self.wants(level, true));
        let path = &mut self.paths.active;
        if pending && !path.amplification_blocked {
            path.amplification_blocked = true;
            path.amplification_rounds = path.amplification_rounds.saturating_add(1);
        }
    }

    /// The bytes of the largest datagram that this end sends now: the datagram size of the
    /// active path.
    fn datagram_bytes(&self) -> usize {
        self.paths.active.mtu.size()
    }

    /// The top of the search for the datagram size of a path: the limit of this end, and the
    /// limit of the peer.
    fn datagram_top(&self) -> usize {
        let peer = self.peer.map_or(usize::MAX, |peer| {
            usize::try_from(peer.udp_payload_bytes_max).unwrap_or(usize::MAX)
        });
        self.limits.datagram_bytes_max.min(peer)
    }

    /// Whether a PATH_RESPONSE or a PATH_CHALLENGE frame waits for the active path.
    fn path_frames(&self) -> bool {
        let active = self.paths.active.addresses;
        self.answers.iter().flatten().any(|answer| answer.path == active)
            || self.paths.validation.as_ref().is_some_and(|validation| validation.send)
    }

    /// Whether an ack-eliciting frame waits at this level.
    fn has_data(&self, level: Level) -> bool {
        let space = &self.spaces[level as usize];
        space.send.pending()
            || !space.retry.is_empty()
            || (level == Level::Data
                && (self.handshake_done
                    || self.ping
                    || self.path_frames()
                    || self.ids.pending()
                    || self.streams.pending()))
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
        let path = &mut self.paths.active;
        let admitted = data && path.paced(out.len() as u64, now)?;
        let limited = data || self.sides.waiting() || path.room() < out.len() as u64;
        path.controller.limited(now, limited);
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

    /// Builds the datagram of a closing end when a copy of its CONNECTION_CLOSE frame is due, with
    /// the frame in each level that has keys (RFC 9000, section 10.2.1). Each copy after the first
    /// one is the same protected datagram, so the copies use no packet key. An end with no closing
    /// period ends when its frame is out.
    fn closing(&mut self, out: &mut [u8], SendAt { now, mark, .. }: SendAt) -> Option<Transmission> {
        let ending = self.ending?;
        let close = ending.close.filter(|_| ending.send)?;
        let room = self.room();
        let len = if let Some((sealed, len)) = ending.sealed {
            if room < len {
                self.amplification_blocked();
                return None;
            }
            out[..len].copy_from_slice(&sealed[..len]);
            len
        } else {
            let keyed = Level::ALL.map(|level| match level {
                Level::Data => self.one_rtt.is_some(),
                _ => self.spaces[level as usize].keys.is_some(),
            });
            // A datagram with an Initial packet has 1,200 bytes, so the frame waits for that credit.
            if room < if keyed[0] { DATAGRAM_MIN } else { 1 } {
                self.amplification_blocked();
                return None;
            }
            let last = keyed.iter().rposition(|&keyed| keyed);
            let mut at = 0;
            for level in Level::ALL {
                if !keyed[level as usize] {
                    continue;
                }
                let pad = last
                    .filter(|_| keyed[0])
                    .map(|i| (DATAGRAM_MIN.saturating_sub(at), Level::ALL[i]));
                let send = SendAt {
                    now,
                    mark,
                    admitted: false,
                };
                // The frame goes in one datagram with each level, or it waits: for the credit of
                // that datagram, and at most to the deadline.
                let Ok(Some(len)) = self.packet_out(level, &mut out[at..room], pad, Some(close), send) else {
                    if self.paths.active.amplification_credit.is_some() {
                        self.amplification_blocked();
                    }
                    return None;
                };
                at += len;
            }
            at
        };
        if let Some(ending) = &mut self.ending {
            ending.send = false;
            let mut sealed = [0; CLOSE_BYTES_MAX];
            if ending.sealed.is_none()
                && len > 0
                && let Some(copy) = sealed.get_mut(..len)
            {
                copy.copy_from_slice(&out[..len]);
                ending.sealed = Some((sealed, len));
            }
        }
        if ending.until.is_none() {
            self.ending = None;
            self.outcome = Some(ending.outcome);
        }
        let path = &mut self.paths.active;
        path.charge(len as u64);
        (len > 0).then_some(Transmission {
            len,
            ecn: mark,
            path: path.addresses,
        })
    }

    /// The number of the next packet of `level`, and the bytes of its encoding.
    fn number(&self, level: Level) -> Result<(u64, usize), Failure> {
        let space = &self.spaces[level as usize];
        let number = space.next;
        let number_len = packet::number_len(number, space.history.largest)
            .filter(|_| number <= VARINT_MAX)
            .ok_or(Failure::local(Error::new(
                Kind::Overload,
                "the packet numbers of a QUIC space passed their limit",
            )))?;
        Ok((
            number,
            if level == Level::Data {
                number_len.max(packet::number_len(self.window - 1, None).unwrap_or(4))
            } else {
                number_len
            },
        ))
    }

    /// Seals the packet of `builder`, which has the number `number` of `level`. Gives its bytes.
    /// Refuses a 1-RTT packet past the limit of its key: this end then sends no packet more (RFC
    /// 9001, section 6.6).
    fn seal(&mut self, level: Level, builder: Builder<'_>, number: u64) -> Result<usize, Failure> {
        if level == Level::Data && self.one_rtt.as_ref().is_some_and(|keys| keys.sealed >= keys.limit) {
            return Err(Failure::transport(
                ErrorCode::AEAD_LIMIT_REACHED,
                0,
                Error::new(Kind::Overload, "the QUIC packet key sealed each packet of its limit"),
            ));
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
        Ok(len)
    }

    /// Builds a datagram with one 1-RTT packet: `frame`, to the address `peer` with the connection
    /// ID `dcid`. An output of 1,200 bytes or more gives a datagram of its size, with padding. A
    /// smaller output gives a datagram with no padding. A datagram with a frame of the paths has
    /// 1,200 bytes or no expansion (RFC 9000, sections 8.2.1 and 8.2.2). With `record`, the packet
    /// counts on the active path, and the record tells its delivery or its loss. Else the packet
    /// goes to another path, and no delivery state of the active path follows it.
    fn single(
        &mut self,
        out: &mut [u8],
        (peer, dcid): (SocketAddr, ConnectionId),
        frame: &Frame<'_>,
        record: Option<Record>,
        SendAt { now, mark, .. }: SendAt,
    ) -> Result<Option<usize>, Failure> {
        let (number, number_len) = self.number(Level::Data)?;
        self.key_limit(now)?;
        let header = Outgoing::OneRtt {
            dcid: &dcid,
            spin: false,
            key_phase: self.one_rtt.as_ref().is_some_and(|keys| keys.phase),
        };
        let size = if out.len() < DATAGRAM_MIN { 0 } else { out.len() };
        let Ok(builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let mut output = Output::new(builder, &self.budget);
        let written = match record {
            Some(record) => output.track(frame, record),
            None => output.builder.frame(frame),
        };
        if written.is_err() || output.builder.pad_to(size).is_err() {
            return Ok(None);
        }
        if output.refused {
            return Err(Failure::local(recovery::NO_ROOM));
        }
        let Output { builder, records, .. } = output;
        let len = self.seal(Level::Data, builder, number)?;
        self.sent_to(peer, dcid);
        if record.is_none() {
            return Ok(Some(len));
        }
        let space = &mut self.spaces[Level::Data as usize];
        space.history.ect_sent += u64::from(mark == Ecn::Ect0);
        space.history.insert(
            &mut self.paths,
            Sent {
                mark,
                number,
                time: now,
                bytes: len as u64,
                eliciting: true,
                records,
            },
        )?;
        Ok(Some(len))
    }

    /// Builds a datagram for a path that does not carry the connection: the PATH_RESPONSE for a
    /// path that the peer probes, or the PATH_CHALLENGE for the path that the peer left (RFC
    /// 9000, sections 8.2.2 and 9.3.3). The datagram has 1,200 bytes. When the credit of a path
    /// with no validation does not allow them, the answer has no padding. The answer takes its
    /// bytes from that credit. A path that the peer gave no connection ID for gets no datagram.
    fn off_path(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<(usize, Path)>, Failure> {
        let active = self.paths.active.addresses;
        if let Some(slot) = self
            .answers
            .iter_mut()
            .find(|slot| slot.is_some_and(|answer| answer.path != active))
            && let Some(answer) = slot.take()
        {
            let Some(dcid) = self.cid_for(answer.path) else {
                return Ok(None);
            };
            let frame = Frame::PathResponse { data: answer.data };
            let room = if answer.validated {
                DATAGRAM_MIN
            } else {
                self.paths.off_path_room(answer.path)
            };
            let sent = self.single(&mut out[..room], (answer.path.peer, dcid), &frame, None, send)?;
            if let Some(len) = sent.filter(|_| !answer.validated) {
                self.paths.off_path_sent(answer.path, len as u64);
            }
            return Ok(sent.map(|len| (len, answer.path)));
        }
        let left = self.paths.validation.as_ref().filter(|validation| validation.left);
        if let Some(path) = left.map(|validation| validation.fallback.addresses)
            && let Some(dcid) = self.cid_for(path)
            && let Some(validation) = &mut self.paths.validation
        {
            validation.left = false;
            let frame = Frame::PathChallenge {
                data: challenge(self.stream.as_ref(), self.random)?,
            };
            let sent = self.single(&mut out[..DATAGRAM_MIN], (path.peer, dcid), &frame, None, send)?;
            return Ok(sent.map(|len| (len, path)));
        }
        Ok(None)
    }

    /// Builds a probe of the next datagram size of the active path: a PING frame and its padding
    /// (RFC 8899, and RFC 9000, section 14.4). The probe counts in the window. Only a validated
    /// path of a confirmed connection searches.
    fn size_probe(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<usize>, Failure> {
        let searches = self.confirmed && self.paths.validation.is_none();
        let path = &mut self.paths.active;
        let Some(size) = path
            .mtu
            .next()
            .filter(|_| searches && path.amplification_credit.is_none())
        else {
            return Ok(None);
        };
        if !path.paced(size as u64, send.now)? {
            return Ok(None);
        }
        let to = (path.addresses.peer, path.remote_cid);
        let sent = self.single(&mut out[..size], to, &Frame::Ping, Some(Record::Mtu(size)), send)?;
        if sent.is_some() {
            self.paths.active.mtu.sent(size);
        }
        Ok(sent)
    }

    /// Builds one packet of `level` at the start of `out`: a CONNECTION_CLOSE frame for `close`,
    /// or the HANDSHAKE_DONE and CRYPTO frames and the frames of the streams that wait. Pads it
    /// to `pad` bytes. Gives its length, or `None` when `out` has no room for a packet with a
    /// frame.
    fn packet_out(
        &mut self,
        level: Level,
        out: &mut [u8],
        mut pad: Option<(usize, Level)>,
        close: Option<Close>,
        SendAt { now, mark, admitted }: SendAt,
    ) -> Result<Option<usize>, Failure> {
        let (number, number_len) = self.number(level)?;
        let space = &self.spaces[level as usize];
        let admitted = space.probe || (admitted && self.paths.active.room() >= out.len() as u64);
        if level == Level::Data && close.is_none() {
            self.key_limit(now)?;
        }
        let (dcid, scid) = (self.paths.active.remote_cid, self.initial_local);
        let header = match level {
            Level::Initial => Outgoing::Initial {
                dcid: &dcid,
                scid: &scid,
                token: self.initial_token.as_ref().map_or(&[], |t| t.bytes.as_slice()),
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
        // A datagram with a frame of the paths has 1,200 bytes where the limit of the path allows
        // them (RFC 9000, sections 8.2.1 and 8.2.2).
        let full = out.len() >= DATAGRAM_MIN;
        let full_pad = full.then_some((DATAGRAM_MIN, level));
        let Ok(builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let overflow = |_: packet::BuildError| {
            Failure::local(Error::new(Kind::Unsupported, "a QUIC frame did not fit its packet"))
        };
        let mut output = Output::new(builder, &self.budget);
        let room = output.room();
        let mut eliciting = false;
        if let Some(close) = close {
            if output.builder.frame(&close.frame(level)).is_err() {
                return Ok(None);
            }
        } else {
            let space = &mut self.spaces[level as usize];
            space.ranges.write(&mut output.builder, now)?;
            let after_ack = output.room();
            if admitted {
                if level == Level::Data {
                    let active = self.paths.active.addresses;
                    if let Some(slot) = self
                        .answers
                        .iter_mut()
                        .find(|slot| slot.is_some_and(|answer| answer.path == active))
                        && let Some(answer) = *slot
                        && output.builder.frame(&Frame::PathResponse { data: answer.data }).is_ok()
                    {
                        *slot = None;
                        pad = pad.or(full_pad);
                    }
                    if let Some(validation) = self.paths.validation.as_mut().filter(|validation| validation.send) {
                        let data = challenge(self.stream.as_ref(), self.random)?;
                        if output.track(&Frame::PathChallenge { data }, Record::Challenge).is_ok() {
                            validation.sent(data, full);
                            pad = pad.or(full_pad);
                        }
                    }
                }
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
                        .map_err(overflow)?;
                    send.sent(len);
                }
                if level == Level::Data {
                    self.ids.write(&mut output);
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
        let Output {
            mut builder, records, ..
        } = output;
        let before_pad = builder.room();
        if let Some((minimum, last)) = pad
            && (level == last || before_pad < COALESCED_ROOM)
        {
            builder.pad_to(minimum).map_err(overflow)?;
        }
        let in_flight = eliciting || builder.room() < before_pad;
        let len = self.seal(level, builder, number)?;
        self.sent_to(self.paths.active.addresses.peer, dcid);
        self.spaces[level as usize].history.ect_sent += u64::from(mark == Ecn::Ect0);
        // A later bare ACK can be the largest number in an ACK that also covers a live elicitor.
        if close.is_none() && (in_flight || self.spaces[level as usize].history.pto_start().is_some()) {
            let bytes = if in_flight { len as u64 } else { 0 };
            let space = &mut self.spaces[level as usize];
            space.history.insert(
                &mut self.paths,
                Sent {
                    mark,
                    number,
                    time: now,
                    bytes,
                    eliciting,
                    records,
                },
            )?;
            if eliciting {
                if core::mem::take(&mut space.probe) {
                    self.paths.active.probes = self.paths.active.probes.saturating_add(1);
                }
                if core::mem::take(&mut self.received) {
                    self.last_activity = now;
                }
            }
        } else {
            self.paths.untracked();
        }
        Ok(Some(len))
    }

    /// Updates the 1-RTT keys of this end before the key seals the last packet of its limit
    /// (RFC 9001, sections 6 and 6.6). A key update needs a confirmed handshake. After the first
    /// one, it also needs an acknowledgement of a packet of the current phase. Without them the
    /// connection ends with AEAD_LIMIT_REACHED, and the last packet of the key carries that close.
    fn key_limit(&mut self, now: Instant) -> Result<(), Failure> {
        let Some(keys) = &self.one_rtt else {
            return Ok(());
        };
        // The limit is at least 2.
        if keys.sealed < keys.limit - 1 {
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
