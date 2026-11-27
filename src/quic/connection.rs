//! The connection engine of version 1: the TLS 1.3 handshake on rustls's QUIC API, the packet
//! number spaces and their keys, the transport parameters, key updates, and the idle and
//! handshake timeouts (RFC 9000 and RFC 9001).
//!
//! A host drives a [`Connection`] in calls: [`Connection::receive`] with each received region,
//! [`Connection::drive`] at its deadline, and then [`Connection::transmit`] until it gives no
//! batch of datagrams. Each call returns at once: the engine does no I/O and keeps no thread.
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
use core::num::NonZeroUsize;
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
use super::params::{Migration, Parameters, PreferredAddress, Sender};
use super::path::{Path, Probe, Validation};
use super::recovery::{self, DataRange, History, Output, PathState, Paths, Received, Record, RecoveryStats, Sent};
use super::stream::{self, Event, Priority, Stop, StreamId, Streams};
use super::{CongestionControl, ConnectionId, ErrorCode, VARINT_MAX};
use crate::drive::{Blocked, Ecn, Error, Kind, Progress, Turn, TurnLimits, Work};
use crate::tls::memory::{self, ClientStore, Cost, Held, Own, Owns};
use crate::tls::{self, Facts, Negotiated};

mod handshake;
mod receive;
mod transmit;

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
    /// The work of one call: the received bytes and the frames that it reads, the rustls calls
    /// that it makes, each counted as a frame, and the sent packets, side flows, and streams that
    /// it visits. Each limit is at least 1.
    pub turn: TurnLimits,
    /// The address of the server that a client uses after the handshake. A server ignores it.
    pub server_address: ServerAddress,
}

/// The address of the server that a client uses after the handshake (RFC 9000, section 9.6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerAddress {
    /// The preferred address of the server, when the server gives one of the address family of
    /// the handshake path: the client validates it after the handshake is confirmed, and moves to
    /// it when it answers. With no answer in three probe timeouts, the client stays.
    #[default]
    Preferred,
    /// The address of the handshake.
    Handshake,
}

impl Limits {
    /// An idle timeout of 30 s, a handshake timeout of 10 s, datagrams of 1,200 bytes with no search,
    /// connection IDs of 8 bytes, the key limit of the suite, and 1 MiB and 4,096 frames for each
    /// call. A window of 4 MiB for the connection and of 1 MiB for each stream, 100 streams of the
    /// peer in each direction, 6 MiB for data out of order, which the windows never reach, and no
    /// unreliable datagrams. The path uses CUBIC. Side-flow admission is off. Send regions share 4 MiB. Duplicate detection covers 100,000 packets/s for 100 ms.
    /// A client moves to the preferred address of its server.
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
            visits: 16 * 1024,
        },
        server_address: ServerAddress::Preferred,
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
/// The keys of each level that a connection charges before rustls starts: one set for the Initial
/// and Handshake levels, and for the data space the keys of this phase, the keys of the next
/// one, the secrets, and a previous key. So no key that rustls gives arrives with no charge.
const LEVEL_KEYS: [u64; 3] = [KEYS_BYTES, KEYS_BYTES, 3 * KEYS_BYTES];
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
    /// The packets that `keys` sealed.
    sealed: u64,
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
    /// The charge of the keys of the level, which the connection takes before rustls starts, and
    /// of the lost ranges in `retry`.
    credit: Credit,
}

impl Space {
    fn new(budget: &Budget, window: u64) -> Self {
        Self {
            keys: None,
            sealed: 0,
            receive: crypto::Receive::new(budget),
            send: crypto::Send::new(),
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

    /// Installs `keys`. Their charge is in `credit` from the start of the connection.
    fn install(&mut self, keys: rustls::quic::Keys) {
        self.keys = Some(keys);
        self.sealed = 0;
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
    /// The lowest and the highest number of the packets of the peer that opened in this phase.
    received: Option<(u64, u64)>,
    /// The peer acknowledged a packet of this phase, so a later update is allowed.
    acknowledged: bool,
    /// A key update happened: each later one needs an acknowledgement of the current phase.
    updated: bool,
    /// The most packets that one key seals.
    limit: u64,
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
    /// The keys of the first phase. Their charge is in the credit of the data space from the start
    /// of the connection.
    fn new(keys: rustls::quic::Keys, mut secrets: Secrets, limit: u64) -> Self {
        let limit = limit.min(keys.local.packet.confidentiality_limit());
        Self {
            local: keys.local,
            remote: keys.remote,
            previous: None,
            next: secrets.next_packet_keys(),
            secrets,
            phase: false,
            sealed: 0,
            first_sent: None,
            received: None,
            acknowledged: false,
            updated: false,
            limit,
        }
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
        self.received = None;
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

impl Tls {
    /// The state holds a message and waits for a call with no input: the choice of a
    /// configuration, or the check of an identity.
    const fn ready(&self) -> bool {
        matches!(
            self,
            Self::Client(ClientHandshake::VerifyServerIdentity(_))
                | Self::Server(ServerHandshake::Accepted(_) | ServerHandshake::VerifyClientIdentity(_))
        )
    }

    /// The bytes of the transport parameters of the peer that rustls keeps, or 0 before they
    /// show.
    fn parameters_bytes(&self) -> u64 {
        let parameters = match self {
            Self::Client(ClientHandshake::NeedsInput(needs)) => needs.quic_transport_parameters(),
            Self::Server(ServerHandshake::NeedsInput(needs)) => needs.quic_transport_parameters(),
            Self::ClientDone(connection) => connection.quic_transport_parameters(),
            Self::ServerDone(connection) => connection.quic_transport_parameters(),
            _ => None,
        };
        parameters.map_or(0, |parameters| parameters.len() as u64)
    }
}

/// The end of a client or a server: its configuration.
enum End {
    Client {
        tickets: Option<Arc<ClientStore>>,
        service: [u8; 32],
        /// The preferred address of the server, until the client starts its validation.
        preferred: Option<SocketAddr>,
        /// After the move to the preferred address: the path of the handshake, which the server
        /// sends on until it validates its preferred address (RFC 9000, section 9.6.2).
        left: Option<Path>,
    },
    Server {
        config: Arc<rustls::ServerConfig>,
        /// The encoded transport parameters, until rustls takes them.
        parameters: Option<Vec<u8>>,
        /// The preferred addresses that this server gives: IPv4, then IPv6.
        preferred: [Option<SocketAddr>; 2],
        /// After the move to a preferred address: the local address that the server left, and the
        /// largest number of a packet that is not a probe at the move. A packet with a higher
        /// number that arrives at the address that the server left drops (RFC 9000, section 9.6.2).
        left: Option<(SocketAddr, u64)>,
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

/// A batch of outgoing UDP datagrams for one path, with one IP ECN codepoint: the datagrams are
/// `out[..len].chunks(segment_bytes)`. A host with segmentation offload (GSO, USO) sends the batch
/// in one call, with `segment_bytes` as its segment size. Each other host sends each chunk as one
/// datagram. When the host accepts only the first datagrams of a batch, it sends the chunks that
/// remain later. It never sends a part of the batch that does not start at a chunk as one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmission {
    /// The initialized prefix of the output buffer.
    pub len: usize,
    /// The bytes of each datagram except the last, which can have fewer.
    pub segment_bytes: usize,
    /// The codepoint for the host to apply to each datagram.
    pub ecn: Ecn,
    /// Send each datagram from `path.local` to `path.peer`.
    pub path: Path,
}

impl Transmission {
    /// A batch of one datagram.
    const fn one(len: usize, ecn: Ecn, path: Path) -> Self {
        Self {
            len,
            segment_bytes: len,
            ecn,
            path,
        }
    }
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
    /// The charge of the output of rustls: the room of its events, what the next call can
    /// write, and the CRYPTO messages that wait for their acknowledgement.
    output: Credit,
    /// The charge of the transport parameters of this end, which rustls keeps.
    kept: Credit,
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
    if_classical: Option<tls::ClassicalSelection>,
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
    /// The CRYPTO data on which the last rustls call made no progress: its level, its bytes in
    /// order, and whether the call before it made none either. It stays across turns, so rustls
    /// runs again only for more data, another level, or another state.
    stall: Option<(Level, usize, bool)>,
    /// The CRYPTO bytes of the message that rustls holds for its next call, in a state that
    /// chooses a configuration or checks an identity.
    message: usize,
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
pub(super) fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
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
pub(super) fn check(limits: &Limits, protocols: &[rustls::enums::ApplicationProtocol<'_>]) -> Result<(), Error> {
    if protocols.iter().any(|name| name.as_ref() == b"h3") {
        crate::h3::check_transport(limits)?;
    }
    if !(DATAGRAM_MIN..=DATAGRAM_MAX).contains(&limits.datagram_bytes_max)
        || limits.cid_bytes > ConnectionId::MAX
        || limits.key_packets_max < 2
        || limits.handshake_timeout.is_zero()
        || limits.turn.bytes == 0
        || limits.turn.frames == 0
        || limits.turn.visits == 0
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

/// The output charge that one rustls call reserves: the bytes that it can write, with the growth
/// of their vectors, and the list entries of its messages. rustls encodes each QUIC message into a
/// vector that doubles its capacity as it grows, and the old and the new buffer are both alive
/// while it grows. Thus a message of `n` bytes takes less than `3 * n` during the call, and its
/// vector keeps less than `2 * n` after it, which [`Connection::settle_output`] charges.
fn output(own: &Own) -> u64 {
    3 * own.flight() as u64 + EVENTS as u64 * crypto::ENTRY_BYTES
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
        check(&limits, &config.config.alpn_protocols)?;
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
                    preferred: None,
                    left: None,
                },
                Tls::Failed,
                config.if_classical,
            ),
            (stream, random, held, config.cost, Arc::clone(&config.own)),
            (local_cid, original_cid, original_cid),
            path,
            limits,
            budget,
            now,
        )?;
        connection.spaces[Level::Initial as usize].install(packet::initial_keys(&original_cid, Side::Client));
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
        admission: Option<(Issuer, Option<endpoint::Proof>, [Option<SocketAddr>; 2])>,
        path: Path,
        limits: Limits,
        budget: &Budget,
        now: Instant,
    ) -> Result<Self, Error> {
        check(&limits, &config.config.alpn_protocols)?;
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
            Some((issuer, ..)) => issuer.issue(random),
            None => random_cid(random, limits.cid_bytes),
        })?;
        let own = config.own.get();
        let held = Held::new(budget, &config.cost, 0, &own)?;
        let mut connection = Self::new(
            (
                End::Server {
                    config: Arc::clone(&config.config),
                    parameters: None,
                    preferred: [None; 2],
                    left: None,
                },
                Tls::Server(ServerHandshake::NeedsInput(ServerHandshake::start(TlsVersion::V1))),
                config.if_classical,
            ),
            (stream, random, held, config.cost, Arc::clone(&config.own)),
            (local_cid, scid, dcid),
            path,
            limits,
            budget,
            now,
        )?;
        let mut offered = None;
        if let Some((issuer, proof, preferred)) = admission {
            connection.issuer = Some(issuer);
            if proof.is_some() {
                connection.paths.active.amplification_credit = None;
            }
            if let Some(endpoint::Proof::Retry { original, retry }) = proof {
                connection.original_cid = original;
                connection.retry_cid = Some(retry);
            }
            offered = connection.offer(preferred)?;
        }
        connection.initial_peer = Some(scid);
        connection.spaces[Level::Initial as usize].install(packet::initial_keys(&dcid, Side::Server));
        let parameters = Parameters {
            preferred_address: offered,
            ..connection.parameters()
        };
        let parameters = encode(&parameters, &mut connection.kept)?;
        if let End::Server { parameters: slot, .. } = &mut connection.end {
            *slot = Some(parameters);
        }
        Ok(connection)
    }

    fn new(
        (end, tls, if_classical): (End, Tls, Option<tls::ClassicalSelection>),
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
        let mut spaces: [Space; 3] = core::array::from_fn(|_| Space::new(budget, window));
        for (space, keys) in spaces.iter_mut().zip(LEVEL_KEYS) {
            space.credit.charge(keys).map_err(|_| KEYS_REFUSED)?;
        }
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
            events,
            spaces,
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
            if_classical,
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
            stall: None,
            message: 0,
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

    /// A connection ID of the peer that no path uses: not the active path, not the path that the
    /// connection left, and not the path of the preferred address while it is validated.
    fn spare(&self) -> Option<Id> {
        let active = self.paths.active.remote_cid;
        let fallback = self.paths.validation.as_ref();
        let probe = self.paths.probe.as_ref();
        self.ids.spare([
            active,
            fallback.map_or(active, |left| left.fallback.remote_cid),
            probe.map_or(active, |probe| probe.remote_cid),
        ])
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
        if let Some(probe) = self.paths.probe.as_ref().filter(|probe| probe.path == path) {
            return Some(probe.remote_cid);
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
    /// disabled migration, and with [`Kind::Overload`] after 2^32 - 2 changes of path.
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
        let old = self.paths.switch(next)?;
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

    /// Whether `path` arrives at a preferred address of this server that the connection does not
    /// use yet.
    pub(super) fn to_preferred(&self, path: Path) -> bool {
        path.local != self.paths.active.addresses.local
            && matches!(&self.end, End::Server { preferred, .. } if preferred.contains(&Some(path.local)))
    }

    /// Starts the validation of `path`, a path to or from the preferred address of the server, at
    /// `now`. The path takes a connection ID of the peer that no path uses: with none, the
    /// connection stays on its path.
    pub(super) fn probe_preferred(&mut self, path: Path, now: Instant) -> Result<(), Error> {
        if self.paths.probe.as_ref().is_some_and(|probe| probe.path == path) {
            return Ok(());
        }
        let Some(spare) = self.spare() else {
            return Ok(());
        };
        let until = self.validation_end(now)?;
        self.paths.probe = Some(Probe::new(path, spare.id, now, until));
        Ok(())
    }

    /// Starts the validation of the preferred address of the server, after the handshake of the
    /// client is confirmed at `now` (RFC 9000, section 9.6.1).
    pub(super) fn prefer(&mut self, now: Instant) -> Result<(), Error> {
        let End::Client { preferred, .. } = &mut self.end else {
            return Ok(());
        };
        let Some(peer) = preferred.take() else {
            return Ok(());
        };
        let local = self.paths.active.addresses.local;
        self.probe_preferred(Path { local, peer }, now)
    }

    /// Moves to the path of a validation of the preferred address that the data of a
    /// PATH_RESPONSE frame answers. The connection ID of the path that the connection leaves is
    /// not used again (RFC 9000, section 9.5). A client then sends a packet that is not a probe,
    /// so the server sees the move, and keeps the path that it leaves, where the server still
    /// sends. A server keeps the address that it leaves, and drops newer packets that arrive
    /// there. Gives false when no such validation waits.
    fn moved_to_preferred(&mut self, data: [u8; 8]) -> Result<bool, Failure> {
        let Some(probe) = self.paths.probe.take_if(|probe| probe.answered(data)) else {
            return Ok(false);
        };
        let violation = |code| Failure::transport(code, 0x1b, VIOLATION);
        let next = self.paths.active.next(
            probe.path,
            probe.remote_cid,
            self.datagram_top(),
            self.limits.congestion_control,
        );
        let left = self.paths.switch(next).map_err(Failure::local)?;
        self.paths.validation = None;
        if let Some(old) = self.ids.peer(left.remote_cid) {
            self.ids.retire_peer(old.sequence).map_err(violation)?;
        }
        match &mut self.end {
            End::Client { left: from, .. } => {
                *from = Some(left.addresses);
                self.ping = true;
            }
            End::Server { left: from, .. } => {
                *from = Some((left.addresses.local, self.non_probing.unwrap_or(0)));
            }
        }
        Ok(true)
    }

    /// Ends a validation of the preferred address that reached its end at `now` with no answer:
    /// the connection stays on its path. The connection ID of the validation went to that path,
    /// so it is not used on another one (RFC 9000, section 9.5).
    pub(super) fn probe_ended(&mut self, now: Instant) -> Result<(), Error> {
        let Some(probe) = self
            .paths
            .probe
            .take_if(|probe| probe.until.as_nanos() <= now.as_nanos())
        else {
            return Ok(());
        };
        if let Some(old) = self.ids.peer(probe.remote_cid) {
            self.ids.retire_peer(old.sequence).map_err(|_| endpoint::NO_ROOM)?;
        }
        Ok(())
    }

    /// Takes a PATH_RESPONSE frame. The data of a challenge of the active path shows that the
    /// peer is at its address. When the datagram of that challenge had 1,200 bytes, it also shows
    /// that the path carries QUIC, and the validation is complete. Else a challenge of 1,200 bytes
    /// follows, with its own period (RFC 9000, section 8.2.1).
    fn responded(&mut self, data: [u8; 8], now: Instant) -> Result<(), Failure> {
        if self.moved_to_preferred(data)? {
            return Ok(());
        }
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
        let (id, reset) = self.new_id()?;
        self.ids.issue(id, reset).map_err(|_| endpoint::NO_ROOM)
    }

    /// A new connection ID of this end and its stateless reset token.
    fn new_id(&self) -> Result<(ConnectionId, [u8; 16]), Error> {
        tls::scoped(self.stream.as_ref(), || -> Result<_, Error> {
            if let Some(issuer) = &self.issuer {
                let id = issuer.issue(self.random)?;
                return Ok((id, issuer.reset(&id)));
            }
            let id = random_cid(self.random, self.limits.cid_bytes)?;
            let mut reset = [0; 16];
            self.random.fill(&mut reset).map_err(|_| endpoint::RANDOM)?;
            Ok((id, reset))
        })
    }

    /// Gives the transport parameter of the `preferred` addresses of a server, IPv4 then IPv6, with
    /// a new connection ID that carries the route of the worker (RFC 9000, section 9.6). Gives
    /// `None` when the server has no preferred address.
    fn offer(&mut self, preferred: [Option<SocketAddr>; 2]) -> Result<Option<PreferredAddress>, Error> {
        if preferred == [None; 2] {
            return Ok(None);
        }
        let (connection_id, reset_token) = self.new_id()?;
        self.ids
            .offer(connection_id, reset_token)
            .map_err(|_| endpoint::NO_ROOM)?;
        if let End::Server { preferred: offered, .. } = &mut self.end {
            *offered = preferred;
        }
        let ipv4 = match preferred[0] {
            Some(SocketAddr::V4(address)) => (address.ip().octets(), address.port()),
            _ => ([0; 4], 0),
        };
        let ipv6 = match preferred[1] {
            Some(SocketAddr::V6(address)) => (address.ip().octets(), address.port()),
            _ => ([0; 16], 0),
        };
        Ok(Some(PreferredAddress {
            ipv4,
            ipv6,
            connection_id,
            reset_token,
        }))
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

    pub(crate) const fn local_limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) const fn side(&self) -> Side {
        match self.end {
            End::Client { .. } => Side::Client,
            End::Server { .. } => Side::Server,
        }
    }

    pub(crate) fn connection_credit(&self) -> u64 {
        self.streams.connection_credit()
    }

    pub(crate) fn stream_credit(&self, id: StreamId) -> Result<u64, Error> {
        self.streams.stream_credit(id)
    }

    pub(crate) fn send_room(
        &self,
        id: StreamId,
        storage_reserve: usize,
        flow_reserve: u64,
    ) -> Result<Option<usize>, Error> {
        self.live()?;
        self.streams.send_room(id, storage_reserve, flow_reserve)
    }

    pub(crate) fn abort_stream(&mut self, stream: StreamId, code: u64) -> Result<(), Error> {
        self.live()?;
        self.streams.abort(stream, code)
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
    /// before, when the peer acknowledged each byte and the end, and when `code` is above
    /// 2^62 - 1.
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
