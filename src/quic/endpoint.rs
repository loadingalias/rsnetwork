//! The server listener. Each worker owns its routing table and shares the service keys.

mod keys;
mod table;

use core::alloc::Layout;
use core::fmt;
use core::net::SocketAddr;
use core::num::NonZeroU64;
use std::sync::Arc;

pub use keys::EndpointKeys;
pub(super) use keys::{Proof, Token};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::Instant;
use rustls::crypto::SecureRandom;
use table::Table;

use super::packet::{self, Header, Kind as PacketKind};
use super::{Connection, ConnectionId, Limits, Path};
use crate::drive::{Error, Kind};
use crate::tls;

pub(super) const NO_ROOM: Error = Error::new(Kind::Overload, "the QUIC endpoint reached its capacity");
pub(super) const RANDOM: Error = Error::new(Kind::Unsupported, "the QUIC entropy source refused a draw");
pub(super) const TIME: Error = Error::new(Kind::Unsupported, "the address token needs a wall clock");

/// Limits for one worker. Each admitted connection gets its own byte budget.
#[derive(Clone, Copy, Debug)]
pub struct EndpointLimits {
    /// The largest number of live connections.
    pub connections_max: u16,
    /// The hard limit on concurrent handshakes.
    pub handshakes_max: u16,
    /// Require an address proof at this many concurrent handshakes. Zero always requires proof.
    pub retry_at: u16,
    /// Bytes that each connection may use. New handshakes cannot take these from an established connection.
    pub connection_bytes_max: NonZeroU64,
}

impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            connections_max: 1024,
            handshakes_max: 64,
            retry_at: 32,
            connection_bytes_max: NonZeroU64::new(16 << 20).expect("16 MiB is positive"),
        }
    }
}

/// A connection in this listener. An old handle cannot refer to the next occupant of its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle {
    slot: u16,
    generation: u64,
}

/// What the listener did with one UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Give the datagram to this new connection through [`Endpoint::with_connection`].
    Accepted(Handle),
    /// Give the datagram to this existing connection.
    Existing(Handle),
    /// Send this many bytes of the reply buffer back to the source address.
    Reply(usize),
    /// A reset from the peer put this connection into draining.
    Reset(Handle),
    /// No connection or reply took this datagram.
    Dropped,
    /// The listener has no room for a new handshake.
    Refused,
}

#[derive(Clone)]
pub(super) struct Issuer {
    keys: Arc<EndpointKeys>,
    worker: u64,
    peer: SocketAddr,
}

impl Issuer {
    pub(super) fn issue(&self, rng: &dyn SecureRandom) -> Result<ConnectionId, Error> {
        self.keys.issue(self.worker, rng)
    }
    pub(super) fn reset(&self, cid: &ConnectionId) -> [u8; 16] {
        self.keys.reset(cid)
    }
    pub(super) fn repeat(&self, now: u64, rng: &dyn SecureRandom, budget: &Budget) -> Result<Token, Error> {
        self.keys.seal(Proof::Repeat, self.peer, now, rng, budget)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum Key {
    Local(ConnectionId),
    Initial(SocketAddr, ConnectionId),
    Reset(SocketAddr, [u8; 16]),
}

struct Registered {
    connection: Box<Connection>,
    /// The route of the first Initial packets, until the handshake is confirmed.
    initial: Option<Key>,
    ids: [Option<ConnectionId>; 2],
    /// The route of a stateless reset: the address of the peer, which follows a peer that moves,
    /// and the token of the connection ID that this end sends to.
    reset: Option<(SocketAddr, [u8; 16])>,
    _storage: Permit,
}

struct Slot {
    generation: u64,
    free: Option<u16>,
    entry: Option<Registered>,
}

/// A sans-I/O QUIC server listener for one worker.
///
/// Pass each UDP payload and its path to [`Self::route`]. A connection keeps its route when its
/// client moves to a new address: the connection validates that address.
/// On acceptance or an existing route, call [`Connection::receive`] through [`Self::with_connection`].
/// Drive the connection at its deadline and drain its transmissions through the same handle.
/// Call [`Self::remove`] when the connection reaches its terminal outcome.
pub struct Endpoint {
    config: tls::ServerConfig,
    keys: Arc<EndpointKeys>,
    worker: u64,
    limits: EndpointLimits,
    connection_limits: Limits,
    stream: Option<rscrypto_rustls::replay::Stream>,
    budget: Budget,
    routes: Table<Key, Handle>,
    slots: Vec<Slot>,
    free: Option<u16>,
    handshakes: u16,
    resets: usize,
    _slots: Permit,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("handshakes", &self.handshakes)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    /// Creates a listener. The endpoint budget pays for routing, connection objects, and temporary address proofs.
    /// Listener-issued connection IDs have 17 bytes. Share the keys between workers of this service.
    pub fn new(
        config: &tls::ServerConfig,
        keys: Arc<EndpointKeys>,
        worker: u64,
        limits: EndpointLimits,
        mut connection_limits: Limits,
        budget: &Budget,
    ) -> Result<Self, Error> {
        if limits.handshakes_max == 0
            || limits.handshakes_max > limits.connections_max
            || limits.retry_at > limits.handshakes_max
        {
            return Err(Error::new(Kind::Misuse, "invalid QUIC handshake admission limits"));
        }
        connection_limits.cid_bytes = keys::CID_BYTES;
        super::connection::check(&connection_limits)?;
        let stream = config.entropy.stream(b"quic-end");
        let rng = config.config.provider().secure_random;
        let capacity = usize::from(limits.connections_max);
        // Two issued IDs, one Initial alias, and one used reset token per connection.
        let routes = Table::new(4 * capacity, |b| tls::scoped(stream.as_ref(), || rng.fill(b)), budget)?;
        let (slots, storage) = table::array(capacity, budget, |i| Slot {
            generation: 0,
            free: u16::try_from(i + 1).ok().filter(|&n| n < limits.connections_max),
            entry: None,
        })?;
        Ok(Self {
            config: config.clone(),
            keys,
            worker,
            limits,
            connection_limits,
            stream,
            budget: budget.clone(),
            slots,
            routes,
            free: Some(0),
            handshakes: 0,
            resets: 0,
            _slots: storage,
        })
    }

    /// Routes one complete UDP payload that arrived on `path`. Pass the same datagram and path to an
    /// accepted or existing connection. The caller supplies space for the stateless reply, which
    /// goes back on `path`. A 1,200-byte buffer fits every reply.
    pub fn route(&mut self, path: Path, bytes: &[u8], reply: &mut [u8], now: Instant) -> Result<Route, Error> {
        let peer = path.peer;
        if self.resets != 0
            && let Some(tail) = reset_suffix(bytes)
        {
            let key = Key::Reset(peer, *tail);
            // Only a match of the secret table hash pays for a full token check.
            if let Some(h) = self.routes.checked(&key, |found| matches!(found, Key::Reset(addr, expected) if *addr == peer && self.keys.matches_reset(expected, tail))) {
                let entry = self.slots[usize::from(h.slot)].entry.as_mut().expect("a live reset token has an owner");
                entry.connection.stateless_reset(now)?;
                return Ok(Route::Reset(h))
            }
        }
        let Ok(header) = Header::parse(bytes, keys::CID_BYTES) else {
            return Ok(Route::Dropped);
        };
        let rng = self.config.config.provider().secure_random;
        let Header::Protected {
            kind,
            dcid,
            scid,
            ref token,
            ..
        } = header
        else {
            if bytes.len() >= 1200 && matches!(header, Header::Unsupported { .. }) {
                let len = tls::scoped(self.stream.as_ref(), || {
                    packet::negotiation(reply, (bytes, &header), rng)
                })
                .map_err(build)?;
                return Ok(len.map_or(Route::Dropped, Route::Reply));
            }
            return Ok(Route::Dropped);
        };
        if kind == PacketKind::Initial && bytes.len() < 1200 {
            return Ok(Route::Dropped);
        }
        // The connection decides what a datagram from a new address means (RFC 9000, section 9).
        if let Some(handle) = self.routes.get(&Key::Local(dcid)) {
            return Ok(Route::Existing(handle));
        }
        if kind != PacketKind::Initial {
            if kind == PacketKind::OneRtt && bytes.len() > 21 && self.keys.worker(&dcid) == Some(self.worker) {
                let max = (bytes.len() - 1).min(43);
                let out = reply.get_mut(..max).ok_or_else(|| build(packet::BuildError::Full))?;
                tls::scoped(self.stream.as_ref(), || rng.fill(out)).map_err(|_| RANDOM)?;
                let min = (22 + keys::CID_BYTES).min(max);
                let len = min + usize::from(out[0]) % (max - min + 1);
                out[0] = (out[0] & 0x3f) | 0x40;
                out[len - 16..len].copy_from_slice(&self.keys.reset(&dcid));
                return Ok(Route::Reply(len));
            }
            return Ok(Route::Dropped);
        }
        if let Some(h) = self.routes.get(&Key::Initial(peer, dcid)) {
            return Ok(Route::Existing(h));
        }
        let Some(index) = self.free.filter(|_| self.handshakes < self.limits.handshakes_max) else {
            return Ok(Route::Refused);
        };
        if dcid.as_bytes().len() < 8 {
            return Ok(Route::Dropped);
        }
        let clock = self.config.config.time_provider.current_time().ok_or(TIME)?.as_secs();
        let raw = &bytes[token.clone()];
        let proof = self.keys.open(raw, peer, clock, &self.budget)?;
        if matches!(proof, Some(Proof::Retry { retry, .. }) if retry != dcid)
            || (raw.first() == Some(&1) && proof.is_none())
        {
            return Ok(Route::Dropped);
        }
        if proof.is_none() && self.handshakes >= self.limits.retry_at {
            let len = tls::scoped(self.stream.as_ref(), || {
                let retry = self.keys.issue(self.worker, rng)?;
                let token = self
                    .keys
                    .seal(Proof::Retry { original: dcid, retry }, peer, clock, rng, &self.budget)?;
                packet::retry(reply, (&scid, &retry, &dcid), token.bytes(), rng).map_err(build)
            })?;
            return Ok(Route::Reply(len));
        }
        let storage = self
            .budget
            .reserve(Layout::new::<Connection>().size() as u64 + Budget::ALLOCATION_BYTES)
            .map_err(|_| NO_ROOM)?;
        let budget = Budget::try_new(self.limits.connection_bytes_max).map_err(|_| NO_ROOM)?;
        let issuer = Issuer {
            worker: self.worker,
            peer,
            keys: Arc::clone(&self.keys),
        };
        let conn = Connection::server_admitted(
            &self.config,
            &header,
            Some((issuer, proof)),
            path,
            self.connection_limits,
            &budget,
            now,
        )?;
        let ids = conn.local_ids();
        let connection = Box::try_new(conn).map_err(|_| NO_ROOM)?;
        let slot = &mut self.slots[usize::from(index)];
        let handle = Handle {
            slot: index,
            generation: slot.generation,
        };
        for cid in ids.into_iter().flatten() {
            assert!(
                self.routes.insert(Key::Local(cid), handle),
                "the issuer never repeats a nonce"
            );
        }
        assert!(
            self.routes.insert(Key::Initial(peer, dcid), handle),
            "an existing Initial alias routes before admission"
        );
        self.free = slot.free;
        self.handshakes += 1;
        slot.entry = Some(Registered {
            connection,
            initial: Some(Key::Initial(peer, dcid)),
            ids,
            reset: None,
            _storage: storage,
        });
        Ok(Route::Accepted(handle))
    }

    /// Operates on the connection, then updates its routes and admission slot before the next datagram.
    /// Returns `None` for a removed handle.
    pub fn with_connection<T>(&mut self, h: Handle, work: impl FnOnce(&mut Connection) -> T) -> Option<T> {
        let slot = self
            .slots
            .get_mut(usize::from(h.slot))
            .filter(|s| s.generation == h.generation)?;
        let entry = slot.entry.as_mut()?;
        let result = work(&mut entry.connection);
        let ids = entry.connection.local_ids();
        if ids != entry.ids {
            for old in entry.ids.into_iter().flatten().filter(|old| !ids.contains(&Some(*old))) {
                self.routes.remove(&Key::Local(old));
            }
            for new in ids.into_iter().flatten().filter(|new| !entry.ids.contains(&Some(*new))) {
                assert!(
                    self.routes.insert(Key::Local(new), h),
                    "the issuer never repeats a nonce"
                );
            }
            entry.ids = ids;
        }
        let peer = entry.connection.path().peer;
        let reset = entry.connection.used_reset().map(|token| (peer, token));
        if reset != entry.reset {
            if let Some((peer, token)) = entry.reset.take() {
                self.routes.remove(&Key::Reset(peer, token));
                self.resets -= 1;
            }
            if let Some((peer, token)) = reset
                && self.routes.insert(Key::Reset(peer, token), h)
            {
                entry.reset = reset;
                self.resets += 1;
            }
        }
        if (entry.connection.is_confirmed() || entry.connection.ended())
            && let Some(initial) = entry.initial.take()
        {
            self.routes.remove(&initial);
            self.handshakes -= 1;
        }
        Some(result)
    }

    /// Drops the connection, its routes, and its admission slot. A stale handle returns false.
    pub fn remove(&mut self, h: Handle) -> bool {
        let Some(slot) = self
            .slots
            .get_mut(usize::from(h.slot))
            .filter(|s| s.generation == h.generation)
        else {
            return false;
        };
        let Some(entry) = slot.entry.take() else { return false };
        for cid in entry.ids.into_iter().flatten() {
            self.routes.remove(&Key::Local(cid));
        }
        if let Some(initial) = entry.initial {
            self.routes.remove(&initial);
            self.handshakes -= 1;
        }
        if let Some((peer, token)) = entry.reset {
            self.routes.remove(&Key::Reset(peer, token));
            self.resets -= 1;
        }
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            slot.free = self.free;
            self.free = Some(h.slot);
        }
        true
    }
}

pub(super) fn reset_suffix(datagram: &[u8]) -> Option<&[u8; 16]> {
    if datagram.len() < 21 {
        return None;
    }
    datagram.last_chunk()
}

fn build(error: packet::BuildError) -> Error {
    match error {
        packet::BuildError::Full => Error::new(Kind::Misuse, "the buffer has no room for the QUIC reply"),
        _ => RANDOM,
    }
}
