//! Address proofs and encrypted worker routes. The provider owns every cryptographic operation.

use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rscrypto_rustls::quic::{
    AddressTokenKey, FirstOctet, LoadBalancerConfig, LoadBalancerKey, RotationId, StatelessResetKey,
};
use rstypes::capacity::Budget;
use rustls::crypto::SecureRandom;

use super::{NO_ROOM, RANDOM};
use crate::drive::{Error, Kind};
use crate::quic::{ConnectionId, Reader};
use crate::tls;

pub(super) const CID_BYTES: usize = 17;
const TOKEN_MAX: usize = 1 + 8 + 2 * (1 + ConnectionId::MAX) + AddressTokenKey::OVERHEAD;
const RETRY: u8 = 1;
const REPEAT: u8 = 2;
/// The seconds that a Retry token and a NEW_TOKEN token are valid.
const RETRY_LIFETIME: u64 = 10;
const REPEAT_LIFETIME: u64 = 24 * 60 * 60;
/// The bytes at the end of a token that name it: the nonce that sealed it.
const NONCE_BYTES: usize = 16;
/// The bits that the record of redeemed tokens sets for each token. With at most one token for
/// each 10 bits, a token that was not redeemed looks redeemed with a chance below 1%.
const PROBES: u64 = 7;
const BITS_PER_TOKEN: u64 = 10;
/// The live endpoints of one set of keys, each with its own worker number.
pub const ENDPOINT_WORKERS_MAX: usize = 1024;
/// The memory of the record of redeemed tokens that [`EndpointKeys::generate`] suggests: about
/// 1.6 million tokens in each day of the token lifetime.
pub const REDEEMED_BYTES_DEFAULT: NonZeroUsize = NonZeroUsize::new(4 << 20).expect("4 MiB is positive");

/// Keys shared by endpoints of one service. Keep them across endpoint replacement.
/// A connection ID carries an eight-byte worker number and a unique eight-byte nonce.
///
/// At most one live [`Endpoint`](super::Endpoint) holds each worker number, because an endpoint
/// sends a stateless reset for each connection ID of its worker that it does not know (RFC 9000,
/// section 21.11). To replace an endpoint that keeps its connections while they drain, give the
/// new one another worker number. To replace an endpoint that lost its state, drop it first.
///
/// Each address token that the endpoints of these keys issue validates one handshake (RFC 9000,
/// section 8.1.4). The keys keep a record of the redeemed tokens: a later use of a token gets
/// normal address validation. The retransmissions of one handshake reach its connection, so they
/// keep its proof.
pub struct EndpointKeys {
    route: LoadBalancerConfig,
    reset: StatelessResetKey,
    address: AddressTokenKey,
    lookup: rscrypto::SecretBytes<32>,
    start: u64,
    issued: AtomicU64,
    /// The worker number of each live endpoint, with room for [`ENDPOINT_WORKERS_MAX`].
    workers: Mutex<Vec<u64>>,
    redeemed: Mutex<Redeemed>,
}

/// The tokens that validated a handshake: one Bloom filter for each period of the NEW_TOKEN
/// lifetime, of the tokens that were issued in it. A token is valid for one lifetime at most, so
/// a filter of a period two periods back holds only expired tokens, and the next period clears
/// it. A Retry token is valid for less time, and goes in the filter of its period too.
///
/// A filter that holds as many tokens as its bits allow refuses each later token of its period,
/// and so does a token whose bits a false positive set: the client then gets normal address
/// validation, never a failure.
struct Redeemed {
    /// The bits of each filter.
    bits: [Vec<u64>; 2],
    /// The period of the tokens in each filter, and how many it holds.
    periods: [Option<u64>; 2],
    tokens: [u64; 2],
}

impl Redeemed {
    /// Two filters of half of `bytes` each.
    fn new(bytes: NonZeroUsize) -> Result<Self, Error> {
        let words = (bytes.get() / (2 * size_of::<u64>())).max(1);
        let filter = || {
            let mut bits = Vec::new();
            bits.try_reserve_exact(words).map_err(|_| {
                Error::new(
                    Kind::Overload,
                    "the memory for the record of QUIC tokens is not available",
                )
            })?;
            bits.resize(words, 0);
            Ok::<_, Error>(bits)
        };
        Ok(Self {
            bits: [filter()?, filter()?],
            periods: [None; 2],
            tokens: [0; 2],
        })
    }

    /// Records the token with `nonce` that was issued at `issued`, and gives whether this is its
    /// first use. A token of a period that a newer one replaced is refused: it expired.
    fn first_use(&mut self, nonce: &[u8; NONCE_BYTES], issued: u64) -> bool {
        let period = issued / REPEAT_LIFETIME;
        let at = usize::from(period % 2 == 1);
        match self.periods[at] {
            Some(held) if held > period => return false,
            Some(held) if held == period => {}
            _ => {
                self.bits[at].fill(0);
                (self.periods[at], self.tokens[at]) = (Some(period), 0);
            }
        }
        let bits = &mut self.bits[at];
        let len = bits.len() as u64 * u64::from(u64::BITS);
        if self.tokens[at] >= len / BITS_PER_TOKEN {
            return false;
        }
        // The nonce came from the entropy of the service, and a token that opens proves that the
        // service drew it, so its halves give the places of the bits with no hash.
        let (low, high) = nonce.split_at(NONCE_BYTES / 2);
        let start = u64::from_le_bytes(low.try_into().expect("a half nonce has 8 bytes"));
        let step = u64::from_le_bytes(high.try_into().expect("a half nonce has 8 bytes"));
        let mut redeemed = true;
        for probe in 0..PROBES {
            let hash = start.wrapping_add(probe.wrapping_mul(step));
            // The high half of the product maps the hash onto the bits with no division.
            let bit = ((u128::from(hash) * u128::from(len)) >> 64) as u64;
            let (word, mask) = ((bit / 64) as usize, 1 << (bit % 64));
            redeemed &= bits[word] & mask != 0;
            bits[word] |= mask;
        }
        self.tokens[at] += u64::from(!redeemed);
        !redeemed
    }
}

/// The worker number of a live endpoint. It frees the number when it drops.
pub(super) struct Claim {
    keys: Arc<EndpointKeys>,
    worker: u64,
}

impl Drop for Claim {
    fn drop(&mut self) {
        let mut workers = self.keys.workers.lock().unwrap_or_else(PoisonError::into_inner);
        let at = workers
            .iter()
            .position(|&worker| worker == self.worker)
            .expect("a live claim holds its worker number");
        workers.swap_remove(at);
    }
}

impl core::fmt::Debug for EndpointKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EndpointKeys").finish_non_exhaustive()
    }
}

impl EndpointKeys {
    /// Generates independent keys from the configuration's entropy. The rotation code is 0 through
    /// 6. The record of redeemed tokens takes `redeemed_bytes` of memory: give 2.5 bytes for each
    /// token that the service redeems in a day, or [`REDEEMED_BYTES_DEFAULT`]. Refuses with
    /// [`Kind::Overload`] when the memory is not available.
    pub fn generate(config: &tls::ServerConfig, rotation: u8, redeemed_bytes: NonZeroUsize) -> Result<Self, Error> {
        let rotation = RotationId::new(rotation).ok_or(Error::new(Kind::Misuse, "invalid QUIC route key rotation"))?;
        let rng = config.config.provider().secure_random;
        let stream = config.entropy.stream(b"quic-key");
        tls::scoped(stream.as_ref(), || {
            let key = LoadBalancerKey::generate(rng).map_err(|_| RANDOM)?;
            let mut start = [0; 8];
            rng.fill(&mut start).map_err(|_| RANDOM)?;
            let mut workers = Vec::new();
            workers
                .try_reserve_exact(ENDPOINT_WORKERS_MAX)
                .map_err(|_| Error::new(Kind::Overload, "the memory for the QUIC worker list is not available"))?;
            Ok(Self {
                route: LoadBalancerConfig::new(rotation, 8, 8, FirstOctet::Random, key)
                    .expect("a worker number and nonce fill one AES block"),
                reset: StatelessResetKey::generate(rng).map_err(|_| RANDOM)?,
                address: AddressTokenKey::generate(rng).map_err(|_| RANDOM)?,
                lookup: rscrypto::SecretBytes::try_fill_with(|b| rng.fill(b)).map_err(|_| RANDOM)?,
                start: u64::from_be_bytes(start),
                issued: AtomicU64::new(0),
                workers: Mutex::new(workers),
                redeemed: Mutex::new(Redeemed::new(redeemed_bytes)?),
            })
        })
    }

    /// Claims `worker` for a new endpoint. Refuses while another live endpoint of these keys
    /// holds it, or while [`ENDPOINT_WORKERS_MAX`] endpoints are live.
    pub(super) fn claim(self: &Arc<Self>, worker: u64) -> Result<Claim, Error> {
        let mut workers = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
        if workers.contains(&worker) {
            return Err(Error::new(
                Kind::Misuse,
                "a live QUIC endpoint of these keys has this worker number: drop it, or give another number",
            ));
        }
        if workers.len() >= ENDPOINT_WORKERS_MAX {
            return Err(Error::new(Kind::Overload, "the QUIC keys have the most live endpoints"));
        }
        workers.push(worker);
        Ok(Claim {
            keys: Arc::clone(self),
            worker,
        })
    }

    /// Decodes the worker of this rotation. A decoded route does not authenticate its sender.
    pub fn worker(&self, id: &ConnectionId) -> Option<u64> {
        let route = self.route.decode(id.as_bytes())?;
        Some(u64::from_be_bytes(route.as_slice().try_into().ok()?))
    }

    pub(super) fn issue(&self, worker: u64, rng: &dyn SecureRandom) -> Result<ConnectionId, Error> {
        // Only uniqueness depends on the counter. The counter publishes no other data.
        let sequence = self
            .issued
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::new(Kind::Overload, "the QUIC route key exhausted its nonces"))?;
        let nonce = self.start.wrapping_add(sequence).to_be_bytes();
        let id = self
            .route
            .encode(&worker.to_be_bytes(), &nonce, rng)
            .map_err(|_| RANDOM)?;
        Ok(ConnectionId::new(id.as_slice()).expect("a QUIC-LB connection ID fits version one"))
    }

    pub(super) fn reset(&self, id: &ConnectionId) -> [u8; 16] {
        self.reset.token(id.as_bytes())
    }

    pub(super) fn matches_reset(&self, expected: &[u8; 16], tail: &[u8; 16]) -> bool {
        let key = self.lookup.as_bytes();
        rscrypto::HmacSha256::verify_tag(key, tail, &rscrypto::HmacSha256::mac(key, expected)).is_ok()
    }

    pub(super) fn seal(
        &self,
        proof: Proof,
        peer: SocketAddr,
        now: u64,
        rng: &dyn SecureRandom,
        budget: &Budget,
    ) -> Result<Token, Error> {
        let _permit = budget
            .reserve(TOKEN_MAX as u64 + tls::memory::RECORD_KEY)
            .map_err(|_| NO_ROOM)?;
        let mut data = Vec::new();
        data.try_reserve_exact(TOKEN_MAX).map_err(|_| NO_ROOM)?;
        data.extend_from_slice(&now.to_be_bytes());
        if let Proof::Retry { original, retry } = proof {
            for cid in [original, retry] {
                data.push(u8::try_from(cid.as_bytes().len()).expect("a CID length fits one octet"));
                data.extend_from_slice(cid.as_bytes());
            }
        }
        let tag = proof.tag();
        self.address
            .seal(rng, &mut data, &context(tag, peer))
            .map_err(|_| RANDOM)?;
        let mut token = Token {
            bytes: [0; TOKEN_MAX],
            len: data.len() + 1,
        };
        token.bytes[0] = tag;
        token.bytes[1..token.len].copy_from_slice(&data);
        Ok(token)
    }

    /// Opens the token `wire` that came from `peer` at the time `now`. Gives its proof on its first
    /// use, and `None` for a token that is not valid, expired, or validated a handshake before.
    pub(super) fn open(
        &self,
        wire: &[u8],
        peer: SocketAddr,
        now: u64,
        budget: &Budget,
    ) -> Result<Option<Proof>, Error> {
        let Some((&tag @ (RETRY | REPEAT), ciphertext)) = wire.split_first() else {
            return Ok(None);
        };
        if wire.len() > TOKEN_MAX || ciphertext.len() < AddressTokenKey::OVERHEAD + 8 {
            return Ok(None);
        }
        let _permit = budget.reserve(tls::memory::RECORD_KEY).map_err(|_| NO_ROOM)?;
        let mut buf = [0; TOKEN_MAX];
        buf[..ciphertext.len()].copy_from_slice(ciphertext);
        let Ok(plain) = self.address.open(&mut buf[..ciphertext.len()], &context(tag, peer)) else {
            return Ok(None);
        };
        let mut r = Reader::new(plain);
        let Some(issued) = r.array().map(u64::from_be_bytes) else {
            return Ok(None);
        };
        let lifetime = if tag == RETRY { RETRY_LIFETIME } else { REPEAT_LIFETIME };
        if now.checked_sub(issued).is_none_or(|age| age > lifetime) {
            return Ok(None);
        }
        let mut cid = || {
            let len = usize::from(r.u8()?);
            ConnectionId::new(r.take(len)?)
        };
        let proof = if tag == RETRY {
            let (Some(original), Some(retry)) = (cid(), cid()) else {
                return Ok(None);
            };
            Proof::Retry { original, retry }
        } else {
            Proof::Repeat
        };
        if r.at() != plain.len() {
            return Ok(None);
        }
        let nonce = wire.last_chunk().expect("an open token ends with its nonce");
        let mut redeemed = self.redeemed.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(redeemed.first_use(nonce, issued).then_some(proof))
    }
}

/// Bind Retry to the UDP port as well as the IP. A repeat connection can use a new port.
fn context(tag: u8, peer: SocketAddr) -> [u8; 20] {
    let mut aad = [0; 20];
    aad[0] = tag;
    match peer.ip() {
        core::net::IpAddr::V4(ip) => {
            aad[1] = 4;
            aad[2..6].copy_from_slice(&ip.octets());
        }
        core::net::IpAddr::V6(ip) => {
            aad[1] = 6;
            aad[2..18].copy_from_slice(&ip.octets());
        }
    }
    if tag == RETRY {
        aad[18..].copy_from_slice(&peer.port().to_be_bytes());
    }
    aad
}

#[derive(Clone, Copy)]
pub(in crate::quic) enum Proof {
    Retry {
        original: ConnectionId,
        retry: ConnectionId,
    },
    Repeat,
}

impl Proof {
    fn tag(self) -> u8 {
        match self {
            Self::Retry { .. } => RETRY,
            Self::Repeat => REPEAT,
        }
    }
}

pub(in crate::quic) struct Token {
    bytes: [u8; TOKEN_MAX],
    len: usize,
}

impl Token {
    pub(in crate::quic) fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
