//! Address proofs and encrypted worker routes. The provider owns every cryptographic operation.

use core::net::SocketAddr;
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
/// The live endpoints of one set of keys, each with its own worker number.
pub const ENDPOINT_WORKERS_MAX: usize = 1024;

/// Keys shared by endpoints of one service. Keep them across endpoint replacement.
/// A connection ID carries an eight-byte worker number and a unique eight-byte nonce.
///
/// At most one live [`Endpoint`](super::Endpoint) holds each worker number, because an endpoint
/// sends a stateless reset for each connection ID of its worker that it does not know (RFC 9000,
/// section 21.11). To replace an endpoint that keeps its connections while they drain, give the
/// new one another worker number. To replace an endpoint that lost its state, drop it first.
pub struct EndpointKeys {
    route: LoadBalancerConfig,
    reset: StatelessResetKey,
    address: AddressTokenKey,
    lookup: rscrypto::SecretBytes<32>,
    start: u64,
    issued: AtomicU64,
    /// The worker number of each live endpoint, with room for [`ENDPOINT_WORKERS_MAX`].
    workers: Mutex<Vec<u64>>,
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
    /// Generates independent keys from the configuration's entropy. The rotation code is 0 through 6.
    pub fn generate(config: &tls::ServerConfig, rotation: u8) -> Result<Self, Error> {
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
        let lifetime = if tag == RETRY { 10 } else { 24 * 60 * 60 };
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
        Ok((r.at() == plain.len()).then_some(proof))
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
