//! The charge of the memory of rustls, which allocates with the global allocator and takes no
//! budget. The core charges a bound of each part before rustls can allocate it:
//!
//! - **State.** Before rustls starts, a connection charges the state that its configuration
//!   fixes: the key shares, the transcript, and the key schedule.
//! - **Calls.** Before each rustls call, it also charges the working memory of the call: a part
//!   for its own chain, and a factor times the bytes that rustls can read. After the call, it
//!   keeps a bound of the chain of the peer that rustls can keep, and gives the rest back. The
//!   output has its own charge: before a call, the growth of the bytes that the call can write,
//!   and after the call, its capacity.
//! - **Kernel.** At the hand-off, the charge drops to the state of the kernel connection, and on a
//!   client to the exact size of the chain that rustls keeps for its tickets.
//! - **Sessions.** The stores of a configuration charge each session to the budget of the
//!   configuration. When rustls takes a session, the store charge ends, and the store charges the
//!   session and its later copies to the connection, or gives no session.
//!
//! Each bound holds for the decoders of rustls 0.24.0-dev.3 with the provider of rscrypto. The test
//! `tests/tls_memory.rs` checks each one at each allocation, so a new rustls needs that test again.

use core::cell::RefCell;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use rstypes::capacity::{Budget, Credit, Permit};
use rustls::client::{ClientSessionKey, ClientSessionStore, Tls12Session, Tls13Session};
use rustls::crypto::kx::NamedGroup;
use rustls::crypto::{Identity, VerifiedIdentity};
use rustls::pki_types::CertificateDer;
use rustls::server::{ServerSessionKey, StoresServerSessions};

use crate::drive::{Error, Kind};

/// The bytes that one call of a client can decode for each byte that it reads. rustls decodes the
/// ECH retry configurations of EncryptedExtensions also when the client offered no ECH: 112 bytes
/// for each entry of 4 bytes, in a list whose capacity can be twice its length.
const READ_CLIENT: u64 = 2 * 112 / 4;
/// The same for a server: the ALPN names and the PSK binders of a ClientHello, 24 bytes for each
/// entry of 2 bytes, doubled.
const READ_SERVER: u64 = 2 * 24 / 2;
/// The bytes that rustls can keep after a call for the chain of the peer, for each byte that one
/// call read: three copies of a certificate of one byte, 25 bytes each, from an entry of 6 bytes,
/// and the transcript of an end with client authentication, which keeps each message of the peer
/// in a list whose capacity can be twice its length, for at most two messages before its last call.
const KEPT: u64 = 3 * 25 / 6 + 2 * 2 + 1;
/// The working memory of a call that does not depend on its bytes: a key exchange, a signature
/// and its check, and the key schedule.
const CALL: u64 = 16 * 1024;
/// The state of a client handshake: the key shares of X25519MLKEM768 and X25519, the transcript,
/// and the key schedule.
const CLIENT_STATE: u64 = 20 * 1024;
/// The state of a client handshake for each ALPN name that it offers, and for each byte of a name.
const PROTOCOL: u64 = 96;
const PROTOCOL_BYTE: u64 = 4;
/// The state of a server handshake.
const SERVER_STATE: u64 = 4 * 1024;
/// The state that a server adds when it asks for a client certificate.
const SERVER_AUTH_STATE: u64 = 8 * 1024;
/// The working memory of a call that sends the own chain, for each certificate and each byte.
const OWN: u64 = 128;
const OWN_BYTE: u64 = 2;
/// The bytes that one call writes besides the own chain: a ServerHello with its ML-KEM
/// ciphertext, a ClientHello, a Finished, session tickets, and alerts, with their records.
const FLIGHT: usize = 4 * 1024;
/// The state of the kernel connection of each end after the handshake, with the working memory of
/// a KeyUpdate and of a session ticket.
const KERNEL_CLIENT: u64 = 1024;
const KERNEL_SERVER: u64 = 512;
/// A ticket in the client store besides its chain and its ticket: the shared parts, the secret,
/// the server name, and the ALPN name.
const TICKET: u64 = 1024;
/// A session in the server store besides its encoded value.
const SESSION: u64 = 256;

/// What the configuration of one end fixes for each of its connections.
#[derive(Clone, Copy, Debug)]
pub(super) struct Cost {
    /// The state of a handshake.
    state: u64,
    /// The bytes that a call can decode for each byte that it reads.
    pub(super) read: u64,
    /// The factor of the chain of the peer that rustls keeps between calls, or 0 when the peer
    /// sends no chain.
    kept: u64,
    /// Whether rustls keeps a copy of each handshake message for client authentication: a
    /// client with an identity, and a server that asks for one.
    transcript: bool,
    /// The state of the kernel connection.
    pub(super) kernel: u64,
}

impl Cost {
    /// The cost of a client that offers `protocols`, and shows an identity when it has one.
    pub(super) fn client(protocols: &[&[u8]], identity: bool) -> Self {
        let bytes: usize = protocols.iter().map(|name| name.len()).sum();
        Self {
            state: CLIENT_STATE + PROTOCOL * protocols.len() as u64 + PROTOCOL_BYTE * bytes as u64,
            read: READ_CLIENT,
            kept: KEPT,
            transcript: identity,
            kernel: KERNEL_CLIENT,
        }
    }

    /// The cost of a server, which asks for a client chain to `client_roots` when it has some.
    pub(super) fn server(client_roots: Option<&[CertificateDer<'_>]>) -> Self {
        let roots: usize = client_roots.unwrap_or_default().iter().map(|root| root.len()).sum();
        Self {
            state: SERVER_STATE + client_roots.map_or(0, |_| SERVER_AUTH_STATE + 2 * roots as u64),
            read: READ_SERVER,
            kept: client_roots.map_or(0, |_| KEPT),
            transcript: client_roots.is_some(),
            kernel: KERNEL_SERVER,
        }
    }
}

/// The part of the working memory and of the output of a call for what this end sends from its
/// configuration: its own chain, and the trust roots that a server names in its
/// CertificateRequest.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Own {
    /// The working memory.
    work: u64,
    /// The bytes that a call can write besides [`FLIGHT`].
    flight: usize,
}

impl Own {
    /// The part for `ders`.
    pub(super) fn new(ders: &[CertificateDer<'_>]) -> Self {
        let bytes: usize = ders.iter().map(|der| der.len()).sum();
        Self {
            work: OWN * ders.len() as u64 + OWN_BYTE * bytes as u64,
            // Each certificate entry has a 3-byte length and 2 bytes of extensions, and each record
            // of 2^14 bytes has 22 bytes of header, content type, and tag.
            flight: bytes + 5 * ders.len() + bytes / 512,
        }
    }

    /// The part for `bytes` more that a call writes, as the ALPN names of a ClientHello.
    pub(super) fn plus_bytes(self, bytes: usize) -> Self {
        Self {
            flight: self.flight + bytes,
            ..self
        }
    }

    /// The sum of two parts.
    pub(super) fn plus(self, other: Self) -> Self {
        Self {
            work: self.work + other.work,
            flight: self.flight + other.flight,
        }
    }

    /// The working memory of a call that reads `visible` bytes, with the factor `read`.
    pub(super) fn work(&self, read: u64, visible: usize) -> u64 {
        (CALL + self.work).saturating_add(read.saturating_mul(visible as u64))
    }

    /// The bytes that one call can write.
    pub(super) fn flight(&self) -> usize {
        FLIGHT + self.flight
    }

    /// The copy of what this end sends that a transcript for client authentication keeps.
    fn transcript(&self) -> u64 {
        2 * self.flight() as u64
    }
}

/// The part of the own chain of a configuration. A rotation of the identity of a server only
/// raises it, so a call charges enough also when the identity changes while it runs.
#[derive(Debug, Default)]
pub(super) struct Owns {
    work: AtomicU64,
    flight: AtomicUsize,
}

impl Owns {
    pub(super) fn new(own: Own) -> Self {
        Self {
            work: AtomicU64::new(own.work),
            flight: AtomicUsize::new(own.flight),
        }
    }

    /// Raises the part to cover `own` too.
    pub(super) fn raise(&self, own: Own) {
        // Ordering: each part is a bound on its own; nothing else depends on the order.
        self.work.fetch_max(own.work, Ordering::Relaxed);
        self.flight.fetch_max(own.flight, Ordering::Relaxed);
    }

    pub(super) fn get(&self) -> Own {
        Own {
            work: self.work.load(Ordering::Relaxed),
            flight: self.flight.load(Ordering::Relaxed),
        }
    }
}

/// The bytes that one copy of the chain of `identity` holds: each certificate, and the list of
/// the intermediate certificates.
pub(super) fn chain_bytes(identity: Option<&VerifiedIdentity<'_>>) -> u64 {
    let bytes = match identity.map(|identity| identity.identity()) {
        Some(Identity::X509(chain)) => {
            chain.end_entity.len()
                + chain.intermediates.iter().map(|der| der.len()).sum::<usize>()
                + chain.intermediates.len() * size_of::<CertificateDer<'_>>()
        }
        Some(Identity::RawPublicKey(key)) => key.len(),
        // The verifiers of a configuration give an X.509 chain or none.
        _ => 0,
    };
    bytes as u64
}

/// The charge of the rustls memory of one connection: the state of its handshake, and after the
/// hand-off the state of its kernel connection.
pub(super) struct Held {
    budget: Budget,
    credit: Credit,
    /// The state that the configuration fixes, until the hand-off.
    state: u64,
    /// The factor of the chain that rustls keeps between calls.
    kept: u64,
    /// Whether rustls keeps a transcript for client authentication.
    transcript: bool,
    /// The bound of the chain of the peer that rustls keeps between calls.
    chain: u64,
    /// What the stores gave to rustls, until the hand-off.
    sessions: u64,
}

impl Held {
    /// Charges the state of a handshake of `cost` and the working memory of its first call, which
    /// sends `own`, or refuses with [`Kind::Overload`].
    pub(super) fn new(budget: &Budget, cost: &Cost, state: u64, own: &Own) -> Result<Self, Error> {
        let mut credit = budget.credit(0);
        let state = cost.state + state;
        let transcript = if cost.transcript { own.transcript() } else { 0 };
        credit
            .charge(state + transcript + CALL)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the state of a TLS handshake"))?;
        Ok(Self {
            budget: budget.clone(),
            credit,
            state,
            kept: cost.kept,
            transcript: cost.transcript,
            chain: 0,
            sessions: 0,
        })
    }

    /// Charges the working memory of the next call, or gives the units that it needs.
    pub(super) fn charge(&mut self, work: u64) -> Result<(), u64> {
        self.credit.charge(work).map_err(|_| work)
    }

    /// Gives back the working memory of a call that read `visible` bytes and sent `own`, and keeps
    /// the bound of what rustls can keep.
    pub(super) fn after(&mut self, visible: usize, own: &Own) {
        self.chain = self.chain.max(self.kept.saturating_mul(visible as u64));
        self.keep(self.state + self.transcript(own) + self.chain + self.sessions);
    }

    /// After the last call of the handshake that sent `own`: rustls keeps two copies of the chain
    /// of `peer`, one for each later ticket and one for the facts of the connection, until the
    /// hand-off.
    pub(super) fn finished(&mut self, peer: u64, own: &Own) {
        self.keep(self.state + self.transcript(own) + 2 * peer + self.sessions);
    }

    /// The transcript for client authentication: a copy of what this end sends.
    fn transcript(&self, own: &Own) -> u64 {
        if self.transcript { own.transcript() } else { 0 }
    }

    /// At the hand-off: the state of the kernel connection, with `peer` bytes of chain that it keeps.
    pub(super) fn hand_off(&mut self, kernel: u64, peer: u64) {
        self.state = 0;
        self.chain = 0;
        self.sessions = 0;
        self.keep(kernel + peer);
    }

    /// Gives back each charged unit above `kept`.
    fn keep(&mut self, kept: u64) {
        let rest = self.credit.charged().saturating_sub(kept);
        let refunded = self.credit.refund(rest);
        assert!(refunded.is_ok(), "a credit refunds at most its charged units");
    }
}

/// What a session store reaches while rustls runs one call of a connection.
enum Call {
    /// A call of the handshake. A store charges a session that it gives to rustls to the credit,
    /// and the ClientHello that carries a ticket to the output.
    Handshake {
        credit: Credit,
        output: Credit,
        sessions: u64,
    },
    /// The hand-off of a session ticket to the client store, with its charge.
    Ticket(Ticket),
}

thread_local! {
    /// The call that runs on this thread, if any.
    static RUNNING: RefCell<Option<Call>> = const { RefCell::new(None) };
}

/// Runs `f`, a call of the handshake, with the credit of `held` and the charge `output` of the
/// output in the reach of the stores. Both charges come from the budget of `held`.
pub(super) fn handshake<R>(held: &mut Held, output: &mut Credit, f: impl FnOnce() -> R) -> R {
    let call = Call::Handshake {
        credit: core::mem::replace(&mut held.credit, held.budget.credit(0)),
        output: core::mem::replace(output, held.budget.credit(0)),
        sessions: 0,
    };
    let (result, call) = run(call, f);
    if let Some(Call::Handshake {
        credit,
        output: taken,
        sessions,
    }) = call
    {
        held.credit = credit;
        *output = taken;
        held.sessions += sessions;
    }
    result
}

/// Runs `f`, which gives a session ticket to rustls, with its charge `ticket` for the store.
pub(super) fn ticket<R>(ticket: Ticket, f: impl FnOnce() -> R) -> R {
    run(Call::Ticket(ticket), f).0
}

/// Runs `f` with `call` in the reach of the stores, and gives the call back. A store borrows the
/// call and never takes it.
fn run<R>(call: Call, f: impl FnOnce() -> R) -> (R, Option<Call>) {
    let before = RUNNING.replace(Some(call));
    assert!(before.is_none(), "a rustls call runs inside no other");
    let result = f();
    let call = RUNNING.take();
    assert!(call.is_some(), "a store leaves the call in place");
    (result, call)
}

/// The charge of a session ticket that the core gives to the client store.
pub(super) struct Ticket {
    charge: Option<Permit>,
    /// The bytes of the chain in the ticket.
    chain: u64,
    /// The bytes of the ticket message.
    message: u64,
}

impl Ticket {
    /// The charge of a ticket that a message of `message` bytes carries to a connection whose peer
    /// showed a chain of `chain` bytes, or `None` when `budget` cannot pay for it.
    pub(super) fn new(budget: &Budget, message: usize, chain: u64) -> Option<Self> {
        let message = message as u64;
        let charge = budget.reserve(TICKET + chain + message).ok()?;
        Some(Self {
            charge: Some(charge),
            chain,
            message,
        })
    }

    fn none() -> Self {
        Self {
            charge: None,
            chain: 0,
            message: 0,
        }
    }
}

/// The sessions of a client configuration: at most `count` tickets, the newest last, each with
/// the charge that the core computed when it gave the ticket to rustls.
pub(super) struct ClientStore {
    budget: Budget,
    tickets: Mutex<Vec<Stored>>,
    /// The charge of the places of the list.
    _places: Permit,
}

struct Stored {
    key: ClientSessionKey<'static>,
    value: Tls13Session,
    charge: Permit,
    chain: u64,
    message: u64,
}

// The stores show no session: each holds the secrets of its tickets.
impl fmt::Debug for ClientStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientStore").finish_non_exhaustive()
    }
}

impl fmt::Debug for ServerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerStore").finish_non_exhaustive()
    }
}

/// A list of `count` places, with its charge to `budget`.
fn places<T>(budget: &Budget, count: usize) -> Result<(Vec<T>, Permit), Error> {
    let bytes = count
        .checked_mul(size_of::<T>())
        .ok_or(Error::new(Kind::Misuse, "the TLS session store is too large"))?;
    let charge = budget
        .reserve(bytes as u64)
        .map_err(|_| Error::new(Kind::Overload, "the budget refused the TLS session store"))?;
    let mut list = Vec::new();
    list.try_reserve_exact(count)
        .map_err(|_| Error::new(Kind::Overload, "the memory for the TLS session store is not available"))?;
    Ok((list, charge))
}

impl ClientStore {
    /// A store of `count` tickets, which charges each ticket to `budget`.
    pub(super) fn new(budget: &Budget, count: usize) -> Result<Self, Error> {
        let (tickets, places) = places(budget, count)?;
        Ok(Self {
            budget: budget.clone(),
            tickets: Mutex::new(tickets),
            _places: places,
        })
    }

    /// The charge of a ticket for this store, as [`Ticket::new`] computes it.
    pub(super) fn charge(&self, message: usize, chain: u64) -> Option<Ticket> {
        Ticket::new(&self.budget, message, chain)
    }
}

impl ClientSessionStore for ClientStore {
    // The client offers a key share for each of its groups, so a hint saves no round trip, and a
    // hint of X25519 removes the hybrid group from each later ClientHello.
    fn set_kx_hint(&self, _: ClientSessionKey<'static>, _: NamedGroup) {}

    fn kx_hint(&self, _: &ClientSessionKey<'_>) -> Option<NamedGroup> {
        None
    }

    // The provider has TLS 1.3 suites only.
    fn set_tls12_session(&self, _: ClientSessionKey<'static>, _: Tls12Session) {}

    fn tls12_session(&self, _: &ClientSessionKey<'_>) -> Option<Tls12Session> {
        None
    }

    fn remove_tls12_session(&self, _: &ClientSessionKey<'static>) {}

    fn insert_tls13_ticket(&self, key: ClientSessionKey<'static>, value: Tls13Session) {
        // A ticket with no charge drops here.
        let Some(Ticket {
            charge: Some(charge),
            chain,
            message,
        }) = RUNNING.with_borrow_mut(|call| match call {
            Some(Call::Ticket(ticket)) => Some(core::mem::replace(ticket, Ticket::none())),
            _ => None,
        })
        else {
            return;
        };
        let mut tickets = self.tickets.lock().unwrap_or_else(PoisonError::into_inner);
        if tickets.len() == tickets.capacity() {
            // The oldest ticket and its charge go.
            drop(tickets.remove(0));
        }
        tickets.push(Stored {
            key,
            value,
            charge,
            chain,
            message,
        });
    }

    fn take_tls13_ticket(&self, key: &ClientSessionKey<'static>) -> Option<Tls13Session> {
        let mut tickets = self.tickets.lock().unwrap_or_else(PoisonError::into_inner);
        let at = tickets.iter().rposition(|stored| stored.key == *key)?;
        let stored = tickets.get(at)?;
        // The connection keeps the ticket and two copies of its chain for the resumed handshake.
        // The ClientHello holds the ticket in its PSK identity, in the encoding for its binder, and
        // in its transcript, the last two in lists whose capacity can be twice their length, and
        // it writes the ticket to the output.
        let work = stored.charge.amount() + 2 * stored.chain + 5 * stored.message;
        let output = 2 * stored.message;
        let paid = RUNNING.with_borrow_mut(|call| match call {
            Some(Call::Handshake {
                credit,
                output: written,
                sessions,
            }) => {
                credit.charge(work).ok()?;
                if written.charge(output).is_err() {
                    let refunded = credit.refund(work);
                    assert!(refunded.is_ok(), "a credit refunds what it charged");
                    return None;
                }
                *sessions += work;
                Some(())
            }
            _ => None,
        });
        paid?;
        Some(tickets.remove(at).value)
    }
}

/// The sessions of a server configuration: at most `count` encoded sessions, the newest last,
/// each charged to the budget of the configuration.
pub(super) struct ServerStore {
    budget: Budget,
    sessions: Mutex<Vec<Session>>,
    /// The charge of the places of the list.
    _places: Permit,
}

struct Session {
    key: Vec<u8>,
    value: Vec<u8>,
    _charge: Permit,
}

impl ServerStore {
    /// A store of `count` sessions, which charges each session to `budget`.
    pub(super) fn new(budget: &Budget, count: usize) -> Result<Self, Error> {
        let (sessions, places) = places(budget, count)?;
        Ok(Self {
            budget: budget.clone(),
            sessions: Mutex::new(sessions),
            _places: places,
        })
    }
}

impl StoresServerSessions for ServerStore {
    fn put(&self, key: ServerSessionKey<'_>, value: Vec<u8>) -> bool {
        // A session that the budget cannot pay for drops, and rustls then sends no ticket.
        let key = key.as_ref();
        let Ok(charge) = self.budget.reserve(SESSION + (key.len() + value.capacity()) as u64) else {
            return false;
        };
        let mut owned = Vec::new();
        if owned.try_reserve_exact(key.len()).is_err() {
            return false;
        }
        owned.extend_from_slice(key);
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        sessions.retain(|session| session.key != owned);
        if sessions.len() == sessions.capacity() {
            drop(sessions.remove(0));
        }
        sessions.push(Session {
            key: owned,
            value,
            _charge: charge,
        });
        true
    }

    // The provider has TLS 1.3 suites only, which take each session one time.
    fn get(&self, _: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        None
    }

    fn take(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let at = sessions.iter().position(|session| session.key == key.as_ref())?;
        let session = sessions.get(at)?;
        // The connection keeps the decoded session and its copies for later tickets until the
        // hand-off: the factor of the decoders bounds them.
        let work = (SESSION + session.value.capacity() as u64)
            .saturating_add(READ_SERVER.saturating_mul(session.value.len() as u64));
        let paid = RUNNING.with_borrow_mut(|call| match call {
            Some(Call::Handshake { credit, sessions, .. }) => {
                credit.charge(work).ok()?;
                *sessions += work;
                Some(())
            }
            _ => None,
        });
        paid?;
        Some(sessions.remove(at).value)
    }

    fn can_cache(&self) -> bool {
        true
    }
}
