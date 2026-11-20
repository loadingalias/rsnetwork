//! TLS 1.3 in the core: the configuration of each end, and [`Tls`], the engine that runs an inner
//! engine, for example an HTTP/1.1 server, over TLS records.
//!
//! The host gives [`Tls`] ciphertext, and sends the ciphertext that it writes. rustls, with the
//! cryptography of rscrypto, decrypts each record in place in the region that its bytes arrived
//! in. The inner engine reads the plaintext as views of that region, with no copy. Encryption
//! writes the plaintext of the inner engine into the ciphertext output. [`Copies`] counts each
//! copy by its cause, also the encryption, which each sent byte needs.
//!
//! - **Configuration.** [`ClientConfig`] and [`ServerConfig`] take each choice explicitly: the
//!   trust roots, the identity of each end, ALPN, resumption, and the wall clock that checks the
//!   validity of certificates. The key exchange offers X25519MLKEM768 first and X25519 second, and
//!   a server selects X25519MLKEM768 whenever a client offers it. Each configuration has its own
//!   provider, so nothing installs a provider for the process.
//! - **Receive.** A host receives into the region that
//!   [`host::Connection::region`](crate::host::Connection::region) lends: the tail of the input
//!   region, so a record that continues after a receive joins in place. A region that the host
//!   owns, for example one that the kernel selected, goes to
//!   [`host::Connection::received`](crate::host::Connection::received): a record that continues
//!   into it costs one copy of the rest of that record. A read-only region goes to
//!   [`host::Connection::receive`](crate::host::Connection::receive), and costs one copy of its
//!   bytes.
//! - **Delivery.** The plaintext of a region reaches the inner engine when the region freezes.
//!   When a partial record ends the region, the engine copies the smaller part: the partial
//!   record to a new region, or the plaintext to its own region.
//! - **Resumption.** Sessions resume only in the process that made them ([`Resumption`]).
//! - **0-RTT.** Off: neither end sends or accepts early data.
//! - **End.** A `close_notify` of the peer ends the input of the inner engine. When the transport
//!   ends with no `close_notify`, the inner engine also sees the end, and [`Tls::closure`] reports
//!   [`Closure::Unnotified`]. Only a protocol with its own framing can then tell that no byte is
//!   lost.

use core::fmt;
use core::num::NonZeroUsize;
use core::ops::Range;
use std::sync::{Arc, PoisonError, RwLock};

use rstypes::buffer::{Backing, Buffer as _, BufferMut as _, Lease, WriteLoan};
use rstypes::capacity::{Budget, Credit, Permit};
use rustls::crypto::cipher::OutboundPlain;
use rustls::crypto::{Credentials, Identity as Chain, SelectedCredential, SingleCredential};
use rustls::enums::ApplicationProtocol;
use rustls::error::{AlertDescription, CertificateError, PeerMisbehaved};
use rustls::pki_types::ServerName;
use rustls::server::{
    ClientHello, NoServerSessionStorage, PreferServerOrder, ServerCredentialResolver, ServerSessionMemoryCache,
    Tls13Tickets, WebPkiClientVerifier,
};
use rustls::{ClientSide, HandshakeKind, RootCertStore, ServerSide, SideData, Tcp, TlsInputBuffer};

pub use rustls::pki_types::pem::PemObject;
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
pub use rustls::time_provider::{DefaultTimeProvider, TimeProvider};

use crate::drive::{Blocked, Endpoint, Error, Inbound, Kind, Outbound, Progress, Received, Turn, TurnLimits, Work};
use crate::host::Engine;
use crate::time::Instant;

/// The largest TLS 1.3 record that a peer can send: a 5-byte header, 2^14 bytes of plaintext,
/// and 256 bytes of content type, padding, and tag (RFC 8446, section 5.2).
pub const RECORD_BYTES_MAX: usize = 5 + (1 << 14) + 256;

/// The most plaintext in one record.
const RECORD_PLAINTEXT_MAX: usize = 1 << 14;

/// The bytes that each record of this end adds to its plaintext: the header, the content type,
/// and the 16-byte tag of each suite of the provider.
const RECORD_OVERHEAD: usize = 5 + 1 + 16;

/// The identity that one end shows: its certificate chain, with the end-entity certificate first,
/// and the private key of that certificate.
pub struct Identity {
    /// The certificate chain, end-entity certificate first.
    pub chain: Vec<CertificateDer<'static>>,
    /// The private key of the end-entity certificate.
    pub key: PrivateKeyDer<'static>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// Where sessions can resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resumption {
    /// Nowhere: each connection runs a full handshake.
    Off,
    /// Only in this process, which keeps at most this many sessions. The ticket keys are local to
    /// the process, so another instance, or this one after a restart, runs a full handshake.
    Process(NonZeroUsize),
}

/// The choices of a TLS client.
#[derive(Debug)]
pub struct ClientOptions<'a> {
    /// The roots that the chain of the server must reach. Only these roots are trusted.
    pub roots: &'a [CertificateDer<'a>],
    /// The identity of the client, for a server that asks for one (mTLS), or `None`.
    pub identity: Option<Identity>,
    /// The application protocols to offer, the most preferred first (ALPN). Empty offers none.
    pub protocols: &'a [&'a [u8]],
    /// Where sessions can resume.
    pub resumption: Resumption,
    /// The wall clock that checks the validity of each certificate. [`DefaultTimeProvider`] reads
    /// the clock of the system.
    pub clock: Arc<dyn TimeProvider>,
}

/// The choices of a TLS server.
#[derive(Debug)]
pub struct ServerOptions<'a> {
    /// The identity of the server.
    pub identity: Identity,
    /// The roots that the chain of each client must reach, or `None` when the server asks for no
    /// client certificate. With roots, each client must show a chain to one of them (mTLS).
    pub client_roots: Option<&'a [CertificateDer<'a>]>,
    /// The application protocols that the server accepts, the most preferred first (ALPN). Empty
    /// accepts none, and a client that offers some then gets no selection.
    pub protocols: &'a [&'a [u8]],
    /// Where sessions can resume.
    pub resumption: Resumption,
    /// The wall clock that checks the validity of each client certificate and session.
    pub clock: Arc<dyn TimeProvider>,
}

/// The configuration of TLS clients. Each connection that [`Tls::client`] makes shares it, and
/// its sessions for resumption.
#[derive(Clone)]
pub struct ClientConfig {
    config: Arc<rustls::ClientConfig>,
    resumption: Resumption,
}

impl ClientConfig {
    /// Makes the configuration from `options`. Refuses with [`Kind::Misuse`] when it has no root,
    /// a root or the identity is not valid, or a protocol name is empty or longer than 255 bytes.
    pub fn new(options: ClientOptions<'_>) -> Result<Self, Error> {
        let provider = Arc::new(rscrypto_rustls::default_provider());
        let builder = rustls::ClientConfig::builder_with_details(provider, options.clock)
            .with_root_certificates(roots(options.roots)?);
        let mut config = match options.identity {
            None => builder.with_no_client_auth(),
            Some(identity) => builder.with_client_auth_cert(chain(identity.chain)?, identity.key),
        }
        .map_err(|error| configuration(&error))?;
        config.alpn_protocols = protocols(options.protocols)?;
        config.resumption = match options.resumption {
            Resumption::Off => rustls::client::Resumption::disabled(),
            Resumption::Process(sessions) => rustls::client::Resumption::in_memory_sessions(sessions.get()),
        };
        Ok(Self {
            config: Arc::new(config),
            resumption: options.resumption,
        })
    }

    /// Where the sessions of this configuration can resume.
    pub fn resumption(&self) -> Resumption {
        self.resumption
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("resumption", &self.resumption)
            .finish_non_exhaustive()
    }
}

/// The configuration of TLS servers. Each connection that [`Tls::server`] makes shares it, its
/// identity, and its sessions for resumption.
#[derive(Clone)]
pub struct ServerConfig {
    config: Arc<rustls::ServerConfig>,
    identity: Arc<Rotation>,
    resumption: Resumption,
}

impl ServerConfig {
    /// Makes the configuration from `options`. Refuses with [`Kind::Misuse`] when the identity is
    /// not valid, its key does not match its certificate, a client root is not valid, or a
    /// protocol name is empty or longer than 255 bytes.
    pub fn new(options: ServerOptions<'_>) -> Result<Self, Error> {
        let provider = Arc::new(rscrypto_rustls::default_provider());
        let identity = Arc::new(Rotation(RwLock::new(credential(options.identity, &provider)?)));
        let builder = rustls::ServerConfig::builder_with_details(Arc::clone(&provider), options.clock);
        let builder = match options.client_roots {
            None => builder.with_no_client_auth(),
            Some(client_roots) => builder.with_client_cert_verifier(Arc::new(
                WebPkiClientVerifier::builder(roots(client_roots)?, &provider)
                    .build()
                    .map_err(|_| Error::new(Kind::Misuse, "rustls refused the client roots"))?,
            )),
        };
        let mut config = builder
            .with_server_credential_resolver(Arc::clone(&identity) as Arc<dyn ServerCredentialResolver>)
            .map_err(|error| configuration(&error))?;
        // The order of the server decides: X25519MLKEM768 whenever the client offers it, with a
        // HelloRetryRequest when the client sent no key share for it.
        config.kx_selector = &PreferServerOrder;
        config.alpn_protocols = protocols(options.protocols)?;
        config.session_storage = match options.resumption {
            Resumption::Off => Arc::new(NoServerSessionStorage {}),
            Resumption::Process(sessions) => ServerSessionMemoryCache::new(sessions.get()),
        };
        if options.resumption == Resumption::Off {
            config.send_tls13_tickets = Tls13Tickets { default: 0, max: 0 };
        }
        Ok(Self {
            config: Arc::new(config),
            identity,
            resumption: options.resumption,
        })
    }

    /// Replaces the identity that each later handshake shows. A connection that has started keeps
    /// the identity that it showed. Refuses with [`Kind::Misuse`], and keeps the identity, when
    /// the new one is not valid.
    pub fn rotate(&self, identity: Identity) -> Result<(), Error> {
        let credential = credential(identity, self.config.provider())?;
        *self.identity.0.write().unwrap_or_else(PoisonError::into_inner) = credential;
        Ok(())
    }

    /// Where the sessions of this configuration can resume.
    pub fn resumption(&self) -> Resumption {
        self.resumption
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("resumption", &self.resumption)
            .finish_non_exhaustive()
    }
}

/// The identity that each new handshake of a server shows. [`ServerConfig::rotate`] replaces it.
struct Rotation(RwLock<Arc<SingleCredential>>);

impl ServerCredentialResolver for Rotation {
    fn resolve(&self, hello: &ClientHello<'_>) -> Result<SelectedCredential, rustls::Error> {
        let current = Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner));
        current.resolve(hello)
    }
}

impl fmt::Debug for Rotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rotation")
    }
}

/// The trust store of `roots`. Refuses an empty list and a root that is not a valid certificate.
fn roots(roots: &[CertificateDer<'_>]) -> Result<Arc<RootCertStore>, Error> {
    if roots.is_empty() {
        return Err(Error::new(Kind::Misuse, "the configuration has no trust root"));
    }
    let mut store = RootCertStore::empty();
    for root in roots {
        store
            .add(root.clone().into_owned())
            .map_err(|_| Error::new(Kind::Misuse, "a trust root is not a valid certificate"))?;
    }
    Ok(Arc::new(store))
}

/// The certificate chain of an identity. Refuses an empty chain.
fn chain(chain: Vec<CertificateDer<'static>>) -> Result<Arc<Chain<'static>>, Error> {
    Chain::from_cert_chain(chain)
        .map(Arc::new)
        .map_err(|_| Error::new(Kind::Misuse, "the certificate chain is empty"))
}

/// The credential of a server identity, after a check that the key matches the certificate.
fn credential(identity: Identity, provider: &rustls::crypto::CryptoProvider) -> Result<Arc<SingleCredential>, Error> {
    Credentials::from_der(chain(identity.chain)?, identity.key, provider)
        .map(|credentials| Arc::new(SingleCredential::from(credentials)))
        .map_err(|error| configuration(&error))
}

/// The ALPN names of `protocols`. Refuses a name that is empty or longer than 255 bytes, which
/// the protocol cannot encode (RFC 7301, section 3.1).
fn protocols(protocols: &[&[u8]]) -> Result<Vec<ApplicationProtocol<'static>>, Error> {
    protocols
        .iter()
        .map(|name| {
            if (1..=255).contains(&name.len()) {
                Ok(ApplicationProtocol::from(name.to_vec()))
            } else {
                Err(Error::new(
                    Kind::Misuse,
                    "an ALPN name is empty or longer than 255 bytes",
                ))
            }
        })
        .collect()
}

/// The error of a configuration that rustls refused.
fn configuration(error: &rustls::Error) -> Error {
    Error::new(
        Kind::Misuse,
        match error {
            rustls::Error::InconsistentKeys(_) => "the private key does not match the certificate",
            _ => "rustls refused the identity of the configuration",
        },
    )
}

/// The limits of a TLS connection, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The capacity of each input region that the connection allocates, at least
    /// [`RECORD_BYTES_MAX`]. It also bounds the largest handshake message, for example a
    /// certificate chain, because rustls joins a message in the input region.
    pub input_bytes: usize,
    /// The work of one drive: the bytes and the records that the connection decrypts and
    /// encrypts.
    pub turn: TurnLimits,
}

/// The bytes that a connection copied, by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Copies {
    /// Received bytes from a read-only region, which decryption in place needs in a writable one.
    pub received: u64,
    /// Bytes of a partial record that moved to a new input region.
    pub partial: u64,
    /// Plaintext that moved to its own region, because it was smaller than the partial record
    /// after it.
    pub joined: u64,
    /// Plaintext that rustls gave in its own buffer, not in the input region.
    pub rustls: u64,
    /// Plaintext that encryption wrote into the ciphertext output. Each sent byte needs it.
    pub encrypted: u64,
}

/// A key-exchange group, by its IANA code point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Group(pub u16);

impl Group {
    /// The hybrid of X25519 and ML-KEM-768.
    pub const X25519_MLKEM768: Self = Self(0x11ec);
    /// X25519 alone, a classical group.
    pub const X25519: Self = Self(0x001d);
}

/// How the handshake of a connection ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake {
    /// A full handshake.
    Full,
    /// A full handshake in which the server asked for another key share (HelloRetryRequest).
    Retried,
    /// A resumption of an earlier session of this process.
    Resumed,
}

/// What the handshake of a connection negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated<'a> {
    /// The key-exchange group.
    pub group: Group,
    /// The application protocol that ALPN selected, or `None`.
    pub protocol: Option<&'a [u8]>,
    /// How the handshake ran.
    pub handshake: Handshake,
}

/// How the input of a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closure {
    /// The peer sent `close_notify`: its data ended there.
    Notified,
    /// The transport ended with no `close_notify`. A protocol with its own framing can tell
    /// whether a message is incomplete. For data that ends only at the end of the connection,
    /// treat the end as partial.
    Unnotified,
}

/// The rustls connection of one end.
enum Session {
    Client(rustls::Connection<ClientSide, Tcp>),
    Server(rustls::Connection<ServerSide, Tcp>),
}

impl Session {
    fn common(&self) -> &rustls::CommonState {
        match self {
            Self::Client(connection) => connection,
            Self::Server(connection) => connection,
        }
    }

    fn write(&mut self, plaintext: &[u8], output: &mut Vec<u8>) -> Result<(), rustls::Error> {
        match self {
            Self::Client(connection) => connection.write(OutboundPlain::Single(plaintext), output),
            Self::Server(connection) => connection.write(OutboundPlain::Single(plaintext), output),
        }
    }

    fn close(&mut self, output: &mut Vec<u8>) -> Result<(), rustls::Error> {
        match self {
            Self::Client(connection) => connection.send_close_notify(output),
            Self::Server(connection) => connection.send_close_notify(output),
        }
    }
}

/// A writable input region: received ciphertext, which rustls decrypts in place.
struct Region {
    backing: Backing,
    /// The charge of the backing when this engine allocated it. A region of the host carries
    /// its own.
    charge: Option<Permit>,
    /// The bytes before `start` are done: rustls discarded them.
    start: usize,
}

impl Region {
    /// Allocates a region of `capacity` bytes that starts with `bytes`, charged to `budget`.
    fn new(budget: &Budget, bytes: &[u8], capacity: usize) -> Result<Self, Error> {
        let charge = budget
            .reserve(capacity as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused a TLS input region"))?;
        let mut region = Vec::new();
        region
            .try_reserve_exact(capacity)
            .map_err(|_| Error::new(Kind::Overload, "the memory for a TLS input region is not available"))?;
        region.extend_from_slice(bytes);
        Ok(Self {
            backing: Backing::from(region),
            charge: Some(charge),
            start: 0,
        })
    }

    /// The bytes after the discarded ones: a partial record, or records that the engine has not
    /// decrypted yet.
    fn pending(&self) -> &[u8] {
        self.backing.bytes().get(self.start..).unwrap_or_default()
    }

    /// The capacity after the received bytes.
    fn room(&self) -> usize {
        self.backing.capacity() - self.backing.initialized()
    }

    /// Adds `bytes` after the received bytes, and gives how many fit.
    fn append(&mut self, bytes: &[u8]) -> usize {
        let backing = core::mem::replace(&mut self.backing, Backing::from(Vec::new()));
        let mut loan = WriteLoan::new(backing);
        let added = loan.fill_from(bytes);
        self.backing = loan.into_inner();
        added
    }

    /// Freezes the region into a lease, which keeps its charge until its last view drops.
    fn freeze(self) -> Lease {
        let size = self.backing.allocation_size();
        match self.charge {
            Some(charge) => Lease::from_owner(
                Charged {
                    bytes: self.backing,
                    _charge: charge,
                },
                size,
            ),
            None => Lease::from(self.backing),
        }
    }
}

/// The view of an input region that rustls reads: the bytes after the ones that it discarded.
struct View<'a> {
    region: &'a mut Region,
    notified: &'a mut bool,
    ended: bool,
}

impl TlsInputBuffer for View<'_> {
    fn slice_mut(&mut self) -> &mut [u8] {
        let start = self.region.start;
        self.region.backing.bytes_mut().get_mut(start..).unwrap_or_default()
    }

    fn discard(&mut self, len: usize) {
        self.region.start = self
            .region
            .start
            .saturating_add(len)
            .min(self.region.backing.initialized());
    }

    fn received_close_notify(&mut self) {
        *self.notified = true;
    }

    fn has_seen_eof(&self) -> bool {
        self.ended
    }
}

/// Plaintext that waits for its region to freeze.
enum Plaintext {
    /// Bytes that rustls decrypted in place, at this range of the region.
    InPlace(Range<usize>),
    /// Bytes that rustls gave in its own buffer, already copied to a region of their own.
    Copied(Lease),
}

/// Ciphertext that this end writes before it goes to the output queue, with the charge of its
/// capacity: the charge always equals the capacity.
struct Written {
    bytes: Vec<u8>,
    charge: Credit,
}

impl Written {
    fn new(budget: &Budget) -> Self {
        Self {
            bytes: Vec::new(),
            charge: budget.credit(0),
        }
    }

    /// Makes room for `additional` bytes: it charges them, and then allocates them.
    fn reserve(&mut self, additional: usize) -> Result<(), Error> {
        let target = self.bytes.len().saturating_add(additional);
        if let Some(more) = target.checked_sub(self.bytes.capacity()).filter(|&more| more > 0) {
            self.charge.charge(more as u64).map_err(|_| overload())?;
            if self.bytes.try_reserve_exact(additional).is_err() {
                self.charge.refund(more as u64).map_err(|_| overload())?;
                return Err(overload());
            }
        }
        self.settle()
    }

    /// Charges the capacity that the allocator or rustls added.
    fn settle(&mut self) -> Result<(), Error> {
        let capacity = self.bytes.capacity() as u64;
        if let Some(more) = capacity.checked_sub(self.charge.charged()).filter(|&more| more > 0) {
            self.charge.charge(more).map_err(|_| overload())?;
        }
        Ok(())
    }
}

/// The error of a refused charge of the output.
fn overload() -> Error {
    Error::new(Kind::Overload, "the budget refused the TLS output")
}

/// Bytes and the charge that pays for them, as the owner of a lease: the last view drops both.
struct Charged<T, C> {
    bytes: T,
    _charge: C,
}

impl<T: AsRef<[u8]>, C> AsRef<[u8]> for Charged<T, C> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

/// A region of the host that waits until the record that continues into it is complete.
struct Next {
    backing: Backing,
    /// The bytes before `start` completed the record.
    start: usize,
}

/// The charge and the place of the input region that the host holds for a receive.
struct Lent {
    address: usize,
    charge: Option<Permit>,
    start: usize,
}

/// An inner engine that runs over TLS records: the TLS 1.3 connection of one end.
///
/// The host gives it ciphertext and sends its ciphertext. The inner engine reads and writes
/// plaintext in its own queues, which [`parts`](Self::parts) lends to the application.
pub struct Tls<E> {
    engine: E,
    /// The plaintext queues of the inner engine.
    inbound: Inbound,
    outbound: Outbound,
    session: Session,
    budget: Budget,
    limits: Limits,
    /// The region that rustls decrypts in, or `None` when no received byte is pending.
    region: Option<Region>,
    lent: Option<Lent>,
    next: Option<Next>,
    /// The plaintext of the region that the inner engine has not received yet. Its capacity is
    /// the size of the inbound queue of the inner engine.
    plaintext: Vec<Plaintext>,
    _plaintext_charge: Permit,
    /// The facts of the last received region.
    endpoint: Option<Endpoint>,
    capacity: u64,
    written: Written,
    copies: Copies,
    /// The peer sent `close_notify`.
    notified: bool,
    closure: Option<Closure>,
    /// The end of the connection, after this end wrote its last bytes.
    end: Option<Result<(), Error>>,
}

impl<E: Engine> Tls<E> {
    /// Makes the client end of a connection to the server `name`, a DNS name or an IP address,
    /// over which `engine` runs with its plaintext queues. It writes the ClientHello at once.
    ///
    /// Refuses with [`Kind::Misuse`] when `name` is not valid or `limits` cannot work, and with
    /// [`Kind::Overload`] when `budget` cannot pay.
    pub fn client(
        config: &ClientConfig,
        name: &str,
        engine: E,
        (inbound, outbound): (Inbound, Outbound),
        limits: Limits,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let name = ServerName::try_from(name)
            .map_err(|_| Error::new(Kind::Misuse, "the server name is not a DNS name or an IP address"))?
            .to_owned();
        let mut written = Written::new(budget);
        let session = config
            .config
            .connect(name)
            .build(&mut written.bytes)
            .map_err(|error| refused(&error))?;
        written.settle()?;
        Self::new(
            Session::Client(session),
            written,
            engine,
            (inbound, outbound),
            limits,
            budget,
        )
    }

    /// Makes the server end of a connection, over which `engine` runs with its plaintext queues.
    ///
    /// Refuses with [`Kind::Misuse`] when `limits` cannot work, and with [`Kind::Overload`] when
    /// `budget` cannot pay.
    pub fn server(
        config: &ServerConfig,
        engine: E,
        (inbound, outbound): (Inbound, Outbound),
        limits: Limits,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let session =
            rustls::Connection::<ServerSide, Tcp>::new(Arc::clone(&config.config)).map_err(|error| refused(&error))?;
        Self::new(
            Session::Server(session),
            Written::new(budget),
            engine,
            (inbound, outbound),
            limits,
            budget,
        )
    }

    fn new(
        session: Session,
        written: Written,
        engine: E,
        (inbound, outbound): (Inbound, Outbound),
        limits: Limits,
        budget: &Budget,
    ) -> Result<Self, Error> {
        if limits.input_bytes < RECORD_BYTES_MAX {
            return Err(Error::new(
                Kind::Misuse,
                "the TLS input region is smaller than a record",
            ));
        }
        let slots = inbound.free();
        let charge = slots
            .checked_mul(size_of::<Plaintext>())
            .and_then(|bytes| budget.reserve(bytes as u64).ok())
            .ok_or_else(|| Error::new(Kind::Overload, "the budget refused the TLS plaintext list"))?;
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve_exact(slots)
            .map_err(|_| Error::new(Kind::Overload, "the memory for the TLS plaintext list is not available"))?;
        Ok(Self {
            engine,
            inbound,
            outbound,
            session,
            budget: budget.clone(),
            limits,
            region: None,
            lent: None,
            next: None,
            plaintext,
            _plaintext_charge: charge,
            endpoint: None,
            capacity: 0,
            written,
            copies: Copies::default(),
            notified: false,
            closure: None,
            end: None,
        })
    }

    /// The inner engine and its plaintext output queue, for the calls of the application, such as
    /// a response.
    pub fn parts(&mut self) -> (&mut E, &mut Outbound) {
        (&mut self.engine, &mut self.outbound)
    }

    /// What the handshake negotiated, or `None` before it completed.
    pub fn negotiated(&self) -> Option<Negotiated<'_>> {
        let common = self.session.common();
        if common.is_handshaking() {
            return None;
        }
        Some(Negotiated {
            group: Group(u16::from(common.negotiated_key_exchange_group()?.name())),
            protocol: common.alpn_protocol().map(AsRef::as_ref),
            // A handshake that neither resumed nor retried is full.
            handshake: match common.handshake_kind()? {
                HandshakeKind::Resumed => Handshake::Resumed,
                HandshakeKind::FullWithHelloRetryRequest => Handshake::Retried,
                _ => Handshake::Full,
            },
        })
    }

    /// The bytes that the connection copied, by cause.
    pub fn copies(&self) -> Copies {
        self.copies
    }

    /// How the input ended, or `None` before its end.
    pub fn closure(&self) -> Option<Closure> {
        self.closure
    }

    /// One turn, up to the progress of the inner engine.
    fn turn(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> Result<(Option<E::Event>, Turn), Error> {
        let mut work = Work::default();
        self.take_queued(inbound)?;
        let stopped = loop {
            self.complete_from_next()?;
            let stopped = self.decrypt(inbound.ended() && inbound.front().is_none(), &mut work)?;
            self.deliver()?;
            // A region of the host continues the input once the record before it is complete.
            if self.region.is_some() || work.reached(&self.limits.turn) {
                break stopped;
            }
            let Some(next) = self.next.take() else { break stopped };
            self.region = Some(Region {
                backing: next.backing,
                charge: None,
                start: next.start,
            });
        };
        let handshaking = self.session.common().is_handshaking();
        if self.notified && !self.inbound.ended() {
            self.closure = Some(Closure::Notified);
            self.inbound.end();
        }
        let input_ended = inbound.ended() && inbound.front().is_none() && self.next.is_none();
        let partial = self.region.as_ref().is_some_and(|region| !region.pending().is_empty());
        if input_ended && partial && !stopped {
            return Err(Error::new(Kind::Partial, "the transport ended inside a TLS record"));
        }
        if input_ended && !partial && !self.inbound.ended() {
            if handshaking {
                return Err(Error::new(
                    Kind::Partial,
                    "the transport ended before the TLS handshake completed",
                ));
            }
            self.closure = Some(Closure::Unnotified);
            self.inbound.end();
        }
        let (event, inner) = if handshaking {
            (None, None)
        } else {
            let (event, turn) = self.engine.drive(&mut self.inbound, &mut self.outbound, now);
            (event, Some(turn))
        };
        if !handshaking {
            self.encrypt(outbound, &mut work)?;
        }
        if let Some(Turn {
            progress: Progress::Terminal(end),
            ..
        }) = inner
        {
            self.written.reserve(RECORD_OVERHEAD + 2)?;
            self.session
                .close(&mut self.written.bytes)
                .map_err(|error| refused(&error))?;
            self.written.settle()?;
            self.end = Some(end);
        }
        self.flush(outbound);
        let deadline = inner.and_then(|turn| turn.deadline);
        let progress = if let Some(end) = self.end {
            self.ending(end)
        } else if work.reached(&self.limits.turn) || (stopped && self.inbound.free() > 0) {
            Progress::Pending
        } else if !self.written.bytes.is_empty() {
            Progress::Blocked(Blocked::Output)
        } else {
            match inner.map(|turn| turn.progress) {
                // The handshake waits for the peer.
                None => Progress::Blocked(Blocked::Input),
                // The encryption acknowledged the plaintext output that the engine waited for.
                Some(Progress::Blocked(Blocked::Output)) if self.outbound.outstanding().is_empty() => Progress::Pending,
                Some(progress) => progress,
            }
        };
        Ok((event, Turn { progress, deadline }))
    }

    /// The progress of an engine that ended: it waits until its last bytes are in the queue.
    fn ending(&self, end: Result<(), Error>) -> Progress {
        if self.written.bytes.is_empty() {
            Progress::Terminal(end)
        } else {
            Progress::Blocked(Blocked::Output)
        }
    }

    /// Copies the bytes of read-only received regions into the input region.
    fn take_queued(&mut self, inbound: &mut Inbound) -> Result<(), Error> {
        while let Some(front) = inbound.front() {
            if self.lent.is_some() || self.next.is_some() {
                break;
            }
            let region = match &mut self.region {
                Some(region) if region.room() > 0 => region,
                Some(_) => {
                    self.relocate()?;
                    let Some(region) = &mut self.region else { break };
                    region
                }
                None => self
                    .region
                    .insert(Region::new(&self.budget, &[], self.limits.input_bytes)?),
            };
            let added = region.append(front.region.bytes());
            self.copies.received += added as u64;
            self.endpoint = Some(front.endpoint);
            self.capacity = front.capacity;
            inbound.consume(added)?;
            if added == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Moves the pending bytes of a full input region to a new one, which has room for the rest of
    /// their record. Refuses when no region of the limit can hold them.
    fn relocate(&mut self) -> Result<(), Error> {
        let Some(region) = self.region.take() else {
            return Ok(());
        };
        let pending = region.pending();
        if pending.len() >= self.limits.input_bytes {
            return Err(Error::new(
                Kind::Overload,
                "a TLS message is larger than the input region",
            ));
        }
        let moved = Region::new(&self.budget, pending, self.limits.input_bytes)?;
        self.copies.partial += pending.len() as u64;
        self.region = Some(moved);
        Ok(())
    }

    /// Copies from the waiting region of the host the bytes that complete the pending record.
    fn complete_from_next(&mut self) -> Result<(), Error> {
        loop {
            let (Some(region), Some(next)) = (&self.region, &self.next) else {
                return Ok(());
            };
            let pending = region.pending();
            let need = record_end(pending).saturating_sub(pending.len());
            let rest = next.backing.bytes().get(next.start..).unwrap_or_default();
            let take = need.min(rest.len());
            if take == 0 {
                return Ok(());
            }
            if region.room() < take {
                self.relocate()?;
            }
            let (Some(region), Some(next)) = (&mut self.region, &mut self.next) else {
                return Ok(());
            };
            let rest = next.backing.bytes().get(next.start..).unwrap_or_default();
            let added = region.append(rest.get(..take).unwrap_or_default());
            self.copies.partial += added as u64;
            next.start += added;
            if next.start == next.backing.initialized() {
                self.next = None;
            }
            if added < need {
                return Ok(());
            }
        }
    }

    /// Decrypts the complete records of the input region, until a limit of the turn stops it or
    /// the inbound queue of the inner engine has no place for more plaintext. Gives whether such a
    /// stop left records to decrypt.
    fn decrypt(&mut self, ended: bool, work: &mut Work) -> Result<bool, Error> {
        let Some(region) = &mut self.region else {
            return Ok(false);
        };
        let base = region.backing.as_ptr().addr();
        let room = self.inbound.free();
        let mut sink = Sink {
            base,
            plaintext: &mut self.plaintext,
            room,
            budget: &self.budget,
            copies: &mut self.copies,
            limits: &self.limits.turn,
            work,
        };
        let mut view = View {
            region,
            notified: &mut self.notified,
            ended,
        };
        let read = match &mut self.session {
            Session::Client(connection) => read(connection, &mut view, &mut self.written.bytes, &mut sink),
            Session::Server(connection) => read(connection, &mut view, &mut self.written.bytes, &mut sink),
        };
        self.written.settle()?;
        read
    }

    /// Gives the waiting plaintext to the inner engine: it freezes the region, or it copies the
    /// plaintext when that is smaller than the pending bytes after it.
    fn deliver(&mut self) -> Result<(), Error> {
        let Some(region) = self.region.take() else {
            return Ok(());
        };
        let Some(endpoint) = self.endpoint else {
            assert!(self.plaintext.is_empty(), "each plaintext comes from a received region");
            return Ok(());
        };
        let pending = region.pending().len();
        if self.plaintext.is_empty() {
            // A region with no pending byte is done: an idle connection keeps no input region.
            if pending > 0 {
                self.region = Some(region);
            }
            return Ok(());
        }
        let in_place: usize = self
            .plaintext
            .iter()
            .map(|plaintext| match plaintext {
                Plaintext::InPlace(range) => range.len(),
                Plaintext::Copied(_) => 0,
            })
            .sum();
        if pending <= in_place {
            let rest = if pending > 0 {
                let rest = Region::new(&self.budget, region.pending(), self.limits.input_bytes)?;
                self.copies.partial += pending as u64;
                Some(rest)
            } else {
                None
            };
            let lease = region.freeze();
            for plaintext in self.plaintext.drain(..) {
                let view = match plaintext {
                    Plaintext::InPlace(range) => lease.view(range),
                    Plaintext::Copied(lease) => Some(lease),
                };
                if let Some(region) = view {
                    push(&mut self.inbound, region, endpoint, self.capacity);
                }
            }
            self.region = rest;
        } else {
            let mut joined = Vec::new();
            let total: usize = self
                .plaintext
                .iter()
                .map(|plaintext| match plaintext {
                    Plaintext::InPlace(range) => range.len(),
                    Plaintext::Copied(lease) => lease.initialized(),
                })
                .sum();
            let charge = charged(&self.budget, &mut joined, total)?;
            for plaintext in self.plaintext.drain(..) {
                match plaintext {
                    Plaintext::InPlace(range) => {
                        joined.extend_from_slice(region.backing.bytes().get(range).unwrap_or_default());
                    }
                    Plaintext::Copied(lease) => joined.extend_from_slice(lease.bytes()),
                }
            }
            self.copies.joined += total as u64;
            let size = joined.capacity();
            let lease = Lease::from_owner(
                Charged {
                    bytes: joined,
                    _charge: charge,
                },
                size,
            );
            push(&mut self.inbound, lease, endpoint, self.capacity);
            self.region = Some(region);
        }
        Ok(())
    }

    /// Encrypts the plaintext output of the inner engine, until a limit of the turn stops it or
    /// the output queue has no place for more ciphertext.
    fn encrypt(&mut self, outbound: &Outbound, work: &mut Work) -> Result<(), Error> {
        while !work.reached(&self.limits.turn) {
            if outbound.free() == 0 && !self.written.bytes.is_empty() {
                break;
            }
            let Some(output) = self.outbound.submit() else { break };
            let plaintext = output.region.bytes();
            let records = plaintext.len().div_ceil(RECORD_PLAINTEXT_MAX);
            self.written.reserve(plaintext.len() + records * RECORD_OVERHEAD)?;
            // rustls can write an alert before it refuses: the charge covers it first.
            let wrote = self.session.write(plaintext, &mut self.written.bytes);
            self.written.settle()?;
            wrote.map_err(|error| refused(&error))?;
            self.outbound.ack(output.id, plaintext.len())?;
            self.copies.encrypted += plaintext.len() as u64;
            work.add(plaintext.len(), records);
        }
        Ok(())
    }

    /// Gives the written ciphertext to the output queue, when it has a place.
    fn flush(&mut self, outbound: &mut Outbound) {
        if self.written.bytes.is_empty() || outbound.free() == 0 {
            return;
        }
        let written = core::mem::replace(&mut self.written, Written::new(&self.budget));
        let size = written.bytes.capacity();
        let lease = Lease::from_owner(
            Charged {
                bytes: written.bytes,
                _charge: written.charge,
            },
            size,
        );
        let pushed = outbound.push(lease);
        assert!(pushed.is_ok(), "a queue with a free place takes each region");
    }
}

/// Queues plaintext for the inner engine. The caller checked that the queue has a place.
fn push(inbound: &mut Inbound, region: Lease, endpoint: Endpoint, capacity: u64) {
    let pushed = inbound.push(Received {
        region,
        endpoint,
        capacity,
    });
    assert!(pushed.is_ok(), "the decryption keeps a place for each plaintext region");
}

/// Charges `capacity` bytes for `bytes`, and then allocates them.
fn charged(budget: &Budget, bytes: &mut Vec<u8>, capacity: usize) -> Result<Permit, Error> {
    let charge = budget
        .reserve(capacity as u64)
        .map_err(|_| Error::new(Kind::Overload, "the budget refused a TLS plaintext region"))?;
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::new(Kind::Overload, "the memory for a TLS plaintext region is not available"))?;
    Ok(charge)
}

/// The end of the record that starts `pending`: its header and its payload. A partial header
/// needs at least its 5 bytes.
fn record_end(pending: &[u8]) -> usize {
    match pending {
        [_, _, _, high, low, ..] => 5 + usize::from(u16::from_be_bytes([*high, *low])),
        _ => 5,
    }
}

/// Where the decryption of one turn puts its plaintext, and its limits.
struct Sink<'a> {
    /// The address of the first byte of the input region.
    base: usize,
    plaintext: &'a mut Vec<Plaintext>,
    /// The places of the inbound queue of the inner engine.
    room: usize,
    budget: &'a Budget,
    copies: &'a mut Copies,
    limits: &'a TurnLimits,
    work: &'a mut Work,
}

impl Sink<'_> {
    /// Whether the turn can decrypt no more.
    fn full(&self) -> bool {
        self.plaintext.len() >= self.room || self.work.reached(self.limits)
    }

    /// Records one payload: its range in the input region, or a copy when rustls gave it in its own
    /// buffer.
    fn take(&mut self, bytes: &[u8], len: usize) -> Result<(), Error> {
        self.work.add(bytes.len(), 1);
        if bytes.is_empty() {
            return Ok(());
        }
        let start = bytes.as_ptr().addr().wrapping_sub(self.base);
        let end = start.checked_add(bytes.len()).filter(|&end| end <= len);
        let plaintext = if let Some(end) = end {
            Plaintext::InPlace(start..end)
        } else {
            let mut copy = Vec::new();
            let charge = charged(self.budget, &mut copy, bytes.len())?;
            copy.extend_from_slice(bytes);
            self.copies.rustls += bytes.len() as u64;
            let size = copy.capacity();
            Plaintext::Copied(Lease::from_owner(
                Charged {
                    bytes: copy,
                    _charge: charge,
                },
                size,
            ))
        };
        self.plaintext.push(plaintext);
        Ok(())
    }
}

/// Decrypts the complete records of `input` into `sink`, and writes any handshake output into
/// `output`.
fn read<S: SideData>(
    connection: &mut rustls::Connection<S, Tcp>,
    input: &mut View<'_>,
    output: &mut Vec<u8>,
    sink: &mut Sink<'_>,
) -> Result<bool, Error> {
    let len = input.region.backing.initialized();
    let mut handler = connection.read_tls(input, output);
    while !sink.full() {
        let Some(payload) = handler.next_payload() else {
            return Ok(false);
        };
        let payload = payload.map_err(|error| refused(&error))?;
        sink.take(payload.bytes(), len)?;
    }
    Ok(true)
}

impl<E: Engine> Engine for Tls<E> {
    type Event = E::Event;

    fn drive(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> (Option<E::Event>, Turn) {
        if let Some(end) = self.end {
            self.flush(outbound);
            return (
                None,
                Turn {
                    progress: self.ending(end),
                    deadline: None,
                },
            );
        }
        match self.turn(inbound, outbound, now) {
            Ok(result) => result,
            Err(error) => {
                // rustls wrote its alert before it refused: it goes out before the end.
                self.end = Some(Err(error));
                self.flush(outbound);
                (
                    None,
                    Turn {
                        progress: self.ending(Err(error)),
                        deadline: None,
                    },
                )
            }
        }
    }

    fn timed(&self) -> bool {
        self.engine.timed()
    }

    fn region(&mut self) -> Result<Option<Backing>, Error> {
        if self.lent.is_some() {
            return Err(Error::new(Kind::Misuse, "the lent TLS input region has not come back"));
        }
        if let Some(region) = &self.region {
            let pending = region.pending();
            if region.room() < record_end(pending).saturating_sub(pending.len()).max(1) {
                self.relocate()?;
            }
        }
        let region = match self.region.take() {
            Some(region) => region,
            None => Region::new(&self.budget, &[], self.limits.input_bytes)?,
        };
        self.lent = Some(Lent {
            address: region.backing.as_ptr().addr(),
            charge: region.charge,
            start: region.start,
        });
        Ok(Some(region.backing))
    }

    fn received(&mut self, _: &mut Inbound, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        match self.lent.take() {
            Some(lent) if lent.address == region.as_ptr().addr() => {
                self.region = Some(Region {
                    backing: region,
                    charge: lent.charge,
                    start: lent.start,
                });
            }
            Some(lent) => {
                self.lent = Some(lent);
                return Err(region);
            }
            None if self.next.is_some() => return Err(region),
            None if self.region.as_ref().is_some_and(|region| !region.pending().is_empty()) => {
                self.next = Some(Next {
                    backing: region,
                    start: 0,
                });
            }
            None => {
                self.region = Some(Region {
                    backing: region,
                    charge: None,
                    start: 0,
                });
            }
        }
        self.endpoint = Some(endpoint);
        self.capacity = capacity;
        Ok(())
    }
}

impl<E: fmt::Debug> fmt::Debug for Tls<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls")
            .field("engine", &self.engine)
            .field("handshaking", &self.session.common().is_handshaking())
            .field("copies", &self.copies)
            .field("closure", &self.closure)
            .finish_non_exhaustive()
    }
}

/// The error that ends a connection, from the error of rustls. It keeps no text of the peer.
fn refused(error: &rustls::Error) -> Error {
    match error {
        rustls::Error::InvalidCertificate(certificate) => Error::new(
            Kind::Trust,
            match certificate {
                CertificateError::Expired | CertificateError::ExpiredContext { .. } => "the peer certificate expired",
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                    "the peer certificate is not valid yet"
                }
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                    "the peer certificate is not valid for its name"
                }
                CertificateError::UnknownIssuer => "the peer certificate chain reaches no trusted root",
                _ => "the peer certificate failed verification",
            },
        ),
        rustls::Error::PeerMisbehaved(PeerMisbehaved::NoCertificatesPresented) => {
            Error::new(Kind::Trust, "the peer showed no certificate")
        }
        rustls::Error::AlertReceived(alert) => match *alert {
            AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCa
            | AlertDescription::AccessDenied
            | AlertDescription::CertificateRequired => {
                Error::new(Kind::Trust, "the peer refused the certificate of this end")
            }
            AlertDescription::HandshakeFailure
            | AlertDescription::ProtocolVersion
            | AlertDescription::InsufficientSecurity
            | AlertDescription::NoApplicationProtocol => {
                Error::new(Kind::Unsupported, "the peer found no TLS parameters in common")
            }
            _ => Error::new(Kind::Malformed, "the peer ended the TLS connection with an alert"),
        },
        rustls::Error::PeerIncompatible(_) | rustls::Error::NoApplicationProtocol => Error::new(
            Kind::Unsupported,
            "the peer has no TLS parameters in common with this end",
        ),
        rustls::Error::FailedToGetCurrentTime | rustls::Error::FailedToGetRandomBytes => {
            Error::new(Kind::Unsupported, "the wall clock or the entropy source failed")
        }
        _ => Error::new(Kind::Malformed, "the peer sent TLS bytes that the protocol forbids"),
    }
}
