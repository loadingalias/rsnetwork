//! TLS 1.3 in the core: the configuration of each end, and [`Tls`], the engine that runs an inner
//! engine, for example an HTTP/1.1 server, over TLS records.
//!
//! The host gives [`Tls`] ciphertext, and sends the ciphertext that it writes. rustls runs the
//! handshake with the cryptography of rscrypto, and then gives the traffic keys to the record
//! layer of the core. The record layer opens each record with rscrypto in place, in the region
//! that its bytes arrived in, and the inner engine reads the plaintext as views of that region,
//! with no copy. It seals the plaintext of the inner engine into the ciphertext output, so a sent
//! byte costs only its encryption. [`Copies`] counts each copy by its cause, also the encryption.
//!
//! - **Configuration.** [`ClientConfig`] and [`ServerConfig`] take each choice explicitly: the
//!   trust roots, the identity of each end, ALPN, resumption, and the wall clock that checks the
//!   validity of certificates. The key exchange offers X25519MLKEM768 first and X25519 second, and
//!   a server selects X25519MLKEM768 whenever a client offers it. Each configuration has its own
//!   provider, so nothing installs a provider for the process.
//! - **Receive.** A host receives into the region that
//!   [`host::Connection::region`](crate::host::Connection::region) lends: the tail of the input
//!   region, so a record that continues after a receive completes in place. A region that the host
//!   owns, for example one that the kernel selected, goes to
//!   [`host::Connection::received`](crate::host::Connection::received): a record that continues
//!   into it costs one copy of the rest of that record. A read-only region goes to
//!   [`host::Connection::receive`](crate::host::Connection::receive), and costs one copy of its
//!   bytes.
//! - **Delivery.** The plaintext of each record reaches the inner engine in the turn that opens
//!   it: the region freezes its bytes up to the end of the record, and the rest of the region
//!   stays writable for the next receive.
//! - **Keys.** rustls keeps the key schedule. This end sends a KeyUpdate before a key seals more
//!   records than the confidentiality limit of its suite or [`Limits::key_records_max`], and it
//!   takes each KeyUpdate of the peer. A client gives each session ticket to rustls.
//! - **Randomness.** Each configuration takes its randomness explicitly: the system, or a seeded
//!   generator whose child streams replay a run byte for byte ([`Entropy`]).
//! - **Resumption.** Sessions resume only in the process that made them ([`Resumption`]).
//! - **0-RTT.** Off: neither end sends or accepts early data.
//! - **End.** A `close_notify` of the peer ends the input of the inner engine. When the transport
//!   ends with no `close_notify`, the inner engine also sees the end, and [`Tls::closure`] reports
//!   [`Closure::Unnotified`]. Only a protocol with its own framing can then tell that no byte is
//!   lost.

mod memory;
mod peer;
mod record;
mod sent;
pub(crate) mod stream;

use core::alloc::Layout;
use core::fmt;
use core::num::{NonZeroU32, NonZeroUsize};
use core::sync::atomic::{AtomicU64, Ordering};
use std::borrow::Cow;
use std::sync::{Arc, PoisonError, RwLock};

use memory::{ClientStore, Cost, Held, Own, Owns, ServerStore};
use record::{CONTENT_MAX, Content, HEADER, PROTECTED_MAX, Protection, TAG, Violation};
use rscrypto_rustls::kx_group::{X25519Group, X25519MlKem768Group};
use rscrypto_rustls::replay::{self, ScopedRandom};
use rstypes::buffer::{Backing, Buffer as _, BufferMut as _, Lease, Pool, PoolRefused, WriteLoan};
use rstypes::capacity::{Budget, Credit};
use rustls::client::ClientSessionStore;
use rustls::crypto::CryptoProvider;
use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{Credentials, Identity as Chain, SelectedCredential, SingleCredential};
use rustls::enums::ApplicationProtocol;
use rustls::error::{AlertDescription, CertificateError, PeerMisbehaved};
use rustls::kernel::KernelConnection;
use rustls::pki_types::ServerName;
use rustls::server::{
    ClientHello, NoServerSessionStorage, PreferServerOrder, ServerCredentialResolver, StoresServerSessions,
    Tls13Tickets, WebPkiClientVerifier,
};
use rustls::split::SplitConnection;
use rustls::{
    ClientSide, CommonState, ConnectionTrafficSecrets, ExtractedSecrets, HandshakeKind, MessageHandler, RootCertStore,
    ServerSide, SideData, SupportedCipherSuite, Tcp, TlsInputBuffer,
};
use sent::Sent;

pub use rscrypto::ChaCha20Rng;
pub use rustls::pki_types::pem::PemObject;
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
pub use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
pub use stream::{Stream, StreamLimits};

use crate::drive::{
    Accepted, Blocked, Endpoint, Error, Inbound, Kind, Outbound, Progress, Received, Turn, TurnLimits, Work,
};
use crate::host::Engine;
use crate::time::Instant;

/// The largest TLS 1.3 record that a peer can send: a 5-byte header, 2^14 bytes of plaintext,
/// and 256 bytes of content type, padding, and tag (RFC 8446, section 5.2).
pub const RECORD_BYTES_MAX: usize = HEADER + PROTECTED_MAX;

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
    /// Only in this process, which keeps at most this many sessions, each charged to the budget of
    /// the configuration. The ticket keys are local to the process, so another instance, or this
    /// one after a restart, runs a full handshake.
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
    /// The budget that each stored session is charged to. A ticket that it cannot pay for is not
    /// kept.
    pub budget: &'a Budget,
    /// The wall clock that checks the validity of each certificate. [`DefaultTimeProvider`] reads
    /// the clock of the system.
    pub clock: Arc<dyn TimeProvider>,
    /// Where the randomness of each handshake and key comes from.
    pub entropy: Entropy,
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
    /// The budget that each stored session is charged to. A session that it cannot pay for is not
    /// kept, and the client then gets no ticket for it.
    pub budget: &'a Budget,
    /// The wall clock that checks the validity of each client certificate and session.
    pub clock: Arc<dyn TimeProvider>,
    /// Where the randomness of each handshake and key comes from.
    pub entropy: Entropy,
}

/// Where the randomness of a configuration comes from.
#[expect(
    clippy::large_enum_variant,
    reason = "a configuration takes one value by move, one time, so a box would add an allocation and save nothing"
)]
pub enum Entropy {
    /// The operating system, which the provider reads at each draw.
    System,
    /// A seeded generator. Each connection, and each key that the configuration loads, draws from
    /// its own child of it, in the order of the calls that make them. So a run with the same seed,
    /// the same configurations, and the same calls in the same order replays byte for byte. Give
    /// each process its own seed: a draw in a copy of the process that seeded it refuses.
    Seeded(ChaCha20Rng),
}

impl fmt::Debug for Entropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::System => "System",
            Self::Seeded(_) => "Seeded",
        })
    }
}

/// The draws of a seeded configuration go through the stream of the innermost scope.
static SCOPED: ScopedRandom = ScopedRandom;
/// The keys of a seeded configuration draw from the scope that loads or uses them.
static SCOPED_KEYS: rscrypto_rustls::sign::Provider = rscrypto_rustls::sign::Provider::scoped();
/// The key-exchange groups of a seeded configuration, in the order of the default provider:
/// X25519MLKEM768, then X25519. Each draws its key shares from the scope.
static SCOPED_HYBRID: X25519MlKem768Group = X25519MlKem768Group::new(&SCOPED);
static SCOPED_X25519: X25519Group = X25519Group::new(&SCOPED);
static SCOPED_GROUPS: [&dyn SupportedKxGroup; 2] = [&SCOPED_HYBRID, &SCOPED_X25519];

/// The randomness of a configuration: the root generator of each stream, or `None` for the
/// system, and the index of the next stream.
struct Source {
    root: Option<ChaCha20Rng>,
    next: AtomicU64,
}

impl Source {
    fn new(entropy: Entropy) -> Self {
        Self {
            root: match entropy {
                Entropy::System => None,
                Entropy::Seeded(root) => Some(root),
            },
            next: AtomicU64::new(0),
        }
    }

    /// The provider whose draws come from this source.
    fn provider(&self) -> CryptoProvider {
        let provider = rscrypto_rustls::default_provider();
        if self.root.is_none() {
            return provider;
        }
        CryptoProvider {
            kx_groups: Cow::Borrowed(&SCOPED_GROUPS),
            secure_random: &SCOPED,
            key_provider: &SCOPED_KEYS,
            ..provider
        }
    }

    /// The stream of the next owner that `label` names, or `None` for the system.
    fn stream(&self, label: &[u8; 8]) -> Option<replay::Stream> {
        // Ordering: each call takes its own index; nothing else depends on the order.
        let root = self.root.as_ref()?;
        Some(replay::Stream::new(
            root.child(label, self.next.fetch_add(1, Ordering::Relaxed)),
        ))
    }
}

/// Runs `f` with the draws of rustls in `stream`, or from the system when it is `None`.
fn scoped<R>(stream: Option<&replay::Stream>, f: impl FnOnce() -> R) -> R {
    match stream {
        Some(stream) => replay::scope(stream, f),
        None => f(),
    }
}

/// The label of the stream of each connection.
const CONNECTION: &[u8; 8] = b"tls-con\0";
/// The label of the stream that loads a key.
const KEY: &[u8; 8] = b"tls-key\0";

/// The configuration of TLS clients. Each connection that [`Tls::client`] makes shares it, and
/// its sessions for resumption.
#[derive(Clone)]
pub struct ClientConfig {
    config: Arc<rustls::ClientConfig>,
    resumption: Resumption,
    entropy: Arc<Source>,
    /// What each connection charges for rustls.
    cost: Cost,
    own: Arc<Owns>,
    /// The store of the sessions, or `None` when they do not resume.
    store: Option<Arc<ClientStore>>,
}

impl ClientConfig {
    /// Makes the configuration from `options`. Refuses with [`Kind::Misuse`] when it has no root,
    /// a root or the identity is not valid, or a protocol name is empty or longer than 255 bytes,
    /// and with [`Kind::Overload`] when `budget` cannot pay for the places of the session store.
    pub fn new(options: ClientOptions<'_>) -> Result<Self, Error> {
        let entropy = Source::new(options.entropy);
        let identity = options.identity.is_some();
        // The ClientHello carries each ALPN name with its length.
        let own = options
            .identity
            .as_ref()
            .map_or_else(Own::default, |identity| Own::new(&identity.chain))
            .plus_bytes(options.protocols.iter().map(|name| 1 + name.len()).sum());
        let store = match options.resumption {
            Resumption::Off => None,
            Resumption::Process(sessions) => Some(Arc::new(ClientStore::new(options.budget, sessions.get())?)),
        };
        let builder = rustls::ClientConfig::builder_with_details(Arc::new(entropy.provider()), options.clock)
            .with_root_certificates(roots(options.roots)?);
        let mut config = match options.identity {
            None => builder.with_no_client_auth(),
            Some(identity) => {
                let chain = chain(identity.chain)?;
                scoped(entropy.stream(KEY).as_ref(), || {
                    builder.with_client_auth_cert(chain, identity.key)
                })
            }
        }
        .map_err(|error| configuration(&error))?;
        config.alpn_protocols = protocols(options.protocols)?;
        // rustls gives the traffic keys to the record layer of the core when the handshake completes.
        config.enable_secret_extraction = true;
        config.resumption = match &store {
            None => rustls::client::Resumption::disabled(),
            Some(store) => rustls::client::Resumption::store(Arc::clone(store) as Arc<dyn ClientSessionStore>),
        };
        Ok(Self {
            config: Arc::new(config),
            resumption: options.resumption,
            entropy: Arc::new(entropy),
            cost: Cost::client(options.protocols, identity),
            own: Arc::new(Owns::new(own)),
            store,
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
    entropy: Arc<Source>,
    /// What each connection charges for rustls.
    cost: Cost,
    own: Arc<Owns>,
    /// The part of the trust roots that the CertificateRequest names.
    hints: Own,
}

impl ServerConfig {
    /// Makes the configuration from `options`. Refuses with [`Kind::Misuse`] when the identity is
    /// not valid, its key does not match its certificate, a client root is not valid, or a
    /// protocol name is empty or longer than 255 bytes, and with [`Kind::Overload`] when `budget`
    /// cannot pay for the places of the session store.
    pub fn new(options: ServerOptions<'_>) -> Result<Self, Error> {
        let entropy = Source::new(options.entropy);
        let hints = Own::new(options.client_roots.unwrap_or_default());
        let own = Own::new(&options.identity.chain).plus(hints);
        let session_storage: Arc<dyn StoresServerSessions> = match options.resumption {
            Resumption::Off => Arc::new(NoServerSessionStorage {}),
            Resumption::Process(sessions) => Arc::new(ServerStore::new(options.budget, sessions.get())?),
        };
        let provider = Arc::new(entropy.provider());
        let identity = Arc::new(Rotation(RwLock::new(credential(
            options.identity,
            &provider,
            &entropy,
        )?)));
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
        config.enable_secret_extraction = true;
        config.session_storage = session_storage;
        if options.resumption == Resumption::Off {
            config.send_tls13_tickets = Tls13Tickets { default: 0, max: 0 };
        }
        Ok(Self {
            config: Arc::new(config),
            identity,
            resumption: options.resumption,
            entropy: Arc::new(entropy),
            cost: Cost::server(options.client_roots),
            own: Arc::new(Owns::new(own)),
            hints,
        })
    }

    /// Replaces the identity that each later handshake shows. A connection that has started keeps
    /// the identity that it showed. Refuses with [`Kind::Misuse`], and keeps the identity, when
    /// the new one is not valid.
    pub fn rotate(&self, identity: Identity) -> Result<(), Error> {
        let own = Own::new(&identity.chain).plus(self.hints);
        let credential = credential(identity, self.config.provider(), &self.entropy)?;
        // The charge covers the new chain before a handshake can show it.
        self.own.raise(own);
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
fn credential(identity: Identity, provider: &CryptoProvider, entropy: &Source) -> Result<Arc<SingleCredential>, Error> {
    let chain = chain(identity.chain)?;
    scoped(entropy.stream(KEY).as_ref(), || {
        Credentials::from_der(chain, identity.key, provider)
    })
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
    /// The most records that this end seals under one key, at least 2. The last of them is a
    /// KeyUpdate, and the next records use a new key. The connection uses the smaller of this
    /// limit and the confidentiality limit of its suite (RFC 8446, section 5.5), so `u64::MAX`
    /// gives the limit of the suite.
    pub key_records_max: u64,
    /// The work of one drive: the bytes and the records that the connection opens and seals.
    pub turn: TurnLimits,
}

/// The bytes that a connection copied, by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Copies {
    /// Received bytes from a read-only region, which an open in place needs in a writable one.
    pub received: u64,
    /// Bytes of a partial record that moved to a new input region.
    pub partial: u64,
    /// Bytes of a handshake message after the handshake, for example a session ticket, whose
    /// records hold it in two or more parts: the parts join in a buffer of their own.
    pub handshake: u64,
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

/// What the handshake of a connection negotiated: the security evidence of the connection.
///
/// The key exchange and the authentication are two guarantees, and each has its own field: a
/// post-quantum `group` does not make the authentication post-quantum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated<'a> {
    /// The key-exchange group.
    pub group: Group,
    /// The application protocol that ALPN selected, or `None`.
    pub protocol: Option<&'a [u8]>,
    /// How the handshake ran.
    pub handshake: Handshake,
    /// How the peer authenticated, or `None` when it did not: a client with no certificate.
    pub peer: Option<Peer<'a>>,
}

/// How the peer of a connection authenticated: the certificate that the trust roots verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer<'a> {
    /// The DER of the end-entity certificate of the peer.
    pub certificate: &'a [u8],
    /// The key algorithm of the certificate, which signed the handshake.
    pub authentication: Authentication,
}

/// The key algorithm of the end-entity certificate of a peer, which signed its handshake. Each
/// of them is a classical signature, so it gives no post-quantum authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// ECDSA with the P-256 curve.
    EcdsaP256,
    /// ECDSA with the P-384 curve.
    EcdsaP384,
    /// Ed25519.
    Ed25519,
    /// RSA.
    Rsa,
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
    /// The transport failed, for example with a reset. The peer can have sent more data.
    Reset,
}

/// The rustls connection of one end during the handshake.
enum Session {
    Client(rustls::Connection<ClientSide, Tcp>),
    Server(rustls::Connection<ServerSide, Tcp>),
}

impl Session {
    fn common(&self) -> &CommonState {
        match self {
            Self::Client(connection) => connection,
            Self::Server(connection) => connection,
        }
    }

    /// Reads the records that `input` shows, and writes the handshake output into `output`.
    fn read(&mut self, input: &mut View<'_>, output: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Client(connection) => read(connection.read_tls(input, output)),
            Self::Server(connection) => read(connection.read_tls(input, output)),
        }
    }
}

/// Runs the handler of the records of one read. The handshake gives no application data: 0-RTT
/// is off, and the input ends at the record that completes the handshake.
fn read<S: SideData>(mut handler: MessageHandler<'_, '_, S>) -> Result<(), Error> {
    match handler.next_payload() {
        None => Ok(()),
        Some(Err(error)) => Err(refused(&error)),
        Some(Ok(_)) => Err(Error::new(
            Kind::Malformed,
            "the peer sent application data before the TLS handshake completed",
        )),
    }
}

/// The rustls state of one end after the handshake: the key schedule, which gives the keys of each
/// KeyUpdate, and the session store of a client.
enum Kernel {
    Client(KernelConnection<ClientSide>),
    Server(KernelConnection<ServerSide>),
}

impl Kernel {
    /// The connection after the handshake of `session`, and its traffic keys.
    fn new(session: Session) -> Result<(Self, ExtractedSecrets), Error> {
        match session {
            Session::Client(connection) => keys(connection).map(|(secrets, kernel)| (Self::Client(kernel), secrets)),
            Session::Server(connection) => keys(connection).map(|(secrets, kernel)| (Self::Server(kernel), secrets)),
        }
    }

    fn suite(&self) -> SupportedCipherSuite {
        match self {
            Self::Client(kernel) => kernel.negotiated_cipher_suite(),
            Self::Server(kernel) => kernel.negotiated_cipher_suite(),
        }
    }

    /// The keys of the next records of the peer, after its KeyUpdate.
    fn update_rx(&mut self) -> Result<Protection, Error> {
        let update = match self {
            Self::Client(kernel) => kernel.update_rx_secret(),
            Self::Server(kernel) => kernel.update_rx_secret(),
        };
        protection(update.ok().as_ref())
    }

    /// The keys of the next records of this end, after its KeyUpdate.
    fn update_tx(&mut self) -> Result<Protection, Error> {
        let update = match self {
            Self::Client(kernel) => kernel.update_tx_secret(),
            Self::Server(kernel) => kernel.update_tx_secret(),
        };
        protection(update.ok().as_ref())
    }
}

/// The traffic keys of the connection after `connection`'s handshake, and its kernel state.
fn keys<S: SideData>(connection: rustls::Connection<S, Tcp>) -> Result<(ExtractedSecrets, KernelConnection<S>), Error> {
    connection
        .split()
        .and_then(SplitConnection::dangerous_into_kernel_connection)
        .map_err(|_| no_keys())
}

/// The protection of the keys of one direction and their sequence number.
fn protection(keys: Option<&(u64, ConnectionTrafficSecrets)>) -> Result<Protection, Error> {
    keys.and_then(|(seq, secrets)| Protection::new(secrets, *seq))
        .ok_or_else(no_keys)
}

fn no_keys() -> Error {
    Error::new(Kind::Unsupported, "rustls did not give the TLS traffic keys")
}

/// The handshake message types after the handshake (RFC 8446, section 4).
const NEW_SESSION_TICKET: u8 = 4;
const KEY_UPDATE: u8 = 24;
/// A KeyUpdate that does not ask the peer for one (RFC 8446, section 4.6.3).
const KEY_UPDATE_NOT_REQUESTED: [u8; 5] = [KEY_UPDATE, 0, 0, 1, 0];
/// The bytes of a handshake message header: its type and its 3-byte length.
const MESSAGE_HEADER: usize = 4;
/// The alert levels (RFC 8446, section 6).
const WARNING: u8 = 1;
const FATAL: u8 = 2;

/// The record layer of one end after the handshake.
struct Records {
    kernel: Kernel,
    /// The protection of the records of the peer.
    rx: Protection,
    /// The protection of the records of this end.
    tx: Protection,
    /// The records that one key of this end seals: the last of them is a KeyUpdate.
    tx_limit: u64,
    /// The peer asked for a KeyUpdate, which this end sends before its next record.
    update: bool,
    /// A handshake message whose records have not all arrived.
    joined: Option<Bytes>,
    /// The bytes of one copy of the chain of the peer, which each session ticket copies.
    chain: u64,
    /// The store of the session tickets of a client, or `None` when they do not resume.
    tickets: Option<Arc<ClientStore>>,
}

impl Records {
    fn new(
        kernel: Kernel,
        secrets: &ExtractedSecrets,
        key_records_max: u64,
        (chain, tickets): (u64, Option<Arc<ClientStore>>),
    ) -> Result<Self, Error> {
        let SupportedCipherSuite::Tls13(suite) = kernel.suite() else {
            return Err(no_keys());
        };
        Ok(Self {
            rx: protection(Some(&secrets.rx))?,
            tx: protection(Some(&secrets.tx))?,
            tx_limit: key_records_max.min(suite.common.confidentiality_limit),
            update: false,
            joined: None,
            chain,
            tickets,
            kernel,
        })
    }

    /// Seals one record of type `content` after the bytes of `written`. First, it sends a
    /// KeyUpdate when the peer asked for one, or when the key reached its limit.
    fn seal(&mut self, content: Content, plaintext: &[&[u8]], written: &mut Bytes) -> Result<(), Error> {
        if self.update || self.tx.seq().saturating_add(1) >= self.tx_limit {
            self.update_tx(written)?;
        }
        seal(&mut self.tx, content, plaintext, written)
    }

    /// Sends a KeyUpdate under the old key, and then seals with the new key. The KeyUpdate does
    /// not ask the peer for one: only the key of this end changes.
    fn update_tx(&mut self, written: &mut Bytes) -> Result<(), Error> {
        seal(&mut self.tx, Content::Handshake, &[&KEY_UPDATE_NOT_REQUESTED], written)?;
        self.tx = self.kernel.update_tx()?;
        self.update = false;
        Ok(())
    }

    /// Takes the handshake messages in the content of one record. A message that continues into
    /// the next record joins in a buffer of at most `limit` bytes.
    fn handshake(
        &mut self,
        mut content: &[u8],
        limit: usize,
        budget: &Budget,
        copies: &mut Copies,
    ) -> Result<(), Fault> {
        if content.is_empty() {
            return Err(Violation::new(AlertDescription::UnexpectedMessage, "a TLS handshake record is empty").into());
        }
        if let Some(mut joined) = self.joined.take() {
            let taken = join(&mut joined, content, limit)?;
            copies.handshake += taken as u64;
            content = content.get(taken..).unwrap_or_default();
            if joined.bytes.len() < message_end(&joined.bytes) {
                self.joined = Some(joined);
                return Ok(());
            }
            let (kind, body) = split_message(&joined.bytes).unwrap_or_default();
            self.message(kind, body, content.is_empty(), budget)?;
        }
        while !content.is_empty() {
            let end = message_end(content);
            let Some((whole, rest)) = content.split_at_checked(end) else {
                let mut joined = Bytes::joined(budget);
                copies.handshake += join(&mut joined, content, limit)? as u64;
                self.joined = Some(joined);
                return Ok(());
            };
            let (kind, body) = split_message(whole).unwrap_or_default();
            self.message(kind, body, rest.is_empty(), budget)?;
            content = rest;
        }
        Ok(())
    }

    /// Takes one handshake message of the peer after the handshake. `last` tells whether it ends
    /// its record, as each message before a key change must (RFC 8446, section 5.1).
    fn message(&mut self, kind: u8, body: &[u8], last: bool, budget: &Budget) -> Result<(), Fault> {
        match (kind, &mut self.kernel) {
            (NEW_SESSION_TICKET, Kernel::Client(kernel)) => {
                // rustls copies the chain into each ticket. The charge goes to the budget of the
                // store that keeps the ticket, or to the connection for this call. A ticket that
                // the budget cannot pay for does not go to rustls.
                let ticket = match &self.tickets {
                    Some(store) => store.charge(body.len(), self.chain),
                    None => memory::Ticket::new(budget, body.len(), self.chain),
                };
                if let Some(ticket) = ticket {
                    memory::ticket(ticket, || kernel.handle_new_session_ticket(body)).map_err(|_| {
                        Violation::new(
                            AlertDescription::DecodeError,
                            "rustls refused a session ticket of the server",
                        )
                    })?;
                }
            }
            (KEY_UPDATE, _) => {
                if !last {
                    return Err(Violation::new(
                        AlertDescription::UnexpectedMessage,
                        "a KeyUpdate does not end its TLS record",
                    )
                    .into());
                }
                let requested = match body {
                    [0] => false,
                    [1] => true,
                    [_] => {
                        return Err(Violation::new(
                            AlertDescription::IllegalParameter,
                            "a KeyUpdate has an unknown request",
                        )
                        .into());
                    }
                    _ => {
                        return Err(
                            Violation::new(AlertDescription::DecodeError, "a KeyUpdate has the wrong length").into(),
                        );
                    }
                };
                self.rx = self.kernel.update_rx()?;
                self.update |= requested;
            }
            _ => {
                return Err(Violation::new(
                    AlertDescription::UnexpectedMessage,
                    "the peer sent a handshake message that TLS 1.3 forbids after the handshake",
                )
                .into());
            }
        }
        Ok(())
    }
}

/// Seals one record with `tx` after the bytes of `written`, which it charges first.
fn seal(tx: &mut Protection, content: Content, plaintext: &[&[u8]], written: &mut Bytes) -> Result<(), Error> {
    let len: usize = plaintext.iter().map(|part| part.len()).sum();
    written.reserve(HEADER + len + 1 + TAG, OUTPUT_REFUSED)?;
    tx.seal(content, plaintext, &mut written.bytes)
        .map_err(|_| Error::new(Kind::Unsupported, "the cipher refused to seal a TLS record"))?;
    written.settle(OUTPUT_REFUSED)
}

/// The end of the handshake message that starts `bytes`: its header and its body. A partial
/// header needs at least its 4 bytes.
fn message_end(bytes: &[u8]) -> usize {
    match bytes {
        [_, high, middle, low, ..] => {
            MESSAGE_HEADER + (usize::from(*high) << 16 | usize::from(*middle) << 8 | usize::from(*low))
        }
        _ => MESSAGE_HEADER,
    }
}

/// The type and the body of one complete handshake message.
fn split_message(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (&[kind, ..], body) = bytes.split_first_chunk::<MESSAGE_HEADER>()?;
    Some((kind, body))
}

/// Adds to `joined` the first bytes of `content` that its message needs, and gives how many it
/// took. Refuses a message larger than `limit`.
fn join(joined: &mut Bytes, content: &[u8], limit: usize) -> Result<usize, Error> {
    let mut taken = 0;
    loop {
        let end = message_end(&joined.bytes);
        if end > limit {
            return Err(Error::new(
                Kind::Overload,
                "a TLS handshake message is larger than the input region",
            ));
        }
        let take = (end - joined.bytes.len()).min(content.len() - taken);
        if take == 0 {
            return Ok(taken);
        }
        joined.reserve(end - joined.bytes.len(), MESSAGE_REFUSED)?;
        joined
            .bytes
            .extend_from_slice(content.get(taken..taken + take).unwrap_or_default());
        taken += take;
    }
}

/// The phase of a connection.
#[expect(
    clippy::large_enum_variant,
    reason = "a connection holds one phase in place, and a box would add an allocation for each connection"
)]
enum Phase {
    /// rustls runs the handshake on the input region.
    Handshake(Session),
    /// The record layer of the core protects each record.
    Records(Records),
    /// rustls did not give the traffic keys, so the connection ended.
    Failed,
}

/// The application protocol that ALPN selected: at most 255 bytes (RFC 7301, section 3.1).
#[derive(Clone, Copy)]
struct Protocol {
    bytes: [u8; 255],
    len: u8,
}

impl Protocol {
    fn new(name: &[u8]) -> Option<Self> {
        let mut bytes = [0; 255];
        bytes.get_mut(..name.len())?.copy_from_slice(name);
        Some(Self {
            bytes,
            len: u8::try_from(name.len()).ok()?,
        })
    }

    fn name(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// What the handshake negotiated. The connection keeps it after rustls gives its keys.
struct Facts {
    group: Group,
    protocol: Option<Protocol>,
    handshake: Handshake,
    peer: Option<Evidence>,
}

/// The authentication of the peer, which the connection keeps: a copy of its end-entity
/// certificate, charged with the kernel state.
struct Evidence {
    certificate: Vec<u8>,
    authentication: Authentication,
}

impl Facts {
    /// The facts of a completed handshake, or `None` when rustls lacks one of them. Refuses with
    /// [`Kind::Overload`] when the memory for the certificate of the peer is not available.
    fn of(common: &CommonState) -> Result<Option<Self>, Error> {
        let peer = match common.peer_identity().map(|identity| identity.identity()) {
            Some(Chain::X509(chain)) => {
                let der = chain.end_entity.as_ref();
                let authentication = peer::authentication(der).ok_or(Error::new(
                    Kind::Unsupported,
                    "the key algorithm of the peer is not one that the provider verifies",
                ))?;
                let mut certificate = Vec::new();
                certificate.try_reserve_exact(der.len()).map_err(|_| {
                    Error::new(
                        Kind::Overload,
                        "the memory for the certificate of the peer is not available",
                    )
                })?;
                certificate.extend_from_slice(der);
                Some(Evidence {
                    certificate,
                    authentication,
                })
            }
            _ => None,
        };
        let (Some(group), Some(kind)) = (common.negotiated_key_exchange_group(), common.handshake_kind()) else {
            return Ok(None);
        };
        let protocol = match common.alpn_protocol() {
            Some(name) => match Protocol::new(name.as_ref()) {
                Some(protocol) => Some(protocol),
                None => return Ok(None),
            },
            None => None,
        };
        Ok(Some(Self {
            group: Group(u16::from(group.name())),
            protocol,
            // A handshake that neither resumed nor retried is full.
            handshake: match kind {
                HandshakeKind::Resumed => Handshake::Resumed,
                HandshakeKind::FullWithHelloRetryRequest => Handshake::Retried,
                _ => Handshake::Full,
            },
            peer,
        }))
    }
}

/// A writable input region: received ciphertext, which rustls reads during the handshake and the
/// record layer opens in place after it.
struct Region {
    backing: Backing,
    /// The bytes before `start` are done.
    start: usize,
    /// During the handshake, the end of the records that rustls can read. It reads one record at
    /// a time, so it stops at the record that completes the handshake.
    seen: usize,
}

impl Region {
    /// Allocates a region of `capacity` bytes that starts with `bytes`, charged to `budget`.
    fn new(budget: &Budget, bytes: &[u8], capacity: usize) -> Result<Self, Error> {
        // A pool of one slot charges its region before it allocates it. The parts that
        // `freeze_prefix` makes share the slot, so the charge ends after the last of them.
        let refused = |refused: PoolRefused| match refused {
            PoolRefused::Budget(_) => Error::new(Kind::Overload, "the budget refused a TLS input region"),
            PoolRefused::Layout => Error::new(Kind::Misuse, "the TLS input region is too large"),
            PoolRefused::Allocation => Error::new(Kind::Overload, "the memory for a TLS input region is not available"),
        };
        let slot = Layout::array::<u8>(capacity).map_err(|_| refused(PoolRefused::Layout))?;
        let backing = Pool::new(budget, NonZeroU32::MIN, slot)
            .map_err(refused)?
            .acquire()
            .map_err(|_| refused(PoolRefused::Allocation))?;
        let mut region = Self {
            backing,
            start: 0,
            seen: 0,
        };
        region.append(bytes);
        Ok(region)
    }

    /// The bytes after the done ones: a partial record, or records that the engine has not read.
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

    /// Freezes the bytes before `end`, the end of the opened records, into a lease, with no copy.
    /// The rest of the region stays writable.
    fn freeze_prefix(&mut self, end: usize) -> Lease {
        assert!(
            end == self.start && end <= self.backing.initialized(),
            "a region freezes at the end of its opened records"
        );
        let backing = core::mem::replace(&mut self.backing, Backing::from(Vec::new()));
        match backing.freeze_prefix(end) {
            Ok((lease, rest)) => {
                self.backing = rest;
                self.start = 0;
                lease
            }
            Err(backing) => {
                self.backing = backing;
                Lease::from(Vec::new())
            }
        }
    }
}

/// The view of an input region that rustls reads: the bytes after the ones that it discarded, up
/// to the end of the records that it can see.
struct View<'a> {
    region: &'a mut Region,
    notified: &'a mut bool,
    ended: bool,
}

impl TlsInputBuffer for View<'_> {
    fn slice_mut(&mut self) -> &mut [u8] {
        let Region { backing, start, seen } = &mut *self.region;
        backing.bytes_mut().get_mut(*start..*seen).unwrap_or_default()
    }

    fn discard(&mut self, len: usize) {
        self.region.start = self.region.start.saturating_add(len).min(self.region.seen);
    }

    fn received_close_notify(&mut self) {
        *self.notified = true;
    }

    fn has_seen_eof(&self) -> bool {
        self.ended
    }
}

/// Bytes that the engine writes, its ciphertext output or a joined handshake message, with their
/// charge: their capacity, and for an output the one allocation of the lease that it becomes.
struct Bytes {
    bytes: Vec<u8>,
    charge: Credit,
    /// The allocation of the lease of the bytes, or 0 for bytes that the engine keeps.
    lease: u64,
}

/// The one allocation of the lease of each ciphertext output.
const OUTPUT_LEASE: u64 = Lease::owner_layout::<Charged<Vec<u8>, Credit>>().size() as u64;

/// The refusals of a charge of [`Bytes`].
const OUTPUT_REFUSED: Error = Error::new(Kind::Overload, "the budget refused the TLS output");
const MESSAGE_REFUSED: Error = Error::new(Kind::Overload, "the budget refused a TLS handshake message");

impl Bytes {
    /// A ciphertext output, which goes out as a lease.
    fn output(budget: &Budget) -> Self {
        Self {
            bytes: Vec::new(),
            charge: budget.credit(0),
            lease: OUTPUT_LEASE,
        }
    }

    /// A joined handshake message, which the engine keeps.
    fn joined(budget: &Budget) -> Self {
        Self {
            lease: 0,
            ..Self::output(budget)
        }
    }

    /// The charge of `capacity` bytes, with the allocation of their lease.
    fn target(&self, capacity: usize) -> u64 {
        if capacity == 0 { 0 } else { capacity as u64 + self.lease }
    }

    /// Makes room for `additional` bytes: it charges them, and then allocates them. Refuses with
    /// `refused`.
    fn reserve(&mut self, additional: usize, refused: Error) -> Result<(), Error> {
        let target = self.bytes.len().saturating_add(additional);
        if target > self.bytes.capacity() {
            let more = self.target(target).saturating_sub(self.charge.charged());
            self.charge.charge(more).map_err(|_| refused)?;
            if self.bytes.try_reserve_exact(additional).is_err() {
                self.charge.refund(more).map_err(|_| refused)?;
                return Err(refused);
            }
        }
        self.settle(refused)
    }

    /// Charges the growth of the bytes when a call writes at most `flight` more, or gives the
    /// units that it needs. A vector grows to at most twice its length, so its capacity stays
    /// within twice the length after the call, or its capacity before it.
    fn room(&mut self, flight: usize) -> Result<(), u64> {
        let bound = self
            .bytes
            .len()
            .saturating_add(flight)
            .saturating_mul(2)
            .max(self.bytes.capacity());
        let more = self.target(bound).saturating_sub(self.charge.charged());
        self.charge.charge(more).map_err(|_| more)
    }

    /// Makes the charge equal the charge of the capacity: it charges what the allocator or rustls
    /// added, or gives back what a growth bound did not use. Refuses with `refused`.
    fn settle(&mut self, refused: Error) -> Result<(), Error> {
        let target = self.target(self.bytes.capacity());
        let charged = self.charge.charged();
        if let Some(more) = target.checked_sub(charged).filter(|&more| more > 0) {
            self.charge.charge(more).map_err(|_| refused)?;
        } else if let Some(rest) = charged.checked_sub(target).filter(|&rest| rest > 0) {
            self.charge.refund(rest).map_err(|_| refused)?;
        }
        Ok(())
    }
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

/// The place of the input region that the host holds for a receive.
struct Lent {
    address: usize,
    start: usize,
    seen: usize,
}

/// The failure of a turn, and the alert that this end sends for it, if any.
struct Fault {
    error: Error,
    alert: Option<AlertDescription>,
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self { error, alert: None }
    }
}

impl From<Violation> for Fault {
    fn from(violation: Violation) -> Self {
        Self {
            error: Error::new(Kind::Malformed, violation.reason),
            alert: Some(violation.alert),
        }
    }
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
    phase: Phase,
    /// What the handshake negotiated, after it completed.
    facts: Option<Facts>,
    /// The stream of each draw of the connection, or `None` for the system.
    stream: Option<replay::Stream>,
    /// The charge of the memory of rustls.
    held: Held,
    cost: Cost,
    own: Arc<Owns>,
    /// The store of the session tickets of a client, until the hand-off.
    tickets: Option<Arc<ClientStore>>,
    /// The capacity that the next rustls call waits for.
    wait: Option<u64>,
    budget: Budget,
    limits: Limits,
    /// The region that the engine reads, or `None` when no received byte is pending.
    region: Option<Region>,
    lent: Option<Lent>,
    next: Option<Next>,
    /// The facts of the last received region.
    endpoint: Option<Endpoint>,
    capacity: u64,
    written: Bytes,
    /// The plaintext regions that the record layer sealed, until the transport accepts them.
    sent: Sent,
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
            .map_err(|_| Error::new(Kind::Misuse, "the server name is not a DNS name or an IP address"))?;
        check(&limits)?;
        // The charges come before rustls starts, so a refusal allocates nothing. The connection
        // keeps the name, and the ClientHello carries it.
        let sent = Sent::new(NonZeroUsize::new(outbound.limit()).unwrap_or(NonZeroUsize::MIN), budget)?;
        let name_bytes = match &name {
            ServerName::DnsName(dns) => dns.as_ref().len(),
            _ => 0,
        };
        let own = config.own.get();
        let mut held = Held::new(budget, &config.cost, 2 * name_bytes as u64, &own)?;
        let mut written = Bytes::output(budget);
        written.room(own.flight() + name_bytes).map_err(|_| OUTPUT_REFUSED)?;
        let name = name.to_owned();
        let stream = config.entropy.stream(CONNECTION);
        let Bytes { bytes, charge, .. } = &mut written;
        let session = memory::handshake(&mut held, charge, || {
            scoped(stream.as_ref(), || config.config.connect(name).build(bytes))
        });
        written.settle(OUTPUT_REFUSED)?;
        held.after(0, &own);
        let session = session.map_err(|error| refused(&error))?;
        Ok(Self::new(
            (Session::Client(session), stream),
            (held, config.cost, Arc::clone(&config.own), config.store.clone()),
            (written, sent),
            engine,
            (inbound, outbound),
            limits,
            budget,
        ))
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
        check(&limits)?;
        let sent = Sent::new(NonZeroUsize::new(outbound.limit()).unwrap_or(NonZeroUsize::MIN), budget)?;
        let own = config.own.get();
        let mut held = Held::new(budget, &config.cost, 0, &own)?;
        let stream = config.entropy.stream(CONNECTION);
        let mut written = Bytes::output(budget);
        let session = memory::handshake(&mut held, &mut written.charge, || {
            scoped(stream.as_ref(), || {
                rustls::Connection::<ServerSide, Tcp>::new(Arc::clone(&config.config))
            })
        });
        held.after(0, &own);
        let session = session.map_err(|error| refused(&error))?;
        Ok(Self::new(
            (Session::Server(session), stream),
            (held, config.cost, Arc::clone(&config.own), None),
            (written, sent),
            engine,
            (inbound, outbound),
            limits,
            budget,
        ))
    }

    fn new(
        (session, stream): (Session, Option<replay::Stream>),
        (held, cost, own, tickets): (Held, Cost, Arc<Owns>, Option<Arc<ClientStore>>),
        (written, sent): (Bytes, Sent),
        engine: E,
        (inbound, outbound): (Inbound, Outbound),
        limits: Limits,
        budget: &Budget,
    ) -> Self {
        Self {
            engine,
            inbound,
            outbound,
            phase: Phase::Handshake(session),
            facts: None,
            stream,
            held,
            cost,
            own,
            tickets,
            wait: None,
            budget: budget.clone(),
            limits,
            region: None,
            lent: None,
            next: None,
            endpoint: None,
            capacity: 0,
            written,
            sent,
            copies: Copies::default(),
            notified: false,
            closure: None,
            end: None,
        }
    }

    /// The inner engine and its plaintext output queue, for the calls of the application, such as
    /// a response.
    pub fn parts(&mut self) -> (&mut E, &mut Outbound) {
        (&mut self.engine, &mut self.outbound)
    }

    /// What the handshake negotiated, or `None` before it completed.
    pub fn negotiated(&self) -> Option<Negotiated<'_>> {
        let facts = self.facts.as_ref()?;
        Some(Negotiated {
            group: facts.group,
            protocol: facts.protocol.as_ref().map(Protocol::name),
            handshake: facts.handshake,
            peer: facts.peer.as_ref().map(|evidence| Peer {
                certificate: &evidence.certificate,
                authentication: evidence.authentication,
            }),
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

    /// The plaintext whose records the transport accepted, when it accepted `accepted` bytes of
    /// the ciphertext of this connection: each byte, and the body bytes of them. A record counts
    /// when each of its bytes went.
    pub(crate) fn sent(&self, accepted: u64) -> Accepted {
        self.sent.sent(accepted)
    }

    /// One turn, up to the progress of the inner engine.
    fn turn(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> Result<(Option<E::Event>, Turn), Fault> {
        let mut work = Work::default();
        self.wait = None;
        self.take_queued(inbound)?;
        let stopped = loop {
            self.complete_from_next()?;
            self.handshake(inbound.ended() && inbound.front().is_none(), &mut work)?;
            let stopped = self.open(&mut work)?;
            // A region with no pending byte is done: an idle connection keeps no input region.
            if self.region.as_ref().is_some_and(|region| region.pending().is_empty()) {
                self.region = None;
            }
            // A region of the host continues the input once the record before it is complete.
            if self.region.is_some() || work.reached(&self.limits.turn) {
                break stopped;
            }
            let Some(next) = self.next.take() else { break stopped };
            self.region = Some(Region {
                backing: next.backing,
                start: next.start,
                seen: next.start,
            });
        };
        let handshaking = matches!(self.phase, Phase::Handshake(_));
        if self.notified && !self.inbound.ended() {
            self.closure = Some(Closure::Notified);
            self.inbound.end();
        }
        let input_ended = inbound.ended() && inbound.front().is_none() && self.next.is_none();
        let partial = self.region.is_some();
        if input_ended && partial && !stopped && self.wait.is_none() {
            return Err(Error::new(Kind::Partial, "the transport ended inside a TLS record").into());
        }
        if input_ended && !partial && !self.inbound.ended() {
            if handshaking {
                return Err(Error::new(Kind::Partial, "the transport ended before the TLS handshake completed").into());
            }
            if inbound.is_reset() {
                self.closure = Some(Closure::Reset);
                self.inbound.reset();
            } else {
                self.closure = Some(Closure::Unnotified);
                self.inbound.end();
            }
        }
        let (event, inner) = if handshaking {
            (None, None)
        } else {
            let (event, turn) = self.engine.drive(&mut self.inbound, &mut self.outbound, now);
            (event, Some(turn))
        };
        self.encrypt(outbound, &mut work)?;
        if let Some(Turn {
            progress: Progress::Terminal(end),
            ..
        }) = inner
        {
            if let Phase::Records(records) = &mut self.phase {
                records.seal(Content::Alert, &[&[WARNING, 0]], &mut self.written)?;
            }
            self.end = Some(end);
        }
        self.flush(outbound);
        let deadline = inner.and_then(|turn| turn.deadline);
        let progress = if let Some(end) = self.end {
            self.ending(end)
        } else if let Some(units) = self.wait {
            Progress::Blocked(Blocked::Capacity(units))
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

    /// The error of `fault`. When the fault names an alert and the record layer has its keys,
    /// this end seals the alert first, so that it goes out before the end. During the handshake,
    /// rustls wrote its own alert before it refused.
    fn fail(&mut self, fault: Fault) -> Error {
        if let (Some(alert), Phase::Records(records)) = (fault.alert, &mut self.phase) {
            // The connection ends with the error also when its alert cannot go.
            let _unsent = records.seal(Content::Alert, &[&[FATAL, alert.0]], &mut self.written);
        }
        fault.error
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
        let mut moved = Region::new(&self.budget, pending, self.limits.input_bytes)?;
        moved.seen = region.seen.saturating_sub(region.start);
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

    /// Runs the handshake on the complete records of the input region, one record at a time.
    /// When the handshake completes, it gives the traffic keys to the record layer. rustls then
    /// holds no part of a message, because the record that completes the handshake ends at a key
    /// change (RFC 8446, section 5.1).
    fn handshake(&mut self, ended: bool, work: &mut Work) -> Result<(), Error> {
        loop {
            let (Phase::Handshake(session), Some(region)) = (&mut self.phase, &mut self.region) else {
                return Ok(());
            };
            region.seen = region.seen.max(region.start);
            let unread = region.backing.bytes().get(region.seen..).unwrap_or_default();
            let next = match unread {
                // rustls refuses a header that is longer than a record, with its alert.
                [_, _, _, high, low, ..] if usize::from(u16::from_be_bytes([*high, *low])) > PROTECTED_MAX => HEADER,
                _ => record_end(unread),
            };
            if next > unread.len() || work.reached(&self.limits.turn) {
                return Ok(());
            }
            // rustls can read each byte that it did not discard, up to the end of this record. A
            // call that the budget cannot pay for waits.
            let visible = region.seen + next - region.start;
            let own = self.own.get();
            if let Err(units) = self.held.charge(own.work(self.cost.read, visible)) {
                self.wait = Some(units);
                return Ok(());
            }
            if let Err(units) = self.written.room(own.flight()) {
                self.held.after(0, &own);
                self.wait = Some(units);
                return Ok(());
            }
            region.seen += next;
            work.add(next, 1);
            let mut view = View {
                region,
                notified: &mut self.notified,
                ended,
            };
            let stream = self.stream.as_ref();
            let Bytes { bytes, charge, .. } = &mut self.written;
            let read = memory::handshake(&mut self.held, charge, || {
                scoped(stream, || session.read(&mut view, bytes))
            });
            self.written.settle(OUTPUT_REFUSED)?;
            self.held.after(visible, &own);
            read?;
            if !session.common().is_handshaking() {
                let identity = session.common().peer_identity();
                let (peer, evidence) = (memory::chain_bytes(identity), memory::end_entity_bytes(identity));
                self.held.finished(peer, evidence, &own);
                return self.hand_off(peer, evidence);
            }
        }
    }

    /// Gives the traffic keys of the completed handshake to the record layer, at the sequence
    /// numbers of rustls. A client keeps one copy of the `peer` bytes of the chain of the server
    /// for its tickets, and each end keeps the `evidence` bytes of the end-entity certificate of
    /// its peer.
    fn hand_off(&mut self, peer: u64, evidence: u64) -> Result<(), Error> {
        if self.region.as_ref().is_some_and(|region| region.start < region.seen) {
            return Err(Error::new(
                Kind::Unsupported,
                "rustls kept a part of the handshake when it completed",
            ));
        }
        let Phase::Handshake(session) = core::mem::replace(&mut self.phase, Phase::Failed) else {
            return Ok(());
        };
        self.facts = Facts::of(session.common())?;
        let (kernel, secrets) = Kernel::new(session)?;
        let kept = match kernel {
            Kernel::Client(_) => peer,
            Kernel::Server(_) => 0,
        };
        self.held.hand_off(self.cost.kernel, kept + evidence);
        self.phase = Phase::Records(Records::new(
            kernel,
            &secrets,
            self.limits.key_records_max,
            (peer, self.tickets.take()),
        )?);
        Ok(())
    }

    /// Opens the complete records of the input region in place, until a limit of the turn stops
    /// it or the inbound queue of the inner engine has no place. Gives whether such a stop left
    /// records to open. The plaintext of each record reaches the inner engine at once, as a view
    /// of the frozen part of the region.
    fn open(&mut self, work: &mut Work) -> Result<bool, Fault> {
        let (Phase::Records(records), Some(region), Some(endpoint)) =
            (&mut self.phase, &mut self.region, self.endpoint)
        else {
            return Ok(false);
        };
        loop {
            if self.notified {
                // The peer closed: each later byte is ignored (RFC 8446, section 6.1).
                region.start = region.backing.initialized();
                return Ok(false);
            }
            let pending = region.pending();
            let Some(len) = record::length(pending)? else {
                return Ok(false);
            };
            if pending.len() < len {
                return Ok(false);
            }
            if self.inbound.free() == 0 || work.reached(&self.limits.turn) {
                return Ok(true);
            }
            let start = region.start;
            let end = start + len;
            let Some(record) = region.backing.bytes_mut().get_mut(start..end) else {
                return Ok(false);
            };
            let opened = records.rx.open(record)?;
            let content = record.get(opened.range.clone()).unwrap_or_default();
            region.start = end;
            work.add(len, 1);
            if opened.content != Content::Handshake && records.joined.is_some() {
                return Err(Violation::new(
                    AlertDescription::UnexpectedMessage,
                    "a TLS record came between the parts of a handshake message",
                )
                .into());
            }
            match opened.content {
                Content::Data if content.is_empty() => {}
                Content::Data => {
                    let range = start + opened.range.start..start + opened.range.end;
                    if let Some(plaintext) = region.freeze_prefix(end).view(range) {
                        push(&mut self.inbound, plaintext, endpoint, self.capacity);
                    }
                }
                Content::Handshake => {
                    records.handshake(content, self.limits.input_bytes, &self.budget, &mut self.copies)?
                }
                Content::Alert => match *content {
                    [_, description] => match AlertDescription(description) {
                        AlertDescription::CloseNotify => self.notified = true,
                        // A close_notify follows (RFC 8446, section 6.1).
                        AlertDescription::UserCanceled => {}
                        alert => return Err(refused(&rustls::Error::AlertReceived(alert)).into()),
                    },
                    [] => {
                        return Err(
                            Violation::new(AlertDescription::UnexpectedMessage, "a TLS alert record is empty").into(),
                        );
                    }
                    _ => {
                        return Err(Violation::new(
                            AlertDescription::DecodeError,
                            "a TLS alert record does not hold exactly one alert",
                        )
                        .into());
                    }
                },
            }
        }
    }

    /// Seals the plaintext output of the inner engine, until a limit of the turn stops it or the
    /// output queue has no place for more ciphertext.
    fn encrypt(&mut self, outbound: &Outbound, work: &mut Work) -> Result<(), Error> {
        let Phase::Records(records) = &mut self.phase else {
            return Ok(());
        };
        // A KeyUpdate that the peer asked for goes out also when no plaintext waits.
        if records.update {
            records.update_tx(&mut self.written)?;
        }
        self.sent.settle(outbound.accepted().bytes);
        while !work.reached(&self.limits.turn) && !self.sent.full() {
            if outbound.free() == 0 && !self.written.bytes.is_empty() {
                break;
            }
            let payload = self.outbound.front_is_payload();
            let Some(output) = self.outbound.submit() else { break };
            let plaintext = output.region.bytes();
            // The offset of the ciphertext after the output that the queue took.
            let start = outbound.pushed().strict_add(self.written.bytes.len() as u64);
            for chunk in plaintext.chunks(CONTENT_MAX) {
                records.seal(Content::Data, &[chunk], &mut self.written)?;
            }
            let end = outbound.pushed().strict_add(self.written.bytes.len() as u64);
            self.sent.push(start, end, plaintext.len(), payload);
            self.outbound.ack(output.id, plaintext.len())?;
            self.copies.encrypted += plaintext.len() as u64;
            work.add(plaintext.len(), plaintext.len().div_ceil(CONTENT_MAX));
        }
        Ok(())
    }

    /// Gives the written ciphertext to the output queue, when it has a place.
    fn flush(&mut self, outbound: &mut Outbound) {
        if self.written.bytes.is_empty() || outbound.free() == 0 {
            return;
        }
        let written = core::mem::replace(&mut self.written, Bytes::output(&self.budget));
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

/// Refuses `limits` that cannot work.
fn check(limits: &Limits) -> Result<(), Error> {
    if limits.input_bytes < RECORD_BYTES_MAX {
        return Err(Error::new(
            Kind::Misuse,
            "the TLS input region is smaller than a record",
        ));
    }
    if limits.key_records_max < 2 {
        return Err(Error::new(
            Kind::Misuse,
            "a TLS key seals fewer than 2 records, and its KeyUpdate is one of them",
        ));
    }
    Ok(())
}

/// Queues plaintext for the inner engine. The caller checked that the queue has a place.
fn push(inbound: &mut Inbound, region: Lease, endpoint: Endpoint, capacity: u64) {
    let pushed = inbound.push(Received {
        region,
        endpoint,
        capacity,
    });
    assert!(
        pushed.is_ok(),
        "the record layer opens a record only when the queue has a place"
    );
}

/// The end of the record that starts `pending`: its header and its payload. A partial header
/// needs at least its 5 bytes.
fn record_end(pending: &[u8]) -> usize {
    match pending {
        [_, _, _, high, low, ..] => HEADER + usize::from(u16::from_be_bytes([*high, *low])),
        _ => HEADER,
    }
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
            Err(fault) => {
                let error = self.fail(fault);
                // The alert goes out before the end.
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
            start: region.start,
            seen: region.seen,
        });
        Ok(Some(region.backing))
    }

    fn received(&mut self, _: &mut Inbound, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        match self.lent.take() {
            Some(lent) if lent.address == region.as_ptr().addr() => {
                self.region = Some(Region {
                    backing: region,
                    start: lent.start,
                    seen: lent.seen,
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
                    start: 0,
                    seen: 0,
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
            .field("handshaking", &matches!(self.phase, Phase::Handshake(_)))
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
