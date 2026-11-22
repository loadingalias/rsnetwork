//! What the tests of the Tokio binding share: limits, TLS configurations from the certificates of
//! `tests/tls`, the two kinds of runtime, and a proxy that forwards whole TLS records.

use core::alloc::Layout;
use core::net::SocketAddr;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use rsnetwork::buffer::Pool;
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::server::{self, Linger, Response};
use rsnetwork::tls::{
    self, CertificateDer, ClientConfig, ClientOptions, Entropy, Identity, PrivateKeyDer, Resumption, ServerConfig,
    ServerOptions, TimeProvider, UnixTime,
};
use rsnetwork::value::{Authority, Method, Status, Target};
use rsnetwork_tokio::Clock;
use tokio::runtime::{Builder, Runtime};

const CA: &[u8] = include_bytes!("../../../tests/tls/ca.der");
const SERVER: (&[u8], &[u8]) = (
    include_bytes!("../../../tests/tls/server.der"),
    include_bytes!("../../../tests/tls/server.key.der"),
);

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

/// The bytes of a TLS 1.3 alert record: its header, the alert, the content type, and the tag.
pub(crate) const ALERT_RECORD: usize = 5 + 2 + 1 + 16;

/// The longest that a test waits for a peer.
pub(crate) const PATIENCE: Duration = Duration::from_secs(10);

pub(crate) const HEAD: h1::Limits = h1::Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

/// A drain of 64 bytes: the rest of a body within it drains, and a longer rest closes.
pub(crate) const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 26,
    drain_bytes: 64,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

/// The HTTP/2 limits: at most 8 streams at a time.
pub(crate) const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 8,
        max_header_list_size: 4096,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 1 << 20,
};

pub(crate) const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

pub(crate) const QUEUE: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// The time that a server waits for a request head, also over TLS.
pub(crate) const HEAD_TIMEOUT: Duration = Duration::from_millis(300);

/// The linger of a server: at most this time and 1000 bytes.
pub(crate) const LINGER: Linger = Linger {
    time: Duration::from_millis(300),
    bytes: 1000,
};

pub(crate) const TLS: tls::Limits = tls::Limits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

/// TCP, or TLS 1.3 to `server.test`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Plain,
    Tls,
}

/// A wall clock that stays at one time, inside the validity of each certificate.
#[derive(Debug)]
struct At;

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(VALID)))
    }
}

pub(crate) fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 28).unwrap())
}

/// A pool of 16 receive regions of 16 KiB.
pub(crate) fn pool(budget: &Budget) -> Pool {
    Pool::new(
        budget,
        NonZeroU32::new(16).unwrap(),
        Layout::array::<u8>(16 * 1024).unwrap(),
    )
    .unwrap()
}

pub(crate) fn server_config() -> ServerConfig {
    let (chain, key) = SERVER;
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(chain.to_vec())],
            key: PrivateKeyDer::try_from(key.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols: &[b"h2", b"http/1.1"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At),
        entropy: Entropy::System,
    })
    .unwrap()
}

/// A client configuration with ALPN `http/1.1`, which the server selects.
pub(crate) fn client_config() -> ClientConfig {
    client_with(&[b"http/1.1"])
}

fn client_with(protocols: &[&[u8]]) -> ClientConfig {
    ClientConfig::new(ClientOptions {
        roots: &[CertificateDer::from(CA.to_vec())],
        identity: None,
        protocols,
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At),
        entropy: Entropy::System,
    })
    .unwrap()
}

/// A client of the core over `transport`, on the clock of the binding.
pub(crate) fn core_client(transport: Transport) -> client::Http1 {
    match transport {
        Transport::Plain => client::Http1::plain(CLIENT, Clock.domain(), &budget()).unwrap(),
        Transport::Tls => client::Http1::tls(
            &client_config(),
            "server.test",
            (CLIENT, TLS),
            Clock.domain(),
            &budget(),
        )
        .unwrap(),
    }
}

/// The limits of a client of the tests.
const CLIENT: client::Limits = client::Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: QUEUE,
};

/// An HTTP/2 client of the core over `transport`, on the clock of the binding: with prior
/// knowledge over TCP, and with ALPN `h2` over TLS.
pub(crate) fn core_h2_client(transport: Transport) -> client::Http2 {
    match transport {
        Transport::Plain => client::Http2::plain(CLIENT, Clock.domain(), &budget()).unwrap(),
        Transport::Tls => client::Http2::tls(
            &client_with(&[b"h2"]),
            "server.test",
            (CLIENT, TLS),
            Clock.domain(),
            &budget(),
        )
        .unwrap(),
    }
}

/// An HTTP/2 client of the binding over `transport`, connected to `address`.
pub(crate) async fn h2_client(transport: Transport, address: SocketAddr) -> rsnetwork_tokio::client::Http2 {
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    rsnetwork_tokio::client::Http2::new(core_h2_client(transport), stream, pool(&budget())).unwrap()
}

/// A server of the core over `transport` that serves HTTP/2: with prior knowledge over TCP, and
/// when ALPN selects `h2` over TLS.
pub(crate) fn core_h2_server(transport: Transport) -> server::Http {
    let limits = server::Limits {
        cleartext: server::Cleartext::Http2,
        ..server_limits()
    };
    match transport {
        Transport::Plain => server::Http::plain(limits, Clock.domain(), &budget()).unwrap(),
        Transport::Tls => server::Http::tls(&server_config(), (limits, TLS), Clock.domain(), &budget()).unwrap(),
    }
}

/// The limits of a server of the tests.
pub(crate) fn server_limits() -> server::Limits {
    server::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: QUEUE,
        head_timeout: Some(HEAD_TIMEOUT),
        linger: LINGER,
        cleartext: server::Cleartext::Http1,
    }
}

/// A server of the core over `transport`, on the clock of the binding.
pub(crate) fn core_server(transport: Transport) -> server::Http {
    let limits = server_limits();
    match transport {
        Transport::Plain => server::Http::plain(limits, Clock.domain(), &budget()).unwrap(),
        Transport::Tls => server::Http::tls(&server_config(), (limits, TLS), Clock.domain(), &budget()).unwrap(),
    }
}

/// A client of the binding over `transport`, connected to `address`.
pub(crate) async fn client(transport: Transport, address: SocketAddr) -> rsnetwork_tokio::client::Http1 {
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    rsnetwork_tokio::client::Http1::new(core_client(transport), stream, pool(&budget())).unwrap()
}

/// A server of the binding over `transport` on the next connection of `listener`.
pub(crate) async fn server(transport: Transport, listener: &tokio::net::TcpListener) -> rsnetwork_tokio::server::Http {
    let (stream, _) = listener.accept().await.unwrap();
    rsnetwork_tokio::server::Http::new(core_server(transport), stream, pool(&budget())).unwrap()
}

/// An HTTP/2 server of the binding over `transport` on the next connection of `listener`.
pub(crate) async fn h2_server(
    transport: Transport,
    listener: &tokio::net::TcpListener,
) -> rsnetwork_tokio::server::Http {
    let (stream, _) = listener.accept().await.unwrap();
    rsnetwork_tokio::server::Http::new(core_h2_server(transport), stream, pool(&budget())).unwrap()
}

/// A listener on a free loopback port.
pub(crate) async fn listener() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

pub(crate) fn get() -> Request<'static> {
    Request {
        method: Method::GET,
        target: Target::new(b"/").unwrap(),
        authority: Authority::new(b"server.test").unwrap(),
        fields: &[],
        length: Some(0),
    }
}

pub(crate) fn ok(length: Option<u64>) -> Response<'static> {
    Response {
        status: Status::new(200).unwrap(),
        fields: &[],
        length,
    }
}

/// Runs `test` on a current-thread runtime and on a multi-thread runtime, each with I/O and time.
pub(crate) fn on_each_runtime<F: Future<Output = ()>>(test: impl Fn() -> F) {
    let runtimes: [Runtime; 2] = [
        Builder::new_current_thread().enable_all().build().unwrap(),
        Builder::new_multi_thread().enable_all().build().unwrap(),
    ];
    for runtime in runtimes {
        runtime.block_on(test());
    }
}

/// What a [`Proxy`] does with the last record that the server sends before the end of its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Last {
    /// Forwards it, and then the end of the stream.
    Forward,
    /// Holds it back, and forwards the end of the stream: the stream ends before that record.
    Cut,
    /// Holds it back, and resets the connection of the client when the test says so.
    Reset,
}

/// A TCP proxy between a TLS client and a TLS server, which forwards whole records. It records
/// the size of the last record of each side before the end of its stream.
pub(crate) struct Proxy {
    pub(crate) address: SocketAddr,
    /// The test tells the proxy to reset the client, in [`Last::Reset`].
    pub(crate) reset: Sender<()>,
    task: JoinHandle<(Option<usize>, Option<usize>)>,
}

impl Proxy {
    /// A proxy to `server` that does `last` with the last record of the server.
    pub(crate) fn new(server: SocketAddr, last: Last) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (reset, resets) = mpsc::channel();
        let task = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let server = TcpStream::connect(server).unwrap();
            let upstream = {
                let (from, to) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                thread::spawn(move || forward(from, to, Last::Forward, None))
            };
            let downstream = forward(server, client, last, Some(&resets));
            (upstream.join().unwrap(), downstream)
        });
        Self { address, reset, task }
    }

    /// The size of the last record of the client and of the server before the end of each
    /// stream, after both ended.
    pub(crate) fn last_records(self) -> (Option<usize>, Option<usize>) {
        self.task.join().unwrap()
    }
}

/// Forwards each whole record of `from` to `to` at once, until the end of `from`. In a cut and
/// in a reset, an alert record waits until the next record, so the last record, `close_notify`,
/// does not go. Gives the size of the last record.
fn forward(mut from: TcpStream, mut to: TcpStream, last: Last, resets: Option<&Receiver<()>>) -> Option<usize> {
    let (mut pending, mut held, mut size): (Vec<u8>, Option<Vec<u8>>, _) = (Vec::new(), None, None);
    let mut bytes = [0; 64 * 1024];
    loop {
        match from.read(&mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(count) => pending.extend_from_slice(&bytes[..count]),
        }
        while let [_, _, _, high, low, ..] = pending[..] {
            let end = 5 + usize::from(u16::from_be_bytes([high, low]));
            if pending.len() < end {
                break;
            }
            let record: Vec<u8> = pending.drain(..end).collect();
            size = Some(record.len());
            let before = held.take();
            let wait = last != Last::Forward && record.len() == ALERT_RECORD;
            let sent = before
                .iter()
                .chain((!wait).then_some(&record))
                .try_for_each(|bytes| to.write_all(bytes));
            if sent.is_err() {
                return size;
            }
            if wait {
                held = Some(record);
            }
        }
    }
    match last {
        Last::Forward | Last::Cut => drop(to.shutdown(Shutdown::Write)),
        Last::Reset => {
            let resets = resets.expect("the server side can reset");
            resets.recv_timeout(PATIENCE).expect("the test resets the client");
            socket2::SockRef::from(&to).set_linger(Some(Duration::ZERO)).unwrap();
            // The other direction holds a second handle of the socket: its read ends, so it drops
            // the handle, and the close of the last handle resets the connection.
            drop(to.shutdown(Shutdown::Read));
        }
    }
    size
}

/// Reads from `socket` until its end, and gives each byte.
pub(crate) fn read_to_end(socket: &mut TcpStream) -> Vec<u8> {
    socket.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut bytes = Vec::new();
    match socket.read_to_end(&mut bytes) {
        Ok(_) => bytes,
        Err(error) if error.kind() == ErrorKind::ConnectionReset => bytes,
        Err(error) => panic!("the peer cannot read: {error}"),
    }
}
