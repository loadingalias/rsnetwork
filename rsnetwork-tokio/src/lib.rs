//! The Tokio binding of rsnetwork: the protocol engines of the core on the Tokio runtime of the
//! application.
//!
//! - [`client::Http1`], [`client::Http2`], [`server::Http`], and [`tls::Stream`] are the
//!   connections of the core on a Tokio TCP socket. Each call awaits the progress that it needs,
//!   so a body read moves its own bytes: no task and no second object to poll.
//! - On HTTP/2, each stream has its own handle, a [`client::Exchange`] or a [`server::Exchange`],
//!   which can go to a task of its own. The handle that awaits drives the shared connection, and
//!   wakes only the handles whose streams changed.
//! - [`server::Server`] accepts connections, drives each one in a task of its own, and runs the
//!   handler once for each request: on HTTP/2 in a task for each stream. Its close stops the
//!   accepts, drains each connection, and joins each task.
//! - [`Blocking`] admits blocking jobs, for example host lookups, under a bound, before they go to
//!   the blocking pool of Tokio, which has no bound of its own.
//! - [`Socket`] is the step of each call: a connection of the core, its socket, and the [`Clock`].
//!   It drives each vocabulary of the core, also a [`Connection`](rsnetwork::host::Connection).
//!
//! The binding starts no runtime and no thread. Call it in a task of a Tokio runtime whose I/O
//! driver and timer are on, for example a runtime that `Builder::enable_all` made. The socket
//! rules are those of [`host::Tcp`](rsnetwork::host::Tcp).
//!
//! A server answers each request with `hello`, and a client sends one request over loopback:
//!
//! ```
//! use core::alloc::Layout;
//! use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
//! use core::time::Duration;
//!
//! use rsnetwork::body::Collect;
//! use rsnetwork::buffer::{Lease, Pool, WriteLoan};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::client::{self, Request};
//! use rsnetwork::drive::TurnLimits;
//! use rsnetwork::h1::{self, BodyLimits};
//! use rsnetwork::h2;
//! use rsnetwork::server::{self, Cleartext, Linger, Response};
//! use rsnetwork::value::{Authority, Method, Status, Target};
//! use rsnetwork_tokio::Clock;
//! use rsnetwork_tokio::server::Server;
//!
//! let head = h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
//! let body = BodyLimits {
//!     body_bytes: 1 << 20,
//!     drain_bytes: 64 * 1024,
//!     extension_bytes: 256,
//!     trailer_bytes: 4 * 1024,
//!     trailer_fields: 16,
//! };
//! let turn = TurnLimits { bytes: 256 * 1024, frames: 1024, visits: 4096 };
//! let queue = NonZeroUsize::new(16).expect("not zero");
//! let linger = Linger { time: Duration::from_secs(5), bytes: 64 * 1024 };
//! let head_timeout = Some(Duration::from_secs(30));
//! // The HTTP/2 connection, which a server over TLS can select with ALPN `h2`.
//! let h2_settings = h2::Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..h2::Settings::INITIAL };
//! let h2 = h2::Limits { settings: h2_settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 };
//! let cleartext = Cleartext::Http1;
//! let server_limits = server::Limits { head, h2, body, turn, queue, head_timeout, linger, cleartext };
//! let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
//! // Each socket has 4 receive regions of 16 KiB, charged to the budget.
//! let slot = Layout::array::<u8>(16 * 1024)?;
//! let pool = {
//!     let budget = budget.clone();
//!     move || Pool::new(&budget, NonZeroU32::new(4).expect("not zero"), slot)
//! };
//! let ok = Status::new(200)?;
//!
//! let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
//! runtime.block_on(async {
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
//!     let address = listener.local_addr()?;
//!     // Each accepted connection gets a server of the core and its receive regions.
//!     let make = {
//!         let (budget, pool) = (budget.clone(), pool.clone());
//!         move || Ok((server::Http::plain(server_limits, Clock.domain(), &budget)?, pool()?))
//!     };
//!     let connections = NonZeroUsize::new(1024).expect("not zero");
//!     let server = Server::serve(listener, connections, make, move |mut exchange| async move {
//!         let hello = Response { status: ok, fields: &[], length: Some(5) };
//!         exchange.respond(&hello).await?;
//!         exchange.write(&Lease::from(&b"hello"[..])).await?;
//!         exchange.finish().await
//!     });
//!
//!     let core = client::Http1::plain(client::Limits { head, h2, body, turn, queue }, Clock.domain(), &budget)?;
//!     let stream = tokio::net::TcpStream::connect(address).await?;
//!     let mut client = rsnetwork_tokio::client::Http1::new(core, stream, pool()?)?;
//!     let request = Request {
//!         method: Method::GET,
//!         target: Target::new(b"/hello")?,
//!         authority: Authority::new(b"127.0.0.1")?,
//!         fields: &[],
//!         length: Some(0),
//!     };
//!     // One deadline covers the response head and each byte of the body.
//!     client.send(&request, Clock.deadline(Duration::from_secs(5))).await?;
//!     assert_eq!(client.response().await?.status(), ok);
//!     let mut region = WriteLoan::new(Vec::with_capacity(64));
//!     assert!(matches!(client.collect(&mut region).await?, Collect::Complete(None)));
//!     assert_eq!(region.filled(), b"hello");
//!     client.close().await?;
//!
//!     // The close drains each connection, and joins each task of the server.
//!     let report = server.close(Clock.deadline(Duration::from_secs(5))).await;
//!     assert_eq!((report.accepted, report.failed, report.aborted), (1, 0, 0));
//!     Ok::<(), Box<dyn std::error::Error>>(())
//! })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![feature(allocator_ext)]

mod blocking;
pub mod client;
pub mod server;
mod shared;
mod socket;
mod stream;
pub mod tls;

use core::time::Duration;
use std::sync::OnceLock;

use rsnetwork::body::Read;
use rsnetwork::drive::{Error, Kind};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};

pub use blocking::Blocking;
pub use socket::Socket;

/// The identifier of the domain of [`Clock`].
const DOMAIN: u32 = u32::from_be_bytes(*b"TOKI");

/// The clock of the binding: the monotonic clock of Tokio, as the time of the core.
///
/// Make each connection of the core with [`domain`](Self::domain), and each deadline with
/// [`deadline`](Self::deadline). Each clock of a process has the same start, so their times
/// compare. The clock stops while the system is suspended, as the monotonic clock of the target
/// does: on Windows it goes on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Clock;

impl Clock {
    /// The domain of the times of this clock.
    pub const fn domain(self) -> ClockDomain {
        let suspend = cfg_select! {
            windows => Suspend::Advances,
            _ => Suspend::Pauses,
        };
        ClockDomain::new(DOMAIN, suspend)
    }

    /// The time now.
    pub fn now(self) -> Instant {
        let nanos = start().elapsed().as_nanos();
        Instant::new(self.domain(), u64::try_from(nanos).unwrap_or(u64::MAX))
    }

    /// The deadline `after` the time now. It saturates at the end of the clock.
    pub fn deadline(self, after: Duration) -> Deadline {
        let now = self.now();
        let nanos = u64::try_from(after.as_nanos()).unwrap_or(u64::MAX);
        Deadline::at(Instant::new(self.domain(), now.as_nanos().saturating_add(nanos)))
    }

    /// The Tokio time of `deadline`.
    fn tokio(self, deadline: Deadline) -> tokio::time::Instant {
        let after = Duration::from_nanos(deadline.instant().as_nanos());
        let start = start();
        start.checked_add(after).unwrap_or_else(|| far_future(start))
    }
}

/// The start of each [`Clock`] of the process.
fn start() -> tokio::time::Instant {
    static START: OnceLock<tokio::time::Instant> = OnceLock::new();
    *START.get_or_init(tokio::time::Instant::now)
}

/// A time that no deadline of the process reaches: about thirty years after `start`, as Tokio
/// itself uses for a timer with no end.
fn far_future(start: tokio::time::Instant) -> tokio::time::Instant {
    const THIRTY_YEARS: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);
    start.checked_add(THIRTY_YEARS).unwrap_or(start)
}

/// What a body read gave, with no borrow: the outcome stays in the connection, which gives it
/// again.
enum Step {
    Bytes(usize),
    Full,
    Done,
}

impl Step {
    /// The step of `read`, or `None` when no byte waits.
    fn of(read: &Read<'_>) -> Option<Self> {
        match read {
            Read::Bytes(count) => Some(Self::Bytes(*count)),
            Read::Full => Some(Self::Full),
            Read::Done(_) => Some(Self::Done),
            Read::Wait => None,
        }
    }
}

/// The result of a call that queues output: `None` while the output queue is full, so the
/// binding sends the output and calls again.
fn queued(result: Result<(), Error>) -> Result<Option<()>, Error> {
    match result {
        Ok(()) => Ok(Some(())),
        Err(error) if error.kind() == Kind::Overload => Ok(None),
        Err(error) => Err(error),
    }
}
