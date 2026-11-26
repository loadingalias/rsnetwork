//! The server: take requests on streams, read their bodies, send their responses, and know when
//! the transport accepted each response.
//!
//! [`Http`] is one server connection over TCP or TLS, with no I/O, for HTTP/1.1 and HTTP/2. Over
//! TLS, ALPN selects the version: `h2`, or `http/1.1` and no protocol. Over TCP,
//! [`Limits::cleartext`] selects it. A binding, or the application in a
//! [caller-driven host](crate::host), moves the bytes of the transport with the same calls as a
//! [`Connection`]: [`received`](Http::received) or [`receive`](Http::receive),
//! [`output`](Http::output) and [`ack`](Http::ack), and [`wait`](Http::wait) to know when to call
//! again. The calls of the exchange are the handler interface, and they are the same for each
//! version:
//!
//! 1. [`request`](Http::request) gives the next request head and its [`Stream`]. It also drives
//!    the connection, so call it again each time that [`wait`](Http::wait) says.
//! 2. [`read_into`](Http::read_into), [`next`](Http::next), and [`collect`](Http::collect) read
//!    the request body of a stream.
//! 3. [`respond`](Http::respond) sends the response head, [`write`](Http::write) sends its body,
//!    and [`finish`](Http::finish) ends it. Then the response is finished.
//! 4. [`delivery`](Http::delivery) tells how much of the response the transport accepted.
//! 5. [`close`](Http::close) ends the handler of the stream. Until then, the stream keeps its
//!    place.
//! 6. [`shutdown`](Http::shutdown) closes the connection. [`release`](Http::release) gives its
//!    end when it can drop.
//!
//! - **Streams.** HTTP/2 carries many streams at a time: at most
//!   `SETTINGS_MAX_CONCURRENT_STREAMS`, open or not closed by their handler. HTTP/1.1 carries one:
//!   the next request comes after the handler closed the stream before it and the transport
//!   accepted its response.
//! - **Handler and delivery.** A finished response is not a delivered one. [`Delivery`] names
//!   one event: the transport accepted the bytes. It counts the body bytes, exactly over TCP and
//!   in whole records over TLS. A peer that resets the stream or the connection after the handler
//!   finished makes the delivery [`Delivery::Partial`], with `finished` true.
//! - **Cancel.** [`cancel`](Http::cancel) ends one exchange. On HTTP/2, it resets its stream, and
//!   the connection goes on. On HTTP/1.1, the connection closes, because only the close can end
//!   a response before its end.
//! - **Close.** A close has four steps, and each is its own event. [`shutdown`](Http::shutdown)
//!   refuses new work, and tells the client which requests the server did not process: on
//!   HTTP/1.1 with `connection: close` or `503`, and on HTTP/2 with GOAWAY and `REFUSED_STREAM`.
//!   The streams in flight drain until the deadline. Then the protocol closes: over TLS with
//!   `close_notify`, and then the TCP half-close. The terminal release follows.
//! - **Linger.** After the last output, [`wait`](Http::wait) gives [`Wait::Linger`]: half-close
//!   the transport, and give the bytes that still arrive. The server discards them, up to
//!   [`Linger::bytes`] and [`Linger::time`]. A client that sends a body that the server did not
//!   read then gets no reset before it read the response.
//! - **Report.** [`Closed`] keeps the first failure of the connection. A failure of the drain or
//!   of the close comes after it, as [`Closed::cleanup`], and never replaces it.

mod http1;
mod http2;

use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroUsize};
use core::time::Duration;

use rstypes::buffer::{Backing, Buffer as _, BufferMut, Lease, Pool, PoolRefused, WriteLoan};
use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Deadline, Instant};

use crate::body::{Collect, Part, Read};
use crate::drive::{
    AckError, ActionId, Blocked, Endpoint, Error, Inbound, Kind, Outbound, Output, Outstanding, Received, Turn,
    TurnLimits,
};
use crate::h1::{self, BodyLimits, ServerEvent};
use crate::h2::session::{Session, Step};
use crate::h2::{self, Role};
use crate::host::{Connection, Engine, Io, Wait};
use crate::link::{Link, earliest, queues};
use crate::message::{RequestHead, Stream};
use crate::priority::Priority;
#[cfg(feature = "tls")]
use crate::tls::{self, Negotiated, ServerConfig, Tls};
use crate::value::{Field, Status};

use http1::H1;
use http2::H2;

/// The limits of a server connection, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The HTTP/1.1 request head. Its `head_bytes` is also the size of the region of each
    /// response head and trailer section, in each version.
    pub head: h1::Limits,
    /// The HTTP/2 connection: its settings, its header blocks, and its windows.
    pub h2: h2::Limits,
    /// The request body, in each version, and its HTTP/1.1 drain, extensions, and trailers.
    pub body: BodyLimits,
    /// The work of one drive.
    pub turn: TurnLimits,
    /// The regions that each queue of the connection holds.
    pub queue: NonZeroUsize,
    /// The most time to wait for a request head, as [`h1::Server::head_timeout`] sets it, for
    /// example [`h1::HEAD_TIMEOUT`]. On HTTP/2, the most time with no stream, after which the
    /// server closes the connection with GOAWAY. Over TLS, it also bounds the handshake, from the
    /// first call of [`Http::request`]. `None` turns each of them off.
    pub head_timeout: Option<Duration>,
    /// The linger after the last output.
    pub linger: Linger,
    /// The version of a connection over TCP, with no TLS.
    pub cleartext: Cleartext,
}

/// The version of a server connection over TCP, which has no ALPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cleartext {
    /// HTTP/1.1, which also answers HTTP/1.0 clients.
    Http1,
    /// HTTP/2 with prior knowledge (RFC 9113, section 3.3): each client sends the HTTP/2 preface
    /// first. RFC 9113 has no upgrade from HTTP/1.1.
    Http2,
}

/// The linger of a connection after its last output: the server reads and discards the bytes
/// that still arrive, so that a reset of the peer does not discard a response that the peer has
/// not read yet. A zero time turns it off.
///
/// nginx lingers for at most 30 seconds in total (`lingering_time`), and for at most 5 seconds
/// with no byte (`lingering_timeout`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Linger {
    /// The most time from the start of the linger to its end.
    pub time: Duration,
    /// The most bytes that the linger discards. More bytes end it.
    pub bytes: u64,
}

/// A response head: its status, its fields, and the length of its body.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// The status, for example `Status::OK`. A status of 1xx refuses.
    pub status: Status,
    /// The fields, in their order. `content-length` and `transfer-encoding` refuse: the length
    /// gives them. On HTTP/1.1, the server adds `connection: close` when the connection closes
    /// after the response. On HTTP/2, a connection-specific field refuses (RFC 9113, section
    /// 8.2.2).
    pub fields: &'a [Field<'a>],
    /// The length of the body: `Some(0)` for no body, `Some(n)`, or `None` when the length is
    /// not known. On HTTP/1.1, an unknown length goes in chunks, and to an HTTP/1.0 client until
    /// the close. On HTTP/2, the stream ends the body.
    pub length: Option<u64>,
}

/// How much of a response the transport accepted. `accepted` counts body bytes: exactly over
/// TCP, and in whole records over TLS. "Accepted" is the event of the transport, for example a
/// socket that took the bytes, not a proof that the peer read them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The transport has not accepted each byte of the response yet.
    Sending {
        /// The application finished the response.
        finished: bool,
        /// The body bytes that the transport accepted.
        accepted: u64,
    },
    /// The application finished the response, and the transport accepted each of its bytes.
    Complete {
        /// The body bytes, each of which the transport accepted.
        accepted: u64,
    },
    /// The response ended before the transport accepted each of its bytes.
    Partial {
        /// The application finished the response before it ended.
        finished: bool,
        /// The body bytes that the transport accepted.
        accepted: u64,
        /// Why it ended: for example [`Kind::Partial`] after a reset of the transport or of the
        /// stream.
        error: Error,
    },
}

/// The end of a connection, which [`Http::release`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closed {
    /// The first failure of the connection, or `Ok` when it closed with none.
    pub result: Result<(), Error>,
    /// A failure of the drain or of the close, after the result. It never replaces the result.
    pub cleanup: Option<Error>,
}

/// The engine of a server connection and the exchanges that run on it: the version that ALPN or
/// the limits selected, or none yet, while the TLS handshake runs.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "a connection holds its one engine in place, and a box would add an allocation to each connection"
)]
pub(crate) enum Protocol {
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            dead_code,
            reason = "only a TLS connection selects its version after the construction"
        )
    )]
    Pending,
    H1(h1::Server, H1),
    H2(Session, H2),
}

/// An event of a [`Protocol`].
pub(crate) enum Event {
    H1(ServerEvent),
    H2(Step),
}

impl Engine for Protocol {
    type Event = Event;

    /// Before the selection, a drive asks for the next one at once: the server selects the version
    /// between them.
    fn drive(&mut self, inbound: &mut Inbound, outbound: &mut Outbound, now: Option<Instant>) -> (Option<Event>, Turn) {
        match self {
            Self::Pending => (
                None,
                Turn {
                    progress: crate::drive::Progress::Pending,
                    deadline: None,
                },
            ),
            Self::H1(server, _) => {
                let (event, turn) = server.drive(inbound, outbound, now);
                (event.map(Event::H1), turn)
            }
            Self::H2(session, _) => {
                let (step, turn) = session.drive(inbound, outbound, now);
                (step.map(Event::H2), turn)
            }
        }
    }

    fn timed(&self) -> bool {
        true
    }
}

/// The linger after the last output.
#[derive(Clone, Copy, Debug)]
struct Lingering {
    deadline: Deadline,
    /// The bytes that the linger discarded.
    bytes: u64,
}

/// One server connection over TCP or TLS, for HTTP/1.1 and HTTP/2, with no I/O.
///
/// See the [module](self) for the calls and their rules.
#[derive(Debug)]
pub struct Http {
    link: Link<Protocol>,
    /// The regions of response heads and trailer sections: two slots of `head_bytes`. A slot
    /// comes back when the transport takes its bytes.
    heads: Pool,
    clock: ClockDomain,
    limits: Limits,
    budget: Budget,
    /// The deadline of the TLS handshake, from the first call.
    handshake: Option<Deadline>,
    /// The TLS handshake completed, or the connection has no TLS.
    secure: bool,
    shutdown: Option<Deadline>,
    lingering: Option<Lingering>,
    /// The transport gives no more bytes.
    input_ended: bool,
    /// The transport failed.
    reset: bool,
    failure: Option<Error>,
    cleanup: Option<Error>,
    /// The connection can drop.
    closed: bool,
}

impl Http {
    /// Makes a server connection over TCP, for a host whose clock is `clock`, of the version that
    /// [`Limits::cleartext`] selects. Each part of the connection is charged to `budget`. Refuses
    /// with [`Kind::Overload`], and allocates nothing, when the budget cannot pay.
    pub fn plain(limits: Limits, clock: ClockDomain, budget: &Budget) -> Result<Self, Error> {
        let heads = heads(&limits, budget)?;
        let (inbound, mut outbound) = queues(limits.queue, budget)?;
        let engine = match limits.cleartext {
            Cleartext::Http1 => Protocol::H1(h1_engine(&limits, &outbound, budget)?, H1::new()),
            Cleartext::Http2 => Protocol::H2(
                Session::new(Role::Server, limits.h2, limits.turn, &mut outbound, budget)?,
                H2::new(&limits, budget)?,
            ),
        };
        let connection = Connection::new(engine, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Plain(connection), heads, (clock, limits, budget), true))
    }

    /// Makes a server connection over TLS, with `config`. ALPN selects the version: `h2` for
    /// HTTP/2, and `http/1.1` or no protocol for HTTP/1.1. A client that selects another protocol
    /// ends the connection with [`Kind::Unsupported`]. List `h2` in the protocols of `config` to
    /// serve HTTP/2.
    ///
    /// Refuses as [`Tls::server`] does, and with [`Kind::Overload`] when `budget` cannot pay.
    #[cfg(feature = "tls")]
    pub fn tls(
        config: &ServerConfig,
        (limits, tls): (Limits, tls::Limits),
        clock: ClockDomain,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let heads = heads(&limits, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let tls = Tls::server(config, Protocol::Pending, (inbound, outbound), tls, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let connection = Connection::new(tls, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Tls(connection), heads, (clock, limits, budget), false))
    }

    fn new(
        link: Link<Protocol>,
        heads: Pool,
        (clock, limits, budget): (ClockDomain, Limits, &Budget),
        secure: bool,
    ) -> Self {
        Self {
            link,
            heads,
            clock,
            limits,
            budget: budget.clone(),
            handshake: None,
            secure,
            shutdown: None,
            lingering: None,
            input_ended: false,
            reset: false,
            failure: None,
            cleanup: None,
            closed: false,
        }
    }

    /// Gives the next request head and its stream at `now`, or `None` when none is ready: wait as
    /// [`wait`](Self::wait) says, and call again. It drives the connection, also while it closes.
    ///
    /// On HTTP/1.1, a request comes after the handler closed the stream before it and the
    /// transport accepted each byte of its response, so [`delivery`](Self::delivery) always
    /// names one response. Refuses with [`Kind::Misuse`] when the time is not on the clock of the
    /// server.
    pub fn request(&mut self, now: Instant) -> Result<Option<(Stream, RequestHead)>, Error> {
        self.check(now)?;
        self.tick(now);
        while !self.closed {
            let next = match self.link.engine_ref() {
                Protocol::Pending => None,
                Protocol::H1(..) => self.h1_next(now)?,
                Protocol::H2(..) => self.h2_next(),
            };
            if next.is_some() {
                return Ok(next);
            }
            if !self.pump(now)? {
                break;
            }
        }
        self.settle(now);
        Ok(None)
    }

    /// Copies the next bytes of the request body of `stream` into the free capacity of `region`,
    /// as many as fit, or gives its outcome after its last byte. [`Read::Wait`] means that no byte
    /// arrived: wait as [`wait`](Self::wait) says, and read again. Refuses with [`Kind::Misuse`]
    /// when the stream is not open.
    pub fn read_into<B: BufferMut>(
        &mut self,
        stream: Stream,
        now: Instant,
        region: &mut WriteLoan<B>,
    ) -> Result<Read<'_>, Error> {
        self.fill(stream, now)?;
        let read = match self.link.engine().0 {
            Protocol::H2(_, h2) => h2.read_into(stream, region)?,
            Protocol::H1(_, h1) => h1.body.read_into(region),
            Protocol::Pending => return Err(not_open()),
        };
        Ok(read)
    }

    /// Gives the next part of the request body of `stream` as a view of its received region, with
    /// no copy, or its end with its outcome, or `None` when no byte arrived: wait as
    /// [`wait`](Self::wait) says, and call again. Refuses as [`read_into`](Self::read_into) does.
    pub fn next(&mut self, stream: Stream, now: Instant) -> Result<Option<Part>, Error> {
        self.fill(stream, now)?;
        match self.link.engine().0 {
            Protocol::H2(_, h2) => h2.next(stream),
            Protocol::H1(_, h1) => Ok(match h1.body.take() {
                Some(data) => Some(Part::Data(data)),
                None => h1.body.outcome().cloned().map(Part::End),
            }),
            Protocol::Pending => Err(not_open()),
        }
    }

    /// Collects the request body of `stream` into `region`, whose free capacity bounds it. Gives
    /// [`Collect::More`] while bytes are still to come: wait as [`wait`](Self::wait) says, and
    /// collect again. Only [`Collect::Complete`] holds a complete body. Refuses as
    /// [`read_into`](Self::read_into) does.
    pub fn collect<B: BufferMut>(
        &mut self,
        stream: Stream,
        now: Instant,
        region: &mut WriteLoan<B>,
    ) -> Result<Collect, Error> {
        loop {
            // The fill gives the credit of the bytes that the collect before took, so the check
            // of the wait comes after it: else the peer waits for that credit, and this body for
            // the peer.
            self.fill(stream, now)?;
            if self.body_waits(stream) {
                return Ok(Collect::More);
            }
            let collect = match self.link.engine().0 {
                Protocol::H2(_, h2) => h2.collect(stream, region)?,
                Protocol::H1(_, h1) => h1.body.collect(region),
                Protocol::Pending => return Err(not_open()),
            };
            if !matches!(collect, Collect::More) {
                return Ok(collect);
            }
        }
    }

    /// Sends the head of `response` to the request of `stream`, at `now`. A response with the
    /// length `Some(0)` is finished at once. For another body, send it with
    /// [`write`](Self::write), and end it with [`finish`](Self::finish), also when the request
    /// was HEAD or the status has no body.
    ///
    /// Gives `false` when the transport still holds the regions of the heads before: wait as
    /// [`wait`](Self::wait) says, and respond again. Refuses with [`Kind::Misuse`] when the stream
    /// waits for no response, with a field that the version forbids, and with
    /// [`Kind::Unsupported`] for a 101 response or a 2xx response to CONNECT: this server does
    /// not change the protocol.
    pub fn respond(&mut self, stream: Stream, response: &Response<'_>, now: Instant) -> Result<bool, Error> {
        self.writable(now)?;
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_respond(stream, response, now),
            Protocol::H2(..) => self.h2_respond(stream, response, now),
            Protocol::Pending => Err(not_open()),
        }
    }

    /// Queues `data` as the next bytes of the response body of `stream`, with no copy. Refuses
    /// with [`Kind::Overload`] when the output queue is full also after a drive, so send the
    /// output first, and with [`Kind::Misuse`] when `data` passes the length of the response.
    pub fn write(&mut self, stream: Stream, data: &Lease, now: Instant) -> Result<(), Error> {
        self.writable(now)?;
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_write(stream, data, now),
            Protocol::H2(..) => self.h2_write(stream, data, now),
            Protocol::Pending => Err(not_open()),
        }
    }

    /// Ends the response body of `stream`: the response is finished, and
    /// [`delivery`](Self::delivery) tracks the rest. Refuses as [`write`](Self::write) does, and
    /// with [`Kind::Misuse`] when the body is shorter than the length of the response.
    pub fn finish(&mut self, stream: Stream, now: Instant) -> Result<(), Error> {
        self.writable(now)?;
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_finish(stream, now),
            Protocol::H2(..) => self.h2_finish(stream, now),
            Protocol::Pending => Err(not_open()),
        }
    }

    /// Ends the response body of `stream` with `trailers`, as [`finish`](Self::finish) does.
    /// Gives `false` while the transport holds the regions of the heads before, while the output
    /// queue is full, or, on HTTP/2, while the chunk before waits for the output: wait, and call
    /// again. Refuses with [`Kind::Overload`] when the trailer section is larger than the head
    /// region. On HTTP/1.1, refuses with [`Kind::Misuse`] when the length of the response is
    /// known: only chunks carry trailers.
    pub fn finish_with_trailers(
        &mut self,
        stream: Stream,
        trailers: &[Field<'_>],
        now: Instant,
    ) -> Result<bool, Error> {
        self.writable(now)?;
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_finish_with_trailers(stream, trailers, now),
            Protocol::H2(..) => self.h2_finish_with_trailers(stream, trailers, now),
            Protocol::Pending => Err(not_open()),
        }
    }

    /// Cancels the exchange of `stream`, so the client sees an incomplete response, never a
    /// complete one. On HTTP/2, the stream resets with `CANCEL`, and the connection goes on. On
    /// HTTP/1.1, the connection closes after the bytes that it queued, and it ends with
    /// [`Kind::Cancelled`]. Close the stream after it.
    pub fn cancel(&mut self, stream: Stream) {
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_cancel(stream),
            Protocol::H2(..) => self.h2_cancel(stream),
            Protocol::Pending => {}
        }
    }

    /// Gives the response of `stream` the priority `priority` (RFC 9218, section 8). On HTTP/2,
    /// the send scheduler orders the stream by it from the next frame, and a later PRIORITY_UPDATE
    /// of the client changes it again: the latest signal wins. HTTP/1.1 carries one stream at a
    /// time, so there it changes nothing, and neither does it for a stream whose response ended.
    pub fn prioritize(&mut self, stream: Stream, priority: Priority) {
        if let Protocol::H2(..) = self.link.engine_ref() {
            self.h2_prioritize(stream, priority);
        }
    }

    /// Ends the handler of `stream`. A response that is not finished is cancelled, as
    /// [`cancel`](Self::cancel) does. After the close, [`delivery`](Self::delivery) gives `None`
    /// for the stream on HTTP/2, and the stream frees its place for a new request. On HTTP/1.1,
    /// the delivery stays until the next request.
    pub fn close(&mut self, stream: Stream) {
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_close(stream),
            Protocol::H2(..) => self.h2_close(stream),
            Protocol::Pending => {}
        }
    }

    /// How much of the response of `stream` the transport accepted, or `None` before its
    /// response, and for a stream that the server does not know.
    pub fn delivery(&self, stream: Stream) -> Option<Delivery> {
        match self.link.engine_ref() {
            Protocol::H1(_, h1) => h1.delivery(stream, self.link.accepted()),
            Protocol::H2(_, h2) => h2.delivery(stream),
            Protocol::Pending => None,
        }
    }

    /// Closes the connection at `now`: it refuses new work, drains the streams in flight, and
    /// then closes the protocol and lingers.
    ///
    /// On HTTP/1.1, the response in flight gets `connection: close` when its head is not out yet.
    /// Else the next request whose head arrived whole, which the application does not see, gets
    /// `503` with `connection: close`, as [`h1::Server::shutdown`] says. On HTTP/2, the server
    /// sends GOAWAY and PING, and then GOAWAY with its last stream (RFC 9113, section 6.8). A
    /// request that came before it and that the application did not see gets `REFUSED_STREAM`.
    /// Thus the client can send each request that the server did not process again.
    ///
    /// At `deadline`, the connection ends whatever remains, and [`Closed::cleanup`] reports
    /// [`Kind::Deadline`]. Refuses with [`Kind::Misuse`] when `deadline` or `now` is not on the
    /// clock of the server.
    pub fn shutdown(&mut self, deadline: Deadline, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        if deadline.instant().domain() != self.clock {
            return Err(misuse("the deadline is not on the clock of the server"));
        }
        self.shutdown = earliest(self.shutdown, Some(deadline));
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_shutdown(now),
            Protocol::H2(..) => self.h2_shutdown(now),
            // The selection after the handshake starts the shutdown of the version.
            Protocol::Pending => self.request(now).map(drop),
        }
    }

    /// Gives each stream whose exchange changed since the last call: a part or the end of its
    /// request body, the output took its last chunk, or the stream ended. A new request changes
    /// its stream too. A binding that shares the connection among handles wakes the handle of
    /// each stream that it gives, and no other. The end of the connection, when
    /// [`wait`](Self::wait) gives [`Wait::Ended`] or [`Wait::Linger`], changes each stream.
    pub fn changed(&mut self, each: impl FnMut(Stream)) {
        match self.link.engine().0 {
            Protocol::H1(_, h1) => h1.changed(each),
            Protocol::H2(_, h2) => h2.changed(each),
            Protocol::Pending => {}
        }
    }

    /// What the TLS handshake negotiated, or `None` before it completed and over TCP.
    #[cfg(feature = "tls")]
    pub fn negotiated(&mut self) -> Option<Negotiated<'_>> {
        self.link.negotiated()
    }

    /// Derives `output.len()` bytes of keying material with `label` and `context` from the regular
    /// exporter of the TLS connection, as [`Tls::export`] says. Over TCP, refuses with
    /// [`ExportError::Unavailable`](tls::ExportError::Unavailable).
    #[cfg(feature = "tls")]
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), tls::ExportError> {
        self.link.export(label, context, output)
    }

    /// Selects the version after the TLS handshake. Gives whether it selected one.
    fn select(&mut self, now: Instant) -> Result<bool, Error> {
        if !matches!(self.link.engine_ref(), Protocol::Pending) {
            return Ok(false);
        }
        #[cfg(feature = "tls")]
        {
            let Some(negotiated) = self.link.negotiated() else {
                return Ok(false);
            };
            let h2 = match negotiated.protocol {
                None | Some(b"http/1.1") => false,
                Some(b"h2") => true,
                Some(_) => {
                    self.fail(Error::new(
                        Kind::Unsupported,
                        "ALPN selected a protocol other than HTTP/1.1 and HTTP/2",
                    ));
                    self.closed = true;
                    return Ok(false);
                }
            };
            self.secure = true;
            self.handshake = None;
            let (limits, budget) = (self.limits, self.budget.clone());
            let (engine, outbound) = self.link.engine();
            let made = if h2 {
                Session::new(Role::Server, limits.h2, limits.turn, outbound, &budget)
                    .and_then(|session| Ok(Protocol::H2(session, H2::new(&limits, &budget)?)))
            } else {
                h1_engine(&limits, outbound, &budget).map(|server| Protocol::H1(server, H1::new()))
            };
            let protocol = match made {
                Ok(made) => made,
                Err(error) => {
                    self.fail(error);
                    self.closed = true;
                    return Ok(false);
                }
            };
            *engine = protocol;
            if self.shutdown.is_some() {
                match self.link.engine_ref() {
                    Protocol::H1(..) => self.h1_shutdown(now)?,
                    Protocol::H2(..) => self.h2_shutdown(now)?,
                    Protocol::Pending => {}
                }
            }
            Ok(true)
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = now;
            Ok(false)
        }
    }

    /// Refuses a call with a time on another clock.
    fn check(&self, now: Instant) -> Result<(), Error> {
        if now.domain() != self.clock {
            return Err(misuse("the time is not on the clock of the server"));
        }
        Ok(())
    }

    /// Refuses a call of the exchange after the end.
    fn writable(&mut self, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        self.tick(now);
        if self.closed {
            return Err(self.failure.unwrap_or_else(|| misuse("the connection ended")));
        }
        Ok(())
    }

    /// Drives the connection until the body of `stream` has a part or its end for a read, or
    /// until no event comes.
    fn fill(&mut self, stream: Stream, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        self.tick(now);
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_accept(stream)?,
            Protocol::H2(..) => self.h2_feed(stream)?,
            Protocol::Pending => return Err(not_open()),
        }
        while self.body_waits(stream) {
            if !self.pump(now)? {
                break;
            }
        }
        Ok(())
    }

    /// Whether the body of `stream` has no part and no end for a read.
    fn body_waits(&self, stream: Stream) -> bool {
        match self.link.engine_ref() {
            Protocol::H1(_, h1) => h1.body.wants_data(),
            Protocol::H2(_, h2) => h2.body_waits(stream),
            Protocol::Pending => false,
        }
    }

    /// Runs `queue`, which queues plaintext output and changes nothing when it refuses. Over TLS,
    /// only a drive seals the plaintext into records and frees its queue. So when `queue` refuses
    /// with [`Kind::Overload`], the connection drives one time, and `queue` runs again.
    fn queue<T>(&mut self, now: Instant, mut queue: impl FnMut(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        match queue(self) {
            Err(error) if error.kind() == Kind::Overload => {
                self.pump(now)?;
                queue(self)
            }
            result => result,
        }
    }

    /// Drives the connection one time, and takes its event. Gives whether it made progress: an
    /// event, the selection of the version, or a turn that has more work behind it.
    fn pump(&mut self, now: Instant) -> Result<bool, Error> {
        if self.lingering.is_some() || (self.closed && !self.reset) {
            return Ok(false);
        }
        match self.link.engine_ref() {
            Protocol::H1(..) => self.h1_before_drive(),
            Protocol::H2(..) => self.h2_before_drive()?,
            Protocol::Pending => {}
        }
        let event = self.link.drive(now)?;
        if let Wait::Ended(Err(error)) = self.link.wait() {
            self.fail(error);
        }
        let selected = self.select(now)?;
        let Some(event) = event else {
            if matches!(self.link.wait(), Wait::Ended(_)) {
                self.engine_ended();
            }
            return Ok(selected || self.link.wait() == Wait::Now);
        };
        match event {
            Event::H1(event) => self.h1_event(event),
            Event::H2(step) => self.h2_event(step)?,
        }
        Ok(true)
    }

    /// The engine ended: each stream that it carried ends with it.
    fn engine_ended(&mut self) {
        if let Protocol::H2(..) = self.link.engine_ref() {
            self.h2_engine_ended();
        }
    }

    /// Applies the deadlines at `now`: of the TLS handshake, of a shutdown, of the linger, and of
    /// an HTTP/2 connection with no stream.
    fn tick(&mut self, now: Instant) {
        if self.closed {
            return;
        }
        if !self.secure && self.handshake.is_none() {
            self.handshake = self
                .limits
                .head_timeout
                .and_then(|timeout| now.checked_add(timeout).ok())
                .map(Deadline::at);
        }
        let reached =
            |deadline: Option<Deadline>| deadline.is_some_and(|deadline| deadline.is_reached(now) == Ok(true));
        if reached(self.handshake) {
            self.fail(Error::new(
                Kind::Deadline,
                "the TLS handshake did not complete before its deadline",
            ));
            self.closed = true;
        } else if reached(self.shutdown) {
            let error = Error::new(
                Kind::Deadline,
                "the shutdown deadline came before the connection closed",
            );
            self.cleanup.get_or_insert(error);
            match self.link.engine_ref() {
                Protocol::H1(..) => self.h1_expire(error),
                Protocol::H2(..) => self.h2_expire(error),
                Protocol::Pending => {}
            }
            self.lingering = None;
            self.closed = true;
        } else if reached(self.lingering.map(|lingering| lingering.deadline)) {
            self.lingering = None;
            self.closed = true;
        } else if let Protocol::H2(..) = self.link.engine_ref() {
            self.h2_idle(now);
        }
    }

    /// Starts the linger when the engine ended and the transport accepted each output, or ends
    /// the connection when the linger cannot help.
    fn settle(&mut self, now: Instant) {
        if self.closed || self.lingering.is_some() || !matches!(self.link.wait(), Wait::Ended(_)) {
            return;
        }
        if !self.link.outstanding().is_empty() {
            return;
        }
        let deadline = now.checked_add(self.limits.linger.time).ok().map(Deadline::at);
        match deadline {
            Some(deadline) if !self.input_ended && !self.limits.linger.time.is_zero() => {
                self.lingering = Some(Lingering { deadline, bytes: 0 });
            }
            _ => self.closed = true,
        }
    }

    /// Discards `len` received bytes during the linger, or after the end. Gives whether it did.
    /// The linger ends when it discarded more than its limit.
    fn discard(&mut self, len: usize) -> bool {
        if let Some(lingering) = &mut self.lingering {
            lingering.bytes = lingering.bytes.saturating_add(len as u64);
            if lingering.bytes > self.limits.linger.bytes {
                self.lingering = None;
                self.closed = true;
            }
            return true;
        }
        self.closed && !self.reset
    }

    /// Records `error` as the failure of the connection, unless a failure came before it, and as
    /// the end of each response that the transport has not accepted.
    fn fail(&mut self, error: Error) {
        self.failure.get_or_insert(error);
        let accepted = self.link.accepted();
        match self.link.engine().0 {
            Protocol::H1(_, h1) => h1.fail(error, accepted),
            Protocol::H2(_, h2) => h2.fail(error),
            Protocol::Pending => {}
        }
    }

    fn result(&self) -> Result<(), Error> {
        self.failure.map_or(Ok(()), Err)
    }

    /// Whether the version has work for the next call with no wait.
    fn ready(&self) -> bool {
        match self.link.engine_ref() {
            Protocol::H1(_, h1) => h1.next.is_some() && h1.delivered(self.link.accepted()),
            Protocol::H2(_, h2) => h2.ready(),
            Protocol::Pending => false,
        }
    }

    /// The deadline of the version: of an HTTP/2 connection with no stream.
    fn version_deadline(&self) -> Option<Deadline> {
        match self.link.engine_ref() {
            Protocol::H2(_, h2) => h2.idle,
            Protocol::H1(..) | Protocol::Pending => None,
        }
    }
}

impl Io for Http {
    type End = Closed;

    /// When to call again: now, when the transport gives what the connection waits for, at a
    /// deadline, during the linger, or never after the end.
    fn wait(&self) -> Wait {
        if self.closed {
            return Wait::Ended(self.result());
        }
        if let Some(lingering) = self.lingering {
            return Wait::Linger {
                deadline: lingering.deadline,
            };
        }
        if self.ready() {
            return Wait::Now;
        }
        let deadline = earliest(earliest(self.shutdown, self.handshake), self.version_deadline());
        match self.link.wait() {
            // The linger starts at the next call, after the last output.
            Wait::Ended(_) if self.link.outstanding().is_empty() => Wait::Now,
            Wait::Ended(_) => Wait::Until {
                blocked: Blocked::Output,
                deadline,
            },
            Wait::Until { blocked, deadline: own } => Wait::Until {
                blocked,
                deadline: earliest(own, deadline),
            },
            wait => wait,
        }
    }

    /// During the linger, it discards the bytes.
    fn receive(&mut self, received: Received) -> Result<(), Received> {
        if self.discard(received.region.initialized()) {
            return Ok(());
        }
        self.link.receive(received)
    }

    /// During the linger and after the end, it lends none.
    fn region(&mut self) -> Result<Option<Backing>, Error> {
        if self.lingering.is_some() || self.closed {
            return Ok(None);
        }
        self.link.region()
    }

    /// During the linger, it discards the region.
    fn received(&mut self, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        if self.discard(region.initialized()) {
            return Ok(());
        }
        self.link.received(region, endpoint, capacity)
    }

    /// Records that the transport gives no more bytes. It ends the linger.
    fn end_input(&mut self) {
        self.input_ended = true;
        if self.lingering.take().is_some() {
            self.closed = true;
        } else {
            self.link.end_input();
        }
    }

    /// Each response that the transport has not accepted becomes [`Delivery::Partial`], and the
    /// connection can drop at once: [`outstanding`](Self::outstanding) reports the output that
    /// did not go. The application can still read the request bytes that arrived, and then the
    /// outcome of each body.
    fn reset(&mut self) {
        // A reset during the linger or after the end is no failure.
        let quiet = self.lingering.take().is_some() || self.closed;
        let unsent = matches!(self.link.wait(), Wait::Ended(_)) && !self.link.outstanding().is_empty();
        self.input_ended = true;
        self.reset = true;
        self.link.reset();
        if !quiet {
            let error = Error::new(Kind::Partial, "the transport failed before the connection closed");
            let busy = match self.link.engine_ref() {
                Protocol::H1(_, h1) => h1.busy(self.link.accepted()),
                Protocol::H2(_, h2) => h2.busy(),
                Protocol::Pending => false,
            };
            if busy {
                self.fail(error);
            } else if unsent {
                // The output of a connection that ended did not go.
                self.cleanup.get_or_insert(error);
            }
            if let Protocol::H2(_, h2) = self.link.engine().0 {
                h2.reset_bodies();
            }
        }
        self.closed = true;
    }

    fn output_region(&mut self, region: Backing) -> Result<(), (Error, Backing)> {
        self.link.output_region(region)
    }

    fn take_output_region(&mut self) -> Option<Backing> {
        self.link.take_output_region()
    }

    fn output(&mut self) -> Option<Output> {
        self.link.output()
    }

    /// On HTTP/2, it counts the accepted bytes into the delivery of each stream.
    fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        self.link.ack(id, accepted)?;
        if let Protocol::H2(..) = self.link.engine_ref() {
            self.h2_accepted();
        }
        Ok(())
    }

    fn outstanding(&self) -> Outstanding {
        self.link.outstanding()
    }

    /// Gives the end of the connection when it can drop: after the protocol closed, the transport
    /// accepted each output, and the linger ended. After a reset or at the deadline of a
    /// shutdown, it does not wait for the output. Gives `None` before that.
    fn release(&self) -> Option<Closed> {
        self.closed.then(|| Closed {
            result: self.result(),
            cleanup: self.cleanup,
        })
    }
}

/// The HTTP/1.1 engine of a connection, with the head timeout of `limits`.
fn h1_engine(limits: &Limits, outbound: &Outbound, budget: &Budget) -> Result<h1::Server, Error> {
    Ok(h1::Server::new(limits.head, limits.body, limits.turn, outbound, budget)?.head_timeout(limits.head_timeout))
}

/// The pool of the regions of response heads and trailer sections: two slots of `head_bytes`.
fn heads(limits: &Limits, budget: &Budget) -> Result<Pool, Error> {
    let slot = Layout::array::<u8>(limits.head.head_bytes)
        .map_err(|_| misuse("the head region of a response is too large"))?;
    Pool::new(budget, NonZeroU32::new(2).unwrap_or(NonZeroU32::MIN), slot).map_err(|refused| match refused {
        PoolRefused::Budget(_) => Error::new(Kind::Overload, "the budget refused the regions of response heads"),
        PoolRefused::Layout => misuse("the head region of a response is too large"),
        PoolRefused::Allocation => Error::new(
            Kind::Overload,
            "the memory for the regions of response heads is not available",
        ),
    })
}

fn misuse(reason: &'static str) -> Error {
    Error::new(Kind::Misuse, reason)
}

/// The refusal of a call on a stream that the server does not carry.
fn not_open() -> Error {
    misuse("the stream is not open")
}
