//! The server: take a request, read its body, send its response, and know when the transport
//! accepted the response.
//!
//! [`Http1`] is one HTTP/1.1 connection over TCP or TLS, with no I/O. A binding, or the
//! application in a [caller-driven host](crate::host), moves the bytes of the transport with the
//! same calls as a [`Connection`]: [`received`](Http1::received) or
//! [`receive`](Http1::receive), [`output`](Http1::output) and [`ack`](Http1::ack), and
//! [`wait`](Http1::wait) to know when to call again. The calls of the exchange are the handler
//! interface:
//!
//! 1. [`request`](Http1::request) gives the next request head. It also drives the connection when
//!    no exchange is in flight, so call it again each time that [`wait`](Http1::wait) says.
//! 2. [`read_into`](Http1::read_into), [`next`](Http1::next), and [`collect`](Http1::collect)
//!    read the request body. The first read accepts the body: a request that waits for
//!    `100 Continue` gets it then.
//! 3. [`respond`](Http1::respond) sends the response head, [`write`](Http1::write) sends its
//!    body, and [`finish`](Http1::finish) ends it. Then the handler is complete.
//! 4. [`delivery`](Http1::delivery) tells how much of the response the transport accepted. The
//!    next request comes after the transport accepted each byte of the response before it.
//! 5. [`shutdown`](Http1::shutdown) closes the connection. [`release`](Http1::release) gives its
//!    end when it can drop.
//!
//! - **Handler and delivery.** A finished response is not a delivered one. [`Delivery`] names
//!   one event: the transport accepted the bytes. It counts the body bytes, exactly over TCP and
//!   in whole records over TLS. A peer that resets the connection after the handler finished
//!   makes the delivery [`Delivery::Partial`], with `finished` true.
//! - **Close.** A close has four steps, and each is its own event. [`shutdown`](Http1::shutdown)
//!   refuses new work: a request that the application did not see gets `503` and
//!   `connection: close`. The exchange in flight drains until its deadline. Then the protocol
//!   closes: over TLS with `close_notify`, and then the TCP half-close. The terminal release
//!   follows.
//! - **Linger.** After the last output, [`wait`](Http1::wait) gives
//!   [`Wait::Linger`]: half-close the transport, and give the bytes
//!   that still arrive. The server discards them, up to [`Linger::bytes`] and [`Linger::time`].
//!   A client that sends a body that the server did not read then gets no reset before it read
//!   the response.
//! - **Report.** [`Closed`] keeps the first failure of the connection. A failure of the drain or
//!   of the close comes after it, as [`Closed::cleanup`], and never replaces it.

use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroUsize};
use core::time::Duration;

use rstypes::buffer::{Backing, Buffer as _, BufferMut, Lease, Pool, PoolRefused, WriteLoan};
use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Deadline, Instant};

use crate::body::{Collect, Consumer, Outcome, Part, Read};
use crate::drive::{
    AckError, ActionId, Blocked, Endpoint, Error, Kind, Outbound, Output, Outstanding, Received, TurnLimits,
};
use crate::h1::{self, BodyLimits, Framing, RetainedRequest, ServerEvent};
use crate::host::{Connection, Io, Wait};
use crate::link::{Link, earliest, queues};
#[cfg(feature = "tls")]
use crate::tls::{self, Negotiated, ServerConfig, Tls};
use crate::value::{Field, Method, Status};

/// The limits of an HTTP/1.1 server connection, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The request head. Its `head_bytes` is also the size of the region of each response head
    /// and trailer section.
    pub head: h1::Limits,
    /// The request body, its drain, and its trailers.
    pub body: BodyLimits,
    /// The work of one drive.
    pub turn: TurnLimits,
    /// The regions that each queue of the connection holds.
    pub queue: NonZeroUsize,
    /// The most time to wait for a request head, as [`h1::Server::head_timeout`] sets it, for
    /// example [`h1::HEAD_TIMEOUT`]. Over TLS, it also bounds the handshake, from the first call
    /// of [`Http1::request`]. `None` turns both off.
    pub head_timeout: Option<Duration>,
    /// The linger after the last output.
    pub linger: Linger,
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

/// A response head: its status, its fields, and the framing of its body.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// The status, for example `Status::OK`. A status of 1xx refuses.
    pub status: Status,
    /// The fields, in their order. The engine adds `connection: close` when the connection
    /// closes after the response.
    pub fields: &'a [Field<'a>],
    /// The framing of the response body: `Length(0)` for no body, `Length(n)`, `Chunked`, or
    /// `Close`.
    pub body: Framing,
}

/// How much of a response the transport accepted. `accepted` counts body bytes: exactly over
/// TCP, and in whole records over TLS. "Accepted" is the event of the transport, for example a
/// socket that took the bytes, not a proof that the peer read them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The transport has not accepted each byte of the response yet.
    Sending {
        /// The application finished the response: the handler is complete.
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
        /// Why it ended: for example [`Kind::Partial`] after a reset of the transport.
        error: Error,
    },
}

/// The end of a connection, which [`Http1::release`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closed {
    /// The first failure of the connection, or `Ok` when it closed with none.
    pub result: Result<(), Error>,
    /// A failure of the drain or of the close, after the result. It never replaces the result.
    pub cleanup: Option<Error>,
}

/// The place of the server in the exchanges of the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// No exchange is in flight.
    Idle,
    /// The application has a request head, and its response is not finished.
    Exchange,
    /// The application finished the response, and its delivery goes on.
    Delivering,
}

/// The delivery of the response in flight, from its head on.
#[derive(Clone, Copy, Debug)]
struct Track {
    /// The body bytes that the transport accepted before this response.
    base: u64,
    /// The end of the response in the plaintext output, after `finish`.
    end: Option<u64>,
    /// Why the response ended before the transport accepted each of its bytes.
    error: Option<Error>,
}

/// The linger after the last output.
#[derive(Clone, Copy, Debug)]
struct Lingering {
    deadline: Deadline,
    /// The bytes that the linger discarded.
    bytes: u64,
}

/// One HTTP/1.1 server connection over TCP or TLS, with no I/O.
///
/// It carries one exchange at a time: a request, its body, its response, and the delivery of the
/// response. See the [module](self) for the calls and their rules.
#[derive(Debug)]
pub struct Http1 {
    link: Link<h1::Server>,
    /// The regions of response heads and trailer sections: two slots of `head_bytes`. A slot
    /// comes back when the transport takes its bytes.
    heads: Pool,
    clock: ClockDomain,
    limits: Limits,
    state: State,
    /// A request head that came while the response before it went out.
    next: Option<RetainedRequest>,
    /// The method of the request in flight is CONNECT.
    connect: bool,
    /// The application read the request body, so the engine accepts it.
    accepted: bool,
    body: Consumer,
    response: Option<Track>,
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

impl Http1 {
    /// Makes a server connection over TCP, for a host whose clock is `clock`. Each part of the
    /// connection is charged to `budget`. Refuses with [`Kind::Overload`], and allocates nothing,
    /// when the budget cannot pay.
    pub fn plain(limits: Limits, clock: ClockDomain, budget: &Budget) -> Result<Self, Error> {
        let heads = heads(&limits, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let engine = engine(&limits, &outbound, budget)?;
        let connection = Connection::new(engine, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Plain(connection), heads, clock, limits, true))
    }

    /// Makes a server connection over TLS, with `config`. The client must select ALPN
    /// `http/1.1` or no protocol: a connection to another protocol ends with
    /// [`Kind::Unsupported`].
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
        let engine = engine(&limits, &outbound, budget)?;
        let tls = Tls::server(config, engine, (inbound, outbound), tls, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let connection = Connection::new(tls, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Tls(connection), heads, clock, limits, false))
    }

    fn new(link: Link<h1::Server>, heads: Pool, clock: ClockDomain, limits: Limits, secure: bool) -> Self {
        Self {
            link,
            heads,
            clock,
            limits,
            state: State::Idle,
            next: None,
            connect: false,
            accepted: false,
            body: Consumer::new(),
            response: None,
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

    /// Gives the next request head at `now`, or `None` when none is ready: wait as
    /// [`wait`](Self::wait) says, and call again. It drives the connection, also while it closes.
    ///
    /// A request comes after the transport accepted each byte of the response before it, so
    /// [`delivery`](Self::delivery) always names one response. Refuses with [`Kind::Misuse`]
    /// while the response of the request before is not finished, and when the time is not on the
    /// clock of the server.
    pub fn request(&mut self, now: Instant) -> Result<Option<RetainedRequest>, Error> {
        self.check(now)?;
        if self.state == State::Exchange {
            return Err(misuse("the response of the request before is not finished"));
        }
        self.tick(now);
        while !self.closed {
            // After a shutdown, a request that the application did not see is new work: refuse
            // it. Its refusal goes after the response before it.
            if self.shutdown.is_some() && self.next.is_some() && self.refuse(now)? {
                self.next = None;
            }
            if self.delivered() {
                self.state = State::Idle;
                if self.shutdown.is_none()
                    && let Some(head) = self.next.take()
                {
                    return Ok(Some(self.start(head)));
                }
            }
            if !self.pump(now)? {
                break;
            }
        }
        self.settle(now);
        Ok(None)
    }

    /// Copies the next bytes of the request body into the free capacity of `region`, as many as
    /// fit, or gives its outcome after its last byte. [`Read::Wait`] means that no byte arrived:
    /// wait as [`wait`](Self::wait) says, and read again. Refuses with [`Kind::Misuse`] when no
    /// request is in flight.
    pub fn read_into<B: BufferMut>(&mut self, now: Instant, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        self.fill(now)?;
        Ok(self.body.read_into(region))
    }

    /// Gives the next part of the request body as a view of its received region, with no copy,
    /// or its end with its outcome, or `None` when no byte arrived: wait as
    /// [`wait`](Self::wait) says, and call again. Refuses as [`read_into`](Self::read_into) does.
    pub fn next(&mut self, now: Instant) -> Result<Option<Part>, Error> {
        self.fill(now)?;
        Ok(match self.body.take() {
            Some(data) => Some(Part::Data(data)),
            None => self.body.outcome().cloned().map(Part::End),
        })
    }

    /// Collects the request body into `region`, whose free capacity bounds it. Gives
    /// [`Collect::More`] while bytes are still to come: wait as [`wait`](Self::wait) says, and
    /// collect again. Only [`Collect::Complete`] holds a complete body. Refuses as
    /// [`read_into`](Self::read_into) does.
    pub fn collect<B: BufferMut>(&mut self, now: Instant, region: &mut WriteLoan<B>) -> Result<Collect, Error> {
        loop {
            self.fill(now)?;
            // No part came: the bytes are still to come.
            if self.body.wants_data() {
                return Ok(Collect::More);
            }
            match self.body.collect(region) {
                Collect::More => {}
                collect => return Ok(collect),
            }
        }
    }

    /// Sends the head of `response` to the request in flight, at `now`. A response with
    /// `Framing::Length(0)` is finished at once. For another body, send it with
    /// [`write`](Self::write), and end it with [`finish`](Self::finish), also when the request
    /// was HEAD or the status has no body.
    ///
    /// The engine reads a request body that the application did not read, up to
    /// [`BodyLimits::drain_bytes`], or the connection closes after the response. Gives `false`
    /// when the transport still holds the regions of the heads before: wait as
    /// [`wait`](Self::wait) says, and respond again. Refuses with [`Kind::Misuse`] when no request
    /// waits for a response, and with [`Kind::Unsupported`] for a 101 response or a 2xx response
    /// to CONNECT: this server does not change the protocol.
    pub fn respond(&mut self, response: &Response<'_>, now: Instant) -> Result<bool, Error> {
        self.writable(now)?;
        if self.response.is_some() {
            return Err(misuse("the request in flight has its response"));
        }
        let Response { status, fields, body } = *response;
        if status.code() == 101 || (self.connect && (200..300).contains(&status.code())) {
            return Err(Error::new(Kind::Unsupported, "the server does not change the protocol"));
        }
        let Ok(head) = self.heads.acquire() else {
            return Ok(false);
        };
        let base = self.link.accepted().payload;
        let (engine, outbound) = self.link.engine();
        engine.respond(outbound, status, fields, body, head)?;
        let empty = body == Framing::Length(0);
        if empty {
            engine.finish(outbound)?;
        }
        self.response = Some(Track {
            base,
            end: None,
            error: None,
        });
        if empty {
            self.finished();
        }
        // Over TLS, the drive encrypts the head.
        self.pump(now)?;
        Ok(true)
    }

    /// Queues `data` as the next bytes of the response body, with no copy. Refuses as
    /// [`h1::Server::send`] does: with [`Kind::Overload`] when the output queue is full also after
    /// a drive, so send the output first.
    pub fn write(&mut self, data: &Lease, now: Instant) -> Result<(), Error> {
        self.responding(now)?;
        self.queue(now, |server| {
            let (engine, outbound) = server.link.engine();
            engine.send(outbound, data)
        })?;
        self.pump(now).map(drop)
    }

    /// Ends the response body: the handler is complete, and [`delivery`](Self::delivery) tracks
    /// the rest. Refuses as [`h1::Server::finish`] does.
    pub fn finish(&mut self, now: Instant) -> Result<(), Error> {
        self.responding(now)?;
        self.queue(now, |server| {
            let (engine, outbound) = server.link.engine();
            engine.finish(outbound)
        })?;
        self.finished();
        self.pump(now).map(drop)
    }

    /// Ends a chunked response body with `trailers`, as [`finish`](Self::finish) does. Gives
    /// `false` when the transport still holds the regions of the heads before: wait, and call
    /// again. Refuses with [`Kind::Misuse`] when the body is not chunked.
    pub fn finish_with_trailers(&mut self, trailers: &[Field<'_>], now: Instant) -> Result<bool, Error> {
        self.responding(now)?;
        let queued = self.queue(now, |server| {
            let Ok(region) = server.heads.acquire() else {
                return Ok(false);
            };
            let (engine, outbound) = server.link.engine();
            engine.finish_with_trailers(outbound, trailers, region).map(|()| true)
        })?;
        if !queued {
            return Ok(false);
        }
        self.finished();
        self.pump(now)?;
        Ok(true)
    }

    /// Cancels the exchange in flight: the connection closes after the bytes that it queued, so
    /// the client sees an incomplete response, never a complete one. The connection ends with
    /// [`Kind::Cancelled`].
    pub fn cancel(&mut self) {
        let error = Error::new(Kind::Cancelled, "the application cancelled the response");
        self.link.engine().0.cancel();
        self.fail(error);
        self.body.end(Outcome::Cancelled);
        if self.state == State::Exchange {
            self.state = State::Delivering;
        }
    }

    /// How much of the response of the last exchange the transport accepted, or `None` before
    /// the first response.
    pub fn delivery(&self) -> Option<Delivery> {
        let track = self.response?;
        let sent = self.link.accepted();
        let accepted = sent.payload.strict_sub(track.base);
        let finished = track.end.is_some();
        Some(match (track.error, track.end) {
            (Some(error), _) => Delivery::Partial {
                finished,
                accepted,
                error,
            },
            (None, Some(end)) if sent.bytes >= end => Delivery::Complete { accepted },
            (None, _) => Delivery::Sending { finished, accepted },
        })
    }

    /// Closes the connection at `now`: it refuses new work, drains the exchange in flight, and
    /// then closes the protocol and lingers. A request that the application did not see gets
    /// `503` with `connection: close`, and the client can send it again. At `deadline`, the
    /// connection ends whatever remains, and [`Closed::cleanup`] reports
    /// [`Kind::Deadline`]. Refuses with [`Kind::Misuse`] when `deadline` or `now` is not on the
    /// clock of the server.
    pub fn shutdown(&mut self, deadline: Deadline, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        if deadline.instant().domain() != self.clock {
            return Err(misuse("the deadline is not on the clock of the server"));
        }
        self.shutdown = earliest(self.shutdown, Some(deadline));
        self.link.engine().0.shutdown();
        if self.state == State::Exchange {
            self.tick(now);
            self.pump(now).map(drop)
        } else {
            // With a shutdown, `request` gives no head: it refuses the one that waits.
            self.request(now).map(drop)
        }
    }

    /// What the TLS handshake negotiated, or `None` before it completed and over TCP.
    #[cfg(feature = "tls")]
    pub fn negotiated(&mut self) -> Option<Negotiated<'_>> {
        self.link.negotiated()
    }

    /// Gives `head` to the application as the request in flight.
    fn start(&mut self, head: RetainedRequest) -> RetainedRequest {
        self.state = State::Exchange;
        self.connect = head.head().method() == Method::CONNECT;
        self.accepted = false;
        self.body = Consumer::new();
        self.response = None;
        head
    }

    /// Answers the request that waits, which the application did not see, with `503` and
    /// `connection: close`. Gives `false` when no head region is free yet.
    fn refuse(&mut self, now: Instant) -> Result<bool, Error> {
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let (engine, outbound) = self.link.engine();
        engine.respond(outbound, Status(503), &[], Framing::Length(0), region)?;
        engine.finish(outbound)?;
        self.pump(now)?;
        Ok(true)
    }

    /// Refuses a call with a time on another clock.
    fn check(&self, now: Instant) -> Result<(), Error> {
        if now.domain() != self.clock {
            return Err(misuse("the time is not on the clock of the server"));
        }
        Ok(())
    }

    /// Refuses a write when no request waits for a response, or after the end.
    fn writable(&mut self, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        self.tick(now);
        if self.closed {
            return Err(self.failure.unwrap_or_else(|| misuse("the connection ended")));
        }
        if self.state != State::Exchange {
            return Err(misuse("no request waits for a response"));
        }
        Ok(())
    }

    /// Refuses a write of the body when no response is open.
    fn responding(&mut self, now: Instant) -> Result<(), Error> {
        self.writable(now)?;
        if self.response.is_none() {
            return Err(misuse("respond first"));
        }
        Ok(())
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

    /// Records the end of the response in the output: the handler is complete.
    fn finished(&mut self) {
        let end = self.link.pushed();
        if let Some(track) = &mut self.response {
            track.end = Some(end);
        }
        self.state = State::Delivering;
    }

    /// Whether no response waits for the transport: the last one is complete, or it ended.
    fn delivered(&self) -> bool {
        self.state != State::Exchange && !matches!(self.delivery(), Some(Delivery::Sending { .. }))
    }

    /// Drives the connection until the body has a part or its end for a read, or until no event
    /// comes.
    fn fill(&mut self, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        if self.state != State::Exchange {
            return Err(misuse("no request body waits"));
        }
        self.tick(now);
        if !self.accepted && !self.closed {
            let (engine, outbound) = self.link.engine();
            engine.accept_body(outbound)?;
            self.accepted = true;
        }
        while self.body.wants_data() {
            if !self.pump(now)? {
                break;
            }
        }
        Ok(())
    }

    /// Drives the connection one time, and takes its event. Gives whether it took one. The
    /// engine holds the body while a part waits for a read, and while a request head waits for
    /// the delivery before it, so each part that comes has a place.
    fn pump(&mut self, now: Instant) -> Result<bool, Error> {
        if self.lingering.is_some() || (self.closed && !self.reset) {
            return Ok(false);
        }
        let hold = !self.body.wants_data() || self.next.is_some();
        self.link.engine().0.hold_body(hold);
        let event = self.link.drive(now)?;
        if !self.secure && self.link_secure() {
            self.secure = true;
            self.handshake = None;
        }
        if let Some(error) = self.link.refused("ALPN selected a protocol other than HTTP/1.1") {
            self.fail(error);
            self.link.engine().0.cancel();
            self.closed = true;
            return Ok(false);
        }
        if let Wait::Ended(Err(error)) = self.link.wait() {
            self.fail(error);
        }
        let Some(event) = event else {
            return Ok(false);
        };
        match event {
            ServerEvent::Request(head) => self.next = Some(head),
            ServerEvent::Data(data) => {
                let taken = self.body.data(data);
                assert!(taken.is_ok(), "the server drives the body only when it takes a part");
            }
            ServerEvent::End(outcome) => self.body.end(outcome),
            // `respond` refuses each response that changes the protocol.
            ServerEvent::Handoff => {
                self.fail(Error::new(Kind::Unsupported, "the server does not change the protocol"));
                self.closed = true;
            }
        }
        Ok(true)
    }

    /// Whether the TLS handshake completed.
    fn link_secure(&mut self) -> bool {
        cfg_select! {
            feature = "tls" => self.link.negotiated().is_some(),
            _ => true,
        }
    }

    /// Applies the deadlines at `now`: of the TLS handshake, of a shutdown, and of the linger.
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
            let complete = matches!(self.delivery(), Some(Delivery::Complete { .. }));
            if let Some(track) = &mut self.response
                && !complete
            {
                track.error.get_or_insert(error);
            }
            if self.state == State::Exchange {
                self.body.end(Outcome::Cancelled);
            }
            self.link.engine().0.cancel();
            self.lingering = None;
            self.closed = true;
        } else if reached(self.lingering.map(|lingering| lingering.deadline)) {
            self.lingering = None;
            self.closed = true;
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
    /// the end of a response that the transport has not accepted.
    fn fail(&mut self, error: Error) {
        self.failure.get_or_insert(error);
        let complete = matches!(self.delivery(), Some(Delivery::Complete { .. }));
        if let Some(track) = &mut self.response
            && !complete
        {
            track.error.get_or_insert(error);
        }
    }

    fn result(&self) -> Result<(), Error> {
        self.failure.map_or(Ok(()), Err)
    }
}

impl Io for Http1 {
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
        if self.next.is_some() && self.delivered() {
            return Wait::Now;
        }
        let deadline = earliest(self.shutdown, self.handshake);
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

    /// A response that the transport has not accepted becomes [`Delivery::Partial`], and the
    /// connection can drop at once: [`outstanding`](Self::outstanding) reports the output that
    /// did not go. The application can still read the request bytes that arrived, and then the
    /// outcome of the body.
    fn reset(&mut self) {
        // A reset during the linger or after the end is no failure.
        let quiet = self.lingering.take().is_some() || self.closed;
        let unsent = matches!(self.link.wait(), Wait::Ended(_)) && !self.link.outstanding().is_empty();
        self.input_ended = true;
        self.reset = true;
        self.link.reset();
        if !quiet {
            let error = Error::new(Kind::Partial, "the transport failed before the connection closed");
            if self.state == State::Exchange || !self.delivered() {
                self.fail(error);
            } else if unsent {
                // The output of a connection that ended did not go.
                self.cleanup.get_or_insert(error);
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

    fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        self.link.ack(id, accepted)
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

/// The engine of a connection, with the head timeout of `limits`.
fn engine(limits: &Limits, outbound: &Outbound, budget: &Budget) -> Result<h1::Server, Error> {
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
