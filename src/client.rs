//! The client: send a request with a deadline, read its response head and its body, and close.
//!
//! [`Http1`] is one HTTP/1.1 connection over TCP or TLS, with no I/O, and [`Http2`] is one HTTP/2
//! connection. They have the same calls, with the same message, body, deadline, and trust rules.
//! An [`Http2`] carries many streams at a time, so each of its calls names the [`Stream`].
//!
//! [`Stream`]: crate::message::Stream
//!
//! The rest of this page is about [`Http1`]. [`Http2`] says where it differs. A binding, or the
//! application in a [caller-driven host](crate::host), moves the bytes of the transport with the
//! same calls as a [`Connection`]: [`received`](Http1::received) or [`receive`](Http1::receive),
//! [`output`](Http1::output) and [`ack`](Http1::ack), and [`wait`](Http1::wait) to know when to
//! call again. The application makes the calls of the exchange:
//!
//! 1. [`send`](Http1::send) a [`Request`] with its deadline.
//! 2. [`response`](Http1::response) gives the response head.
//! 3. [`read_into`](Http1::read_into) copies the body into regions that the application admits,
//!    [`next`](Http1::next) gives it as views of the received regions with no copy, and
//!    [`collect`](Http1::collect) collects it into one region of a fixed size. Each of them ends
//!    with the terminal outcome of the body, with its trailers.
//! 4. [`close`](Http1::close) ends the connection, or the next `send` reuses it.
//!
//! - **One deadline.** The deadline of a request covers the TLS handshake, the response head, and
//!   each byte of the body until the body ends. At the deadline, the call fails with
//!   [`Kind::Deadline`], [`delivered`](Http1::delivered) tells how much of the body arrived, and
//!   the connection ends. [`wait`](Http1::wait) includes the deadline.
//! - **No second object.** Each call of the exchange drives the connection, so a body read makes
//!   its own progress.
//! - **Reuse.** The connection carries the next request only when HTTP/1.1 lets it persist. A body
//!   that the application leaves unread, through [`cancel`](Http1::cancel) or the next `send`,
//!   drains up to [`BodyLimits::drain_bytes`](crate::h1::BodyLimits::drain_bytes), or the
//!   connection closes. A dirty connection never carries a request.
//! - **One connection.** When the connection ends, the client takes no more requests: make a new
//!   one.

mod http2;

use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroUsize};

use rstypes::buffer::{Backing, BufferMut, Lease, Pool, PoolRefused, WriteLoan};
use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Deadline, Instant};

use crate::body::{Collect, Consumer, Outcome, Part, Read};
use crate::drive::{AckError, ActionId, Endpoint, Error, Kind, Output, Outstanding, Received, TurnLimits};
use crate::h1::{self, BodyLimits, ClientEvent, Framing};
use crate::h2;
use crate::host::{Connection, Io, Wait};
use crate::link::{Link, earliest, queues};
use crate::message::ResponseHead;
#[cfg(feature = "tls")]
use crate::tls::{self, ClientConfig, Closure, Negotiated, Tls};
use crate::value::{Authority, Field, Method, Target};

pub use http2::Http2;

/// The limits of a client connection, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The HTTP/1.1 response head. Its `head_bytes` is also the size of the region of each
    /// request head, in each version.
    pub head: h1::Limits,
    /// The HTTP/2 connection of [`Http2`]: its settings, its header blocks, and its windows.
    pub h2: h2::Limits,
    /// The response body, its drain, and its trailers.
    pub body: BodyLimits,
    /// The work of one drive.
    pub turn: TurnLimits,
    /// The regions that each queue of the connection holds.
    pub queue: NonZeroUsize,
}

/// A request: its method, target, authority, fields, and the length of its body.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The method, for example `Method::GET`.
    pub method: Method<'a>,
    /// The request target, for example `/search?q=tls`.
    pub target: Target<'a>,
    /// The authority of the target URI. HTTP/1.1 writes it as the Host field, and HTTP/2 as the
    /// `:authority`.
    pub authority: Authority<'a>,
    /// The other fields, in their order. `host`, `content-length`, and `transfer-encoding`
    /// refuse: the authority and the length give them. On HTTP/2, a connection-specific field
    /// refuses (RFC 9113, section 8.2.2).
    pub fields: &'a [Field<'a>],
    /// The length of the request body: `Some(0)` for no body, `Some(n)`, or `None` when the length
    /// is not known. HTTP/1.1 sends an unknown length in chunks.
    pub length: Option<u64>,
}

/// The place of the client in the current exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// No exchange is in flight.
    Idle,
    /// The request went out, and its response head has not arrived.
    Head,
    /// The head arrived, and the body arrives.
    Body,
    /// Each byte of the body and its outcome arrived. Some can wait for a read.
    Arrived,
    /// The application left the body unread: the connection drains its rest, or closes.
    Draining,
}

/// One HTTP/1.1 client connection over TCP or TLS, with no I/O.
///
/// It carries one exchange at a time: a request, its response head, and its body. See the
/// [module](self) for the calls and their rules.
#[derive(Debug)]
pub struct Http1 {
    link: Link<h1::Client>,
    /// The region of each request head: one slot, which comes back when the transport takes the
    /// head.
    heads: Pool,
    clock: ClockDomain,
    state: State,
    /// The deadline of the exchange in flight.
    deadline: Option<Deadline>,
    head: Option<ResponseHead>,
    /// The framing of the response body.
    framing: Framing,
    body: Consumer,
    /// The failure that ended the client before its connection did, for example a deadline.
    end: Option<Error>,
}

impl Http1 {
    /// Makes a client connection over TCP, for a host whose clock is `clock`. Each part of the
    /// connection is charged to `budget`. Refuses with [`Kind::Overload`], and allocates nothing,
    /// when the budget cannot pay.
    pub fn plain(limits: Limits, clock: ClockDomain, budget: &Budget) -> Result<Self, Error> {
        let heads = heads(&limits, budget, 1)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let engine = h1::Client::new(limits.head, limits.body, limits.turn, &outbound, budget)?;
        let connection = Connection::new(engine, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Plain(connection), heads, clock))
    }

    /// Makes a client connection over TLS to the server `name`, a DNS name or an IP address. The
    /// ClientHello is ready at once. The server must select ALPN `http/1.1` or no protocol: a
    /// connection to another protocol ends with [`Kind::Unsupported`].
    ///
    /// Refuses as [`Tls::client`] does, and with [`Kind::Overload`] when `budget` cannot pay.
    #[cfg(feature = "tls")]
    pub fn tls(
        config: &ClientConfig,
        name: &str,
        (limits, tls): (Limits, tls::Limits),
        clock: ClockDomain,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let heads = heads(&limits, budget, 1)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let engine = h1::Client::new(limits.head, limits.body, limits.turn, &outbound, budget)?;
        let tls = Tls::client(config, name, engine, (inbound, outbound), tls, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let connection = Connection::new(tls, inbound, outbound, Some(clock))?;
        Ok(Self::new(Link::Tls(connection), heads, clock))
    }

    fn new(link: Link<h1::Client>, heads: Pool, clock: ClockDomain) -> Self {
        Self {
            link,
            heads,
            clock,
            state: State::Idle,
            deadline: None,
            head: None,
            framing: Framing::Length(0),
            body: Consumer::new(),
            end: None,
        }
    }

    /// Sends `request`, with `deadline` for the whole exchange, at `now`. A request with the
    /// length `Some(0)` is complete at once. For another body, send it with
    /// [`write`](Self::write), and end it with [`finish`](Self::finish).
    ///
    /// A body of the exchange before that the application did not read to its end drains first,
    /// or the connection closes. Gives `false` when the connection cannot take the request yet,
    /// for example while it drains or while the transport holds the last request head: wait as
    /// [`wait`](Self::wait) says, and send again. Refuses with [`Kind::Misuse`] when the response
    /// of the request before has no head yet, when the connection ended, or when the time is not
    /// on the clock of the client, and with [`Kind::Deadline`] at the deadline.
    pub fn send(&mut self, request: &Request<'_>, deadline: Deadline, now: Instant) -> Result<bool, Error> {
        self.live(now)?;
        if deadline.instant().domain() != self.clock {
            return Err(misuse("the deadline is not on the clock of the client"));
        }
        match self.state {
            State::Head => return Err(misuse("the response of the request before has no head yet")),
            State::Body | State::Arrived => self.cancel(),
            State::Idle | State::Draining => {}
        }
        self.deadline = Some(deadline);
        self.expire(now)?;
        while self.state == State::Draining && !self.link.engine().0.ready() {
            if !self.pump(now)? {
                break;
            }
        }
        let (engine, _) = self.link.engine();
        if !engine.ready() {
            if let Wait::Ended(_) = self.link.wait() {
                return Err(misuse("the connection ended: make a new client"));
            }
            return Ok(false);
        }
        self.state = State::Idle;
        let Ok(head) = self.heads.acquire() else {
            return Ok(false);
        };
        let (engine, outbound) = self.link.engine();
        let Request {
            method,
            target,
            authority,
            fields,
            length,
        } = *request;
        let body = length.map_or(Framing::Chunked, Framing::Length);
        engine.request(outbound, method, target, authority, fields, body, head)?;
        if length == Some(0) {
            engine.finish(outbound)?;
        }
        self.state = State::Head;
        self.head = None;
        self.body = Consumer::new();
        // Over TLS, the drive encrypts the request.
        self.pump(now)?;
        Ok(true)
    }

    /// Queues `data` as the next bytes of the request body, with no copy. Refuses as
    /// [`h1::Client::send`] does: with [`Kind::Overload`] when the output queue is full also after
    /// a drive, so send the output first.
    pub fn write(&mut self, data: &Lease, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        self.expire(now)?;
        self.queue(now, |client| {
            let (engine, outbound) = client.link.engine();
            engine.send(outbound, data)
        })?;
        self.pump(now).map(drop)
    }

    /// Ends the request body. Refuses as [`h1::Client::finish`] does.
    pub fn finish(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        self.expire(now)?;
        self.queue(now, |client| {
            let (engine, outbound) = client.link.engine();
            engine.finish(outbound)
        })?;
        self.pump(now).map(drop)
    }

    /// Runs `queue`, which queues plaintext output and changes nothing when it refuses. Over TLS,
    /// only a drive seals the plaintext into records and frees its queue. So when `queue` refuses
    /// with [`Kind::Overload`], the connection drives one time, and `queue` runs again.
    fn queue(&mut self, now: Instant, mut queue: impl FnMut(&mut Self) -> Result<(), Error>) -> Result<(), Error> {
        match queue(self) {
            Err(error) if error.kind() == Kind::Overload => {
                self.pump(now)?;
                queue(self)
            }
            result => result,
        }
    }

    /// Gives the response head of the request in flight, or `None` when it has not arrived:
    /// wait as [`wait`](Self::wait) says, and call again. An informational (1xx) response does
    /// not count. Refuses with [`Kind::Misuse`] when no request is in flight, with
    /// [`Kind::Deadline`] at the deadline, and with the error of the connection when it ended
    /// first, for example [`Kind::Uncertain`] when it closed before the head.
    pub fn response(&mut self, now: Instant) -> Result<Option<ResponseHead>, Error> {
        self.live(now)?;
        if self.state == State::Idle || self.state == State::Draining {
            return Err(misuse("no request is in flight"));
        }
        while self.head.is_none() {
            self.expire(now)?;
            if !self.pump(now)? {
                return self.waiting().map(|()| None);
            }
        }
        Ok(self.head.clone())
    }

    /// Copies the next bytes of the response body into the free capacity of `region`, as many as
    /// fit, or gives its outcome after its last byte. [`Read::Wait`] means that no byte arrived:
    /// wait as [`wait`](Self::wait) says, and read again. Refuses with [`Kind::Misuse`] when no
    /// response head arrived, and with [`Kind::Deadline`] at the deadline.
    pub fn read_into<B: BufferMut>(&mut self, now: Instant, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        self.fill(now)?;
        Ok(self.body.read_into(region))
    }

    /// Gives the next part of the response body as a view of its received region, with no copy,
    /// or its end with its outcome, or `None` when no byte arrived: wait as
    /// [`wait`](Self::wait) says, and call again. Refuses as [`read_into`](Self::read_into) does.
    pub fn next(&mut self, now: Instant) -> Result<Option<Part>, Error> {
        self.fill(now)?;
        Ok(match self.body.take() {
            Some(data) => Some(Part::Data(data)),
            None => self.body.outcome().cloned().map(Part::End),
        })
    }

    /// Collects the response body into `region`, whose free capacity bounds it. Gives
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

    /// The bytes of the response body that the client gave so far, through each read. After a
    /// deadline, this is the part that arrived.
    pub fn delivered(&self) -> u64 {
        self.body.delivered()
    }

    /// Leaves the rest of the response body unread. The connection discards it, up to
    /// [`BodyLimits::drain_bytes`](crate::h1::BodyLimits::drain_bytes), and then carries the next
    /// request, or it closes when the rest is longer or ends only with the close. Before the
    /// response head, the connection closes at once.
    pub fn cancel(&mut self) {
        match self.state {
            State::Head | State::Body => {
                self.link.engine().0.cancel_response();
                self.state = State::Draining;
            }
            State::Arrived => self.state = State::Idle,
            State::Idle | State::Draining => {}
        }
        self.deadline = None;
        self.body = Consumer::new();
    }

    /// Ends the connection at `now`: the exchange in flight ends with it, and over TLS the
    /// connection sends `close_notify`. Send the rest of the output, and then
    /// [`release`](Self::release) the client.
    pub fn close(&mut self, now: Instant) -> Result<(), Error> {
        self.link.engine().0.close();
        self.state = State::Idle;
        self.deadline = None;
        self.link_drive(now).map(drop)
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

    /// Refuses a call after the end of the client, and a time on another clock.
    fn live(&self, now: Instant) -> Result<(), Error> {
        if let Some(error) = self.end {
            return Err(error);
        }
        if now.domain() != self.clock {
            return Err(misuse("the time is not on the clock of the client"));
        }
        Ok(())
    }

    /// Refuses with [`Kind::Deadline`] when `now` is at the deadline of the exchange. The client
    /// ends, unless no request went out on a clean connection.
    fn expire(&mut self, now: Instant) -> Result<(), Error> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        if !deadline
            .is_reached(now)
            .map_err(|_| misuse("the time is not on the clock of the client"))?
        {
            return Ok(());
        }
        self.deadline = None;
        let reason = match self.state {
            State::Idle => {
                return Err(Error::new(
                    Kind::Deadline,
                    "the deadline came before the request went out",
                ));
            }
            State::Draining => "the deadline came before the request went out",
            State::Head => "the deadline came before the response head",
            State::Body | State::Arrived => "the deadline came before the end of the response",
        };
        let error = Error::new(Kind::Deadline, reason);
        self.end = Some(error);
        // The exchange cannot complete, so the connection ends.
        self.link.engine().0.close();
        self.link_drive(now)?;
        Err(error)
    }

    /// Drives the connection until the body has a part or its end for a read, or until no event
    /// comes. Checks the deadline while the body arrives.
    fn fill(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        match self.state {
            State::Body => self.expire(now)?,
            State::Arrived => {}
            State::Head => return Err(misuse("read the response head first")),
            State::Idle | State::Draining => return Err(misuse("no response body waits")),
        }
        while self.body.wants_data() {
            if !self.pump(now)? {
                return self.waiting();
            }
        }
        Ok(())
    }

    /// Drives the connection one time, and takes its event. Gives whether it took one. The
    /// engine holds the body while a part waits for a read, so each part that comes has a place.
    fn pump(&mut self, now: Instant) -> Result<bool, Error> {
        let hold = !self.body.wants_data();
        self.link.engine().0.hold_body(hold);
        let Some(event) = self.link_drive(now)? else {
            return Ok(false);
        };
        match event {
            ClientEvent::Informational(_) => {}
            ClientEvent::Response(head) => {
                self.framing = head.head().framing();
                self.head = Some(ResponseHead::h1_form(head));
                self.state = State::Body;
            }
            ClientEvent::Data(data) => {
                // The client drives only when the consumer takes a part.
                let taken = self.body.data(data);
                assert!(taken.is_ok(), "the client drives only when the body takes a part");
            }
            // The end of a body that the application cancelled changes nothing: the drain goes on.
            ClientEvent::End(_) if self.state == State::Draining => {}
            ClientEvent::End(outcome) => {
                let outcome = self.unnotified(outcome);
                self.body.end(outcome);
                self.state = State::Arrived;
            }
            ClientEvent::Handoff => {
                let error = Error::new(Kind::Unsupported, "the client does not switch protocols");
                self.end = Some(error);
                return Err(error);
            }
        }
        Ok(true)
    }

    /// Drives the connection one time. Over TLS, a server that selected a protocol other than
    /// HTTP/1.1 ends the client.
    fn link_drive(&mut self, now: Instant) -> Result<Option<ClientEvent>, Error> {
        let event = self.link.drive(now)?;
        if let Some(error) = self.link.refused("the server selected a protocol other than HTTP/1.1") {
            self.end = Some(error);
            return Err(error);
        }
        Ok(event)
    }

    /// The outcome of a body over TLS that the close delimits: when the transport ended with no
    /// `close_notify`, its end is not proven, so the body is truncated.
    fn unnotified(&mut self, outcome: Outcome) -> Outcome {
        #[cfg(feature = "tls")]
        if let (Outcome::Complete(_), Framing::Close) = (&outcome, self.framing)
            && self.link.closure() == Some(Closure::Unnotified)
        {
            return Outcome::Truncated;
        }
        outcome
    }

    /// No event came: the call waits, or the error of a connection that ended before the
    /// exchange did.
    fn waiting(&self) -> Result<(), Error> {
        match self.link.wait() {
            Wait::Ended(Err(error)) => Err(error),
            Wait::Ended(Ok(())) => Err(Error::new(Kind::Partial, "the connection ended before the response")),
            _ => Ok(()),
        }
    }
}

impl Io for Http1 {
    type End = Result<(), Error>;

    /// When to call again: now, when the transport gives what the connection waits for, at the
    /// deadline of the exchange, or never after the end.
    fn wait(&self) -> Wait {
        if let Some(error) = self.end {
            return Wait::Ended(Err(error));
        }
        match self.link.wait() {
            Wait::Until { blocked, deadline } => Wait::Until {
                blocked,
                deadline: earliest(deadline, self.deadline),
            },
            wait => wait,
        }
    }

    fn receive(&mut self, received: Received) -> Result<(), Received> {
        self.link.receive(received)
    }

    fn region(&mut self) -> Result<Option<Backing>, Error> {
        self.link.region()
    }

    fn received(&mut self, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        self.link.received(region, endpoint, capacity)
    }

    fn end_input(&mut self) {
        self.link.end_input();
    }

    /// A body in flight ends [`Outcome::Reset`], and the client ends.
    fn reset(&mut self) {
        self.link.reset();
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

    /// Gives the end of the client when it can drop: after its end, when the transport accepted
    /// each output. Gives `None` before that.
    fn release(&self) -> Option<Result<(), Error>> {
        match self.end {
            Some(error) if self.outstanding().is_empty() => Some(Err(error)),
            Some(_) => None,
            None => self.link.release(),
        }
    }
}

/// The pool of the regions of request heads: `slots` slots of `head_bytes`.
fn heads(limits: &Limits, budget: &Budget, slots: u32) -> Result<Pool, Error> {
    let slot =
        Layout::array::<u8>(limits.head.head_bytes).map_err(|_| misuse("the head region of a request is too large"))?;
    Pool::new(budget, NonZeroU32::new(slots).unwrap_or(NonZeroU32::MIN), slot).map_err(|refused| match refused {
        PoolRefused::Budget(_) => Error::new(Kind::Overload, "the budget refused the region of a request head"),
        PoolRefused::Layout => misuse("the head region of a request is too large"),
        PoolRefused::Allocation => Error::new(
            Kind::Overload,
            "the memory for the region of a request head is not available",
        ),
    })
}

fn misuse(reason: &'static str) -> Error {
    Error::new(Kind::Misuse, reason)
}
