//! The HTTP/2 client: many requests at a time on one connection.

use core::alloc::Layout;

use super::ResponseDeadline;
use rstypes::buffer::{Backing, Buffer as _, BufferMut, Lease, Pool, WriteLoan};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::{ClockDomain, Deadline, Instant};

use super::{Limits, Request, heads, misuse};
use crate::body::{Collect, Outcome, Part, Read, Trailers};
use crate::drive::{AckError, ActionId, Endpoint, Error, Inbound, Kind, Outbound, Output, Outstanding, Received, Turn};
use crate::h1;
use crate::h2::Role;
use crate::h2::frame::ErrorCode;
use crate::h2::message::{self, Answer, CHUNK_WAITS, Refusal};
use crate::h2::session::{Inflow, Session, Step};
use crate::host::{Connection, Engine, Io, Wait};
use crate::hpack::FieldLine;
use crate::link::{Link, earliest, queues};
use crate::message::{ResponseHead, Stream};
use crate::priority::Priority;
#[cfg(feature = "tls")]
use crate::tls::{self, ClientConfig, Negotiated, Tls};
use crate::value::{Field, Method, Scheme};

impl Engine for Session {
    type Event = Step;

    fn drive(&mut self, inbound: &mut Inbound, outbound: &mut Outbound, now: Option<Instant>) -> (Option<Step>, Turn) {
        Self::drive(self, inbound, outbound, now)
    }

    fn timed(&self) -> bool {
        true
    }
}

/// The request of a stream: its body, which the application sends.
#[derive(Clone, Copy, Debug)]
struct Out {
    length: Option<u64>,
    written: u64,
    /// A chunk of the body waits for its `Event::Sent`.
    chunk: bool,
    /// The application finished the body.
    finished: bool,
    /// The frame that ends the stream is in the output queue. After a `finish` while a chunk
    /// waits, it goes after the `Event::Sent` of the chunk.
    ended: bool,
}

/// One exchange of the connection.
#[derive(Debug)]
struct Exchange {
    id: u32,
    deadline: ResponseDeadline,
    out: Out,
    head: Option<ResponseHead>,
    /// The request is HEAD: its response has no body.
    bodiless: bool,
    /// The `content-length` of the response.
    declared: Option<u64>,
    inflow: Inflow,
    /// Why the exchange ended before its response.
    error: Option<Error>,
    /// A reset of the client that waits for room in the output queue.
    reset: Option<ErrorCode>,
    /// The stream ended in the engine.
    ended: bool,
    /// The application left the stream.
    left: bool,
    /// The exchange changed since the last [`Http2::changed`].
    changed: bool,
}

impl Exchange {
    /// Ends the exchange with a reset of the client with `code`: before the head with `error`,
    /// and after it with the outcome `outcome` of the body.
    fn refuse(&mut self, code: ErrorCode, error: Error, outcome: Outcome) {
        if !self.ended {
            self.reset.get_or_insert(code);
        }
        self.end(error, outcome);
    }

    fn end(&mut self, error: Error, outcome: Outcome) {
        if self.head.is_none() {
            self.error.get_or_insert(error);
        }
        self.inflow.end(outcome);
    }

    /// Ends the exchange with [`Kind::Deadline`] when `now` reached its deadline, and its stream
    /// resets.
    fn lapse(&mut self, now: Instant) -> Result<(), Error> {
        let Some(deadline) = self.timer() else {
            return Ok(());
        };
        let reached = deadline
            .is_reached(now)
            .map_err(|_| misuse("the time is not on the clock of the client"))?;
        if reached {
            let reason = if self.head.is_none() {
                "the deadline came before the response head"
            } else if self.inflow.ended() {
                "the deadline came before the end of the request"
            } else {
                self.deadline.body_expiry()
            };
            let error = Error::new(Kind::Deadline, reason);
            self.refuse(ErrorCode::CANCEL, error, Outcome::Cancelled);
            self.error = Some(error);
            self.changed = true;
        }
        Ok(())
    }

    /// After an early response, only the absolute lifetime applies to the unfinished upload.
    fn timer(&self) -> Option<Deadline> {
        if self.error.is_some() {
            None
        } else if !self.inflow.ended() {
            Some(self.deadline.next())
        } else {
            (!self.out.ended && !self.ended && self.reset.is_none()).then(|| self.deadline.lifetime())
        }
    }
}

/// One HTTP/2 client connection over TCP or TLS, with no I/O.
///
/// It carries many exchanges at a time, each on its own [`Stream`], with the calls and the rules
/// of [`Http1`](super::Http1). The differences:
///
/// - **Streams.** [`send`](Self::send) gives the stream of the request, and each later call names
///   it. The connection carries at most the smaller of its own and the server's
///   `SETTINGS_MAX_CONCURRENT_STREAMS`. At the limit, `send` gives `None`: wait, and send again.
///   A stream keeps its place until the application [cancelled](Self::cancel) it, or until its
///   exchange ended, the application read the end, and a new request needs the place.
/// - **Deadline.** The deadline of a request ends only its stream, with `RST_STREAM` and
///   `CANCEL`, and the connection goes on. [`delivered`](Self::delivered) then tells how much of
///   the body arrived. Then [cancel](Self::cancel) the stream to free its place.
/// - **Reuse.** The connection carries new requests until the server sends GOAWAY or it ends. A
///   request that the server did not process, above the last stream of the GOAWAY or with
///   `REFUSED_STREAM`, ends with [`Kind::Overload`]: send it again, on a new connection after a
///   GOAWAY.
/// - **Cancel.** [`cancel`](Self::cancel) resets one stream with `CANCEL`, and the connection goes
///   on. No body drains.
/// - **TLS.** Over TLS, the server must select ALPN `h2`. A connection to another protocol, also
///   to no protocol, ends with [`Kind::Unsupported`].
#[derive(Debug)]
pub struct Http2 {
    link: Link<Session>,
    /// The regions of request heads: two slots of `head_bytes`.
    heads: Pool,
    clock: ClockDomain,
    limits: Limits,
    scheme: Scheme<'static>,
    exchanges: Vec<Exchange>,
    _charge: Permit,
    /// The failure that ended the client before its connection did.
    end: Option<Error>,
    /// The application closed the client.
    closing: bool,
    /// The server sent GOAWAY.
    goaway: bool,
}

impl Http2 {
    /// Makes a client connection over TCP with prior knowledge (RFC 9113, section 3.3), for a host
    /// whose clock is `clock`. The client preface is ready at once. Each part of the connection is
    /// charged to `budget`. Refuses with [`Kind::Overload`], and allocates nothing, when the
    /// budget cannot pay.
    pub fn plain(limits: Limits, clock: ClockDomain, budget: &Budget) -> Result<Self, Error> {
        let heads = heads(&limits, budget, 2)?;
        let (inbound, mut outbound) = queues(limits.queue, budget)?;
        let session = Session::new(Role::Client, limits.h2, limits.turn, &mut outbound, budget)?;
        let connection = Connection::new(session, inbound, outbound, Some(clock))?;
        Self::new(Link::Plain(connection), heads, (clock, limits, budget), Scheme::HTTP)
    }

    /// Makes a client connection over TLS to the server `name`, a DNS name or an IP address. The
    /// ClientHello is ready at once. List `h2` in the protocols of `config`: the server must
    /// select it.
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
        let heads = heads(&limits, budget, 2)?;
        let (inbound, mut outbound) = queues(limits.queue, budget)?;
        let session = Session::new(Role::Client, limits.h2, limits.turn, &mut outbound, budget)?;
        let tls = Tls::client(config, name, session, (inbound, outbound), tls, budget)?;
        let (inbound, outbound) = queues(limits.queue, budget)?;
        let connection = Connection::new(tls, inbound, outbound, Some(clock))?;
        Self::new(Link::Tls(connection), heads, (clock, limits, budget), Scheme::HTTPS)
    }

    fn new(
        link: Link<Session>,
        heads: Pool,
        (clock, limits, budget): (ClockDomain, Limits, &Budget),
        scheme: Scheme<'static>,
    ) -> Result<Self, Error> {
        let count = usize::try_from(limits.h2.settings.max_concurrent_streams).unwrap_or(usize::MAX);
        let too_large = Error::new(Kind::Overload, "the table of the streams is too large");
        let bytes = Layout::array::<Exchange>(count).map_err(|_| too_large)?.size();
        let charge = budget
            .reserve(bytes as u64)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the table of the streams"))?;
        let mut exchanges = Vec::new();
        exchanges.try_reserve_exact(count).map_err(|_| {
            Error::new(
                Kind::Overload,
                "the memory for the table of the streams is not available",
            )
        })?;
        Ok(Self {
            link,
            heads,
            clock,
            limits,
            scheme,
            exchanges,
            _charge: charge,
            end: None,
            closing: false,
            goaway: false,
        })
    }

    /// Sends `request` on a new stream, with `deadline` for its exchange, at `now`, and gives the
    /// stream. A request with the length `Some(0)` is complete at once. For another body, send it
    /// with [`write`](Self::write), and end it with [`finish`](Self::finish).
    ///
    /// Gives `None` when the connection cannot take the request yet: each stream is in use, or
    /// the transport holds the request heads before. Wait as [`wait`](Self::wait) says, and send
    /// again. Refuses with [`Kind::Misuse`] after the close, after a GOAWAY of the server, after
    /// the end of the connection, and with a field that HTTP/2 forbids; with
    /// [`Kind::Unsupported`] for CONNECT, because the client opens no tunnel; and with
    /// [`Kind::Deadline`] at the deadline.
    pub fn send(
        &mut self,
        request: &Request<'_>,
        deadline: impl Into<ResponseDeadline>,
        now: Instant,
    ) -> Result<Option<Stream>, Error> {
        let deadline = deadline.into();
        self.live(now)?;
        if deadline.lifetime().instant().domain() != self.clock {
            return Err(misuse("the deadline is not on the clock of the client"));
        }
        if deadline.lifetime().is_reached(now) == Ok(true) {
            return Err(Error::new(
                Kind::Deadline,
                "the deadline came before the request went out",
            ));
        }
        // The input that waits can hold a GOAWAY, which ends the reuse of the connection.
        while self.pump(now)? {}
        if self.closing || self.goaway || matches!(self.link.wait(), Wait::Ended(_)) {
            return Err(misuse("the connection takes no more requests: make a new client"));
        }
        let Request {
            method,
            target,
            authority,
            fields,
            length,
        } = *request;
        if method == Method::CONNECT {
            return Err(Error::new(Kind::Unsupported, "the client opens no tunnel"));
        }
        message::sendable(fields)?;
        self.settle()?;
        if self.exchanges.len() == self.exchanges.capacity() && !self.evict()? {
            return Ok(None);
        }
        let mut digits = [0; 20];
        let length_line = length.filter(|&length| length > 0).map(|length| FieldLine {
            name: b"content-length",
            value: h1::digits(length, 10, &mut digits),
            never_indexed: false,
        });
        let line = |name, value| FieldLine {
            name,
            value,
            never_indexed: false,
        };
        let lines = [
            line(b":method", method.as_bytes()),
            line(b":scheme", self.scheme.as_bytes()),
            line(b":authority", authority.as_bytes()),
            line(b":path", target.as_bytes()),
        ]
        .into_iter()
        .chain(message::lines(fields))
        .chain(length_line);
        let (session, _) = self.link.engine();
        if session.connection().block_room(lines.clone()) > self.limits.head.head_bytes {
            return Err(Error::new(
                Kind::Overload,
                "the request head is larger than the head region: give a larger head_bytes",
            ));
        }
        let Ok(region) = self.heads.acquire() else {
            return Ok(None);
        };
        let end_stream = length == Some(0);
        let (session, outbound) = self.link.engine();
        let id = match session.connection().open(outbound, lines, end_stream, region) {
            Ok(id) => id,
            Err(error) if error.kind() == Kind::Overload => return Ok(None),
            Err(error) => return Err(error),
        };
        self.exchanges.push(Exchange {
            id,
            deadline,
            out: Out {
                length,
                written: 0,
                chunk: false,
                finished: end_stream,
                ended: end_stream,
            },
            head: None,
            bodiless: method == Method::HEAD,
            declared: None,
            inflow: Inflow::default(),
            error: None,
            reset: None,
            ended: false,
            left: false,
            changed: false,
        });
        // Over TLS, the drive encrypts the request.
        self.pump(now)?;
        Ok(Some(Stream(u64::from(id))))
    }

    /// Queues `data` as the next bytes of the request body of `stream`, with no copy. Refuses
    /// with [`Kind::Overload`] while the chunk before waits for the output, so send the output
    /// first, and with [`Kind::Misuse`] when `data` passes the length of the request.
    pub fn write(&mut self, stream: Stream, data: &Lease, now: Instant) -> Result<(), Error> {
        let len = data.initialized() as u64;
        let (index, out) = self.body(stream, now)?;
        if len == 0 {
            return Ok(());
        }
        if out
            .length
            .is_some_and(|length| out.written.saturating_add(len) > length)
        {
            return Err(misuse("the body passes the length of the request"));
        }
        let index = self.chunk_sent(stream, index, now)?.ok_or(CHUNK_WAITS)?;
        let id = self.exchanges[index].id;
        let (session, outbound) = self.link.engine();
        session.connection().data(outbound, id, data.clone(), false)?;
        let out = &mut self.exchanges[index].out;
        out.written += len;
        out.chunk = true;
        self.pump(now).map(drop)
    }

    /// Ends the request body of `stream`. While the chunk before waits for the output, the end
    /// goes after it, at a later drive. Refuses with [`Kind::Misuse`] when the body is shorter than
    /// the length of the request.
    pub fn finish(&mut self, stream: Stream, now: Instant) -> Result<(), Error> {
        let (index, out) = self.body(stream, now)?;
        if out.length.is_some_and(|length| out.written != length) {
            return Err(misuse("the body is shorter than the length of the request"));
        }
        self.exchanges[index].out.finished = true;
        self.end_body(index)?;
        self.pump(now).map(drop)
    }

    /// Ends the request body of `stream` with `trailers`, in a HEADERS frame that ends the stream.
    /// Gives `false` while the chunk before waits for the output, or while no head region or no
    /// place of the output queue is free: send the output, and call again. Refuses with
    /// [`Kind::Misuse`] when the body is shorter than the length of the request or a trailer is a
    /// connection-specific field, and with [`Kind::Overload`] when the trailer section is larger
    /// than the head region.
    pub fn finish_with_trailers(
        &mut self,
        stream: Stream,
        trailers: &[Field<'_>],
        now: Instant,
    ) -> Result<bool, Error> {
        let (index, out) = self.body(stream, now)?;
        if out.length.is_some_and(|length| out.written != length) {
            return Err(misuse("the body is shorter than the length of the request"));
        }
        message::sendable(trailers)?;
        // The trailers go after the chunk before, which can still wait for the output.
        let Some(index) = self.chunk_sent(stream, index, now)? else {
            return Ok(false);
        };
        let lines = message::lines(trailers);
        let (session, _) = self.link.engine();
        if session.connection().block_room(lines.clone()) > self.limits.head.head_bytes {
            return Err(Error::new(
                Kind::Overload,
                "the trailer section is larger than the head region: give a larger head_bytes",
            ));
        }
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let id = self.exchanges[index].id;
        let (session, outbound) = self.link.engine();
        match session.connection().headers(outbound, id, lines, true, region) {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(false),
            Err(error) => return Err(error),
        }
        let out = &mut self.exchanges[index].out;
        out.finished = true;
        out.ended = true;
        self.pump(now)?;
        Ok(true)
    }

    /// Queues the frame that ends the stream at `index`, after the application finished its body
    /// and its last chunk went. Gives whether the output queue had no room.
    fn end_body(&mut self, index: usize) -> Result<bool, Error> {
        let exchange = &self.exchanges[index];
        let (id, out) = (exchange.id, exchange.out);
        if !out.finished || out.ended || out.chunk || exchange.ended || exchange.reset.is_some() {
            return Ok(false);
        }
        let (session, outbound) = self.link.engine();
        match session
            .connection()
            .data(outbound, id, Lease::from(<&[u8]>::default()), true)
        {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(true),
            Err(error) => return Err(error),
        }
        self.exchanges[index].out.ended = true;
        Ok(false)
    }

    /// Gives the response head of `stream`, or `None` when it has not arrived: wait as
    /// [`wait`](Self::wait) says, and call again. An informational (1xx) response does not count.
    /// Refuses with [`Kind::Deadline`] at the deadline, with [`Kind::Overload`] when the server did
    /// not process the request, and with the error that ended the stream before its head, for
    /// example [`Kind::Uncertain`] when the server reset it.
    pub fn response(&mut self, stream: Stream, now: Instant) -> Result<Option<ResponseHead>, Error> {
        self.live(now)?;
        loop {
            let index = self.expire(stream, now)?;
            let exchange = &self.exchanges[index];
            if let Some(head) = &exchange.head {
                return Ok(Some(head.clone()));
            }
            if let Some(error) = exchange.error {
                return Err(error);
            }
            if !self.pump(now)? {
                return Ok(None);
            }
        }
    }

    /// Copies the next bytes of the response body of `stream` into the free capacity of
    /// `region`, as many as fit, or gives its outcome after its last byte. [`Read::Wait`] means
    /// that no byte arrived: wait as [`wait`](Self::wait) says, and read again. Refuses with
    /// [`Kind::Misuse`] when no response head arrived, and with [`Kind::Deadline`] at the
    /// deadline.
    pub fn read_into<B: BufferMut>(
        &mut self,
        stream: Stream,
        now: Instant,
        region: &mut WriteLoan<B>,
    ) -> Result<Read<'_>, Error> {
        let index = self.fill(stream, now)?;
        Ok(self.exchanges[index].inflow.consumer().read_into(region))
    }

    /// Gives the next part of the response body of `stream` as a view of its received region,
    /// with no copy, or its end with its outcome, or `None` when no byte arrived: wait as
    /// [`wait`](Self::wait) says, and call again. Refuses as [`read_into`](Self::read_into) does.
    pub fn next(&mut self, stream: Stream, now: Instant) -> Result<Option<Part>, Error> {
        let index = self.fill(stream, now)?;
        let consumer = self.exchanges[index].inflow.consumer();
        Ok(match consumer.take() {
            Some(data) => Some(Part::Data(data)),
            None => consumer.outcome().cloned().map(Part::End),
        })
    }

    /// Collects the response body of `stream` into `region`, whose free capacity bounds it. Gives
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
            let index = self.fill(stream, now)?;
            let inflow = &mut self.exchanges[index].inflow;
            if inflow.waits() {
                return Ok(Collect::More);
            }
            match inflow.consumer().collect(region) {
                Collect::More => {}
                collect => return Ok(collect),
            }
        }
    }

    /// The bytes of the response body of `stream` that the client gave so far, through each read.
    /// After a deadline, this is the part that arrived. Gives 0 for a stream that the client does
    /// not know.
    pub fn delivered(&mut self, stream: Stream) -> u64 {
        self.find(stream)
            .map_or(0, |index| self.exchanges[index].inflow.consumer().delivered())
    }

    /// Asks the server to send the response of `stream` with `priority`, in a PRIORITY_UPDATE
    /// (RFC 9218, section 7.1): the latest signal wins at the server. A request carries its first
    /// priority in its `priority` field: give [`Priority::field`] in the fields of the request.
    ///
    /// Gives `false` while the output queue has no room: send the output, and call again. A server
    /// that does not use RFC 9218 gets no frame, and neither does a stream whose response ended:
    /// the call changes nothing then. Refuses with [`Kind::Misuse`] when the stream is not open,
    /// and with [`Kind::Deadline`] after its deadline.
    pub fn prioritize(&mut self, stream: Stream, priority: Priority, now: Instant) -> Result<bool, Error> {
        self.live(now)?;
        let index = self.expire(stream, now)?;
        let exchange = &self.exchanges[index];
        let (id, ended) = (exchange.id, exchange.ended || exchange.inflow.ended());
        let (session, outbound) = self.link.engine();
        let connection = session.connection();
        if ended || !connection.is_open(id) {
            return Ok(true);
        }
        match connection.priority_update(outbound, id, priority) {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(false),
            Err(error) => return Err(error),
        }
        self.pump(now)?;
        Ok(true)
    }

    /// Leaves `stream`: the client forgets it. When its exchange did not end, the stream resets
    /// with `CANCEL`, and the connection goes on.
    pub fn cancel(&mut self, stream: Stream) {
        let Some(index) = self.find(stream) else { return };
        let exchange = &mut self.exchanges[index];
        exchange.left = true;
        if !exchange.ended && !(exchange.out.ended && exchange.inflow.ended()) {
            exchange.refuse(
                ErrorCode::CANCEL,
                Error::new(Kind::Cancelled, "the application cancelled the request"),
                Outcome::Cancelled,
            );
        }
    }

    /// Closes the connection at `now`: each exchange in flight ends with it, the client sends
    /// GOAWAY, and over TLS `close_notify`. Send the rest of the output, and then
    /// [`release`](Self::release) the client.
    pub fn close(&mut self, now: Instant) -> Result<(), Error> {
        self.closing = true;
        for exchange in &mut self.exchanges {
            exchange.left = true;
            exchange.refuse(
                ErrorCode::CANCEL,
                Error::new(Kind::Cancelled, "the application closed the client"),
                Outcome::Cancelled,
            );
        }
        if matches!(self.link.wait(), Wait::Ended(_)) {
            return Ok(());
        }
        self.settle()?;
        let (session, outbound) = self.link.engine();
        session.connection().shutdown(outbound)?;
        self.turn(now).map(drop)
    }

    /// Drives the connection at `now`, also when no call of an exchange runs: it answers the
    /// control frames of the server, such as SETTINGS and PING, sends the resets of
    /// [`cancel`](Self::cancel), and reads a GOAWAY. Call it each time that [`wait`](Self::wait)
    /// says while the client has no exchange to call: the server ends a connection whose
    /// SETTINGS get no acknowledgement. Refuses with the error that ended the client.
    pub fn drive(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        while self.pump(now)? {}
        Ok(())
    }

    /// Gives each stream whose exchange changed since the last call: its response head or a
    /// failure arrived, a part or the end of its body, the output took its last chunk, its
    /// deadline came, or the connection ended. A binding that shares the connection among
    /// handles wakes the handle of each stream that it gives, and no other.
    pub fn changed(&mut self, mut each: impl FnMut(Stream)) {
        for exchange in &mut self.exchanges {
            if core::mem::take(&mut exchange.changed) {
                each(Stream(u64::from(exchange.id)));
            }
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

    fn find(&self, stream: Stream) -> Option<usize> {
        self.exchanges
            .iter()
            .position(|exchange| u64::from(exchange.id) == stream.0)
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

    /// The exchange of `stream` that the application did not leave. At its deadline, it ends
    /// with [`Kind::Deadline`], and its stream resets.
    fn expire(&mut self, stream: Stream, now: Instant) -> Result<usize, Error> {
        let index = self
            .find(stream)
            .filter(|&index| !self.exchanges[index].left)
            .ok_or_else(|| misuse("the stream is not open"))?;
        let exchange = &mut self.exchanges[index];
        exchange.lapse(now)?;
        if let Some(error) = exchange.error
            && error.kind() == Kind::Deadline
        {
            return Err(error);
        }
        Ok(index)
    }

    /// The request of `stream`, open for its body.
    fn body(&mut self, stream: Stream, now: Instant) -> Result<(usize, Out), Error> {
        self.live(now)?;
        let index = self.expire(stream, now)?;
        let exchange = &self.exchanges[index];
        if exchange.out.finished {
            return Err(misuse("the request is finished"));
        }
        if exchange.ended || exchange.error.is_some() {
            return Err(exchange.error.unwrap_or(Error::new(
                Kind::Partial,
                "the stream ended before the end of the request",
            )));
        }
        Ok((index, exchange.out))
    }

    /// Waits for the `Event::Sent` of the chunk before, with one drive. Refuses with
    /// [`Kind::Overload`] while it waits.
    fn chunk_sent(&mut self, stream: Stream, index: usize, now: Instant) -> Result<Option<usize>, Error> {
        if !self.exchanges[index].out.chunk {
            return Ok(Some(index));
        }
        self.pump(now)?;
        let (index, out) = self.body(stream, now)?;
        Ok((!out.chunk).then_some(index))
    }

    /// Drives the connection until the body of `stream` has a part or its end for a read, or
    /// until no event comes.
    fn fill(&mut self, stream: Stream, now: Instant) -> Result<usize, Error> {
        self.live(now)?;
        let mut index = self.expire(stream, now)?;
        if self.exchanges[index].head.is_none() {
            if let Some(error) = self.exchanges[index].error {
                return Err(error);
            }
            return Err(misuse("read the response head first"));
        }
        self.exchanges[index].inflow.feed();
        // Each drive can remove an exchange that the application left, so the place of this
        // exchange can change.
        while self.exchanges[index].inflow.waits() && self.pump(now)? {
            index = self.find(stream).ok_or_else(|| misuse("the stream is not open"))?;
            self.exchanges[index].inflow.feed();
        }
        self.find(stream).ok_or_else(|| misuse("the stream is not open"))
    }

    /// The work of the streams before each drive: the credit of the bytes that the application
    /// read, the resets of the client, and the end of each stream that the application left. A
    /// call that finds no room in the output queue waits for the next drive.
    fn settle(&mut self) -> Result<(), Error> {
        if matches!(self.link.wait(), Wait::Ended(_)) {
            self.exchanges.retain(|exchange| !exchange.left);
            return Ok(());
        }
        let mut index = 0;
        while index < self.exchanges.len() {
            if self.end_body(index)? {
                return Ok(());
            }
            let (session, outbound) = self.link.engine();
            let connection = session.connection();
            let exchange = &mut self.exchanges[index];
            let id = exchange.id;
            let credit = exchange.inflow.take_credit();
            if credit > 0
                && let Err(error) = connection.release(outbound, id, credit)
            {
                exchange.inflow.untake_credit(credit);
                return room(error);
            }
            if let Some(code) = exchange.reset {
                if connection.is_open(id)
                    && let Err(error) = connection.reset(outbound, id, code)
                {
                    return room(error);
                }
                exchange.reset = None;
            }
            exchange.ended |= !connection.is_open(id);
            if !(exchange.left && exchange.ended) {
                index += 1;
            } else if !self.remove(index)? {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Frees the place of the oldest stream whose exchange ended and whose end the application
    /// read, for a new request. Gives whether it freed one.
    fn evict(&mut self) -> Result<bool, Error> {
        let Some(index) = self.exchanges.iter_mut().position(|exchange| {
            exchange.ended && (exchange.error.is_some() || exchange.inflow.consumer().outcome().is_some())
        }) else {
            return Ok(false);
        };
        self.remove(index)
    }

    /// Removes the exchange at `index`, whose stream ended: the credit of its bytes goes back, and
    /// its slot is free. Gives `false`, and keeps the exchange, when the output queue has no room
    /// for that credit.
    fn remove(&mut self, index: usize) -> Result<bool, Error> {
        let (session, outbound) = self.link.engine();
        let connection = session.connection();
        let exchange = &mut self.exchanges[index];
        let id = exchange.id;
        let rest = exchange.inflow.drop_rest();
        if rest > 0
            && let Err(error) = connection.release(outbound, id, rest)
        {
            exchange.inflow.untake_credit(rest);
            return room(error).map(|()| false);
        }
        if connection.is_held(id) {
            connection.close(id)?;
        }
        self.exchanges.remove(index);
        Ok(true)
    }

    /// Drives the connection one time at `now`. Over TLS, a server that selected a protocol other
    /// than HTTP/2 ends the client.
    fn turn(&mut self, now: Instant) -> Result<Option<Step>, Error> {
        let step = self.link.drive(now)?;
        #[cfg(feature = "tls")]
        if let Some(negotiated) = self.link.negotiated()
            && negotiated.protocol != Some(b"h2")
        {
            let error = Error::new(Kind::Unsupported, "the server did not select HTTP/2");
            self.end = Some(error);
            return Err(error);
        }
        Ok(step)
    }

    /// Drives the connection one time, and takes its event. Gives whether it made progress: an
    /// event, or a turn that has more work behind it, such as the one of the server's SETTINGS.
    /// Each exchange whose deadline came ends first, so its reset goes out also when the
    /// application does not call it.
    fn pump(&mut self, now: Instant) -> Result<bool, Error> {
        for exchange in self.exchanges.iter_mut().filter(|exchange| !exchange.left) {
            exchange.lapse(now)?;
        }
        self.settle()?;
        let step = self.turn(now)?;
        let Some(step) = step else {
            if let Wait::Ended(end) = self.link.wait() {
                self.ended(end);
            }
            return Ok(self.link.wait() == Wait::Now);
        };
        let budget = self.budget();
        let at = |exchanges: &mut [Exchange], stream: u32| {
            let index = exchanges.iter().position(|exchange| exchange.id == stream)?;
            exchanges[index].changed = true;
            Some(index)
        };
        match step {
            Step::Response {
                stream,
                end_stream,
                answer,
            } => {
                let Some(index) = at(&mut self.exchanges, stream) else {
                    return Ok(true);
                };
                let exchange = &mut self.exchanges[index];
                let malformed = Error::new(Kind::Malformed, "the server sent a malformed response");
                match answer {
                    Ok(Answer::Interim) => {}
                    Ok(Answer::Final(response)) => {
                        let response = if exchange.bodiless {
                            response.bodiless()
                        } else {
                            response
                        };
                        let declared = response.length();
                        exchange.declared = declared;
                        exchange.head = Some(ResponseHead::h2_form(response));
                        exchange.deadline.progress(now);
                        if end_stream {
                            if declared.is_some_and(|declared| declared != 0) {
                                exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                            } else {
                                exchange.inflow.end(Outcome::Complete(None));
                            }
                        }
                    }
                    Err(Refusal::Malformed) => {
                        exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                    }
                    Err(Refusal::Capacity) => exchange.refuse(
                        ErrorCode::CANCEL,
                        Error::new(Kind::Overload, "the budget refused the response head"),
                        Outcome::Cancelled,
                    ),
                }
            }
            Step::TooLarge { stream } => {
                if let Some(index) = at(&mut self.exchanges, stream) {
                    self.exchanges[index].refuse(
                        ErrorCode::CANCEL,
                        Error::new(Kind::Overload, "the response head is larger than the list limit"),
                        Outcome::Malformed,
                    );
                }
            }
            Step::Trailers { stream, trailers } => {
                if let Some(index) = at(&mut self.exchanges, stream) {
                    let exchange = &mut self.exchanges[index];
                    let malformed = Error::new(Kind::Malformed, "the server sent a malformed response");
                    match trailers {
                        Ok(_)
                            if exchange
                                .declared
                                .is_some_and(|declared| declared != exchange.inflow.received()) =>
                        {
                            exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                        }
                        Ok(lines) => exchange.inflow.end(Outcome::Complete(Some(Trailers { lines }))),
                        Err(Refusal::Malformed) => {
                            exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                        }
                        Err(Refusal::Capacity) => exchange.refuse(
                            ErrorCode::CANCEL,
                            Error::new(Kind::Overload, "the budget refused the trailer section"),
                            Outcome::Cancelled,
                        ),
                    }
                }
            }
            Step::Data {
                stream,
                data,
                end_stream,
            } => {
                let Some(index) = at(&mut self.exchanges, stream) else {
                    return Ok(true);
                };
                let exchange = &mut self.exchanges[index];
                let malformed = Error::new(Kind::Malformed, "the server sent a malformed response");
                if exchange.reset.is_some() || exchange.inflow.ended() || exchange.left {
                    exchange.inflow.discard(data);
                    return Ok(true);
                }
                if data.initialized() != 0 {
                    exchange.deadline.progress(now);
                }
                let total = exchange.inflow.received().saturating_add(data.initialized() as u64);
                if exchange.declared.is_some_and(|declared| total > declared) {
                    exchange.inflow.discard(data);
                    exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                } else if exchange.inflow.data(data, &budget).is_err() {
                    exchange.refuse(
                        ErrorCode::CANCEL,
                        Error::new(Kind::Overload, "the budget refused a part of the body"),
                        Outcome::Cancelled,
                    );
                } else if end_stream {
                    if exchange.declared.is_some_and(|declared| declared != total) {
                        exchange.refuse(ErrorCode::PROTOCOL_ERROR, malformed, Outcome::Malformed);
                    } else {
                        exchange.inflow.end(Outcome::Complete(None));
                    }
                }
            }
            Step::Reset { stream, code } => {
                if let Some(index) = at(&mut self.exchanges, stream) {
                    let exchange = &mut self.exchanges[index];
                    exchange.ended = true;
                    exchange.reset = None;
                    let error = if code == ErrorCode::REFUSED_STREAM {
                        Error::new(Kind::Overload, "the server did not process the request: send it again")
                    } else {
                        Error::new(Kind::Uncertain, "the server reset the stream before the response")
                    };
                    exchange.end(error, Outcome::Reset(Some(u64::from(code.0))));
                }
            }
            Step::Sent { stream } => {
                if let Some(index) = at(&mut self.exchanges, stream) {
                    self.exchanges[index].out.chunk = false;
                }
            }
            Step::GoAway { last_stream } => {
                self.goaway = true;
                for exchange in self.exchanges.iter_mut().filter(|exchange| exchange.id > last_stream) {
                    exchange.changed = true;
                    exchange.ended = true;
                    exchange.reset = None;
                    exchange.end(
                        Error::new(
                            Kind::Overload,
                            "the server did not process the request: send it again on a new connection",
                        ),
                        Outcome::Reset(None),
                    );
                }
            }
            Step::Request { .. } => {}
        }
        Ok(true)
    }

    /// The connection ended with `end`: each exchange in flight ends with it.
    fn ended(&mut self, end: Result<(), Error>) {
        let reset = self.link.is_reset();
        for exchange in &mut self.exchanges {
            let error = match end {
                Err(error) => error,
                Ok(()) => Error::new(Kind::Partial, "the connection ended before the response"),
            };
            let outcome = if reset {
                Outcome::Reset(None)
            } else {
                Outcome::Truncated
            };
            exchange.changed = true;
            exchange.ended = true;
            exchange.reset = None;
            exchange.end(error, outcome);
        }
    }

    fn budget(&mut self) -> Budget {
        self.link.engine().0.budget().clone()
    }
}

impl Io for Http2 {
    type End = Result<(), Error>;

    /// When to call again: now, when the transport gives what the connection waits for, at the
    /// earliest deadline of the exchanges in flight, or never after the end.
    fn wait(&self) -> Wait {
        if let Some(error) = self.end {
            return Wait::Ended(Err(error));
        }
        let deadline = self
            .exchanges
            .iter()
            .filter(|exchange| !exchange.left)
            .map(Exchange::timer)
            .fold(None, earliest);
        match self.link.wait() {
            Wait::Until { blocked, deadline: own } => Wait::Until {
                blocked,
                deadline: earliest(own, deadline),
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

    /// Each body in flight ends [`Outcome::Reset`], and the client ends.
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

/// The result of a call that found no room in the output queue: the work waits for the next drive.
fn room(error: Error) -> Result<(), Error> {
    if error.kind() == Kind::Overload {
        Ok(())
    } else {
        Err(error)
    }
}
