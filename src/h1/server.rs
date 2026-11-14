//! The server engine: one connection, for HTTP/1.1 and HTTP/1.0 clients.

use core::fmt;
use core::time::Duration;

use rstypes::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rstypes::capacity::Budget;
use rstypes::time::{Deadline, Instant};

use super::body::{BodyReader, BodyWriter, Read, full, misuse, write_error};
use super::head::{BodyLimits, Limits, ParseError, Version};
use super::join::{Join, Step, join};
use super::write::write_response;
use super::{Framing, RequestHead, RequestParser, RetainedRequest};
use crate::body::Outcome;
use crate::drive::{Blocked, Error, Inbound, Kind, Outbound, Progress, Turn, TurnLimits, Work};
use crate::value::{Field, Method, Status};

/// The default head timeout of a [`Server`]: 30 seconds. It is the default header read timeout of
/// the hyper HTTP/1 server, and half of the 60-second `client_header_timeout` of nginx. A client
/// on a slow link sends a head in far less time, and a slow peer holds its connection no longer.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// The server side of one HTTP/1.1 connection, with no I/O.
///
/// In each drive, the engine reads the requests in the host's [`Inbound`] queue and gives one
/// [`ServerEvent`]. The application answers each request with [`respond`](Self::respond),
/// [`send`](Self::send), and [`finish`](Self::finish), which push the response into the host's
/// [`Outbound`] queue. Responses go in the order of the requests: the engine reads a pipelined
/// request only after the response before it is complete.
///
/// The caller gives the region of each response head. The size line of each chunk comes from a
/// pool that the engine makes at construction, with one slot of 16 bytes for each entry of the
/// output queue, charged to the caller's budget. A slot returns to the pool when the last view of
/// its line drops. Thus the engine allocates after [`new`](Self::new) only for a request head or
/// trailer section that continues in the next region: it joins their bytes into one region of at
/// most the limit of the section, which the budget pays for until the last view of it drops.
pub struct Server {
    limits: Limits,
    body: BodyLimits,
    parser: RequestParser,
    writer: BodyWriter,
    /// The budget that pays for the pool and for each join.
    budget: Budget,
    /// The join of a request head that continues in the next region.
    join: Option<Join>,
    /// The capacity that a join waits for.
    capacity: Option<u64>,
    /// The limits of each turn.
    turn: TurnLimits,
    /// The most time to wait for a request head.
    head_timeout: Option<Duration>,
    /// The deadline of the head that the engine waits for.
    head_deadline: Option<Deadline>,
    /// The last turn stopped at a limit, and work remains.
    more: bool,
    /// The refusal of a request body, which the drive applies after the body's outcome.
    failure: Option<ParseError>,
    /// The error response that waits for room in the output queue. The connection ends after
    /// it.
    owed: Option<&'static [u8]>,
    /// The bytes of the empty lines before the next request line, which count against the head
    /// limit.
    empty: usize,
    /// The last empty line has its CR, and its LF did not arrive.
    cr: bool,
    read: ReadState,
    write: Write,
    /// The facts of the current request.
    request: Request,
    /// The connection closes after the current response.
    close: bool,
    /// The end of the connection.
    end: Option<Result<(), Error>>,
}

/// An event of the server engine.
pub enum ServerEvent {
    /// A request head. Its body follows as [`Data`](Self::Data), then [`End`](Self::End). Answer it
    /// with [`Server::respond`].
    Request(RetainedRequest),
    /// Bytes of the request body: a view of a received region, with no copy.
    Data(Lease),
    /// The end of the request body, with its outcome: complete with its trailers, truncated by
    /// the end of input, or malformed. After a truncated or malformed body, the next turn is
    /// terminal.
    End(Outcome),
    /// The connection changed its protocol after a 101 or a 2xx response to CONNECT. The front of
    /// the `Inbound` queue is exactly the bytes after the request, and they belong to the new
    /// protocol, as each later byte does. The engine reads no more, and the next turn is terminal.
    Handoff,
}

impl fmt::Debug for ServerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(head) => f.debug_tuple("Request").field(head).finish(),
            Self::Data(data) => f.debug_struct("Data").field("len", &data.initialized()).finish(),
            Self::End(outcome) => f.debug_tuple("End").field(outcome).finish(),
            Self::Handoff => f.write_str("Handoff"),
        }
    }
}

/// The place of the engine in the current request.
#[derive(Debug)]
enum ReadState {
    /// Before a request head.
    Head,
    /// In the request body.
    Body(BodyReader),
    /// After the request.
    Done,
}

/// The place of the engine in the current response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    /// No request waits for a response.
    Idle,
    /// A request waits for its final response.
    Waiting,
    /// In the response body, which the body writer holds.
    Body,
    /// After the response.
    Done,
}

/// The facts of the current request that its response needs.
#[derive(Clone, Copy, Debug, Default)]
struct Request {
    version: Option<Version>,
    head: bool,
    connect: bool,
    /// The request waits for `100 Continue` before it sends its body.
    expect: bool,
    /// The request asks to change the protocol.
    upgrade: bool,
    /// The response changes the protocol: a 101, or a 2xx to CONNECT. After the request, the
    /// bytes belong to the new protocol.
    switch: bool,
}

impl Server {
    /// Makes the engine of one connection, for heads within `limits`, bodies within `body`, and
    /// drives within `turn`.
    ///
    /// It makes its pool of chunk-size lines here: one slot for each entry of `outbound`, charged
    /// to `budget`, which also pays for each join later. Refuses with [`Kind::Overload`], and
    /// allocates nothing, when the budget or the memory refuses.
    pub fn new(
        limits: Limits,
        body: BodyLimits,
        turn: TurnLimits,
        outbound: &Outbound,
        budget: &Budget,
    ) -> Result<Self, Error> {
        Ok(Self {
            limits,
            body,
            parser: RequestParser::new(limits),
            writer: BodyWriter::new(outbound, budget)?,
            budget: budget.clone(),
            join: None,
            capacity: None,
            turn,
            head_timeout: Some(HEAD_TIMEOUT),
            head_deadline: None,
            more: false,
            failure: None,
            owed: None,
            empty: 0,
            cr: false,
            read: ReadState::Head,
            write: Write::Idle,
            request: Request::default(),
            close: false,
            end: None,
        })
    }

    /// Reads the requests in `inbound`, and gives the next event and the [`Turn`].
    ///
    /// Drive again after each event, and after more bytes arrive or the application answers.
    /// When the turn is terminal, send the rest of `outbound`, and then close the connection. A
    /// refused request gets its error response in `outbound` before the close, when no response
    /// head was out. When `outbound` has no room for it, the turn is
    /// [`Blocked::Output`](crate::drive::Blocked::Output) until the transport accepts output.
    pub fn drive(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> (Option<ServerEvent>, Turn) {
        self.expire(inbound, now);
        self.flush(outbound);
        let (event, progress) = match self.step(inbound) {
            Ok(event) => {
                let progress = match self.failure.take() {
                    Some(refusal) => self.refuse(refusal, outbound),
                    None if event.is_some() => Progress::Pending,
                    None => self.progress(),
                };
                (event, progress)
            }
            Err(refusal) => (None, self.refuse(refusal, outbound)),
        };
        self.arm(now);
        (
            event,
            Turn {
                progress,
                deadline: self.head_deadline,
            },
        )
    }

    /// Sets the head timeout: the most time from when the engine waits for a request head, after
    /// the connection starts or after a response, to the end of the head. `None` turns it off.
    /// The default is [`HEAD_TIMEOUT`].
    pub fn head_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.head_timeout = timeout;
        self
    }

    /// Whether the engine has a timer, which needs the time of the host.
    pub(crate) fn has_timer(&self) -> bool {
        self.head_timeout.is_some()
    }

    /// Whether the engine waits for a request head.
    fn waits_for_head(&self) -> bool {
        matches!(self.read, ReadState::Head) && self.write == Write::Idle && self.end.is_none()
    }

    /// Ends the connection at `now` when its head deadline passed. With no byte of a head, the
    /// connection was idle, and it closes with no error. With part of a head, it gets a 408 and
    /// then the close (RFC 9110, section 15.5.9). A head timeout needs the time of the host.
    fn expire(&mut self, inbound: &Inbound, now: Option<Instant>) {
        if self.head_timeout.is_none() || self.end.is_some() {
            return;
        }
        let Some(now) = now else {
            self.end = Some(Err(Error::new(
                Kind::Unsupported,
                "the head timeout needs the time of the host",
            )));
            return;
        };
        let Some(deadline) = self.head_deadline.filter(|_| self.waits_for_head()) else {
            return;
        };
        match deadline.is_reached(now) {
            Ok(false) => {}
            Ok(true) if self.join.is_none() && inbound.front().is_none() => self.end = Some(Ok(())),
            Ok(true) => {
                self.owed = Some(b"HTTP/1.1 408 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
                self.end = Some(Err(Error::new(
                    Kind::Deadline,
                    "the request head did not arrive before its deadline",
                )));
            }
            Err(_) => {
                self.end = Some(Err(Error::new(
                    Kind::Misuse,
                    "the time of the host is on another clock than the deadline",
                )));
            }
        }
    }

    /// Starts the head deadline at `now` when the engine starts to wait for a head, and clears it
    /// when the engine does not wait for one.
    fn arm(&mut self, now: Option<Instant>) {
        if !self.waits_for_head() {
            self.head_deadline = None;
        } else if self.head_deadline.is_none()
            && let (Some(timeout), Some(now)) = (self.head_timeout, now)
        {
            self.head_deadline = now.checked_add(timeout).ok().map(Deadline::at);
        }
    }

    /// Reads the next event from `inbound`, or gives `None` when the engine waits.
    fn step(&mut self, inbound: &mut Inbound) -> Result<Option<ServerEvent>, ParseError> {
        let mut work = Work::default();
        loop {
            if self.end.is_some() {
                return Ok(None);
            }
            let reader = match &mut self.read {
                // A pipelined request waits for the response before it.
                ReadState::Head if self.write != Write::Idle => return Ok(None),
                ReadState::Head if inbound.front().is_none() && inbound.ended() => {
                    self.end = Some(match self.join {
                        Some(_) => Err(Error::new(Kind::Partial, "the request head ended before its end")),
                        None => Ok(()),
                    });
                    return Ok(None);
                }
                ReadState::Head => return self.head(inbound),
                ReadState::Done if self.write == Write::Done && self.request.switch => {
                    self.end = Some(Ok(()));
                    return Ok(Some(ServerEvent::Handoff));
                }
                ReadState::Done if self.write == Write::Done => {
                    self.next();
                    continue;
                }
                ReadState::Done => return Ok(None),
                // The body waits until the application accepts it.
                ReadState::Body(_) if self.request.expect => return Ok(None),
                ReadState::Body(reader) => reader,
            };
            let draining = reader.draining();
            let read = match reader.read(inbound, &self.budget, &mut work) {
                Ok(read) => read,
                // A body that breaks its framing ends as malformed. Then the drive refuses the
                // request.
                Err(refusal) => {
                    self.read = ReadState::Done;
                    self.failure = Some(refusal);
                    return Ok((!draining).then_some(ServerEvent::End(Outcome::Malformed)));
                }
            };
            match read {
                Read::Data(data) if !draining => return Ok(Some(ServerEvent::Data(data))),
                // A turn stops at its limits between two steps, and the next turn goes on.
                Read::Data(_) | Read::Again if work.reached(&self.turn) => {
                    self.more = true;
                    return Ok(None);
                }
                Read::Data(_) | Read::Again => {}
                Read::End(trailers) => {
                    self.read = ReadState::Done;
                    if !draining {
                        return Ok(Some(ServerEvent::End(Outcome::Complete(trailers))));
                    }
                }
                Read::Wait => return Ok(None),
                Read::Overdrawn => self.end = Some(Ok(())),
                Read::Truncated => {
                    self.end = Some(Err(Error::new(Kind::Partial, "the request body ended before its end")));
                    if !draining {
                        return Ok(Some(ServerEvent::End(Outcome::Truncated)));
                    }
                }
                Read::Capacity(units) => {
                    self.capacity = Some(units);
                    return Ok(None);
                }
            }
        }
    }

    /// Reads a request head from `inbound`. A head that continues in the next region joins into
    /// one region, charged to the budget.
    fn head(&mut self, inbound: &mut Inbound) -> Result<Option<ServerEvent>, ParseError> {
        if self.join.is_none() {
            self.skip_empty_lines(inbound)?;
            if self.cr {
                return Ok(None);
            }
            let Some(front) = inbound.front() else { return Ok(None) };
            let region = front.region.clone();
            if let Some(head) = self.parser.parse(region.bytes())? {
                let consumed = head.consumed();
                let event = self.accept(head, &region)?;
                inbound.consume(consumed).map_err(|_| ParseError::Malformed)?;
                return Ok(Some(event));
            }
        }
        let parser = &mut self.parser;
        let step = join(&mut self.join, &self.budget, self.limits.head_bytes, inbound, |bytes| {
            Ok(parser.parse(bytes)?.map(|head| head.consumed()))
        })?;
        let region = match step {
            Step::Complete(region) => region,
            Step::Wait => return Ok(None),
            Step::Capacity(units) => {
                self.capacity = Some(units);
                return Ok(None);
            }
        };
        let Some(head) = self.parser.parse(region.bytes())? else {
            return Err(ParseError::Malformed);
        };
        self.accept(head, &region).map(Some)
    }

    /// Discards the empty lines before a request line (RFC 9112, section 2.2). Their bytes count
    /// against the head limit. A CR at the end of a region waits for its LF in the next region,
    /// and a CR before another byte refuses, as in a head. A bare LF stays, and the head refuses.
    fn skip_empty_lines(&mut self, inbound: &mut Inbound) -> Result<(), ParseError> {
        while let Some(front) = inbound.front() {
            let bytes = front.region.bytes();
            let mut skip = 0;
            for &byte in bytes {
                match (self.cr, byte) {
                    (false, b'\r') => self.cr = true,
                    (true, b'\n') => self.cr = false,
                    (true, _) => return Err(ParseError::Malformed),
                    (false, _) => break,
                }
                skip += 1;
            }
            let rest = bytes.len() - skip;
            self.empty = self.empty.saturating_add(skip);
            if self.empty > self.limits.head_bytes {
                return Err(ParseError::HeadTooLarge);
            }
            inbound.consume(skip).map_err(|_| ParseError::Malformed)?;
            if rest > 0 {
                break;
            }
        }
        Ok(())
    }

    /// Takes the request of a complete `head` in `region`: its facts, and the reader of its body.
    fn accept(&mut self, head: RequestHead<'_>, region: &Lease) -> Result<ServerEvent, ParseError> {
        if core::mem::take(&mut self.empty).saturating_add(head.consumed()) > self.limits.head_bytes {
            return Err(ParseError::HeadTooLarge);
        }
        let framing = head.framing();
        if let Framing::Length(length) = framing
            && length > self.body.body_bytes
        {
            return Err(ParseError::BodyTooLarge);
        }
        // A request has no close framing.
        if framing == Framing::Close {
            return Err(ParseError::Framing);
        }
        let Some(retained) = head.retain(region) else {
            return Err(ParseError::Malformed);
        };
        let version = head.version();
        self.request = Request {
            version: Some(version),
            head: head.method() == Method::HEAD,
            connect: head.method() == Method::CONNECT,
            // An HTTP/1.0 client does not wait for 100 (RFC 9110, section 10.1.1).
            expect: head.expects_continue() && version == Version::Http11 && framing != Framing::Length(0),
            upgrade: head.upgrade() && version == Version::Http11,
            switch: false,
        };
        self.close = !head.persistent();
        self.read = ReadState::Body(BodyReader::new(framing, self.body, self.limits));
        self.write = Write::Waiting;
        Ok(ServerEvent::Request(retained))
    }

    /// Ends the exchange of a request and its response: the connection closes, or the next request
    /// can start.
    fn next(&mut self) {
        if self.close {
            self.end = Some(Ok(()));
        } else {
            self.read = ReadState::Head;
            self.write = Write::Idle;
            self.request = Request::default();
        }
    }

    /// The progress of the engine when it gives no event.
    fn progress(&mut self) -> Progress {
        match (self.end, self.capacity.take(), core::mem::take(&mut self.more)) {
            // The connection ends after its error response, which waits for room in the queue.
            (Some(_), _, _) if self.owed.is_some() => Progress::Blocked(Blocked::Output),
            (Some(end), _, _) => Progress::Terminal(end),
            (None, Some(units), _) => Progress::Blocked(Blocked::Capacity(units)),
            (None, None, true) => Progress::Pending,
            (None, None, false) => Progress::Blocked(Blocked::Input),
        }
    }

    /// Ends the connection after a refusal. When no response head is out, it queues the error
    /// response that the refusal names, when the output queue has room, or later.
    fn refuse(&mut self, refusal: ParseError, outbound: &mut Outbound) -> Progress {
        if matches!(self.write, Write::Idle | Write::Waiting) {
            self.owed = Some(error_response(refusal));
            self.flush(outbound);
        }
        self.end = Some(Err(Error::from(refusal)));
        self.progress()
    }

    /// Queues the error response that waits, when the output queue has room.
    fn flush(&mut self, outbound: &mut Outbound) {
        if let Some(response) = self.owed
            && outbound.push(Lease::from(response)).is_ok()
        {
            self.owed = None;
        }
    }

    /// Accepts the body of the current request: it sends `100 Continue` when the request waits
    /// for it, and then the engine reads the body. Without an expectation, it does nothing.
    pub fn accept_body(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        if self.request.expect && self.write == Write::Waiting {
            outbound
                .push(Lease::from(&b"HTTP/1.1 100 Continue\r\n\r\n"[..]))
                .map_err(|_| full())?;
            self.request.expect = false;
        }
        Ok(())
    }

    /// Sends an informational (1xx) response before the final response, for example 103 Early
    /// Hints. Its head is written into `head`.
    ///
    /// Refuses 100, which [`accept_body`](Self::accept_body) sends, and 101, which
    /// [`respond`](Self::respond) sends. An HTTP/1.0 client gets no informational response (RFC
    /// 9110, section 15.2), so the call then does nothing.
    pub fn inform(
        &mut self,
        outbound: &mut Outbound,
        status: Status,
        fields: &[Field<'_>],
        head: Backing,
    ) -> Result<(), Error> {
        if self.write != Write::Waiting || !(102..200).contains(&status.code()) {
            return Err(misuse(
                "an informational response needs a waiting request and a status of 102 to 199",
            ));
        }
        if self.request.version == Some(Version::Http10) {
            return Ok(());
        }
        push_head(outbound, head, status, fields, Framing::Length(0), None)
    }

    /// Writes the final response head of the current request into `head`, and queues it. Then
    /// send the body with [`send`](Self::send), and end it with [`finish`](Self::finish), also when
    /// it has no body.
    ///
    /// `framing` gives the body: `Length(n)`, `Chunked`, or `Close`. A response to HEAD, and a 204
    /// or 304 response, has no body; give its framing as for a GET, or `Length(0)`. An HTTP/1.0
    /// client cannot read chunks, so its chunked response becomes a response that the close
    /// ends.
    ///
    /// The engine adds the `connection` field that the connection needs: `close` when it closes
    /// after the response, and `keep-alive` when an HTTP/1.0 connection persists. It closes when
    /// the request does not let the connection persist, when the response has close framing or a
    /// `close` option, and when the request has unread body bytes that the drain cannot read: a
    /// body that waits for 100, or more bytes than [`BodyLimits::drain_bytes`].
    pub fn respond(
        &mut self,
        outbound: &mut Outbound,
        status: Status,
        fields: &[Field<'_>],
        framing: Framing,
        head: Backing,
    ) -> Result<(), Error> {
        let code = status.code();
        // A 101 needs a request that asked to change the protocol, and a body that does not wait
        // for 100 (RFC 9110, section 7.8).
        let upgrade = code == 101 && self.request.upgrade && !self.request.expect;
        if self.write != Write::Waiting || (code < 200 && !upgrade) {
            return Err(misuse(
                "a final response needs a waiting request and a status of 200 to 599, or 101 to an upgrade",
            ));
        }
        if upgrade || (self.request.connect && (200..300).contains(&code)) {
            // The head has no framing field (RFC 9110, section 9.3.6), as close framing writes
            // it, and no body. The new protocol starts after the request.
            push_head(
                outbound,
                head,
                status,
                fields,
                if upgrade { Framing::Length(0) } else { Framing::Close },
                None,
            )?;
            self.request.switch = true;
            self.writer.open(Framing::Length(0));
            self.write = Write::Body;
            return Ok(());
        }
        let http10 = self.request.version == Some(Version::Http10);
        let framing = match framing {
            Framing::Chunked if http10 => Framing::Close,
            framing => framing,
        };
        let close_option = fields.iter().any(|field| {
            field.name.eq_ignore_ascii_case(b"connection")
                && field
                    .value
                    .split(|&byte| byte == b',')
                    .any(|option| option.trim_ascii().eq_ignore_ascii_case(b"close"))
        });
        let unread = match &self.read {
            ReadState::Body(reader) => {
                self.request.expect || reader.left().is_some_and(|left| left > self.body.drain_bytes)
            }
            ReadState::Head | ReadState::Done => false,
        };
        let close = self.close || close_option || framing == Framing::Close || unread;
        let connection = match (close, http10) {
            (true, _) if !close_option => Some(&b"close"[..]),
            (false, true) => Some(&b"keep-alive"[..]),
            _ => None,
        };
        let no_body = self.request.head || code == 204 || code == 304;
        let written = match framing {
            _ if code == 204 || code == 304 => Framing::Length(0),
            framing => framing,
        };
        push_head(outbound, head, status, fields, written, connection)?;
        self.close = close;
        self.writer.open(if no_body { Framing::Length(0) } else { framing });
        self.write = Write::Body;
        Ok(())
    }

    /// Queues `data` as the next bytes of the response body, with no copy: the queue takes a view
    /// of its own.
    ///
    /// A chunked body sends each call as one chunk, with its size line from the pool and a
    /// static CR LF. Refuses with [`Kind::Overload`], and changes nothing, when the queue or the
    /// pool is full: acknowledge output, then send again. Refuses with [`Kind::Misuse`] when the
    /// response has no open body, or when `data` passes its Content-Length.
    pub fn send(&mut self, outbound: &mut Outbound, data: &Lease) -> Result<(), Error> {
        self.writer.send(outbound, data)
    }

    /// Ends the response body. A chunked body gets its last chunk. Refuses with
    /// [`Kind::Overload`] when the queue is full, and with [`Kind::Misuse`] when no body is open or
    /// a Content-Length body has fewer bytes than its length.
    pub fn finish(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        self.writer.finish(outbound)?;
        self.after_write();
        Ok(())
    }

    /// Ends a chunked response body with a trailer section, which it writes into `region`.
    /// Refuses with [`Kind::Misuse`] when the body is not chunked: only a chunked body can carry
    /// trailers.
    pub fn finish_with_trailers(
        &mut self,
        outbound: &mut Outbound,
        trailers: &[Field<'_>],
        region: Backing,
    ) -> Result<(), Error> {
        self.writer.finish_with_trailers(outbound, trailers, region)?;
        self.after_write();
        Ok(())
    }

    /// Cancels the current response. The connection closes after the bytes that `outbound`
    /// holds, with no end of the body, so the client sees an incomplete response, never a
    /// complete one (RFC 9112, section 9). The turn becomes terminal with [`Kind::Cancelled`].
    pub fn cancel(&mut self) {
        self.writer.cancel();
        self.close = true;
        self.end = Some(Err(Error::new(Kind::Cancelled, "the response was cancelled")));
    }

    /// Starts the drain of the unread request body after a complete response, or ends the
    /// exchange.
    fn after_write(&mut self) {
        self.write = Write::Done;
        match &mut self.read {
            // The next drive gives the handoff, after the rest of the request.
            _ if self.request.switch => {}
            ReadState::Done => self.next(),
            ReadState::Body(reader) if self.close => {
                reader.drain(0);
                self.end = Some(Ok(()));
            }
            ReadState::Body(reader) => reader.drain(self.body.drain_bytes),
            ReadState::Head => {}
        }
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("read", &self.read)
            .field("write", &self.write)
            .field("close", &self.close)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// Writes a response head into `region` and queues it.
fn push_head(
    outbound: &mut Outbound,
    region: Backing,
    status: Status,
    fields: &[Field<'_>],
    framing: Framing,
    connection: Option<&[u8]>,
) -> Result<(), Error> {
    if outbound.free() == 0 {
        return Err(full());
    }
    let mut out = WriteLoan::new(region);
    write_response(&mut out, status, fields, framing, connection).map_err(write_error)?;
    outbound.push(Lease::from(out.into_inner())).map_err(|_| full())
}

/// The error response that a refusal names, with `connection: close` and no body.
const fn error_response(refusal: ParseError) -> &'static [u8] {
    match refusal {
        ParseError::HeadTooLarge | ParseError::TooManyFields | ParseError::FieldTooLarge => {
            b"HTTP/1.1 431 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
        }
        ParseError::Malformed | ParseError::Framing | ParseError::ExtensionTooLarge => {
            b"HTTP/1.1 400 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
        }
        ParseError::Version => b"HTTP/1.1 505 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
        ParseError::TransferCoding => b"HTTP/1.1 501 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
        ParseError::BodyTooLarge => b"HTTP/1.1 413 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
    }
}
