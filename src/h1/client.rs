//! The client engine: one connection to an HTTP/1.1 or HTTP/1.0 server.

use core::fmt;
use core::ops::Range;

use rstypes::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rstypes::capacity::Budget;

use super::body::{BodyReader, BodyWriter, Read, full, misuse, write_error};
use super::head::{BodyLimits, Limits, ParseError};
use super::join::{Join, Step, join};
use super::write::write_request_head;
use super::{Framing, ResponseHead, ResponseParser, RetainedResponse};
use crate::body::Outcome;
use crate::drive::{Blocked, Error, Inbound, Kind, Outbound, Progress, Turn, TurnLimits, Work};
use crate::value::{Authority, Field, Method, Target};

/// The client side of one HTTP/1.1 connection, with no I/O.
///
/// The application sends one request at a time with [`request`](Self::request),
/// [`send`](Self::send), and [`finish`](Self::finish), which push it into the host's
/// [`Outbound`] queue. In each drive, the engine reads the response in the host's [`Inbound`]
/// queue and gives one [`ClientEvent`]. After the response, the connection carries the next
/// request when the request and the response let it persist (RFC 9112, section 9.3).
///
/// As for the [`Server`](super::Server), the caller gives the region of each request head, and
/// the size lines of chunks come from a pool of the engine. The engine allocates after
/// [`new`](Self::new) only to join a response head or trailer section that continues in the next
/// region, and the budget pays for the join.
///
/// A response head with obsolete line folding gets one copy in a join, in which each folding
/// becomes SP before the engine reads the fields (RFC 9112, section 5.2). A head with no folding
/// has no copy. The [`ResponseParser`] itself refuses a folding, as the server does.
pub struct Client {
    limits: Limits,
    body: BodyLimits,
    parser: ResponseParser,
    writer: BodyWriter,
    /// The budget that pays for the pool and for each join.
    budget: Budget,
    /// The join of a response head that continues in the next region.
    join: Option<Join>,
    /// The capacity that a join waits for.
    capacity: Option<u64>,
    /// The limits of each turn.
    turn: TurnLimits,
    /// The last turn stopped at a limit, and work remains.
    more: bool,
    write: Write,
    read: ReadState,
    /// The method of the request in flight, as the framing of its response needs it: HEAD,
    /// CONNECT, or GET for each other method.
    method: Method<'static>,
    /// The connection closes after the current exchange.
    close: bool,
    /// The request in flight asks to change the protocol.
    upgrade: bool,
    /// The application cancelled the response body: the next drive gives its
    /// `End(Outcome::Cancelled)`.
    cancelled: bool,
    /// The end of the connection.
    end: Option<Result<(), Error>>,
}

/// An event of the client engine.
pub enum ClientEvent {
    /// An informational (1xx) response before the final response.
    Informational(RetainedResponse),
    /// The final response head. Its body follows as [`Data`](Self::Data), then
    /// [`End`](Self::End).
    Response(RetainedResponse),
    /// Bytes of the response body: a view of a received region, with no copy.
    Data(Lease),
    /// The end of the response body, with its outcome: complete with its trailers, truncated by
    /// the end of input inside a body with a length or chunks, or malformed. A body that the
    /// close delimits is complete at the end of input. After a truncated or malformed body, the
    /// next turn is terminal.
    End(Outcome),
    /// The connection changed its protocol after a 101 or a 2xx response to CONNECT, and the
    /// request ended. The front of the `Inbound` queue is exactly the bytes after the response
    /// head, and they belong to the new protocol, as each later byte does. The engine reads no
    /// more, and the next turn is terminal.
    Handoff,
}

impl fmt::Debug for ClientEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational(head) => f.debug_tuple("Informational").field(head).finish(),
            Self::Response(head) => f.debug_tuple("Response").field(head).finish(),
            Self::Data(data) => f.debug_struct("Data").field("len", &data.initialized()).finish(),
            Self::End(outcome) => f.debug_tuple("End").field(outcome).finish(),
            Self::Handoff => f.write_str("Handoff"),
        }
    }
}

/// The place of the engine in the current request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Write {
    /// No request is in flight.
    Idle,
    /// In the request body, which the body writer holds.
    Body,
    /// After the request.
    Done,
    /// The application cancelled the upload: the request has no end.
    Cancelled,
}

/// The place of the engine in the current response.
#[derive(Debug)]
enum ReadState {
    /// No request waits for a response.
    Idle,
    /// Before the final response head.
    Head,
    /// In the response body.
    Body(BodyReader),
    /// After a response that changed the protocol, until the end of the request.
    Switch,
    /// After the response.
    Done,
}

impl Client {
    /// Makes the engine of one connection, for response heads within `limits`, bodies within
    /// `body`, and drives within `turn`.
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
            parser: ResponseParser::new(limits),
            writer: BodyWriter::new(outbound, budget)?,
            budget: budget.clone(),
            join: None,
            capacity: None,
            turn,
            more: false,
            write: Write::Idle,
            read: ReadState::Idle,
            method: Method::GET,
            close: false,
            upgrade: false,
            cancelled: false,
            end: None,
        })
    }

    /// Writes a request head into `head`, and queues it. Then send the body with
    /// [`send`](Self::send), and end it with [`finish`](Self::finish), also when it has no body.
    ///
    /// The engine writes `authority` as the Host field, the first field line (RFC 9112, section
    /// 3.2): give the authority of the target URI. `framing` gives the body: `Length(n)` or
    /// `Chunked`. A request has no close framing. Refuses with [`Kind::Misuse`] while an exchange
    /// is in flight, after the connection ended, and when `fields` has a Host field. When the
    /// connection persists, the next request can follow at once, in answer to the end of the
    /// response.
    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is one independent fact of the request, and a struct of them would only repeat these parameters"
    )]
    pub fn request(
        &mut self,
        outbound: &mut Outbound,
        method: Method<'_>,
        target: Target<'_>,
        authority: Authority<'_>,
        fields: &[Field<'_>],
        framing: Framing,
        head: Backing,
    ) -> Result<(), Error> {
        if self.end.is_some() || self.write != Write::Idle || !matches!(self.read, ReadState::Idle) {
            return Err(misuse("a request needs an idle connection"));
        }
        if fields.iter().any(|field| field.name.eq_ignore_ascii_case(b"host")) {
            return Err(misuse("the engine writes the Host field from the authority"));
        }
        if outbound.free() == 0 {
            return Err(full());
        }
        let host = Field {
            name: b"host",
            value: authority.as_bytes(),
        };
        let mut out = WriteLoan::new(head);
        write_request_head(&mut out, method, target, Some(host), fields, framing).map_err(write_error)?;
        outbound.push(Lease::from(out.into_inner())).map_err(|_| full())?;
        self.method = if method == Method::HEAD {
            Method::HEAD
        } else if method == Method::CONNECT {
            Method::CONNECT
        } else {
            Method::GET
        };
        let option = |known: &[u8]| {
            fields.iter().any(|field| {
                field.name.eq_ignore_ascii_case(b"connection")
                    && field
                        .value
                        .split(|&byte| byte == b',')
                        .any(|option| option.trim_ascii().eq_ignore_ascii_case(known))
            })
        };
        self.close = option(b"close");
        self.upgrade = option(b"upgrade") && fields.iter().any(|field| field.name.eq_ignore_ascii_case(b"upgrade"));
        self.writer.open(framing);
        self.write = Write::Body;
        self.read = ReadState::Head;
        Ok(())
    }

    /// Queues `data` as the next bytes of the request body, with no copy, as
    /// [`Server::send`](super::Server::send) does for a response.
    pub fn send(&mut self, outbound: &mut Outbound, data: &Lease) -> Result<(), Error> {
        self.writer.send(outbound, data)
    }

    /// Ends the request body. A chunked body gets its last chunk.
    pub fn finish(&mut self, outbound: &mut Outbound) -> Result<(), Error> {
        self.writer.finish(outbound)?;
        self.write = Write::Done;
        self.settle();
        Ok(())
    }

    /// Ends a chunked request body with a trailer section, which it writes into `region`.
    pub fn finish_with_trailers(
        &mut self,
        outbound: &mut Outbound,
        trailers: &[Field<'_>],
        region: Backing,
    ) -> Result<(), Error> {
        self.writer.finish_with_trailers(outbound, trailers, region)?;
        self.write = Write::Done;
        self.settle();
        Ok(())
    }

    /// Cancels the upload of the request body, for example after the server answered before the
    /// end of the body. The engine sends no more body bytes and no end of the body, so the server
    /// never sees a complete request. The response can still arrive, and then the connection
    /// closes, because the request has no end (RFC 9112, section 9).
    pub fn cancel_upload(&mut self) {
        if self.write == Write::Body {
            self.writer.cancel();
            self.write = Write::Cancelled;
            self.close = true;
            self.settle();
        }
    }

    /// Ends the exchange when its request and its response are both complete: the connection
    /// carries the next request, or it closes (RFC 9112, section 9.3). Thus the application can
    /// send the next request in answer to the end of the response.
    fn settle(&mut self) {
        if !matches!(self.read, ReadState::Done) {
            return;
        }
        match self.write {
            Write::Done if !self.close => {
                self.write = Write::Idle;
                self.read = ReadState::Idle;
            }
            Write::Done | Write::Cancelled => self.end = Some(Ok(())),
            // The response came before the end of the request body.
            Write::Body | Write::Idle => {}
        }
    }

    /// Cancels the read of the response. Inside the body, the next drive gives
    /// [`End(Outcome::Cancelled)`](ClientEvent::End), once, and no more of the body. The engine then
    /// reads and discards the rest of the body, up to [`BodyLimits::drain_bytes`], to reuse the
    /// connection, and closes it when the body is longer or ends only with the close. Before the
    /// response head, the connection closes at once, and the turn becomes terminal with
    /// [`Kind::Cancelled`].
    pub fn cancel_response(&mut self) {
        match &mut self.read {
            // A body that the application cancelled ends `Cancelled`, so its reader sees its end.
            ReadState::Body(reader) if reader.draining() || self.end.is_some() => {}
            ReadState::Body(reader) => {
                self.cancelled = true;
                if self.close || reader.left().is_some_and(|left| left > self.body.drain_bytes) {
                    self.end = Some(Ok(()));
                } else {
                    reader.drain(self.body.drain_bytes);
                }
            }
            ReadState::Head => self.end = Some(Err(Error::new(Kind::Cancelled, "the response was cancelled"))),
            ReadState::Idle | ReadState::Switch | ReadState::Done => {}
        }
    }

    /// Reads the response in `inbound`, and gives the next event and the [`Turn`].
    ///
    /// Drive again after each event, and after more bytes arrive or the application acts. When
    /// the turn is terminal, the connection is at its end: send the rest of `outbound`, and then
    /// close it.
    pub fn drive(&mut self, inbound: &mut Inbound) -> (Option<ClientEvent>, Turn) {
        let (event, progress) = match self.step(inbound) {
            Ok(Some(event)) => (Some(event), Progress::Pending),
            Ok(None) => (
                None,
                match (self.end, self.capacity.take(), core::mem::take(&mut self.more)) {
                    (Some(end), _, _) => Progress::Terminal(end),
                    (None, Some(units), _) => Progress::Blocked(Blocked::Capacity(units)),
                    (None, None, true) => Progress::Pending,
                    (None, None, false) => Progress::Blocked(Blocked::Input),
                },
            ),
            Err(refusal) => {
                let error = Error::from(refusal);
                self.end = Some(Err(error));
                (None, Progress::Terminal(Err(error)))
            }
        };
        (
            event,
            Turn {
                progress,
                deadline: None,
            },
        )
    }

    /// Reads the next event from `inbound`, or gives `None` when the engine waits.
    fn step(&mut self, inbound: &mut Inbound) -> Result<Option<ClientEvent>, ParseError> {
        let mut work = Work::default();
        if core::mem::take(&mut self.cancelled) {
            return Ok(Some(ClientEvent::End(Outcome::Cancelled)));
        }
        loop {
            if self.end.is_some() {
                return Ok(None);
            }
            let reader = match &mut self.read {
                ReadState::Idle => {
                    // Bytes with no request in flight make each later response unclear, for
                    // example a 408 that the server sent before it closed.
                    if inbound.front().is_some() {
                        self.end = Some(Err(Error::new(
                            Kind::Malformed,
                            "the server sent bytes with no request",
                        )));
                    } else if inbound.ended() {
                        self.end = Some(Ok(()));
                    }
                    return Ok(None);
                }
                ReadState::Head => return self.head(inbound),
                // The response came before the end of the request body, which ends the exchange.
                ReadState::Done => {
                    self.refuse_bytes_after(inbound);
                    return Ok(None);
                }
                // The new protocol starts after the end of the request.
                ReadState::Switch if self.write == Write::Done => {
                    self.end = Some(Ok(()));
                    return Ok(Some(ClientEvent::Handoff));
                }
                ReadState::Switch => return Ok(None),
                ReadState::Body(reader) => reader,
            };
            let draining = reader.draining();
            let read = match reader.read(inbound, &self.budget, &mut work) {
                Ok(read) => read,
                // A body that breaks its framing ends as malformed, and then the connection ends.
                Err(refusal) => {
                    self.read = ReadState::Done;
                    self.end = Some(Err(Error::from(refusal)));
                    return Ok((!draining).then_some(ClientEvent::End(Outcome::Malformed)));
                }
            };
            match read {
                Read::Data(data) if !draining => return Ok(Some(ClientEvent::Data(data))),
                // A turn stops at its limits between two steps, and the next turn goes on.
                Read::Data(_) | Read::Again if work.reached(&self.turn) => {
                    self.more = true;
                    return Ok(None);
                }
                Read::Data(_) | Read::Again => {}
                // A body that the close delimits is complete at the end of input.
                Read::End(trailers) => {
                    self.read = ReadState::Done;
                    if !self.refuse_bytes_after(inbound) {
                        self.settle();
                    }
                    if !draining {
                        return Ok(Some(ClientEvent::End(Outcome::Complete(trailers))));
                    }
                }
                Read::Wait => return Ok(None),
                Read::Overdrawn => self.end = Some(Ok(())),
                Read::Truncated => {
                    self.end = Some(Err(Error::new(Kind::Partial, "the response body ended before its end")));
                    if !draining {
                        return Ok(Some(ClientEvent::End(Outcome::Truncated)));
                    }
                }
                Read::Capacity(units) => {
                    self.capacity = Some(units);
                    return Ok(None);
                }
            }
        }
    }

    /// Ends the connection with [`Kind::Malformed`] when `inbound` holds bytes after a complete
    /// response of a connection that persists, and gives whether it did. The bytes arrived before
    /// the next request existed, so they cannot be its response. For example, a body that a server
    /// sent after a response to HEAD would otherwise become the response to the next request. A
    /// connection that closes after the response reads no more bytes, so they change nothing.
    fn refuse_bytes_after(&mut self, inbound: &Inbound) -> bool {
        let after = !self.close && inbound.front().is_some();
        if after {
            self.end = Some(Err(Error::new(Kind::Malformed, "bytes after the response")));
        }
        after
    }

    /// Reads a response head from `inbound`.
    fn head(&mut self, inbound: &mut Inbound) -> Result<Option<ClientEvent>, ParseError> {
        if inbound.front().is_none() && self.join.is_none() && inbound.ended() {
            // The server may have processed the request before it closed.
            self.end = Some(Err(Error::new(
                Kind::Uncertain,
                "the connection closed before the response",
            )));
            return Ok(None);
        }
        if self.join.is_none() {
            let Some(front) = inbound.front() else { return Ok(None) };
            let region = front.region.clone();
            match self.parser.parse(region.bytes(), self.method) {
                Ok(Some(head)) => {
                    let consumed = head.consumed();
                    let event = self.accept(head, &region)?;
                    inbound.consume(consumed).map_err(|_| ParseError::Malformed)?;
                    return Ok(Some(event));
                }
                // A head with obsolete line folding gets a copy in the join, which unfolds it.
                Err(ParseError::Malformed) if folded(region.bytes()) => {}
                Ok(None) => {}
                Err(refusal) => return Err(refusal),
            }
        }
        let (parser, method) = (&mut self.parser, self.method);
        let step = join(
            &mut self.join,
            &self.budget,
            self.limits.head_bytes,
            inbound,
            |bytes| match parser.parse(bytes, method).map(|head| head.map(|head| head.consumed())) {
                Err(ParseError::Malformed) if unfold(bytes) => {
                    Ok(parser.parse(bytes, method)?.map(|head| head.consumed()))
                }
                parsed => parsed,
            },
        )?;
        let region = match step {
            Step::Complete(region) => region,
            Step::Wait if inbound.ended() => {
                self.end = Some(Err(Error::new(
                    Kind::Uncertain,
                    "the connection closed in the response head",
                )));
                return Ok(None);
            }
            Step::Wait => return Ok(None),
            Step::Capacity(units) => {
                self.capacity = Some(units);
                return Ok(None);
            }
        };
        let Some(head) = self.parser.parse(region.bytes(), self.method)? else {
            return Err(ParseError::Malformed);
        };
        self.accept(head, &region).map(Some)
    }

    /// Takes the response of a complete `head` in `region`.
    fn accept(&mut self, head: ResponseHead<'_>, region: &Lease) -> Result<ClientEvent, ParseError> {
        let Some(retained) = head.retain(region) else {
            return Err(ParseError::Malformed);
        };
        let code = head.status().code();
        let framing = head.framing();
        // A server switches only to a protocol that the request asked for (RFC 9110, section
        // 7.8). A 2xx response to CONNECT starts a tunnel (section 9.3.6).
        if (code == 101 && self.upgrade) || (self.method == Method::CONNECT && (200..300).contains(&code)) {
            self.read = ReadState::Switch;
            return Ok(ClientEvent::Response(retained));
        }
        if code == 101 {
            return Err(ParseError::Malformed);
        }
        if code < 200 {
            return Ok(ClientEvent::Informational(retained));
        }
        if let Framing::Length(length) = framing
            && length > self.body.body_bytes
        {
            return Err(ParseError::BodyTooLarge);
        }
        self.close |= !head.persistent();
        self.read = ReadState::Body(BodyReader::new(framing, self.body, self.limits));
        Ok(ClientEvent::Response(retained))
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("write", &self.write)
            .field("read", &self.read)
            .field("close", &self.close)
            .field("end", &self.end)
            .finish_non_exhaustive()
    }
}

/// The positions of the field lines of the complete head at the start of `bytes`, from the start
/// of the first field line to the empty line, or `None` while the head is not complete.
fn field_lines(bytes: &[u8]) -> Option<Range<usize>> {
    let end = bytes.array_windows().position(|window| window == b"\r\n\r\n")?;
    let start = bytes.array_windows().position(|window| window == b"\r\n")? + 2;
    Some(start.min(end)..end)
}

/// Whether an obsolete line folding starts at `at`: the CR LF of a field line before SP or HTAB
/// (RFC 9112, section 5.2).
fn fold_at(bytes: &[u8], at: usize) -> bool {
    bytes[at..].starts_with(b"\r\n") && matches!(bytes.get(at + 2), Some(b' ' | b'\t'))
}

/// Whether the complete head at the start of `bytes` has an obsolete line folding. Whitespace
/// right after the start line is not a folding, and it stays an error (RFC 9112, section 2.2).
fn folded(bytes: &[u8]) -> bool {
    field_lines(bytes).is_some_and(|mut lines| lines.any(|at| fold_at(bytes, at)))
}

/// Replaces each obsolete line folding of the complete head at the start of `bytes` with SP: its
/// CR LF and the SP or HTAB after it. A user agent does this before it reads a field value (RFC
/// 9112, section 5.2). The head keeps its length. Gives whether the head had a folding.
fn unfold(bytes: &mut [u8]) -> bool {
    let Some(lines) = field_lines(bytes) else { return false };
    let mut found = false;
    for at in lines {
        if fold_at(bytes, at) {
            found = true;
            let blank = bytes[at + 2..]
                .iter()
                .take_while(|&&byte| byte == b' ' || byte == b'\t')
                .count();
            bytes[at..at + 2 + blank].fill(b' ');
        }
    }
    found
}
