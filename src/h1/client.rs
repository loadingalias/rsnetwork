//! The client engine: one connection to an HTTP/1.1 or HTTP/1.0 server.

use core::fmt;

use rstypes::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rstypes::capacity::Budget;

use super::body::{BodyReader, BodyWriter, Read, full, misuse, write_error};
use super::head::{BodyLimits, Limits, ParseError};
use super::join::{Join, Step, join};
use super::write::write_request_head;
use super::{Framing, ResponseHead, ResponseParser, RetainedResponse};
use crate::body::Outcome;
use crate::drive::{Blocked, Error, Inbound, Kind, Outbound, Progress, Turn};
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
    write: Write,
    read: ReadState,
    /// The method of the request in flight, as the framing of its response needs it: HEAD,
    /// CONNECT, or GET for each other method.
    method: Method<'static>,
    /// The connection closes after the current exchange.
    close: bool,
    /// The request in flight asks to change the protocol.
    upgrade: bool,
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
    /// Makes the engine of one connection, for response heads within `limits` and bodies within
    /// `body`.
    ///
    /// It makes its pool of chunk-size lines here: one slot for each entry of `outbound`, charged
    /// to `budget`. Refuses with [`Kind::Overload`] when the budget or the memory refuses.
    pub fn new(limits: Limits, body: BodyLimits, outbound: &Outbound, budget: &Budget) -> Result<Self, Error> {
        Ok(Self {
            limits,
            body,
            parser: ResponseParser::new(limits),
            writer: BodyWriter::new(outbound, budget)?,
            budget: budget.clone(),
            join: None,
            capacity: None,
            write: Write::Idle,
            read: ReadState::Idle,
            method: Method::GET,
            close: false,
            upgrade: false,
            end: None,
        })
    }

    /// Writes a request head into `head`, and queues it. Then send the body with
    /// [`send`](Self::send), and end it with [`finish`](Self::finish), also when it has no body.
    ///
    /// The engine writes `authority` as the Host field, the first field line (RFC 9112, section
    /// 3.2): give the authority of the target URI. `framing` gives the body: `Length(n)` or
    /// `Chunked`. A request has no close framing. Refuses with [`Kind::Misuse`] while an exchange
    /// is in flight, after the connection ended, and when `fields` has a Host field.
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
        }
    }

    /// Cancels the read of the response. The engine reads and discards the rest of the body, up to
    /// [`BodyLimits::drain_bytes`], to reuse the connection, and closes it when the body is longer
    /// or ends only with the close. Before the response head, the connection closes at once, and
    /// the turn becomes terminal with [`Kind::Cancelled`].
    pub fn cancel_response(&mut self) {
        match &mut self.read {
            ReadState::Body(reader) if self.close || reader.left().is_some_and(|left| left > self.body.drain_bytes) => {
                self.end = Some(Ok(()));
            }
            ReadState::Body(reader) => reader.drain(self.body.drain_bytes),
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
                match (self.end, self.capacity.take()) {
                    (Some(end), _) => Progress::Terminal(end),
                    (None, Some(units)) => Progress::Blocked(Blocked::Capacity(units)),
                    (None, None) => Progress::Blocked(Blocked::Input),
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
                ReadState::Done => {
                    match self.write {
                        Write::Done if !self.close => {
                            self.write = Write::Idle;
                            self.read = ReadState::Idle;
                        }
                        Write::Done | Write::Cancelled => self.end = Some(Ok(())),
                        // The response came before the end of the request body.
                        Write::Body | Write::Idle => return Ok(None),
                    }
                    continue;
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
            let read = match reader.read(inbound, &self.budget) {
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
                Read::Data(_) | Read::Again => {}
                // A body that the close delimits is complete at the end of input.
                Read::End(trailers) => {
                    self.read = ReadState::Done;
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
            if let Some(head) = self.parser.parse(region.bytes(), self.method)? {
                let consumed = head.consumed();
                let event = self.accept(head, &region)?;
                inbound.consume(consumed).map_err(|_| ParseError::Malformed)?;
                return Ok(Some(event));
            }
        }
        let (parser, method) = (&mut self.parser, self.method);
        let step = join(&mut self.join, &self.budget, self.limits.head_bytes, inbound, |bytes| {
            Ok(parser.parse(bytes, method)?.map(|head| head.consumed()))
        })?;
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
