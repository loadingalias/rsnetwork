//! The server engine: one connection, for HTTP/1.1 and HTTP/1.0 clients.

use core::fmt;

use rstypes::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rstypes::capacity::Budget;

use super::body::{BodyReader, BodyWriter, Read, Trailers, full, misuse, write_error};
use super::head::{BodyLimits, Limits, ParseError, Version};
use super::write::write_response;
use super::{Framing, RequestParser, RetainedRequest};
use crate::drive::{Blocked, Error, Inbound, Kind, Outbound, Progress, Turn};
use crate::value::{Field, Method, Status};

/// The server side of one HTTP/1.1 connection, with no I/O.
///
/// In each drive, the engine reads the requests in the host's [`Inbound`] queue and gives one
/// [`ServerEvent`]. The application answers each request with [`respond`](Self::respond),
/// [`send`](Self::send), and [`finish`](Self::finish), which push the response into the host's
/// [`Outbound`] queue. Responses go in the order of the requests: the engine reads a pipelined
/// request only after the response before it is complete.
///
/// The engine allocates nothing after [`new`](Self::new). The caller gives the region of each
/// response head. The size line of each chunk comes from a pool that the engine makes at
/// construction, with one slot of 16 bytes for each entry of the output queue, charged to the
/// caller's budget. A slot returns to the pool when the last view of its line drops.
pub struct Server {
    limits: Limits,
    body: BodyLimits,
    parser: RequestParser,
    writer: BodyWriter,
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
    /// The end of the request body, with its trailer section if it has trailers.
    End(Option<Trailers>),
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
            Self::End(trailers) => f.debug_tuple("End").field(trailers).finish(),
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
    /// Makes the engine of one connection, for heads within `limits` and bodies within `body`.
    ///
    /// It makes its pool of chunk-size lines here: one slot for each entry of `outbound`, charged
    /// to `budget`. Refuses with [`Kind::Overload`] when the budget or the memory refuses.
    pub fn new(limits: Limits, body: BodyLimits, outbound: &Outbound, budget: &Budget) -> Result<Self, Error> {
        Ok(Self {
            limits,
            body,
            parser: RequestParser::new(limits),
            writer: BodyWriter::new(outbound, budget)?,
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
    /// head was out.
    pub fn drive(&mut self, inbound: &mut Inbound, outbound: &mut Outbound) -> (Option<ServerEvent>, Turn) {
        let (event, progress) = match self.step(inbound) {
            Ok(Some(event)) => (Some(event), Progress::Pending),
            Ok(None) => (None, self.progress()),
            Err(refusal) => (None, self.refuse(refusal, outbound)),
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
    fn step(&mut self, inbound: &mut Inbound) -> Result<Option<ServerEvent>, ParseError> {
        loop {
            if self.end.is_some() {
                return Ok(None);
            }
            let reader = match &mut self.read {
                // A pipelined request waits for the response before it.
                ReadState::Head if self.write != Write::Idle => return Ok(None),
                ReadState::Head if inbound.front().is_none() && inbound.ended() => {
                    self.end = Some(Ok(()));
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
            match reader.read(inbound)? {
                Read::Data(data) if !draining => return Ok(Some(ServerEvent::Data(data))),
                Read::Data(_) | Read::Again => {}
                Read::End(trailers) => {
                    self.read = ReadState::Done;
                    if !draining {
                        return Ok(Some(ServerEvent::End(trailers)));
                    }
                }
                Read::Wait => return Ok(None),
                Read::Overdrawn => self.end = Some(Ok(())),
                Read::Truncated => {
                    self.end = Some(Err(Error::new(Kind::Partial, "the request body ended before its end")));
                }
            }
        }
    }

    /// Reads a request head from `inbound`.
    fn head(&mut self, inbound: &mut Inbound) -> Result<Option<ServerEvent>, ParseError> {
        let Some(front) = inbound.front() else { return Ok(None) };
        let region = front.region.clone();
        // A head that continues in the next region waits for more bytes.
        let Some(head) = self.parser.parse(region.bytes())? else {
            return Ok(None);
        };
        let framing = head.framing();
        if let Framing::Length(length) = framing
            && length > self.body.body_bytes
        {
            return Err(ParseError::BodyTooLarge);
        }
        let Some(retained) = head.retain(&region) else {
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
        // A request has no close framing.
        if framing == Framing::Close {
            return Err(ParseError::Framing);
        }
        self.read = ReadState::Body(BodyReader::new(framing, self.body, self.limits));
        self.write = Write::Waiting;
        inbound.consume(head.consumed()).map_err(|_| ParseError::Malformed)?;
        Ok(Some(ServerEvent::Request(retained)))
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
    fn progress(&self) -> Progress {
        match self.end {
            Some(end) => Progress::Terminal(end),
            None => Progress::Blocked(Blocked::Input),
        }
    }

    /// Ends the connection after a refusal. When no response head is out, it queues the error
    /// response that the refusal names.
    fn refuse(&mut self, refusal: ParseError, outbound: &mut Outbound) -> Progress {
        if matches!(self.write, Write::Idle | Write::Waiting) {
            // A full queue drops the error response: the close still ends the connection.
            drop(outbound.push(Lease::from(error_response(refusal))));
        }
        let error = Error::from(refusal);
        self.end = Some(Err(error));
        Progress::Terminal(Err(error))
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
