//! The exchanges of a server connection on HTTP/2: many streams at a time.
//!
//! Each stream that the engine carries has one entry, from its request until the handler closed
//! it and the engine freed its slot. Thus the entries never pass `SETTINGS_MAX_CONCURRENT_STREAMS`:
//! the engine reads no new stream while each slot is in use ([`Blocked::Streams`]).
//!
//! [`Blocked::Streams`]: crate::drive::Blocked::Streams

use core::alloc::Layout;
use core::time::Duration;

use rstypes::buffer::{Buffer as _, BufferMut, Lease, WriteLoan};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::{Deadline, Instant};

use super::{Delivery, Exchanges, Http, Limits, Protocol, Response, misuse, not_open};
use crate::body::{Collect, Outcome, Part, Read, Trailers};
use crate::drive::{Error, Kind, Outbound};
use crate::h1;
use crate::h2::frame::ErrorCode;
use crate::h2::message::{self, Refusal};
use crate::h2::session::{Inflow, Session, Step};
use crate::hpack::FieldLine;
use crate::message::{RequestHead, Stream};
use crate::value::{Field, Method, Status};

/// Where the request of a stream is.
#[derive(Debug)]
enum Stage {
    /// It waits for [`Http::request`].
    Fresh(RequestHead),
    /// The application has it.
    Given,
    /// The server resets the stream with this code before it goes up.
    Refused(ErrorCode),
    /// The server answers with this status and no body before it goes up: 413 or 431.
    Answer(Status),
}

/// The response of a stream.
#[derive(Clone, Copy, Debug)]
struct Out {
    /// The length of the body: `Some(0)` for a response with no body.
    length: Option<u64>,
    written: u64,
    /// A chunk of the body waits for its `Event::Sent`.
    chunk: bool,
    /// The application finished the response.
    finished: bool,
    /// The frame that ends the stream is in the output queue. After a `finish` while a chunk
    /// waits, it goes after the `Event::Sent` of the chunk.
    ended: bool,
    /// The body bytes of the DATA frames that the transport accepted whole.
    accepted: u64,
    /// The body bytes that the transport accepted of the first DATA frame that it did not accept
    /// whole.
    partial: u64,
    /// The transport accepted the frame that ends the stream.
    complete: bool,
    error: Option<Error>,
}

/// One stream of the connection.
#[derive(Debug)]
struct Exchange {
    id: u32,
    stage: Stage,
    inflow: Inflow,
    /// The `content-length` of the request.
    declared: Option<u64>,
    /// The request is HEAD: its response has no body.
    head: bool,
    connect: bool,
    out: Option<Out>,
    /// A reset of the server that waits for room in the output queue.
    reset: Option<ErrorCode>,
    /// The stream ended in the engine: both sides ended, or a reset.
    ended: bool,
    /// The handler closed the stream.
    closed: bool,
    /// The stream changed since the last [`Http::changed`].
    changed: bool,
}

impl Exchange {
    fn new(id: u32, stage: Stage) -> Self {
        Self {
            id,
            stage,
            inflow: Inflow::default(),
            declared: None,
            head: false,
            connect: false,
            out: None,
            reset: None,
            ended: false,
            closed: false,
            changed: true,
        }
    }

    /// Ends the request body with `outcome`, and the response with `error` when the transport
    /// has not accepted each of its bytes.
    fn end(&mut self, outcome: Outcome, error: Error) {
        self.inflow.end(outcome);
        if let Some(out) = &mut self.out
            && !(out.finished && out.complete)
        {
            out.error.get_or_insert(error);
        }
    }

    /// Ends the stream with a reset of the server with `code`, and the request body with
    /// `outcome`.
    fn refuse(&mut self, code: ErrorCode, outcome: Outcome) {
        if !self.ended {
            self.reset.get_or_insert(code);
        }
        self.end(
            outcome,
            Error::new(
                Kind::Partial,
                "the server reset the stream before the end of the response",
            ),
        );
    }
}

/// The streams of an HTTP/2 connection.
#[derive(Debug)]
pub(super) struct H2 {
    /// In the order of their requests.
    exchanges: Vec<Exchange>,
    _charge: Permit,
    /// The deadline of the connection while it has no stream.
    pub(super) idle: Option<Deadline>,
    timeout: Option<Duration>,
    /// The GOAWAY of a shutdown waits for room in the output queue.
    goaway: bool,
    body_bytes: u64,
}

impl H2 {
    /// Makes the table of the streams: one entry for each of `max_concurrent_streams`, charged to
    /// `budget`.
    pub(super) fn new(limits: &Limits, budget: &Budget) -> Result<Self, Error> {
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
            exchanges,
            _charge: charge,
            idle: None,
            timeout: limits.head_timeout,
            goaway: false,
            body_bytes: limits.body.body_bytes,
        })
    }

    /// Gives each stream that changed since the last call, as [`Http::changed`] says.
    pub(super) fn changed(&mut self, mut each: impl FnMut(Stream)) {
        for exchange in &mut self.exchanges {
            if core::mem::take(&mut exchange.changed) {
                each(Stream(u64::from(exchange.id)));
            }
        }
    }

    fn find(&self, stream: Stream) -> Option<usize> {
        self.exchanges
            .iter()
            .position(|exchange| u64::from(exchange.id) == stream.0)
    }

    /// The stream that the application has.
    fn given(&mut self, stream: Stream) -> Result<&mut Exchange, Error> {
        let index = self.find(stream).ok_or_else(not_open)?;
        let exchange = &mut self.exchanges[index];
        if !matches!(exchange.stage, Stage::Given) || exchange.closed {
            return Err(not_open());
        }
        Ok(exchange)
    }

    pub(super) fn read_into<B: BufferMut>(
        &mut self,
        stream: Stream,
        region: &mut WriteLoan<B>,
    ) -> Result<Read<'_>, Error> {
        Ok(self.given(stream)?.inflow.consumer().read_into(region))
    }

    pub(super) fn next(&mut self, stream: Stream) -> Result<Option<Part>, Error> {
        let consumer = self.given(stream)?.inflow.consumer();
        Ok(match consumer.take() {
            Some(data) => Some(Part::Data(data)),
            None => consumer.outcome().cloned().map(Part::End),
        })
    }

    pub(super) fn collect<B: BufferMut>(
        &mut self,
        stream: Stream,
        region: &mut WriteLoan<B>,
    ) -> Result<Collect, Error> {
        let consumer = self.given(stream)?.inflow.consumer();
        if consumer.wants_data() {
            return Ok(Collect::More);
        }
        Ok(consumer.collect(region))
    }

    /// Whether the body of `stream` has no part and no end for a read.
    pub(super) fn body_waits(&self, stream: Stream) -> bool {
        self.find(stream)
            .is_some_and(|index| self.exchanges[index].inflow.waits())
    }

    pub(super) fn delivery(&self, stream: Stream) -> Option<Delivery> {
        let exchange = &self.exchanges[self.find(stream)?];
        let out = exchange.out?;
        let accepted = out.accepted + out.partial;
        Some(match out.error {
            Some(error) => Delivery::Partial {
                finished: out.finished,
                accepted,
                error,
            },
            None if out.finished && out.complete => Delivery::Complete { accepted },
            None => Delivery::Sending {
                finished: out.finished,
                accepted,
            },
        })
    }

    /// Whether a request waits for [`Http::request`].
    pub(super) fn ready(&self) -> bool {
        self.exchanges
            .iter()
            .any(|exchange| matches!(exchange.stage, Stage::Fresh(_)))
    }

    /// Whether a stream of the application has a body or a response in flight.
    pub(super) fn busy(&self) -> bool {
        self.exchanges.iter().any(|exchange| {
            matches!(exchange.stage, Stage::Given)
                && (!exchange.inflow.ended() || exchange.out.is_none_or(|out| !(out.finished && out.complete)))
        })
    }

    /// Records `error` as the end of each response that the transport has not accepted.
    pub(super) fn fail(&mut self, error: Error) {
        for exchange in &mut self.exchanges {
            if let Some(out) = &mut exchange.out
                && !(out.finished && out.complete)
            {
                out.error.get_or_insert(error);
            }
        }
    }

    /// The transport failed: each body in flight ends reset.
    pub(super) fn reset_bodies(&mut self) {
        for exchange in &mut self.exchanges {
            exchange.inflow.end(Outcome::Reset(None));
            exchange.ended = true;
        }
    }
}

impl Http {
    #[expect(
        clippy::unreachable,
        reason = "`Http` calls the HTTP/2 streams only when its exchanges are `Exchanges::H2`"
    )]
    fn h2(&mut self) -> &mut H2 {
        match &mut self.exchanges {
            Exchanges::H2(h2) => h2,
            _ => unreachable!("an HTTP/2 call comes only on an HTTP/2 connection"),
        }
    }

    /// The engine and the plaintext output queue.
    #[expect(
        clippy::unreachable,
        reason = "`Exchanges::H2` and `Protocol::H2` start together, at the construction or at the selection"
    )]
    fn h2_parts(&mut self) -> (&mut Session, &mut Outbound) {
        match self.link.engine() {
            (Protocol::H2(session), outbound) => (session, outbound),
            _ => unreachable!("the HTTP/2 streams run on the HTTP/2 engine"),
        }
    }

    /// Whether the engine ended, so it takes no more calls.
    fn h2_engine_live(&self) -> bool {
        !matches!(self.link.wait(), crate::host::Wait::Ended(_))
    }

    /// Gives the first request that waits. After a shutdown, each request that waits is refused
    /// with `REFUSED_STREAM`, so the client can send it again.
    pub(super) fn h2_next(&mut self) -> Option<(Stream, RequestHead)> {
        let shutdown = self.shutdown.is_some();
        let h2 = self.h2();
        for exchange in &mut h2.exchanges {
            if !matches!(exchange.stage, Stage::Fresh(_)) {
                continue;
            }
            if shutdown {
                exchange.stage = Stage::Refused(ErrorCode::REFUSED_STREAM);
                exchange.refuse(ErrorCode::REFUSED_STREAM, Outcome::Cancelled);
                continue;
            }
            let Stage::Fresh(head) = core::mem::replace(&mut exchange.stage, Stage::Given) else {
                continue;
            };
            return Some((Stream(u64::from(exchange.id)), head));
        }
        None
    }

    /// Gives the next queued part of the body of `stream` to its consumer.
    pub(super) fn h2_feed(&mut self, stream: Stream) -> Result<(), Error> {
        self.h2().given(stream)?.inflow.feed();
        Ok(())
    }

    /// The work of the streams before each drive: the credit of the bytes that the application
    /// read, the resets and answers of the server, the end of each stream that its handler closed,
    /// and the GOAWAY of a shutdown. A call that finds no room in the output queue waits for the
    /// next drive.
    pub(super) fn h2_before_drive(&mut self) -> Result<(), Error> {
        if !self.h2_engine_live() {
            return Ok(());
        }
        let mut index = 0;
        while index < self.h2().exchanges.len() {
            match self.h2_settle(index)? {
                Settled::Kept => index += 1,
                Settled::Removed => {}
                Settled::Full => return Ok(()),
            }
        }
        if self.h2().goaway {
            let (session, outbound) = self.h2_parts();
            match session.connection().shutdown(outbound) {
                Ok(()) => self.h2().goaway = false,
                Err(error) if error.kind() == Kind::Overload => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// The work of the stream at `index` before a drive.
    fn h2_settle(&mut self, index: usize) -> Result<Settled, Error> {
        let budget_room = |error: Error| {
            if error.kind() == Kind::Overload {
                Ok(Settled::Full)
            } else {
                Err(error)
            }
        };
        // The credit of the bytes that the application read goes back to the peer.
        let exchange = &mut self.h2().exchanges[index];
        let id = exchange.id;
        let credit = exchange.inflow.take_credit();
        if credit > 0 {
            let (session, outbound) = self.h2_parts();
            if let Err(error) = session.connection().release(outbound, id, credit) {
                self.h2().exchanges[index].inflow.untake_credit(credit);
                return budget_room(error);
            }
        }
        // The frame that ends a finished response goes after its last chunk.
        if self.h2_end(index)? {
            return Ok(Settled::Full);
        }
        // A handler that closed a stream before its response ended cancels it.
        let exchange = &mut self.h2().exchanges[index];
        if exchange.closed
            && matches!(exchange.stage, Stage::Given)
            && !exchange.ended
            && exchange.out.is_none_or(|out| !out.finished)
        {
            exchange.refuse(ErrorCode::CANCEL, Outcome::Cancelled);
        }
        // A finished response of a closed stream ends the request too (RFC 9113, section 8.1).
        let exchange = &mut self.h2().exchanges[index];
        if exchange.closed && exchange.reset.is_none() && !exchange.ended && exchange.out.is_some_and(|out| out.ended) {
            exchange.reset = Some(ErrorCode::NO_ERROR);
        }
        if let Stage::Answer(status) = self.h2().exchanges[index].stage {
            match self.h2_answer(index, status)? {
                Settled::Kept => {}
                settled => return Ok(settled),
            }
        }
        if let Some(code) = self.h2().exchanges[index].reset {
            let (session, outbound) = self.h2_parts();
            let connection = session.connection();
            let result = if !connection.is_open(id) {
                Ok(())
            } else if code == ErrorCode::REFUSED_STREAM {
                connection.refuse(outbound, id)
            } else {
                connection.reset(outbound, id, code)
            };
            if let Err(error) = result {
                return budget_room(error);
            }
            let exchange = &mut self.h2().exchanges[index];
            exchange.reset = None;
            exchange.ended = true;
        }
        // A stream whose sides both ended holds its slot in the engine until the close.
        let (session, _) = self.h2_parts();
        let open = session.connection().is_open(id);
        let exchange = &mut self.h2().exchanges[index];
        exchange.ended |= !open;
        let done = match exchange.stage {
            Stage::Refused(_) => exchange.ended,
            Stage::Given => exchange.closed && exchange.ended,
            Stage::Fresh(_) | Stage::Answer(_) => false,
        };
        if !done {
            return Ok(Settled::Kept);
        }
        // The stream ends: the credit of each byte that the application did not read goes back,
        // and its slot is free.
        let rest = exchange.inflow.drop_rest();
        let (session, outbound) = self.h2_parts();
        let connection = session.connection();
        if rest > 0
            && let Err(error) = connection.release(outbound, id, rest)
        {
            self.h2().exchanges[index].inflow.untake_credit(rest);
            return budget_room(error);
        }
        if connection.is_held(id) {
            connection.close(id)?;
        }
        self.h2().exchanges.remove(index);
        Ok(Settled::Removed)
    }

    /// Answers the request of the stream at `index` with `status` and no body, and then resets
    /// a request that still sends with `NO_ERROR`.
    fn h2_answer(&mut self, index: usize, status: Status) -> Result<Settled, Error> {
        let Ok(region) = self.heads.acquire() else {
            return Ok(Settled::Full);
        };
        let id = self.h2().exchanges[index].id;
        let mut digits = [0; 20];
        let code = h1::digits(u64::from(status.code()), 10, &mut digits);
        let line = FieldLine {
            name: b":status",
            value: code,
            never_indexed: false,
        };
        let (session, outbound) = self.h2_parts();
        match session
            .connection()
            .headers(outbound, id, [line].into_iter(), true, region)
        {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(Settled::Full),
            Err(error) => return Err(error),
        }
        let exchange = &mut self.h2().exchanges[index];
        exchange.stage = Stage::Refused(ErrorCode::NO_ERROR);
        exchange.reset = Some(ErrorCode::NO_ERROR);
        Ok(Settled::Kept)
    }

    pub(super) fn h2_event(&mut self, step: Step) -> Result<(), Error> {
        if let Step::Trailers { stream, .. }
        | Step::Data { stream, .. }
        | Step::Reset { stream, .. }
        | Step::Sent { stream }
        | Step::TooLarge { stream } = step
            && let Some(index) = self.h2().find(Stream(u64::from(stream)))
        {
            self.h2().exchanges[index].changed = true;
        }
        let shutdown = self.shutdown.is_some();
        let budget = self.budget.clone();
        let h2 = self.h2();
        let body_bytes = h2.body_bytes;
        match step {
            Step::Request {
                stream,
                end_stream,
                head,
            } => {
                let mut exchange = Exchange::new(stream, Stage::Given);
                exchange.stage = match head {
                    _ if shutdown => Stage::Refused(ErrorCode::REFUSED_STREAM),
                    Err(Refusal::Malformed) => Stage::Refused(ErrorCode::PROTOCOL_ERROR),
                    Err(Refusal::Capacity) => Stage::Refused(ErrorCode::REFUSED_STREAM),
                    Ok(head) if head.length().is_some_and(|length| length > body_bytes) => Stage::Answer(Status(413)),
                    Ok(head) if end_stream && head.length().is_some_and(|length| length != 0) => {
                        Stage::Refused(ErrorCode::PROTOCOL_ERROR)
                    }
                    Ok(head) => {
                        exchange.declared = head.length();
                        exchange.head = head.method() == Method::HEAD;
                        exchange.connect = head.method() == Method::CONNECT;
                        Stage::Fresh(RequestHead::h2_form(head))
                    }
                };
                match exchange.stage {
                    Stage::Refused(code) => exchange.refuse(code, Outcome::Cancelled),
                    Stage::Fresh(_) if end_stream => exchange.inflow.end(Outcome::Complete(None)),
                    _ => {}
                }
                assert!(
                    h2.exchanges.len() < h2.exchanges.capacity(),
                    "the engine carries at most as many streams as the table holds"
                );
                h2.exchanges.push(exchange);
            }
            Step::TooLarge { stream } => match h2.find(Stream(u64::from(stream))) {
                // A trailer section larger than the list limit: the body is not complete.
                Some(index) => h2.exchanges[index].refuse(ErrorCode::CANCEL, Outcome::Malformed),
                None => {
                    assert!(
                        h2.exchanges.len() < h2.exchanges.capacity(),
                        "the engine carries at most as many streams as the table holds"
                    );
                    h2.exchanges.push(Exchange::new(stream, Stage::Answer(Status(431))));
                }
            },
            Step::Trailers { stream, trailers } => {
                if let Some(index) = h2.find(Stream(u64::from(stream))) {
                    let exchange = &mut h2.exchanges[index];
                    match trailers {
                        Ok(_)
                            if exchange
                                .declared
                                .is_some_and(|declared| declared != exchange.inflow.received()) =>
                        {
                            exchange.refuse(ErrorCode::PROTOCOL_ERROR, Outcome::Malformed);
                        }
                        Ok(lines) => exchange.inflow.end(Outcome::Complete(Some(Trailers { lines }))),
                        Err(Refusal::Malformed) => exchange.refuse(ErrorCode::PROTOCOL_ERROR, Outcome::Malformed),
                        Err(Refusal::Capacity) => exchange.refuse(
                            ErrorCode::INTERNAL_ERROR,
                            Outcome::Reset(Some(u64::from(ErrorCode::INTERNAL_ERROR.0))),
                        ),
                    }
                }
            }
            Step::Data {
                stream,
                data,
                end_stream,
            } => {
                let Some(index) = h2.find(Stream(u64::from(stream))) else {
                    return Ok(());
                };
                let exchange = &mut h2.exchanges[index];
                if exchange.reset.is_some()
                    || exchange.inflow.ended()
                    || !matches!(exchange.stage, Stage::Fresh(_) | Stage::Given)
                {
                    // The stream ends: its bytes only count for the credit of the peer.
                    exchange.inflow.discard(data);
                    return Ok(());
                }
                let total = exchange.inflow.received().saturating_add(data.initialized() as u64);
                if exchange.declared.is_some_and(|declared| total > declared) {
                    exchange.inflow.discard(data);
                    exchange.refuse(ErrorCode::PROTOCOL_ERROR, Outcome::Malformed);
                } else if total > body_bytes {
                    exchange.inflow.discard(data);
                    exchange.refuse(ErrorCode::CANCEL, Outcome::Malformed);
                } else if exchange.inflow.data(data, &budget).is_err() {
                    exchange.refuse(
                        ErrorCode::INTERNAL_ERROR,
                        Outcome::Reset(Some(u64::from(ErrorCode::INTERNAL_ERROR.0))),
                    );
                } else if end_stream {
                    if exchange.declared.is_some_and(|declared| declared != total) {
                        exchange.refuse(ErrorCode::PROTOCOL_ERROR, Outcome::Malformed);
                    } else {
                        exchange.inflow.end(Outcome::Complete(None));
                    }
                }
            }
            Step::Reset { stream, code } => {
                if let Some(index) = h2.find(Stream(u64::from(stream))) {
                    let exchange = &mut h2.exchanges[index];
                    exchange.ended = true;
                    exchange.reset = None;
                    exchange.end(
                        Outcome::Reset(Some(u64::from(code.0))),
                        Error::new(Kind::Partial, "the client reset the stream"),
                    );
                }
            }
            Step::Sent { stream } => {
                if let Some(index) = h2.find(Stream(u64::from(stream)))
                    && let Some(out) = &mut h2.exchanges[index].out
                {
                    out.chunk = false;
                }
            }
            // The engine drains the streams up to the last one, and then ends.
            Step::GoAway { .. } | Step::Response { .. } => {}
        }
        Ok(())
    }

    /// The engine ended: each stream ends with it. A response whose end is in the output goes on
    /// to the transport after a graceful end, so only a failure ends its delivery.
    pub(super) fn h2_engine_ended(&mut self) {
        let error = self.failure.unwrap_or(Error::new(
            Kind::Partial,
            "the connection ended before the end of the response",
        ));
        let (reset, failed) = (self.reset, self.failure.is_some());
        for exchange in &mut self.h2().exchanges {
            let outcome = if reset {
                Outcome::Reset(None)
            } else {
                Outcome::Truncated
            };
            if !exchange.inflow.ended() {
                exchange.inflow.end(outcome);
            }
            if let Some(out) = &mut exchange.out
                && !(out.finished && out.complete)
                && (failed || !out.ended)
            {
                out.error.get_or_insert(error);
            }
            exchange.ended = true;
            exchange.reset = None;
            exchange.changed = true;
        }
        self.h2().exchanges.retain(|exchange| !exchange.closed);
    }

    /// Counts the bytes that the transport accepted into the delivery of each stream: each DATA
    /// frame that it accepted whole, and the accepted bytes of the payload of the next one.
    pub(super) fn h2_accepted(&mut self) {
        let accepted = self.link.accepted().bytes;
        loop {
            let (session, _) = self.h2_parts();
            let Some(mark) = session.connection().take_mark(accepted) else {
                break;
            };
            let h2 = self.h2();
            if let Some(index) = h2.find(Stream(u64::from(mark.stream)))
                && let Some(out) = &mut h2.exchanges[index].out
            {
                out.accepted = out.accepted.saturating_add(u64::from(mark.payload));
                out.partial = 0;
                out.complete |= mark.end_stream;
            }
        }
        let (session, _) = self.h2_parts();
        if let Some(mark) = session.connection().front_mark() {
            let start = mark.end - u64::from(mark.payload);
            let h2 = self.h2();
            if let Some(index) = h2.find(Stream(u64::from(mark.stream)))
                && let Some(out) = &mut h2.exchanges[index].out
            {
                out.partial = accepted.saturating_sub(start).min(u64::from(mark.payload));
            }
        }
    }

    /// Refuses a call on `stream` that the application does not have, and a call after the
    /// client reset it.
    fn h2_live(&mut self, stream: Stream) -> Result<usize, Error> {
        let h2 = self.h2();
        h2.given(stream)?;
        let index = h2.find(stream).ok_or_else(not_open)?;
        let exchange = &h2.exchanges[index];
        if exchange.ended && exchange.out.is_none_or(|out| !out.finished) {
            return Err(Error::new(
                Kind::Partial,
                "the stream ended before the end of the response",
            ));
        }
        Ok(index)
    }

    pub(super) fn h2_respond(&mut self, stream: Stream, response: &Response<'_>, now: Instant) -> Result<bool, Error> {
        let index = self.h2_live(stream)?;
        let exchange = &self.h2().exchanges[index];
        if exchange.out.is_some() {
            return Err(misuse("the request in flight has its response"));
        }
        let (id, head, connect) = (exchange.id, exchange.head, exchange.connect);
        let Response { status, fields, length } = *response;
        if status.code() < 200 {
            return Err(misuse("a final response needs a status of 200 to 599"));
        }
        if connect && (200..300).contains(&status.code()) {
            return Err(Error::new(Kind::Unsupported, "the server does not change the protocol"));
        }
        message::sendable(fields)?;
        let bodiless = head || matches!(status.code(), 204 | 304);
        let mut status_digits = [0; 20];
        let mut length_digits = [0; 20];
        let status_line = FieldLine {
            name: b":status",
            value: h1::digits(u64::from(status.code()), 10, &mut status_digits),
            never_indexed: false,
        };
        let length_line = length
            .filter(|_| !matches!(status.code(), 204 | 304))
            .map(|length| FieldLine {
                name: b"content-length",
                value: h1::digits(length, 10, &mut length_digits),
                never_indexed: false,
            });
        let lines = core::iter::once(status_line)
            .chain(message::lines(fields))
            .chain(length_line);
        let end_stream = bodiless || length == Some(0);
        let (session, _) = self.h2_parts();
        if session.connection().block_room(lines.clone()) > self.limits.head.head_bytes {
            return Err(Error::new(
                Kind::Overload,
                "the response head is larger than the head region: give a larger head_bytes",
            ));
        }
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let (session, outbound) = self.h2_parts();
        match session.connection().headers(outbound, id, lines, end_stream, region) {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(false),
            Err(error) => return Err(error),
        }
        self.h2().exchanges[index].out = Some(Out {
            length: if bodiless { Some(0) } else { length },
            written: 0,
            chunk: false,
            finished: end_stream,
            ended: end_stream,
            accepted: 0,
            partial: 0,
            complete: false,
            error: None,
        });
        self.pump(now)?;
        Ok(true)
    }

    /// The response of the stream at `index`, open for its body.
    fn h2_body(&mut self, stream: Stream) -> Result<(usize, Out), Error> {
        let index = self.h2_live(stream)?;
        let out = self.h2().exchanges[index].out.ok_or_else(|| misuse("respond first"))?;
        if out.finished {
            return Err(misuse("the response is finished"));
        }
        Ok((index, out))
    }

    /// Waits for the `Event::Sent` of the chunk before, with one drive. Refuses with
    /// [`Kind::Overload`] while it waits.
    fn h2_chunk_sent(&mut self, stream: Stream, now: Instant) -> Result<(usize, Out), Error> {
        let (index, out) = self.h2_body(stream)?;
        if !out.chunk {
            return Ok((index, out));
        }
        self.pump(now)?;
        let (index, out) = self.h2_body(stream)?;
        if out.chunk {
            return Err(Error::new(
                Kind::Overload,
                "the chunk before waits for the output: send the output, and write again",
            ));
        }
        Ok((index, out))
    }

    pub(super) fn h2_write(&mut self, stream: Stream, data: &Lease, now: Instant) -> Result<(), Error> {
        let len = data.initialized() as u64;
        let (_, out) = self.h2_body(stream)?;
        if len == 0 {
            return Ok(());
        }
        if out
            .length
            .is_some_and(|length| out.written.saturating_add(len) > length)
        {
            return Err(misuse("the body passes the length of the response"));
        }
        let (index, _) = self.h2_chunk_sent(stream, now)?;
        let id = self.h2().exchanges[index].id;
        // A chunk with bytes waits in its stream, so a full output queue cannot refuse it, and
        // no drive moves this exchange.
        let (session, outbound) = self.h2_parts();
        session.connection().data(outbound, id, data.clone(), false)?;
        if let Some(out) = &mut self.h2().exchanges[index].out {
            out.written += len;
            out.chunk = true;
        }
        self.pump(now).map(drop)
    }

    /// Ends the body. While a chunk waits for the output, the frame that ends the stream goes
    /// after it, at a later drive.
    pub(super) fn h2_finish(&mut self, stream: Stream, now: Instant) -> Result<(), Error> {
        let (index, out) = self.h2_body(stream)?;
        if out.length.is_some_and(|length| out.written != length) {
            return Err(misuse("the body is shorter than the length of the response"));
        }
        if let Some(out) = &mut self.h2().exchanges[index].out {
            out.finished = true;
        }
        self.h2_end(index)?;
        self.pump(now).map(drop)
    }

    /// Queues the frame that ends the stream at `index`, after the application finished its body
    /// and its last chunk went. Gives whether the output queue had no room.
    fn h2_end(&mut self, index: usize) -> Result<bool, Error> {
        let exchange = &self.h2().exchanges[index];
        let id = exchange.id;
        let Some(out) = exchange.out else { return Ok(false) };
        if !out.finished || out.ended || out.chunk || exchange.ended {
            return Ok(false);
        }
        let (session, outbound) = self.h2_parts();
        match session
            .connection()
            .data(outbound, id, Lease::from(<&[u8]>::default()), true)
        {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(true),
            Err(error) => return Err(error),
        }
        if let Some(out) = &mut self.h2().exchanges[index].out {
            out.ended = true;
        }
        Ok(false)
    }

    pub(super) fn h2_finish_with_trailers(
        &mut self,
        stream: Stream,
        trailers: &[Field<'_>],
        now: Instant,
    ) -> Result<bool, Error> {
        let (_, out) = self.h2_body(stream)?;
        if out.length.is_some_and(|length| out.written != length) {
            return Err(misuse("the body is shorter than the length of the response"));
        }
        message::sendable(trailers)?;
        let (index, _) = self.h2_chunk_sent(stream, now)?;
        let id = self.h2().exchanges[index].id;
        let lines = message::lines(trailers);
        let (session, _) = self.h2_parts();
        if session.connection().block_room(lines.clone()) > self.limits.head.head_bytes {
            return Err(Error::new(
                Kind::Overload,
                "the trailer section is larger than the head region: give a larger head_bytes",
            ));
        }
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let (session, outbound) = self.h2_parts();
        match session.connection().headers(outbound, id, lines, true, region) {
            Ok(()) => {}
            Err(error) if error.kind() == Kind::Overload => return Ok(false),
            Err(error) => return Err(error),
        }
        if let Some(out) = &mut self.h2().exchanges[index].out {
            out.finished = true;
            out.ended = true;
        }
        self.pump(now)?;
        Ok(true)
    }

    pub(super) fn h2_cancel(&mut self, stream: Stream) {
        let h2 = self.h2();
        let Some(index) = h2.find(stream) else { return };
        let exchange = &mut h2.exchanges[index];
        if !matches!(exchange.stage, Stage::Given) || exchange.out.is_some_and(|out| out.finished && out.complete) {
            return;
        }
        exchange.refuse(ErrorCode::CANCEL, Outcome::Cancelled);
        if let Some(out) = &mut exchange.out {
            out.error = Some(Error::new(Kind::Cancelled, "the application cancelled the response"));
        }
    }

    pub(super) fn h2_close(&mut self, stream: Stream) {
        let h2 = self.h2();
        if let Some(index) = h2.find(stream)
            && matches!(h2.exchanges[index].stage, Stage::Given)
        {
            h2.exchanges[index].closed = true;
        }
        if !self.h2_engine_live() {
            self.h2().exchanges.retain(|exchange| !exchange.closed);
        }
    }

    pub(super) fn h2_shutdown(&mut self, now: Instant) -> Result<(), Error> {
        self.h2().goaway = true;
        self.h2_next();
        self.tick(now);
        self.pump(now).map(drop)
    }

    /// Ends each stream at the deadline of a shutdown.
    pub(super) fn h2_expire(&mut self, error: Error) {
        for exchange in &mut self.h2().exchanges {
            exchange.end(Outcome::Cancelled, error);
            exchange.changed = true;
        }
    }

    /// Closes a connection that had no stream for the head timeout, with GOAWAY.
    pub(super) fn h2_idle(&mut self, now: Instant) {
        let shutdown = self.shutdown.is_some();
        let h2 = self.h2();
        if !h2.exchanges.is_empty() || shutdown || h2.goaway {
            h2.idle = None;
            return;
        }
        let Some(timeout) = h2.timeout else { return };
        match h2.idle {
            None => h2.idle = now.checked_add(timeout).ok().map(Deadline::at),
            Some(deadline) if deadline.is_reached(now) == Ok(true) => {
                h2.idle = None;
                h2.goaway = true;
            }
            Some(_) => {}
        }
    }
}

/// What the work of a stream before a drive did.
enum Settled {
    /// The stream stays.
    Kept,
    /// The stream ended, and its entry went.
    Removed,
    /// The output queue or the head regions had no room: the work goes on at the next drive.
    Full,
}
