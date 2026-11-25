//! The exchanges of a server connection on HTTP/1.1: one stream at a time.

use rstypes::buffer::Lease;
use rstypes::time::Instant;

use super::{Delivery, Http, Protocol, Response, misuse};
use crate::body::{Consumer, Outcome};
use crate::drive::{Accepted, Error, Kind, Outbound};
use crate::h1::{self, Framing, RetainedRequest, ServerEvent};
use crate::message::{RequestHead, Stream};
use crate::value::{Field, Method, Status};

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

/// The exchanges of an HTTP/1.1 connection.
#[derive(Debug)]
pub(crate) struct H1 {
    state: State,
    /// A request head that came while the response before it went out.
    pub(super) next: Option<RetainedRequest>,
    /// The method of the request in flight is CONNECT.
    connect: bool,
    /// The application read the request body, so the engine accepts it.
    accepted: bool,
    pub(super) body: Consumer,
    response: Option<Track>,
    /// The number of the last exchange.
    count: u64,
    /// The handler did not close the stream of the last exchange.
    open: bool,
    /// The exchange changed since the last [`Http::changed`].
    changed: bool,
}

impl H1 {
    pub(super) const fn new() -> Self {
        Self {
            state: State::Idle,
            next: None,
            connect: false,
            accepted: false,
            body: Consumer::new(),
            response: None,
            count: 0,
            open: false,
            changed: false,
        }
    }

    /// Whether `stream` is the stream of the last exchange.
    fn is(&self, stream: Stream) -> bool {
        stream == Stream(self.count) && self.count > 0
    }

    /// Gives the stream of the last exchange when it changed since the last call.
    pub(super) fn changed(&mut self, each: impl FnOnce(Stream)) {
        if core::mem::take(&mut self.changed) && self.count > 0 {
            each(Stream(self.count));
        }
    }

    /// How much of the response of `stream` the transport accepted, of the `sent` bytes.
    pub(super) fn delivery(&self, stream: Stream, sent: Accepted) -> Option<Delivery> {
        if !self.is(stream) {
            return None;
        }
        let track = self.response?;
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

    /// Whether no response waits for the transport: the last one is complete, or it ended.
    pub(super) fn delivered(&self, sent: Accepted) -> bool {
        self.state != State::Exchange
            && !matches!(self.delivery(Stream(self.count), sent), Some(Delivery::Sending { .. }))
    }

    /// Whether an exchange is in flight, or a response waits for the transport.
    pub(super) fn busy(&self, sent: Accepted) -> bool {
        self.state == State::Exchange || !self.delivered(sent)
    }

    /// Records `error` as the end of a response that the transport has not accepted.
    pub(super) fn fail(&mut self, error: Error, sent: Accepted) {
        let complete = matches!(self.delivery(Stream(self.count), sent), Some(Delivery::Complete { .. }));
        if let Some(track) = &mut self.response
            && !complete
        {
            track.error.get_or_insert(error);
        }
    }
}

impl Http {
    /// The exchanges of the connection.
    #[expect(
        clippy::unreachable,
        reason = "`Http` calls an HTTP/1.1 method only after it matched `Protocol::H1`"
    )]
    fn h1(&mut self) -> &mut H1 {
        match self.link.engine().0 {
            Protocol::H1(_, h1) => h1,
            _ => unreachable!("an HTTP/1.1 call comes only on an HTTP/1.1 connection"),
        }
    }

    /// The engine and the plaintext output queue.
    #[expect(
        clippy::unreachable,
        reason = "`Http` calls an HTTP/1.1 method only after it matched `Protocol::H1`"
    )]
    fn h1_parts(&mut self) -> (&mut h1::Server, &mut Outbound) {
        match self.link.engine() {
            (Protocol::H1(server, _), outbound) => (server, outbound),
            _ => unreachable!("an HTTP/1.1 call comes only on an HTTP/1.1 connection"),
        }
    }

    /// Refuses a call on `stream` when it is not the stream of the exchange in flight.
    fn h1_current(&mut self, stream: Stream) -> Result<(), Error> {
        let h1 = self.h1();
        if !h1.is(stream) || !h1.open || h1.state != State::Exchange {
            return Err(misuse("no request of the stream waits for a response"));
        }
        Ok(())
    }

    /// Gives the next request head, when the handler closed the stream before it and the
    /// transport accepted its response.
    pub(super) fn h1_next(&mut self, now: Instant) -> Result<Option<(Stream, RequestHead)>, Error> {
        // After a shutdown, a request that the application did not see is new work: refuse it.
        // Its refusal goes after the response before it.
        if self.shutdown.is_some() && self.h1().next.is_some() && self.h1_refuse(now)? {
            self.h1().next = None;
        }
        let sent = self.link.accepted();
        let shutdown = self.shutdown.is_some();
        let h1 = self.h1();
        if h1.open || !h1.delivered(sent) {
            return Ok(None);
        }
        h1.state = State::Idle;
        if shutdown {
            return Ok(None);
        }
        let Some(head) = h1.next.take() else {
            return Ok(None);
        };
        h1.state = State::Exchange;
        h1.connect = head.head().method() == Method::CONNECT;
        h1.accepted = false;
        h1.body = Consumer::new();
        h1.response = None;
        h1.count = h1.count.strict_add(1);
        h1.open = true;
        Ok(Some((Stream(h1.count), RequestHead::h1_form(head))))
    }

    /// Accepts the body of `stream` at its first read: a request that waits for `100 Continue`
    /// gets it then.
    pub(super) fn h1_accept(&mut self, stream: Stream) -> Result<(), Error> {
        let h1 = self.h1();
        if !h1.is(stream) || !h1.open || h1.state != State::Exchange {
            return Err(misuse("no request body of the stream waits"));
        }
        if !h1.accepted && !self.closed {
            let (engine, outbound) = self.h1_parts();
            engine.accept_body(outbound)?;
            self.h1().accepted = true;
        }
        Ok(())
    }

    pub(super) fn h1_respond(&mut self, stream: Stream, response: &Response<'_>, now: Instant) -> Result<bool, Error> {
        self.h1_current(stream)?;
        if self.h1().response.is_some() {
            return Err(misuse("the request in flight has its response"));
        }
        let Response { status, fields, length } = *response;
        if status.code() == 101 || (self.h1().connect && (200..300).contains(&status.code())) {
            return Err(Error::new(Kind::Unsupported, "the server does not change the protocol"));
        }
        let Ok(head) = self.heads.acquire() else {
            return Ok(false);
        };
        let base = self.link.accepted().payload;
        let framing = length.map_or(Framing::Chunked, Framing::Length);
        let (engine, outbound) = self.h1_parts();
        engine.respond(outbound, status, fields, framing, head)?;
        let empty = length == Some(0);
        if empty {
            engine.finish(outbound)?;
        }
        self.h1().response = Some(Track {
            base,
            end: None,
            error: None,
        });
        if empty {
            self.h1_finished();
        }
        // Over TLS, the drive encrypts the head.
        self.pump(now)?;
        Ok(true)
    }

    pub(super) fn h1_write(&mut self, stream: Stream, data: &Lease, now: Instant) -> Result<(), Error> {
        self.h1_responding(stream)?;
        self.queue(now, |server| {
            let (engine, outbound) = server.h1_parts();
            engine.send(outbound, data)
        })?;
        self.pump(now).map(drop)
    }

    pub(super) fn h1_finish(&mut self, stream: Stream, now: Instant) -> Result<(), Error> {
        self.h1_responding(stream)?;
        self.queue(now, |server| {
            let (engine, outbound) = server.h1_parts();
            engine.finish(outbound)
        })?;
        self.h1_finished();
        self.pump(now).map(drop)
    }

    pub(super) fn h1_finish_with_trailers(
        &mut self,
        stream: Stream,
        trailers: &[Field<'_>],
        now: Instant,
    ) -> Result<bool, Error> {
        self.h1_responding(stream)?;
        if self.h1_parts().1.free() == 0 {
            // Over TLS, only a drive seals the plaintext into records and frees its queue.
            self.pump(now)?;
            if self.h1_parts().1.free() == 0 {
                return Ok(false);
            }
        }
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let (engine, outbound) = self.h1_parts();
        // The queue has a place, so a refusal is final: the section is larger than the region.
        engine.finish_with_trailers(outbound, trailers, region)?;
        self.h1_finished();
        self.pump(now)?;
        Ok(true)
    }

    /// Refuses a write of the body when no response is open.
    fn h1_responding(&mut self, stream: Stream) -> Result<(), Error> {
        self.h1_current(stream)?;
        if self.h1().response.is_none() {
            return Err(misuse("respond first"));
        }
        Ok(())
    }

    /// Records the end of the response in the output: the response is finished.
    fn h1_finished(&mut self) {
        let end = self.link.pushed();
        let h1 = self.h1();
        if let Some(track) = &mut h1.response {
            track.end = Some(end);
        }
        h1.state = State::Delivering;
    }

    pub(super) fn h1_cancel(&mut self, stream: Stream) {
        let h1 = self.h1();
        if !h1.is(stream) || h1.state != State::Exchange {
            return;
        }
        let error = Error::new(Kind::Cancelled, "the application cancelled the response");
        self.h1_parts().0.cancel();
        self.fail(error);
        let h1 = self.h1();
        h1.body.end(Outcome::Cancelled);
        h1.state = State::Delivering;
    }

    pub(super) fn h1_close(&mut self, stream: Stream) {
        if !self.h1().is(stream) {
            return;
        }
        self.h1_cancel(stream);
        self.h1().open = false;
    }

    pub(super) fn h1_shutdown(&mut self, now: Instant) -> Result<(), Error> {
        self.h1_parts().0.shutdown();
        if self.h1().state == State::Exchange {
            self.tick(now);
            self.pump(now).map(drop)
        } else {
            // With a shutdown, `request` gives no head: it refuses the one that waits.
            self.request(now).map(drop)
        }
    }

    /// Answers the request that waits, which the application did not see, with `503` and
    /// `connection: close`. Gives `false` when no head region is free yet.
    fn h1_refuse(&mut self, now: Instant) -> Result<bool, Error> {
        let Ok(region) = self.heads.acquire() else {
            return Ok(false);
        };
        let (engine, outbound) = self.h1_parts();
        engine.respond(outbound, Status(503), &[], Framing::Length(0), region)?;
        engine.finish(outbound)?;
        self.pump(now)?;
        Ok(true)
    }

    /// The engine holds the body while a part waits for a read, and while a request head waits for
    /// the delivery before it, so each part that comes has a place.
    pub(super) fn h1_before_drive(&mut self) {
        let h1 = self.h1();
        let hold = !h1.body.wants_data() || h1.next.is_some();
        self.h1_parts().0.hold_body(hold);
    }

    pub(super) fn h1_event(&mut self, event: ServerEvent) {
        self.h1().changed = true;
        match event {
            ServerEvent::Request(head) => self.h1().next = Some(head),
            ServerEvent::Data(data) => {
                let taken = self.h1().body.data(data);
                assert!(taken.is_ok(), "the server drives the body only when it takes a part");
            }
            ServerEvent::End(outcome) => self.h1().body.end(outcome),
            // `respond` refuses each response that changes the protocol.
            ServerEvent::Handoff => {
                self.fail(Error::new(Kind::Unsupported, "the server does not change the protocol"));
                self.closed = true;
            }
        }
    }

    /// Ends the exchange in flight at the deadline of a shutdown.
    pub(super) fn h1_expire(&mut self, error: Error) {
        let sent = self.link.accepted();
        let h1 = self.h1();
        h1.changed = true;
        h1.fail(error, sent);
        if h1.state == State::Exchange {
            h1.body.end(Outcome::Cancelled);
        }
        self.h1_parts().0.cancel();
    }
}
