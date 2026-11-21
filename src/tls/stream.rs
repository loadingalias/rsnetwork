//! The TLS stream: an encrypted, authenticated byte stream over TCP for a protocol other than HTTP,
//! for example a database wire protocol. It runs on the TLS path of HTTP, with the same trust, key
//! exchange, record layer, close, and backing rules, and no second record path.

use core::num::NonZeroUsize;
use core::time::Duration;

use rstypes::buffer::{Backing, Buffer as _, BufferMut, Lease, WriteLoan};
use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Deadline, Instant};

use super::{ClientConfig, Closure, Limits, Negotiated, ServerConfig, Tls};
use crate::body::{Consumer, Outcome, Part, Read};
use crate::drive::{
    AckError, ActionId, Blocked, Endpoint, Error, Inbound, Kind, Outbound, Output, Outstanding, Progress, Received,
    Turn,
};
use crate::host::{Connection, Engine, Wait};
use crate::link::{earliest, queues};

/// The limits of a TLS stream, which the caller sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamLimits {
    /// The limits of the TLS connection.
    pub tls: Limits,
    /// The regions that each queue of the stream holds.
    pub queue: NonZeroUsize,
    /// The most time from the first call of the stream to the end of the TLS handshake. `None`
    /// turns it off.
    pub handshake_timeout: Option<Duration>,
}

/// One TLS connection over TCP that carries a byte stream in each direction, with no I/O.
///
/// A binding, or the application in a [caller-driven host](crate::host), moves the ciphertext
/// with the same calls as a [`Connection`]: [`received`](Self::received) or
/// [`receive`](Self::receive), [`output`](Self::output) and [`ack`](Self::ack), and
/// [`wait`](Self::wait) to know when to call [`drive`](Self::drive) again. Each read and write
/// also drives the stream. The application makes the calls of the stream:
///
/// - **Read.** [`read_into`](Self::read_into) copies the received bytes into regions that the
///   application admits, and [`next`](Self::next) gives them as views of the received regions,
///   with no copy. The end of the stream is an [`Outcome`]: `Complete` after the `close_notify`
///   of the peer, `Truncated` when the transport ended with no `close_notify`, and `Reset` after
///   a reset. Only `Complete` proves that no byte is lost.
/// - **Write.** [`write`](Self::write) queues a view of the region of the application, with no
///   copy. [`written`](Self::written) counts the bytes that the stream took, and
///   [`sent`](Self::sent) the bytes whose records the transport accepted, so a write that ends
///   early reports its exact progress.
/// - **Close.** [`close`](Self::close) ends the stream: it sends `close_notify` after the bytes
///   that it took, and reads no more.
/// - **Evidence.** [`negotiated`](Self::negotiated) gives the key-exchange group and the
///   authentication of the peer.
#[derive(Debug)]
pub struct Stream {
    connection: Connection<Tls<Raw>>,
    clock: ClockDomain,
    read: Consumer,
    timeout: Option<Duration>,
    /// The deadline of the TLS handshake, from the first call.
    handshake: Option<Deadline>,
    /// The bytes that the stream took.
    written: u64,
    /// The application closed the stream.
    closed: bool,
    /// The failure that ended the stream before its connection did.
    end: Option<Error>,
}

impl Stream {
    /// Makes the client end of a stream to the server `name`, a DNS name or an IP address, for a
    /// host whose clock is `clock`. The ClientHello is ready at once.
    ///
    /// Refuses as [`Tls::client`] does, and with [`Kind::Overload`] when `budget` cannot pay.
    pub fn connect(
        config: &ClientConfig,
        name: &str,
        limits: StreamLimits,
        clock: ClockDomain,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let tls = Tls::client(
            config,
            name,
            Raw::default(),
            queues(limits.queue, budget)?,
            limits.tls,
            budget,
        )?;
        Self::new(tls, limits, clock, budget)
    }

    /// Makes the server end of a stream, for a host whose clock is `clock`.
    ///
    /// Refuses as [`Tls::server`] does, and with [`Kind::Overload`] when `budget` cannot pay.
    pub fn accept(
        config: &ServerConfig,
        limits: StreamLimits,
        clock: ClockDomain,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let tls = Tls::server(
            config,
            Raw::default(),
            queues(limits.queue, budget)?,
            limits.tls,
            budget,
        )?;
        Self::new(tls, limits, clock, budget)
    }

    fn new(tls: Tls<Raw>, limits: StreamLimits, clock: ClockDomain, budget: &Budget) -> Result<Self, Error> {
        let (inbound, outbound) = queues(limits.queue, budget)?;
        Ok(Self {
            connection: Connection::new(tls, inbound, outbound, Some(clock))?,
            clock,
            read: Consumer::new(),
            timeout: limits.handshake_timeout,
            handshake: None,
            written: 0,
            closed: false,
            end: None,
        })
    }

    /// Drives the stream at `now`: the handshake, the encryption of the bytes that wait, and the
    /// close. Call it each time that [`wait`](Self::wait) says. A received part waits for a read,
    /// so the drive gives no part that nothing reads. Refuses as [`read_into`](Self::read_into)
    /// does.
    pub fn drive(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        while self.pump(now)? {}
        Ok(())
    }

    /// Copies the next received bytes into the free capacity of `region`, as many as fit, or
    /// gives the outcome of the stream after its last byte. [`Read::Wait`] means that no byte
    /// arrived: wait as [`wait`](Self::wait) says, and read again. Refuses with the error of the
    /// connection when it ended with one, and with [`Kind::Misuse`] for a time on another clock.
    pub fn read_into<B: BufferMut>(&mut self, now: Instant, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        self.fill(now)?;
        Ok(self.read.read_into(region))
    }

    /// Gives the next received bytes as a view of their received region, with no copy, or the
    /// end of the stream with its outcome, or `None` when no byte arrived: wait as
    /// [`wait`](Self::wait) says, and call again. Refuses as [`read_into`](Self::read_into) does.
    pub fn next(&mut self, now: Instant) -> Result<Option<Part>, Error> {
        self.fill(now)?;
        Ok(match self.read.take() {
            Some(data) => Some(Part::Data(data)),
            None => self.read.outcome().cloned().map(Part::End),
        })
    }

    /// Queues `data` as the next bytes of the stream, with no copy: the stream takes a view of
    /// its own. Before the handshake completes, the bytes wait for it. Refuses with
    /// [`Kind::Overload`], and takes nothing, when the queue is full: send the output, and write
    /// again. Refuses with [`Kind::Misuse`] after [`close`](Self::close).
    pub fn write(&mut self, data: &Lease, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        if self.closed {
            return Err(misuse("the stream is closed"));
        }
        let plaintext = self.connection.parts().0.parts().1;
        plaintext
            .push_payload(data.clone())
            .map_err(|_| Error::new(Kind::Overload, "the output queue of the stream is full"))?;
        self.written = self.written.strict_add(data.initialized() as u64);
        // The drive encrypts the bytes.
        self.pump(now).map(drop)
    }

    /// The bytes that [`write`](Self::write) took.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// The bytes of the stream whose records the transport accepted. A record counts when each
    /// of its bytes went, so the count is exact to whole records of at most 16 KiB.
    pub fn sent(&self) -> u64 {
        self.connection
            .engine()
            .sent(self.connection.queue().accepted().bytes)
            .bytes
    }

    /// Ends the stream at `now`: the connection sends `close_notify` after the bytes that it
    /// took, and reads no more. Drive it as [`wait`](Self::wait) says, send the rest of the
    /// output, and then [`release`](Self::release) the stream. A read after it ends
    /// `Outcome::Cancelled`, unless the peer closed first.
    pub fn close(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        self.closed = true;
        self.read.end(Outcome::Cancelled);
        self.connection.parts().0.parts().0.close = true;
        self.pump(now).map(drop)
    }

    /// What the TLS handshake negotiated, or `None` before it completed: the group, the ALPN
    /// name, the kind of handshake, and the authentication of the peer.
    pub fn negotiated(&self) -> Option<Negotiated<'_>> {
        self.connection.engine().negotiated()
    }

    /// How the input of the peer ended, or `None` before its end.
    pub fn closure(&self) -> Option<Closure> {
        self.connection.engine().closure()
    }

    /// When to call again: now, when the transport gives what the stream waits for, at the
    /// deadline of the handshake, or never after the end.
    pub fn wait(&self) -> Wait {
        if let Some(error) = self.end {
            return Wait::Ended(Err(error));
        }
        match self.connection.wait() {
            Wait::Until { blocked, deadline } => Wait::Until {
                blocked,
                deadline: earliest(deadline, self.handshake),
            },
            wait => wait,
        }
    }

    /// Queues ciphertext that the transport received, as [`Connection::receive`] does.
    #[expect(
        clippy::result_large_err,
        reason = "a refusal gives the caller back its region and facts, and a box would make each refusal allocate"
    )]
    pub fn receive(&mut self, received: Received) -> Result<(), Received> {
        self.connection.receive(received)
    }

    /// Lends the input region of the stream for one receive, as [`Connection::region`] does.
    pub fn region(&mut self) -> Result<Option<Backing>, Error> {
        self.connection.region()
    }

    /// Gives the stream a received region, as [`Connection::received`] does.
    pub fn received(&mut self, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        self.connection.received(region, endpoint, capacity)
    }

    /// Records that the transport gives no more bytes. With no `close_notify` before it, the
    /// stream ends `Outcome::Truncated`.
    pub fn end_input(&mut self) {
        self.connection.end_input();
    }

    /// Records that the transport failed, as [`Connection::reset`] does: the stream ends
    /// `Outcome::Reset`, and [`sent`](Self::sent) keeps the bytes that went.
    pub fn reset(&mut self) {
        self.connection.reset();
    }

    /// Gives the stream a writable region of the host for its next records, as
    /// [`Connection::output_region`] does.
    pub fn output_region(&mut self, region: Backing) -> Result<(), (Error, Backing)> {
        self.connection.output_region(region)
    }

    /// Gives back the region of the host that the stream holds with no record in it, as
    /// [`Connection::take_output_region`] does.
    pub fn take_output_region(&mut self) -> Option<Backing> {
        self.connection.take_output_region()
    }

    /// The next output to give to the transport. Acknowledge it with [`ack`](Self::ack).
    pub fn output(&mut self) -> Option<Output> {
        self.connection.output()
    }

    /// Acknowledges that the transport accepted the first `accepted` bytes of output `id`.
    pub fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        self.connection.ack(id, accepted)
    }

    /// The output that the transport has not accepted.
    pub fn outstanding(&self) -> Outstanding {
        self.connection.outstanding()
    }

    /// Gives the end of the stream when it can drop: after its end, when the transport accepted
    /// each output. At the deadline of the handshake, it does not wait for the output. Gives
    /// `None` before that.
    pub fn release(&self) -> Option<Result<(), Error>> {
        match self.end {
            Some(error) => Some(Err(error)),
            None => self.connection.release(),
        }
    }

    /// Refuses a call after the end of the stream, and a time on another clock.
    fn live(&mut self, now: Instant) -> Result<(), Error> {
        if now.domain() != self.clock {
            return Err(misuse("the time is not on the clock of the stream"));
        }
        if self.handshake.is_none() && self.negotiated().is_none() {
            self.handshake = self
                .timeout
                .and_then(|timeout| now.checked_add(timeout).ok())
                .map(Deadline::at);
        }
        if self.negotiated().is_some() {
            self.handshake = None;
        } else if self
            .handshake
            .is_some_and(|deadline| deadline.is_reached(now) == Ok(true))
        {
            self.end.get_or_insert(Error::new(
                Kind::Deadline,
                "the TLS handshake did not complete before its deadline",
            ));
        }
        match self.end {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Drives the connection until the stream has received bytes or its end for a read, or until
    /// no event comes.
    fn fill(&mut self, now: Instant) -> Result<(), Error> {
        self.live(now)?;
        while self.read.wants_data() {
            if !self.pump(now)? {
                break;
            }
        }
        match self.connection.wait() {
            Wait::Ended(Err(error)) if self.read.wants_data() => Err(error),
            _ => Ok(()),
        }
    }

    /// Drives the connection one time, and takes its event. Gives whether it took one. The engine
    /// holds the received bytes while a part waits for a read, so each part that comes has a
    /// place.
    fn pump(&mut self, now: Instant) -> Result<bool, Error> {
        self.connection.parts().0.parts().0.hold = !self.read.wants_data();
        let Some(event) = self.connection.drive(Some(now))? else {
            return Ok(false);
        };
        match event {
            Event::Data(data) => {
                let taken = self.read.data(data);
                assert!(taken.is_ok(), "the stream drives only when the reader takes a part");
            }
            Event::End => {
                let outcome = match self.closure() {
                    Some(Closure::Notified) => Outcome::Complete(None),
                    Some(Closure::Reset) => Outcome::Reset(None),
                    Some(Closure::Unnotified) | None => Outcome::Truncated,
                };
                self.read.end(outcome);
            }
        }
        Ok(true)
    }
}

/// The inner engine of a stream: it gives each plaintext region when it arrives, and then the end
/// of the input. Its output is the bytes that the stream queues.
#[derive(Debug, Default)]
pub(crate) struct Raw {
    /// The reader of the stream holds a part: give none.
    hold: bool,
    /// The end of the input went to the reader.
    ended: bool,
    /// The application closed the stream: the next turn is terminal.
    close: bool,
}

/// An event of the inner engine of a stream.
#[derive(Debug)]
pub(crate) enum Event {
    /// Received bytes: a view of a region of plaintext.
    Data(Lease),
    /// The end of the input.
    End,
}

impl Engine for Raw {
    type Event = Event;

    fn drive(&mut self, inbound: &mut Inbound, _: &mut Outbound, _: Option<Instant>) -> (Option<Event>, Turn) {
        if self.close {
            return (
                None,
                Turn {
                    progress: Progress::Terminal(Ok(())),
                    deadline: None,
                },
            );
        }
        let event = if self.hold {
            None
        } else if let Some(front) = inbound.take_front() {
            Some(Event::Data(front.region))
        } else if inbound.ended() && !self.ended {
            self.ended = true;
            Some(Event::End)
        } else {
            None
        };
        let progress = match event {
            Some(_) => Progress::Pending,
            None => Progress::Blocked(Blocked::Input),
        };
        (
            event,
            Turn {
                progress,
                deadline: None,
            },
        )
    }

    fn timed(&self) -> bool {
        false
    }
}

fn misuse(reason: &'static str) -> Error {
    Error::new(Kind::Misuse, reason)
}
