//! The caller-driven host: one connection that the application drives from its own event loop.
//!
//! The application owns the byte source, for example a nonblocking socket, and its clock. A
//! [`Connection`] owns one engine and its two queues. The application gives it the received bytes
//! and the time, drives it, writes its output to the transport, and acknowledges the bytes that
//! the transport accepted. After each drive, [`Connection::wait`] tells when to drive again: now,
//! when the host gives what the engine waits for, or at the next deadline. The connection spawns no
//! task and needs no runtime, and it does not need `Send`.
//!
//! The application keeps driving the connection until its terminal release: the engine ended,
//! and the transport accepted each output. [`Connection::release`] tells when that is. A
//! connection that drops before it, through [`Connection::abandon`], reports the output that the
//! transport has not accepted.
//!
//! ```
//! use core::net::{Ipv4Addr, SocketAddr};
//! use core::num::{NonZeroU64, NonZeroUsize};
//!
//! use rsnetwork::buffer::{Backing, Buffer as _, Lease};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
//! use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
//! use rsnetwork::host::{Connection, Wait};
//! use rsnetwork::time::{ClockDomain, Instant, Suspend};
//! use rsnetwork::value::Status;
//!
//! let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
//! let body = BodyLimits {
//!     body_bytes: 1 << 20,
//!     drain_bytes: 64 * 1024,
//!     extension_bytes: 256,
//!     trailer_bytes: 4 * 1024,
//!     trailer_fields: 16,
//! };
//! let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let queue = NonZeroUsize::new(16).expect("not zero");
//! let (inbound, outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
//! let server = Server::new(limits, body, turn, &outbound, &budget)?;
//!
//! // The clock of the host. A real host reads its monotonic clock at each drive.
//! let clock = ClockDomain::new(1, Suspend::Pauses);
//! let now = Some(Instant::new(clock, 0));
//! let mut connection = Connection::new(server, inbound, outbound, Some(clock))?;
//!
//! // The socket received a request.
//! let endpoint = Endpoint {
//!     peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
//!     local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
//!     ecn: Ecn::NotEct,
//!     segment: None,
//! };
//! let region = Lease::from(b"GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec());
//! connection.receive(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");
//!
//! // Drive until the connection waits, and answer the request.
//! while let Some(event) = connection.drive(now)? {
//!     if let ServerEvent::Request(_) = event {
//!         let (server, outbound) = connection.parts();
//!         let head = Backing::from(Vec::with_capacity(256));
//!         server.respond(outbound, Status::new(200)?, &[], Framing::Length(5), head)?;
//!         server.send(outbound, &Lease::from(b"hello".to_vec()))?;
//!         server.finish(outbound)?;
//!     }
//! }
//! assert_eq!(connection.wait(), Wait::Ended(Ok(())));
//!
//! // Write each output to the socket, and acknowledge the bytes that it accepted.
//! let mut sent = Vec::new();
//! while let Some(output) = connection.output() {
//!     sent.extend_from_slice(output.region.bytes());
//!     connection.ack(output.id, output.region.initialized())?;
//! }
//! assert_eq!(sent, b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 5\r\n\r\nhello");
//! assert_eq!(connection.release(), Some(Ok(())));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use rstypes::buffer::{Backing, Lease};

use crate::drive::{
    AckError, ActionId, Blocked, Endpoint, Error, Inbound, Kind, Outbound, Output, Outstanding, Progress, Received,
    Turn,
};
use crate::h1::{Client, ClientEvent, Server, ServerEvent};
use crate::time::{ClockDomain, Deadline, Instant};

/// A protocol engine that a [`Connection`] drives. The engines of this crate implement it.
pub trait Engine: sealed::Sealed {
    /// The event that a drive gives.
    type Event;

    /// Runs one turn: reads `inbound`, writes into `outbound`, and gives the next event and the
    /// turn. `now` is the time of the host, or `None` when the host has no clock.
    fn drive(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> (Option<Self::Event>, Turn);

    /// Whether the engine has a timer, which needs the clock of the host.
    fn timed(&self) -> bool;

    /// Lends the input region of the engine for one receive, or gives `None` when the engine has
    /// none. The host receives into the capacity after the initialized bytes of the region, and
    /// gives it back with [`received`](Self::received).
    fn region(&mut self) -> Result<Option<Backing>, Error> {
        Ok(None)
    }

    /// Takes a received region that the host owns: the region that [`region`](Self::region) lent,
    /// with the bytes that the receive added, or a region of the host, for example one that the
    /// kernel selected. The default freezes it and queues it in `inbound`, with no copy. Gives it
    /// back when the engine cannot take it now: drive first.
    fn received(
        &mut self,
        inbound: &mut Inbound,
        region: Backing,
        endpoint: Endpoint,
        capacity: u64,
    ) -> Result<(), Backing> {
        if inbound.free() == 0 {
            return Err(region);
        }
        let received = Received {
            region: Lease::from(region),
            endpoint,
            capacity,
        };
        let pushed = inbound.push(received);
        assert!(pushed.is_ok(), "a queue with a free place takes each region");
        Ok(())
    }
}

/// The engines of this crate are the only engines: a binding drives them, and does not replace
/// them.
mod sealed {
    pub trait Sealed {}

    impl Sealed for crate::h1::Server {}
    impl Sealed for crate::h1::Client {}
    #[cfg(feature = "tls")]
    impl<E: super::Engine> Sealed for crate::tls::Tls<E> {}
}

impl Engine for Server {
    type Event = ServerEvent;

    fn drive(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> (Option<ServerEvent>, Turn) {
        Self::drive(self, inbound, outbound, now)
    }

    fn timed(&self) -> bool {
        self.has_timer()
    }
}

impl Engine for Client {
    type Event = ClientEvent;

    fn drive(&mut self, inbound: &mut Inbound, _: &mut Outbound, _: Option<Instant>) -> (Option<ClientEvent>, Turn) {
        Self::drive(self, inbound)
    }

    fn timed(&self) -> bool {
        false
    }
}

/// When to drive a [`Connection`] again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Now: the engine gave an event, or it has more work.
    Now,
    /// When the host gives what `blocked` names, or at `deadline`, whichever comes first:
    ///
    /// - [`Blocked::Input`]: when bytes arrive, or the peer closes its side.
    /// - [`Blocked::Output`]: when the transport accepts output.
    /// - [`Blocked::Capacity`]: when that much capacity is free again.
    /// - [`Blocked::Streams`]: when the application closes an HTTP/2 stream that a reset ended.
    ///
    /// A host that waits only for this cause does not wake for an event that cannot help, for
    /// example a socket that can take output while the engine waits for input. Send each
    /// outstanding output in any wait.
    Until {
        /// What the engine waits for.
        blocked: Blocked,
        /// The next deadline of the engine, or `None` when it has none.
        deadline: Option<Deadline>,
    },
    /// Never: the engine ended with this result. Send the rest of the output, and then release
    /// the connection.
    Ended(Result<(), Error>),
}

/// One connection that the application drives: an engine and its two queues.
#[derive(Debug)]
pub struct Connection<E> {
    engine: E,
    inbound: Inbound,
    outbound: Outbound,
    /// The clock of the host, if it has one.
    clock: Option<ClockDomain>,
    wait: Wait,
}

impl<E: Engine> Connection<E> {
    /// Makes a connection of `engine` and its queues, for a host whose clock is `clock`, or `None`
    /// when the host has no clock.
    ///
    /// Refuses with [`Kind::Unsupported`] when the engine has a timer and the host has no clock,
    /// because the timer cannot run.
    pub fn new(engine: E, inbound: Inbound, outbound: Outbound, clock: Option<ClockDomain>) -> Result<Self, Error> {
        if engine.timed() && clock.is_none() {
            return Err(Error::new(
                Kind::Unsupported,
                "the engine has a timer, and the host has no clock",
            ));
        }
        Ok(Self {
            engine,
            inbound,
            outbound,
            clock,
            wait: Wait::Now,
        })
    }

    /// Queues bytes that the transport received. Gives them back when the queue is full: drive
    /// first.
    #[expect(
        clippy::result_large_err,
        reason = "a refusal gives the caller back its region and facts, and a box would make each refusal allocate"
    )]
    pub fn receive(&mut self, received: Received) -> Result<(), Received> {
        self.inbound.push(received)
    }

    /// Lends the input region of the engine for one receive, or gives `None` when the engine has
    /// none: then receive into a region of the host. Receive into the capacity after the
    /// initialized bytes, and give the region back with [`received`](Self::received).
    ///
    /// A TLS engine lends the tail of its input region, so a record that continues after a
    /// receive joins its first bytes in place. Refuses with [`Kind::Overload`] when the budget
    /// cannot pay for a new region, and with [`Kind::Misuse`] while a lent region has not come
    /// back.
    pub fn region(&mut self) -> Result<Option<Backing>, Error> {
        self.engine.region()
    }

    /// Gives the engine a received region that the host owns: the region that
    /// [`region`](Self::region) lent, or a region of the host, for example one that the kernel
    /// selected. Gives it back when the engine cannot take it now: drive first.
    pub fn received(&mut self, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        self.engine.received(&mut self.inbound, region, endpoint, capacity)
    }

    /// Records that the transport gives no more bytes: the peer closed its side.
    pub fn end_input(&mut self) {
        self.inbound.end();
    }

    /// Drives the engine for one turn at `now`, and gives its event, if it has one. Then
    /// [`wait`](Self::wait) tells when to drive again, with the deadline of this turn.
    ///
    /// Give the time of the host as `now`, on the clock that [`new`](Self::new) took, or `None`
    /// when the host has no clock. Refuses with [`Kind::Misuse`] when `now` does not match the
    /// clock. After the engine ended, the drive does nothing.
    pub fn drive(&mut self, now: Option<Instant>) -> Result<Option<E::Event>, Error> {
        if matches!(self.wait, Wait::Ended(_)) {
            return Ok(None);
        }
        if now.map(Instant::domain) != self.clock {
            return Err(Error::new(
                Kind::Misuse,
                "the time is not on the clock of the connection",
            ));
        }
        let (event, turn) = self.engine.drive(&mut self.inbound, &mut self.outbound, now);
        self.wait = match turn.progress {
            Progress::Pending => Wait::Now,
            Progress::Blocked(blocked) => Wait::Until {
                blocked,
                deadline: turn.deadline,
            },
            Progress::Terminal(end) => Wait::Ended(end),
        };
        Ok(event)
    }

    /// When to drive again, from the last turn.
    pub fn wait(&self) -> Wait {
        self.wait
    }

    /// The engine and the output queue, for the calls of the application, such as a response.
    pub fn parts(&mut self) -> (&mut E, &mut Outbound) {
        (&mut self.engine, &mut self.outbound)
    }

    /// The next output to give to the transport. Acknowledge it with [`ack`](Self::ack).
    pub fn output(&mut self) -> Option<Output> {
        self.outbound.submit()
    }

    /// Acknowledges that the transport accepted the first `accepted` bytes of output `id`.
    pub fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        self.outbound.ack(id, accepted)
    }

    /// The output that the transport has not accepted.
    pub fn outstanding(&self) -> Outstanding {
        self.outbound.outstanding()
    }

    /// Gives the end of the connection when it can drop: after the terminal turn, when the
    /// transport accepted each output. Gives `None` before that: drive on, and send the output.
    pub fn release(&self) -> Option<Result<(), Error>> {
        match self.wait {
            Wait::Ended(end) if self.outbound.outstanding().is_empty() => Some(end),
            _ => None,
        }
    }

    /// Drops the connection before its terminal release, and reports the output that the
    /// transport has not accepted. The transport keeps its own view of the submitted output until
    /// its terminal event.
    pub fn abandon(self) -> Outstanding {
        self.outbound.outstanding()
    }
}
