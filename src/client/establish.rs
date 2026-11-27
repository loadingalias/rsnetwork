//! Address establishment under one operation deadline and attempt budget.

use core::alloc::Layout;
use core::fmt;
use core::net::SocketAddr;
use core::num::{NonZeroU64, NonZeroUsize};
use core::ops::Range;
use core::task::Poll;
use core::time::Duration;
use std::io;

use crate::capacity::{Budget, Permit};
use crate::drive::{Error, Kind};
use crate::time::{Deadline, Instant};

const EXPIRED: Error = Error::new(Kind::Deadline, "the operation reached its deadline");
const SPENT: Error = Error::new(Kind::Overload, "the operation spent its attempt budget");
const ROOM: Error = Error::new(Kind::Overload, "the budget refused the address race");
const MIN_DELAY: Duration = Duration::from_millis(10);

/// The absolute lifetime of an exchange and its optional response-body idle limit.
/// Pass an absolute [`Deadline`] or a reference to an [`Operation`] to the client's `send`.
#[derive(Clone, Copy, Debug)]
pub struct ResponseDeadline {
    lifetime: Deadline,
    idle_ns: Option<NonZeroU64>,
    next_ns: u64,
}

impl From<Deadline> for ResponseDeadline {
    fn from(lifetime: Deadline) -> Self {
        Self {
            lifetime,
            idle_ns: None,
            next_ns: lifetime.instant().as_nanos(),
        }
    }
}

impl From<&Operation> for ResponseDeadline {
    fn from(operation: &Operation) -> Self {
        operation.time
    }
}

impl ResponseDeadline {
    /// The absolute end, including time spent before the request went out.
    pub fn lifetime(self) -> Deadline {
        self.lifetime
    }

    pub(super) fn next(self) -> Deadline {
        Deadline::at(Instant::new(self.lifetime.instant().domain(), self.next_ns))
    }

    pub(super) fn body_expiry(self) -> &'static str {
        if self.next_ns == self.lifetime.instant().as_nanos() {
            "the deadline came before the end of the response"
        } else {
            "the response body reached its idle limit"
        }
    }

    pub(super) fn progress(&mut self, now: Instant) {
        if let Some(idle) = self.idle_ns {
            self.next_ns = now
                .as_nanos()
                .saturating_add(idle.get())
                .min(self.lifetime.instant().as_nanos());
        }
    }
}

fn after(now: Instant, delay: Duration, lifetime: Deadline) -> Deadline {
    now.checked_add(delay)
        .ok()
        .filter(|end| end.as_nanos() < lifetime.instant().as_nanos())
        .map_or(lifetime, Deadline::at)
}

/// One request's time and work across DNS, address attempts, fallback, retries, redirects, and its response.
/// Keep this value across attempts. The count of remaining attempts never increases.
#[derive(Debug)]
pub struct Operation {
    time: ResponseDeadline,
    remaining: usize,
    occupied: Option<Budget>,
}

impl Operation {
    /// Sets the lifetime before lookup. Each new lookup or connection attempt spends one work unit.
    pub fn new(lifetime: Deadline, work: NonZeroUsize) -> Self {
        Self {
            time: lifetime.into(),
            remaining: work.get(),
            occupied: None,
        }
    }

    /// Starts an idle timer at the final response head. Only nonempty response body data renews it.
    /// The absolute lifetime still applies. A zero idle duration gives [`Kind::Misuse`].
    pub fn with_body_idle(mut self, idle: Duration) -> Result<Self, Error> {
        let nanos = u64::try_from(idle.as_nanos()).unwrap_or(u64::MAX);
        self.time.idle_ns =
            Some(NonZeroU64::new(nanos).ok_or_else(|| super::misuse("a response body idle limit must be positive"))?);
        Ok(self)
    }

    /// The original absolute deadline, on the caller's clock.
    pub fn deadline(&self) -> Deadline {
        self.time.lifetime
    }

    /// Work units available for further lookups, connections, or application retries.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Attempts whose host still owns their place, including work that outlives cancellation.
    pub fn occupied(&self) -> u64 {
        self.occupied
            .as_ref()
            .map_or(0, |places| places.bound() - places.available())
    }

    /// Checks the operation's clock and lifetime before work starts or a result is accepted.
    pub fn check(&self, now: Instant) -> Result<(), Error> {
        if self
            .deadline()
            .is_reached(now)
            .map_err(|_| super::misuse("the time is not on the operation clock"))?
        {
            return Err(EXPIRED);
        }
        Ok(())
    }

    /// Spends one unit. Move the returned place to the owner of the attempt until it finishes or cancels.
    /// Dropping the place releases occupancy. A future retry still needs a fresh unit.
    pub fn attempt(&mut self, now: Instant) -> Result<Permit, Error> {
        self.check(now)?;
        let left = NonZeroUsize::new(self.remaining).ok_or(SPENT)?;
        let places = self
            .occupied
            .get_or_insert_with(|| Budget::new(NonZeroU64::try_from(left).expect("a work count fits in 64 bits")));
        self.remaining -= 1;
        Ok(places.reserve(1).expect("each issued place spends a different unit"))
    }
}

/// Limits for one address race. The first address family comes from the resolver.
#[derive(Clone, Copy, Debug)]
pub struct Dial {
    /// Maximum size of the resolver result before deduplication.
    pub addresses_max: NonZeroUsize,
    /// Delay between pending attempts. Supply a measured delay when available.
    pub delay: Duration,
}

impl Default for Dial {
    fn default() -> Self {
        Self {
            addresses_max: NonZeroUsize::new(16).expect("sixteen is positive"),
            delay: Duration::from_millis(250),
        }
    }
}

/// A local admission or time error, or the last address or resolver error category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The operation, host, or capacity refused the work.
    Operation(Error),
    /// The operating system could not resolve or connect to an address.
    Io(io::ErrorKind),
}
impl From<Error> for ConnectError {
    fn from(error: Error) -> Self {
        Self::Operation(error)
    }
}
impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(e) => e.fmt(f),
            Self::Io(kind) => kind.fmt(f),
        }
    }
}
impl core::error::Error for ConnectError {}

/// The result of driving an address race.
#[derive(Debug)]
pub enum Step<S> {
    /// The winning connection. The race has dropped each losing handle.
    Connected(S),
    /// Drive on attempt readiness or at this absolute time, whichever comes first.
    Wait(Deadline),
}

/// The caller-driven race. The host owns how an attempt starts, becomes ready, and cancels on drop.
pub struct Race<'a, A> {
    operation: &'a mut Operation,
    addresses: &'a [SocketAddr],
    order: Vec<usize>,
    groups: [Range<usize>; 2],
    family: usize,
    active: Vec<A>,
    _memory: [Permit; 2],
    delay: Duration,
    last_start: Option<Instant>,
    next_start: Deadline,
    last_error: io::ErrorKind,
    ended: bool,
}

impl<A> fmt::Debug for Race<'_, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Race")
            .field("active", &self.active.len())
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl Dial {
    /// Checks the clock, lifetime, work, and stagger before starting a lookup or a race.
    pub fn check(&self, operation: &Operation, now: Instant) -> Result<(), Error> {
        operation.check(now)?;
        if self.delay < MIN_DELAY {
            return Err(super::misuse(
                "address attempts need at least ten milliseconds between starts",
            ));
        }
        if operation.remaining() == 0 {
            return Err(SPENT);
        }
        Ok(())
    }

    /// Makes a race for a bounded resolver result. The first occurrence of each socket address keeps its place.
    /// `memory` pays for the ordering and the live handle slots. The host pays for each handle's external state.
    pub fn race<'a, A>(
        &self,
        addresses: &'a [SocketAddr],
        operation: &'a mut Operation,
        now: Instant,
        memory: &Budget,
    ) -> Result<Race<'a, A>, ConnectError> {
        self.check(operation, now)?;
        if addresses.len() > self.addresses_max.get() {
            return Err(Error::new(Kind::Overload, "the address list exceeds its limit").into());
        }
        let first = addresses
            .first()
            .ok_or(ConnectError::Io(io::ErrorKind::AddrNotAvailable))?;
        let indices = Layout::array::<usize>(addresses.len()).map_err(|_| ROOM)?;
        let order_charge = memory.reserve(indices.size() as u64).map_err(|_| ROOM)?;
        let mut order = Vec::new();
        order.try_reserve_exact(addresses.len()).map_err(|_| ROOM)?;
        order.extend(0..addresses.len());
        order.sort_unstable_by_key(|&i| (addresses[i], i));
        order.dedup_by_key(|i| addresses[*i]);
        order.sort_unstable_by_key(|&i| (addresses[i].is_ipv4() != first.is_ipv4(), i));
        let boundary = order.partition_point(|&i| addresses[i].is_ipv4() == first.is_ipv4());
        let groups = [0..boundary, boundary..order.len()];
        let slots = operation.remaining().min(order.len());
        let handles = Layout::array::<A>(slots).map_err(|_| ROOM)?;
        let handle_charge = memory.reserve(handles.size() as u64).map_err(|_| ROOM)?;
        let mut active = Vec::new();
        active.try_reserve_exact(slots).map_err(|_| ROOM)?;
        Ok(Race {
            operation,
            addresses,
            order,
            groups,
            family: 0,
            active,
            _memory: [order_charge, handle_charge],
            delay: self.delay,
            last_start: None,
            next_start: Deadline::at(now),
            last_error: io::ErrorKind::AddrNotAvailable,
            ended: false,
        })
    }
}

impl<A> Race<'_, A> {
    /// Checks pending attempts and starts at most one address. `start` must return without waiting for a connection.
    /// `poll` returns the socket when connected, its I/O error category, or `Pending`.
    /// Move the place into any host job that cannot cancel on drop. Keep it until that job ends.
    pub fn advance<S>(
        &mut self,
        now: Instant,
        start: impl FnOnce(SocketAddr, Permit) -> Result<A, Error>,
        poll: impl FnMut(&mut A) -> Poll<Result<S, io::ErrorKind>>,
    ) -> Result<Step<S>, ConnectError> {
        if self.ended {
            return Err(super::misuse("the address race has ended").into());
        }
        let step = self.turn(now, start, poll);
        if !matches!(step, Ok(Step::Wait(_))) {
            self.ended = true;
            self.active.clear();
        }
        step
    }

    fn turn<S>(
        &mut self,
        now: Instant,
        start: impl FnOnce(SocketAddr, Permit) -> Result<A, Error>,
        mut poll: impl FnMut(&mut A) -> Poll<Result<S, io::ErrorKind>>,
    ) -> Result<Step<S>, ConnectError> {
        self.operation.check(now)?;
        let lifetime = self.operation.deadline();
        let mut winner = None;
        let mut failure = None;
        self.active.retain_mut(|attempt| {
            if winner.is_some() {
                return false;
            }
            match poll(attempt) {
                Poll::Pending => true,
                Poll::Ready(Ok(socket)) => {
                    winner = Some(socket);
                    false
                }
                Poll::Ready(Err(kind)) => {
                    failure = Some(kind);
                    false
                }
            }
        });
        if let Some(socket) = winner {
            return Ok(Step::Connected(socket));
        }
        if let Some(kind) = failure {
            self.last_error = kind;
            self.next_start = after(
                self.last_start.expect("a pending attempt has a start time"),
                MIN_DELAY,
                lifetime,
            );
        }
        if self.operation.remaining() > 0
            && self.next_start.is_reached(now) == Ok(true)
            && let Some(at) = self.groups[self.family]
                .next()
                .or_else(|| self.groups[1 - self.family].next())
        {
            self.family = 1 - self.family;
            let mut attempt = start(self.addresses[self.order[at]], self.operation.attempt(now)?)?;
            self.last_start = Some(now);
            self.next_start = after(now, self.delay, lifetime);
            match poll(&mut attempt) {
                Poll::Pending => self.active.push(attempt),
                Poll::Ready(Ok(socket)) => return Ok(Step::Connected(socket)),
                Poll::Ready(Err(kind)) => {
                    self.last_error = kind;
                    self.next_start = after(now, MIN_DELAY, lifetime);
                }
            }
        }
        let addresses_left = self.groups.iter().any(|group| !group.is_empty());
        if addresses_left && self.operation.remaining() > 0 {
            return Ok(Step::Wait(self.next_start));
        }
        if !self.active.is_empty() {
            return Ok(Step::Wait(lifetime));
        }
        if addresses_left {
            return Err(SPENT.into());
        }
        Err(ConnectError::Io(self.last_error))
    }
}
