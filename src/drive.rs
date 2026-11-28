//! The drive interface of the core: received regions, output regions, their exact
//! acknowledgements, the result of each drive, and the errors.
//!
//! A protocol engine runs in drives: bounded synchronous calls. In each drive, the host lends the
//! engine its [`Inbound`] queue of received regions and its time, and the engine reads them in
//! place. The engine acknowledges the exact prefix that it consumed. Each byte after that prefix
//! stays with its owner for the next drive. The engine keeps a received byte after the call only
//! through a [`Lease`] view of its backing, never through a reference.
//!
//! Output goes through an [`Outbound`] queue. A socket can acknowledge the bytes it accepted
//! from one [`Output`]. An ordered driver can admit several outputs and later report the exact
//! prefix the kernel accepted. In each case the queue retains the remaining bytes at their original address.
//!
//! Each holder of a region keeps its own view: the queue, the transport, and the engine. The
//! backing stays alive and charged once while any view of it lives, and the last view releases it
//! (the design model `models/backing-release/`).
//!
//! Each drive ends with a [`Turn`]: the [`Progress`] of the engine and its next deadline. Stream
//! events are the types of each protocol engine. [`Error`] is the error of each engine and
//! binding: a [`Kind`] that names the recovery, and a fixed reason.
//!
//! ```
//! use core::net::{Ipv4Addr, SocketAddr};
//! use core::num::{NonZeroU64, NonZeroUsize};
//!
//! use rsnetwork::buffer::{Buffer as _, Lease};
//! use rsnetwork::capacity::Budget;
//! use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received};
//!
//! // One budget pays for each queue of the connection.
//! let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
//! let limit = NonZeroUsize::new(8).expect("not zero");
//!
//! // The host receives a region and queues it for the engine.
//! let mut inbound = Inbound::new(limit, &budget)?;
//! let endpoint = Endpoint {
//!     peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
//!     local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
//!     ecn: Ecn::NotEct,
//!     segment: None,
//! };
//! let region = Lease::from(b"PING\r\nPI".to_vec());
//! inbound.push(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");
//!
//! // In a drive, the engine reads the bytes in place and consumes one complete line.
//! inbound.consume(6)?;
//! // The partial line stays, at its address in the same region, for the next drive.
//! assert_eq!(inbound.front().map(|received| received.region.bytes()), Some(&b"PI"[..]));
//!
//! // The engine queues its output. The host sends it, and the transport accepts 3 bytes.
//! let mut outbound = Outbound::new(limit, &budget)?;
//! outbound.push(Lease::from(b"PONG\r\n".to_vec())).expect("the queue has space");
//! let output = outbound.submit().expect("an output is ready");
//! outbound.ack(output.id, 3)?;
//! // The next output is the rest of the same region, with no copy.
//! let rest = outbound.submit().expect("the rest is ready");
//! assert_eq!(rest.region.bytes(), b"G\r\n");
//! assert_eq!(rest.region.as_ptr(), output.region.as_ptr().wrapping_add(3));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use core::fmt;
use core::net::SocketAddr;
use core::num::NonZeroUsize;
use std::collections::VecDeque;

use rstypes::buffer::{Buffer as _, Lease, PoolRefused};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::Deadline;

/// The Explicit Congestion Notification (ECN) codepoint of an IP datagram (RFC 3168, section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecn {
    /// Not ECN-capable transport. A byte stream also has this codepoint.
    NotEct,
    /// ECN-capable transport, ECT(0).
    Ect0,
    /// ECN-capable transport, ECT(1).
    Ect1,
    /// Congestion experienced.
    Ce,
}

/// The endpoint facts of a received region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The address of the peer that sent the bytes.
    pub peer: SocketAddr,
    /// The local address that the bytes came to: for a datagram, its destination address.
    pub local: SocketAddr,
    /// The ECN codepoint of the datagram.
    pub ecn: Ecn,
    /// The size of each datagram when one region holds several datagrams of one size, as a
    /// coalesced receive gives them. The last datagram can be shorter. `None` for one datagram or
    /// a byte stream.
    pub segment: Option<NonZeroUsize>,
}

/// A received region with its facts.
pub struct Received {
    /// The exact initialized bytes, and the backing that holds them. A view of the region keeps
    /// the backing alive.
    pub region: Lease,
    /// Where the bytes came from and where they went.
    pub endpoint: Endpoint,
    /// The bytes that the host can still admit after this region. An engine that grants receive
    /// credit as input arrives grants no more than this. The HTTP/2 engine grants credit only for
    /// bytes that no consumer holds: the bytes that the consumer releases with
    /// [`Connection::release`](crate::h2::Connection::release), padding, and discarded DATA.
    pub capacity: u64,
}

impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Received")
            .field("len", &self.region.initialized())
            .field("endpoint", &self.endpoint)
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// The received regions of one engine that it has not consumed, in their order.
///
/// The host owns the queue and lends it to the engine for each drive. The engine reads the front
/// region in place and acknowledges the exact prefix that it consumed with
/// [`consume`](Self::consume). Each byte after the prefix stays in the queue, at its address in
/// its region, until a later drive consumes it or [`take_front`](Self::take_front) gives it to a
/// new owner.
///
/// The queue holds at most the number of regions that [`new`](Self::new) sets, and it reserves
/// their space there, charged to the caller's budget. Thus a push never allocates.
pub struct Inbound {
    regions: VecDeque<Received>,
    limit: usize,
    /// The transport gives no more bytes.
    ended: bool,
    /// The transport failed, so its end is not the end of the peer's data.
    reset: bool,
    /// The charge of the queue memory.
    _charge: Permit,
}

impl Inbound {
    /// Makes a queue for at most `limit` regions. It charges their memory to `budget` before it
    /// allocates it, and refuses with [`Kind::Overload`], with no allocation, when the budget
    /// cannot pay.
    pub fn new(limit: NonZeroUsize, budget: &Budget) -> Result<Self, Error> {
        let (regions, charge) = reserve(limit, budget)?;
        Ok(Self {
            regions,
            limit: limit.get(),
            ended: false,
            reset: false,
            _charge: charge,
        })
    }

    /// Records that the transport gives no more bytes after the queued regions: the peer closed
    /// its side. An engine reads the queued regions first, and then sees the end.
    pub fn end(&mut self) {
        self.ended = true;
    }

    /// Records that the transport failed after the queued regions, for example with a reset: no
    /// more bytes come, and the peer's data can continue after them. An engine reads the queued
    /// regions first, and then sees an end with no proof: a body ends
    /// [`Outcome::Reset`](crate::body::Outcome::Reset), never complete.
    pub fn reset(&mut self) {
        self.ended = true;
        self.reset = true;
    }

    /// Whether the transport gives no more bytes after the queued regions.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Whether the transport failed: its end is not the end of the peer's data.
    pub fn is_reset(&self) -> bool {
        self.reset
    }

    /// The number of regions that the queue can take now.
    pub fn free(&self) -> usize {
        self.limit - self.regions.len()
    }

    /// Adds a region after the others. Gives it back if the queue is full. An empty region has
    /// no byte to consume, so the queue drops it.
    // `Received` holds pointers, so it is above the threshold of the lint only on 64-bit targets.
    #[cfg_attr(
        target_pointer_width = "64",
        expect(
            clippy::result_large_err,
            reason = "a refusal gives the caller back its region and facts, and a box would make each refusal allocate"
        )
    )]
    pub fn push(&mut self, received: Received) -> Result<(), Received> {
        if received.region.initialized() == 0 {
            return Ok(());
        }
        if self.regions.len() >= self.limit {
            return Err(received);
        }
        self.regions.push_back(received);
        Ok(())
    }

    /// The front region, with the bytes that no drive consumed.
    pub fn front(&self) -> Option<&Received> {
        self.regions.front()
    }

    /// Acknowledges that the engine consumed the first `len` bytes of the front region.
    ///
    /// The queue keeps a view of the bytes after them, at the same address, and drops the region
    /// when no byte remains. Its backing stays alive while another view of it lives. Refuses, and
    /// changes nothing, if `len` is more than the bytes of the front region.
    pub fn consume(&mut self, len: usize) -> Result<(), AckError> {
        let Some(front) = self.regions.front_mut() else {
            return if len == 0 { Ok(()) } else { Err(AckError::TooLarge) };
        };
        let rest = front.region.view(len..).ok_or(AckError::TooLarge)?;
        if rest.initialized() == 0 {
            self.regions.pop_front();
        } else {
            front.region = rest;
        }
        Ok(())
    }

    /// Removes the front region and gives it, with exactly the bytes that no drive consumed. Use
    /// it to give the bytes after an upgrade or a CONNECT head to their new owner.
    pub fn take_front(&mut self) -> Option<Received> {
        self.regions.pop_front()
    }
}

impl fmt::Debug for Inbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inbound")
            .field("regions", &self.regions.len())
            .field("limit", &self.limit)
            .field("ended", &self.ended)
            .field("reset", &self.reset)
            .finish_non_exhaustive()
    }
}

/// The identifier of one output action. Each [`Outbound`] gives each output a new identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionId(u64);

/// One output action: a region to give to the transport.
///
/// The region is a view of its own, so the transport can keep it until its terminal event, also
/// after the queue drops its view. Report the result with [`Outbound::ack`] or [`Outbound::admit`].
pub struct Output {
    /// The identifier that the acknowledgement names.
    pub id: ActionId,
    /// The bytes to send.
    pub region: Lease,
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("id", &self.id)
            .field("len", &self.region.initialized())
            .finish()
    }
}

/// The output regions of one engine that the transport has not accepted, in their order.
///
/// The host takes each [`Output`] with [`submit`](Self::submit). A direct socket reports its
/// accepted bytes with [`ack`](Self::ack). An ordered driver can take responsibility for the
/// region with [`admit`](Self::admit) and report kernel progress with [`accept_through`](Self::accept_through).
///
/// The queue holds at most the number of regions that [`new`](Self::new) sets, and it reserves
/// their space there, charged to the caller's budget. Thus a push never allocates.
pub struct Outbound {
    regions: VecDeque<Queued>,
    limit: usize,
    /// The charge of the queue memory.
    _charge: Permit,
    /// The identifier of the next output.
    next: u64,
    /// The current offer at index `admitted`, until the host accepts, refuses, or admits it.
    outstanding: Option<ActionId>,
    /// The number of leading regions that the driver owns and the kernel has not fully accepted.
    admitted: usize,
    /// The bytes in those regions that still await kernel acceptance.
    admitted_bytes: u64,
    /// The bytes that the queue took, since it was made.
    pushed: u64,
    /// The bytes that the transport accepted, since the queue was made.
    accepted: Accepted,
}

/// A region in an [`Outbound`] queue.
struct Queued {
    region: Lease,
    /// The region holds body bytes, not framing.
    payload: bool,
}

/// The bytes that a transport accepted, since their queue was made: each byte, and the body bytes
/// of them. Each count only grows, so a count at one time and a count later give the bytes
/// between them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Accepted {
    /// Each byte: framing, such as a head or a chunk-size line, and body bytes.
    pub(crate) bytes: u64,
    /// The body bytes.
    pub(crate) payload: u64,
}

impl Accepted {
    /// Adds `len` bytes, which are body bytes when `payload` is true.
    pub(crate) fn add(&mut self, len: u64, payload: bool) {
        self.bytes = self.bytes.strict_add(len);
        if payload {
            self.payload = self.payload.strict_add(len);
        }
    }
}

impl Outbound {
    /// Makes a queue for at most `limit` regions. It charges their memory to `budget` before it
    /// allocates it, and refuses with [`Kind::Overload`], with no allocation, when the budget
    /// cannot pay.
    pub fn new(limit: NonZeroUsize, budget: &Budget) -> Result<Self, Error> {
        let (regions, charge) = reserve(limit, budget)?;
        Ok(Self {
            regions,
            limit: limit.get(),
            _charge: charge,
            next: 0,
            outstanding: None,
            admitted: 0,
            admitted_bytes: 0,
            pushed: 0,
            accepted: Accepted::default(),
        })
    }

    /// The most regions that the queue holds.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The number of regions that the queue can take now.
    pub fn free(&self) -> usize {
        self.limit - self.regions.len()
    }

    /// Reports all pending output, the current offer, and the portion that the driver already owns.
    pub fn outstanding(&self) -> Outstanding {
        Outstanding {
            regions: self.regions.len(),
            bytes: self.pushed - self.accepted.bytes,
            submitted: self.outstanding,
            admitted_regions: self.admitted,
            admitted_bytes: self.admitted_bytes,
        }
    }

    /// Adds a region after the others. Gives it back if the queue is full or the ending byte offset exceeds `u64`.
    /// The queue drops empty regions.
    pub fn push(&mut self, region: Lease) -> Result<(), Lease> {
        self.queue(region, false)
    }

    /// Adds a region of body bytes after the others, as [`push`](Self::push) does. The queue
    /// counts the body bytes that the transport accepts apart from framing.
    pub(crate) fn push_payload(&mut self, region: Lease) -> Result<(), Lease> {
        self.queue(region, true)
    }

    fn queue(&mut self, region: Lease, payload: bool) -> Result<(), Lease> {
        let len = region.initialized();
        if len == 0 {
            return Ok(());
        }
        if self.regions.len() >= self.limit {
            return Err(region);
        }
        let Some(end) = self.pushed.checked_add(len as u64) else {
            return Err(region);
        };
        self.regions.push_back(Queued { region, payload });
        self.pushed = end;
        Ok(())
    }

    /// The bytes that the queue took, since it was made.
    pub(crate) fn pushed(&self) -> u64 {
        self.pushed
    }

    /// The bytes that the transport accepted, since the queue was made.
    pub(crate) fn accepted(&self) -> Accepted {
        self.accepted
    }

    /// Whether the front region holds body bytes.
    #[cfg(feature = "tls")]
    pub(crate) fn front_is_payload(&self) -> bool {
        self.regions.front().is_some_and(|queued| queued.payload)
    }

    /// Offers the next region in stream order. The driver already owns each region before it.
    ///
    /// Gives `None` until the host reports the previous offer, or when no region remains to offer.
    pub fn submit(&mut self) -> Option<Output> {
        if self.outstanding.is_some() {
            return None;
        }
        let region = self.regions.get(self.admitted)?.region.clone();
        let id = ActionId(self.next);
        self.next = self.next.checked_add(1)?;
        self.outstanding = Some(id);
        Some(Output { id, region })
    }

    /// Acknowledges that the transport accepted the first `accepted` bytes of output `id`.
    ///
    /// Give `0` when the transport accepted no byte, also when it refused the submission. The
    /// queue keeps a view of the bytes after the accepted ones for the next output. Refuses, and
    /// changes nothing, if the action is invalid or the count exceeds its bytes. A positive count
    /// requires kernel acceptance of all earlier regions. A refusal can always return the current offer.
    pub fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        let len = self.offered_len(id)?;
        if accepted > len {
            return Err(AckError::TooLarge);
        }
        if accepted > 0 && self.admitted != 0 {
            return Err(AckError::OutOfOrder);
        }
        self.consume(accepted as u64);
        self.outstanding = None;
        Ok(())
    }

    /// Records that the ordered driver took the whole offered region. Gives its ending byte offset.
    ///
    /// The host can now submit the next region. The queue retains the bytes until kernel acceptance.
    pub fn admit(&mut self, id: ActionId) -> Result<u64, AckError> {
        let len = self.offered_len(id)?;
        self.admitted_bytes = self.admitted_bytes.strict_add(len as u64);
        self.admitted += 1;
        self.outstanding = None;
        Ok(self.accepted.bytes.strict_add(self.admitted_bytes))
    }

    /// Records the total bytes the kernel accepted since the first output on this queue.
    ///
    /// The prefix can end inside a region. A repeated or older report adds no bytes.
    /// A report past the last admitted byte refuses and leaves the queue intact.
    pub fn accept_through(&mut self, end: u64) -> Result<(), AckError> {
        let bytes = end.saturating_sub(self.accepted.bytes);
        if bytes > self.admitted_bytes {
            return Err(AckError::TooLarge);
        }
        let retired = self.consume(bytes);
        self.admitted -= retired;
        self.admitted_bytes -= bytes;
        Ok(())
    }

    fn offered_len(&self, id: ActionId) -> Result<usize, AckError> {
        match self.outstanding {
            Some(offered) if offered == id => Ok(self.regions[self.admitted].region.initialized()),
            _ if id.0 < self.next => Err(AckError::Duplicate),
            _ => Err(AckError::Unknown),
        }
    }

    /// Advances a checked prefix over at most the queue's region limit and returns the number of retired regions.
    fn consume(&mut self, mut bytes: u64) -> usize {
        let before = self.regions.len();
        while bytes != 0 {
            let front = self
                .regions
                .front_mut()
                .expect("the accepted prefix fits the queued regions");
            let len = front.region.initialized();
            let take = len.min(usize::try_from(bytes).unwrap_or(usize::MAX));
            self.accepted.add(take as u64, front.payload);
            if take == len {
                self.regions.pop_front();
            } else {
                front.region = front.region.view(take..).expect("the suffix is within the region");
            }
            bytes -= take as u64;
        }
        before - self.regions.len()
    }
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("regions", &self.regions.len())
            .field("limit", &self.limit)
            .field("outstanding", &self.outstanding)
            .field("admitted", &self.admitted)
            .finish_non_exhaustive()
    }
}

/// The output of an [`Outbound`] queue that the transport has not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outstanding {
    /// The regions that the queue holds.
    pub regions: usize,
    /// The bytes of these regions.
    pub bytes: u64,
    /// The current offer that awaits an acknowledgement or admission.
    pub submitted: Option<ActionId>,
    /// The leading regions that the driver owns and the kernel has not fully accepted.
    pub admitted_regions: usize,
    /// The remaining bytes in those regions. The total in [`bytes`](Self::bytes) includes them.
    pub admitted_bytes: u64,
}

impl Outstanding {
    /// Whether the transport accepted each output.
    pub fn is_empty(&self) -> bool {
        self.regions == 0 && self.submitted.is_none()
    }
}

/// Makes an empty queue with space for `limit` items. It charges that memory to `budget` before
/// it allocates, and the permit pays for the queue until it drops.
pub(crate) fn reserve<T>(limit: NonZeroUsize, budget: &Budget) -> Result<(VecDeque<T>, Permit), Error> {
    let bytes = limit
        .get()
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| Error::new(Kind::Overload, "the queue is too large"))?;
    let charge = budget
        .reserve(bytes)
        .map_err(|_| Error::new(Kind::Overload, "the budget refused the queue"))?;
    let mut queue = VecDeque::new();
    queue
        .try_reserve_exact(limit.get())
        .map_err(|_| Error::new(Kind::Overload, "the memory for the queue is not available"))?;
    Ok((queue, charge))
}

/// A refused acknowledgement. It changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckError {
    /// The action had its acknowledgement before.
    Duplicate,
    /// No action has this identifier: the queue did not give it.
    Unknown,
    /// The byte count exceeds the available input region, output region, or admitted prefix.
    TooLarge,
    /// The host reported accepted bytes after an earlier region that still awaits kernel acceptance.
    OutOfOrder,
}

impl AckError {
    /// The fixed text of the refusal.
    const fn reason(self) -> &'static str {
        match self {
            Self::Duplicate => "the action had its acknowledgement before",
            Self::Unknown => "no action has this identifier",
            Self::TooLarge => "the acknowledgement exceeds the available bytes",
            Self::OutOfOrder => "an earlier output still awaits kernel acceptance",
        }
    }
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl core::error::Error for AckError {}

impl From<AckError> for Error {
    fn from(error: AckError) -> Self {
        Self::new(Kind::Misuse, error.reason())
    }
}

/// The refusal of a pool of regions, for example the receive regions of a socket. A call that
/// makes a pool can then refuse with `?`.
impl From<PoolRefused> for Error {
    fn from(refused: PoolRefused) -> Self {
        match refused {
            PoolRefused::Budget(_) => Self::new(Kind::Overload, "the budget refused the regions of a pool"),
            PoolRefused::Layout => Self::new(Kind::Misuse, "the regions of a pool have no valid layout"),
            PoolRefused::Allocation => {
                Self::new(Kind::Overload, "the memory for the regions of a pool is not available")
            }
        }
    }
}

/// The result of one drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Turn {
    /// What the engine needs next.
    pub progress: Progress,
    /// The earliest deadline of the engine's timers. Drive the engine again when it is reached,
    /// also if nothing else arrives. A new or earlier deadline replaces the host's wait on the
    /// same turn.
    pub deadline: Option<Deadline>,
}

/// The limits of the work of one drive, which the caller sets. One drive call is one turn.
///
/// An engine counts its work in each turn. At a limit, it stops between two steps and gives
/// [`Progress::Pending`]: work remains, so drive again with no wait for input. An event ends the
/// turn at once. A head or a trailer section that the engine starts to read in a turn ends in that
/// turn, because its own limit bounds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TurnLimits {
    /// The most received bytes that one turn reads: framing, discarded bytes, and body bytes.
    pub bytes: u64,
    /// The most frames that one turn decodes, for example the chunks of an HTTP/1.1 body.
    pub frames: usize,
    /// The most entries of its state that one turn visits, for example the sent packets that an
    /// ACK walks, or the streams whose notices it clears. An engine that keeps no such state
    /// visits none.
    pub visits: usize,
}

/// The work of an engine in one turn.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Work {
    bytes: u64,
    frames: usize,
    visits: usize,
}

impl Work {
    /// Counts `bytes` received bytes and `frames` frames.
    pub(crate) fn add(&mut self, bytes: usize, frames: usize) {
        self.bytes = self.bytes.saturating_add(bytes as u64);
        self.frames = self.frames.saturating_add(frames);
    }

    /// Counts one visit of an entry of the state, or gives `false` at a limit of `limits`: the
    /// visit then waits for the next turn.
    #[cfg_attr(
        not(feature = "tls"),
        expect(dead_code, reason = "only the QUIC engine, which needs TLS, counts visits")
    )]
    pub(crate) fn visit(&mut self, limits: &TurnLimits) -> bool {
        if self.reached(limits) {
            return false;
        }
        self.visits += 1;
        true
    }

    /// Whether the work reached a limit of `limits`. A turn makes at least one visit, and an engine
    /// that keeps no such state counts none.
    pub(crate) fn reached(&self, limits: &TurnLimits) -> bool {
        self.bytes >= limits.bytes || self.frames >= limits.frames || self.visits >= limits.visits.max(1)
    }
}

/// What an engine needs after a drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The engine can do nothing more until the host gives what the variant names.
    Blocked(Blocked),
    /// The engine stopped at a limit of the drive, and it has more work. Drive it again, with no
    /// wait for input.
    Pending,
    /// The engine ended: `Ok` when it completed, and the error when it failed.
    Terminal(Result<(), Error>),
}

/// What blocks an engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// More received bytes.
    Input,
    /// The acknowledgement of its outstanding output.
    Output,
    /// This many more bytes of capacity.
    Capacity(u64),
    /// A free stream slot: the engine reads no new stream of the peer until the application
    /// closes a stream that a reset ended, with
    /// [`h2::Connection::close`](crate::h2::Connection::close).
    Streams,
}

/// The error of an engine or a binding: a [`Kind`], which names the recovery, and a fixed reason.
///
/// The reason is fixed text of the code that refused. Thus no error holds peer text, a
/// credential, or a body, and its `Display` and `Debug` output show only the kind and the reason.
///
/// ```
/// use rsnetwork::drive::{Error, Kind};
///
/// let error = Error::new(Kind::Overload, "the connection has no free stream");
/// assert_eq!(error.kind(), Kind::Overload);
/// assert_eq!(error.to_string(), "overload: the connection has no free stream");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    reason: &'static str,
}

impl Error {
    /// Makes an error of `kind`. Give a fixed text as the reason, never text from a peer.
    pub const fn new(kind: Kind, reason: &'static str) -> Self {
        Self { kind, reason }
    }

    /// The kind of the error.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The fixed reason.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.reason)
    }
}

impl core::error::Error for Error {}

/// The kind of an [`Error`]. Each kind has its own recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The caller broke a contract of the API, or gave a configuration that cannot work. Correct
    /// the code or the configuration. A retry gives the same error.
    Misuse,
    /// The peer sent bytes that the protocol forbids. Refuse the message, and close the
    /// connection when the protocol cannot find the next message.
    Malformed,
    /// A trust check failed, for example a certificate chain or a name. Never downgrade.
    Trust,
    /// The peer or the operation needs a capability that this build or this peer does not have.
    Unsupported,
    /// A limit or a budget refused the work. Retry later, or with more capacity.
    Overload,
    /// The deadline came before the operation completed.
    Deadline,
    /// The caller cancelled the operation.
    Cancelled,
    /// Only a part of the data arrived or went before the end.
    Partial,
    /// The operation ended with no proof of whether the peer completed it. Retry it only if
    /// it is safe to do two times.
    Uncertain,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misuse => "misuse or configuration",
            Self::Malformed => "malformed peer input",
            Self::Trust => "trust failure",
            Self::Unsupported => "unsupported capability",
            Self::Overload => "overload",
            Self::Deadline => "deadline",
            Self::Cancelled => "cancellation",
            Self::Partial => "partial delivery",
            Self::Uncertain => "uncertain remote completion",
        })
    }
}
