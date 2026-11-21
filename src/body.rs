//! The body model of the core, which each protocol shares: the terminal outcome of a body, its
//! trailers, a consumer that reads a body into regions of the caller, bounded collection, and the
//! bodies that a sender gives.
//!
//! An engine gives a received body as views of the received regions and then its [`Outcome`].
//! Only [`Outcome::Complete`] makes the bytes a complete value: a body that ends any other way
//! stays a part. The application can keep the views, which costs no copy, or a [`Consumer`] can
//! copy them into regions that the caller admits. Collection into one region is an explicit,
//! bounded operation: no hidden buffer exists.
//!
//! ```
//! use rsnetwork::body::{Collect, Consumer, Outcome};
//! use rsnetwork::buffer::{Lease, WriteLoan};
//!
//! // The engine gave two parts of a body, and then its end.
//! let mut consumer = Consumer::new();
//! let mut region = WriteLoan::new(Vec::with_capacity(16));
//! consumer.data(Lease::from(b"hello, ".to_vec())).expect("no bytes wait");
//! assert!(matches!(consumer.collect(&mut region), Collect::More));
//! consumer.data(Lease::from(b"world".to_vec())).expect("no bytes wait");
//! consumer.end(Outcome::Complete(None));
//!
//! // The body is complete only now: after its last byte and its outcome.
//! assert!(matches!(consumer.collect(&mut region), Collect::Complete(None)));
//! assert_eq!(region.filled(), b"hello, world");
//! ```

use core::fmt;

use rstypes::buffer::{Buffer as _, BufferMut, Lease, WriteLoan};

use crate::h1::Fields;

/// The terminal outcome of a body. Only `Complete` makes the bytes a complete value.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// The body ended as its framing says: at its length, after its last chunk and its trailers,
    /// or at the end of input when the end of input delimits it.
    Complete(Option<Trailers>),
    /// The input ended inside a body with a length or with chunked framing (EOF).
    Truncated,
    /// The peer reset the stream or the connection, with the code of a protocol that has one.
    Reset(Option<u64>),
    /// The application cancelled the body.
    Cancelled,
    /// The framing of the body broke the rules of its protocol.
    Malformed,
}

/// The trailer section of a body: a view of its field lines in the received region.
#[derive(Clone)]
pub struct Trailers {
    /// The field lines, each with its CR LF. The decoder checked each of them.
    pub(crate) lines: Lease,
}

impl Trailers {
    /// The trailer fields, in their received order.
    pub fn fields(&self) -> Fields<'_> {
        Fields {
            block: self.lines.bytes(),
        }
    }
}

impl fmt::Debug for Trailers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trailers").finish_non_exhaustive()
    }
}

/// Reads one body into regions that the caller admits, with its terminal outcome.
///
/// The consumer holds at most one waiting part. It takes the next part only after
/// [`read_into`](Self::read_into) copied the waiting one, so the regions of the caller pace the
/// body. Each copy goes straight from the received region into the caller's region, and the
/// caller's [`WriteLoan`] records its exact extent. The outcome shows only after the last waiting
/// byte, so the body is complete only after its bytes, its trailers, and its outcome.
pub struct Consumer {
    /// The part whose bytes wait for a read.
    waiting: Option<Lease>,
    outcome: Option<Outcome>,
    /// The body bytes that the consumer copied or gave so far.
    delivered: u64,
}

/// What [`Consumer::read_into`] did.
#[derive(Debug)]
pub enum Read<'a> {
    /// It copied this many bytes into the region.
    Bytes(usize),
    /// Bytes wait, and the region has no free capacity: give another region.
    Full,
    /// No byte waits: give the next part of the body.
    Wait,
    /// The body ended with this outcome after its last byte.
    Done(&'a Outcome),
}

/// What [`Consumer::collect`] found.
#[derive(Clone, Debug)]
pub enum Collect {
    /// The region holds each byte so far: give the next part of the body.
    More,
    /// The region holds the whole body, which is a complete value with these trailers.
    Complete(Option<Trailers>),
    /// The body is longer than the region. The region holds its first `collected` bytes, and the
    /// rest waits in the consumer.
    TooLarge {
        /// The body bytes that the region holds.
        collected: u64,
    },
    /// The body ended with an outcome that is not complete. The region holds the bytes that
    /// arrived, which are not a complete value.
    Interrupted(Outcome),
}

impl Consumer {
    /// Makes a consumer of one body.
    pub const fn new() -> Self {
        Self {
            waiting: None,
            outcome: None,
            delivered: 0,
        }
    }

    /// Takes the next part of the body: a view of a received region. Gives it back while the
    /// bytes of the part before it wait, and after the end: read first.
    pub fn data(&mut self, data: Lease) -> Result<(), Lease> {
        if self.waiting.is_some() || self.outcome.is_some() {
            return Err(data);
        }
        if data.initialized() > 0 {
            self.waiting = Some(data);
        }
        Ok(())
    }

    /// Takes the terminal outcome of the body. The first outcome stays: a later one changes
    /// nothing.
    pub fn end(&mut self, outcome: Outcome) {
        self.outcome.get_or_insert(outcome);
    }

    /// Copies the waiting bytes into the free capacity of `region`, as many as fit.
    pub fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Read<'_> {
        if let Some(waiting) = &self.waiting {
            let copied = region.fill_from(waiting.bytes());
            if copied == 0 {
                return Read::Full;
            }
            self.waiting = waiting.view(copied..).filter(|rest| rest.initialized() > 0);
            self.delivered += copied as u64;
            return Read::Bytes(copied);
        }
        match &self.outcome {
            Some(outcome) => Read::Done(outcome),
            None => Read::Wait,
        }
    }

    /// Collects the waiting bytes into `region`, and the outcome after them. The free capacity of
    /// `region` is the bound of the collection.
    ///
    /// Call it after each part. It gives [`Collect::Complete`] only for a complete body. A body
    /// past the bound refuses with [`Collect::TooLarge`], and the region keeps its first bytes.
    pub fn collect<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Collect {
        loop {
            match self.read_into(region) {
                Read::Bytes(_) => {}
                Read::Full => {
                    return Collect::TooLarge {
                        collected: self.delivered,
                    };
                }
                Read::Wait => return Collect::More,
                Read::Done(Outcome::Complete(trailers)) => return Collect::Complete(trailers.clone()),
                Read::Done(outcome) => return Collect::Interrupted(outcome.clone()),
            }
        }
    }

    /// Whether the consumer takes the next part of the body: no byte waits, and the body has not
    /// ended. Then [`read_into`](Self::read_into) gives [`Read::Wait`].
    pub fn wants_data(&self) -> bool {
        self.waiting.is_none() && self.outcome.is_none()
    }

    /// Takes the waiting bytes as a view of their received region, with no copy, or gives `None`
    /// when no byte waits.
    pub fn take(&mut self) -> Option<Lease> {
        let waiting = self.waiting.take()?;
        self.delivered += waiting.initialized() as u64;
        Some(waiting)
    }

    /// The terminal outcome of the body, after its last waiting byte, or `None` before it.
    pub fn outcome(&self) -> Option<&Outcome> {
        self.waiting.is_none().then_some(self.outcome.as_ref()).flatten()
    }

    /// The body bytes that the consumer copied or gave so far.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }
}

impl Default for Consumer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Consumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumer")
            .field("waiting", &self.waiting.as_ref().map(|waiting| waiting.initialized()))
            .field("outcome", &self.outcome)
            .field("delivered", &self.delivered)
            .finish()
    }
}

/// A body to send.
#[derive(Clone)]
pub enum Body {
    /// No body.
    Empty,
    /// Each byte now, in one region. A sender can send it again, for example after a redirect.
    Buffered(Lease),
    /// Bytes that the application produces once, in their order, with their length if it knows
    /// it. A sender cannot send them again.
    OneShot {
        /// The length of the body, if the application knows it before the first byte.
        length: Option<u64>,
    },
}

impl Body {
    /// The length of the body, if it is known before its first byte.
    pub fn length(&self) -> Option<u64> {
        match self {
            Self::Empty => Some(0),
            Self::Buffered(bytes) => Some(bytes.initialized() as u64),
            Self::OneShot { length } => *length,
        }
    }

    /// Whether a sender can send the body again, for example after a redirect or for a retry.
    pub fn replayable(&self) -> bool {
        match self {
            Self::Empty | Self::Buffered(_) => true,
            Self::OneShot { .. } => false,
        }
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Body")
            .field("length", &self.length())
            .field("replayable", &self.replayable())
            .finish()
    }
}
