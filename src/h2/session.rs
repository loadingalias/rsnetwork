//! The HTTP/2 engine of the client and server vocabulary: a [`Connection`] that the host drives,
//! whose header sections come up as checked heads, and the bounded queue of the body bytes of one
//! stream.

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Permit};
use rstypes::time::Instant;

use super::connection::{Connection, Event};
use super::frame::ErrorCode;
use super::message::{self, Answer, Refusal, Request};
use super::{Limits, Role};
use crate::body::{Consumer, Outcome};
use crate::drive::{Error, Inbound, Kind, Outbound, Progress, Turn, TurnLimits};
use crate::hpack::Lines;

/// An event of a [`Session`].
pub(crate) enum Step {
    /// A request on a new stream of a server.
    Request {
        stream: u32,
        end_stream: bool,
        head: Result<Request, Refusal>,
    },
    /// A response section on a stream of a client.
    Response {
        stream: u32,
        end_stream: bool,
        answer: Result<Answer, Refusal>,
    },
    /// The trailer section of a stream: its fields as `name: value` and CR LF.
    Trailers {
        stream: u32,
        trailers: Result<Lease, Refusal>,
    },
    /// A header section larger than `SETTINGS_MAX_HEADER_LIST_SIZE`. The HPACK state stayed in
    /// step, so the connection goes on.
    TooLarge {
        stream: u32,
    },
    Data {
        stream: u32,
        data: Lease,
        end_stream: bool,
    },
    /// The peer reset the stream, or one of its frames was a stream error that reset it.
    Reset {
        stream: u32,
        code: ErrorCode,
    },
    /// The chunk of the stream is all in the output queue.
    Sent {
        stream: u32,
    },
    GoAway {
        last_stream: u32,
    },
}

/// One HTTP/2 connection of the vocabulary, with the one decode buffer of its header blocks.
pub(crate) struct Session {
    connection: Connection,
    lines: Lines,
    budget: Budget,
}

impl Session {
    /// Makes the connection of `role`, which keeps the slot of each stream until the vocabulary
    /// closes it. A server also tracks the delivery of each stream.
    pub(crate) fn new(
        role: Role,
        limits: Limits,
        turn: TurnLimits,
        outbound: &mut Outbound,
        budget: &Budget,
    ) -> Result<Self, Error> {
        let mut connection = Connection::new(role, limits, turn, outbound, budget)?;
        connection.hold_streams();
        if role == Role::Server {
            connection.track(outbound, budget)?;
        }
        let lines = Lines::new(connection.header_limits(), budget)?;
        Ok(Self {
            connection,
            lines,
            budget: budget.clone(),
        })
    }

    pub(crate) fn connection(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Drives the connection one time. An event that the vocabulary does not use, such as the
    /// peer's settings, makes the turn pending, so the host drives again at once.
    pub(crate) fn drive(
        &mut self,
        inbound: &mut Inbound,
        outbound: &mut Outbound,
        now: Option<Instant>,
    ) -> (Option<Step>, Turn) {
        let Self {
            connection,
            lines,
            budget,
        } = self;
        let server = connection.role() == Role::Server;
        let (event, mut turn) = connection.drive(inbound, outbound, lines, now);
        let step = match event {
            Some(Event::Headers {
                stream,
                end_stream,
                lines: Some(block),
            }) => Some(if server {
                Step::Request {
                    stream,
                    end_stream,
                    head: message::request(block, budget),
                }
            } else {
                Step::Response {
                    stream,
                    end_stream,
                    answer: message::response(block, budget),
                }
            }),
            Some(
                Event::Headers {
                    stream, lines: None, ..
                }
                | Event::Trailers { stream, lines: None },
            ) => Some(Step::TooLarge { stream }),
            Some(Event::Trailers {
                stream,
                lines: Some(block),
            }) => Some(Step::Trailers {
                stream,
                trailers: message::trailers(block, budget),
            }),
            Some(Event::Data {
                stream,
                data,
                end_stream,
            }) => Some(Step::Data {
                stream,
                data,
                end_stream,
            }),
            Some(Event::Reset { stream, code } | Event::StreamError { stream, code }) => {
                Some(Step::Reset { stream, code })
            }
            Some(Event::Sent { stream }) => Some(Step::Sent { stream }),
            Some(Event::GoAway { last_stream, .. }) => Some(Step::GoAway { last_stream }),
            Some(Event::Settings(_) | Event::PingAck(_)) => {
                turn.progress = Progress::Pending;
                None
            }
            None => None,
        };
        (step, turn)
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

/// The most received parts that one stream keeps as views of their received regions. A part
/// after them is copied into one charged buffer of the stream, so a peer that sends many small
/// DATA frames makes the stream hold no more than its receive window.
const VIEWS: usize = 4;

/// The received body of one stream: views of the received regions in their order, then the bytes
/// that the views had no place for, and the consumer that gives them to the application.
///
/// The credit of a byte goes back to the peer when the application read it, through the
/// consumer, so the peer sends at most the receive window ahead of the application.
#[derive(Debug, Default)]
pub(crate) struct Inflow {
    consumer: Consumer,
    views: [Option<Lease>; VIEWS],
    /// The first view, in the ring of `views`, and the number of views.
    first: usize,
    count: usize,
    /// The bytes after the views, and the charge of their capacity.
    spill: Option<(Vec<u8>, Permit)>,
    /// The outcome that comes after the bytes that wait.
    outcome: Option<Outcome>,
    /// The bytes that the peer sent.
    received: u64,
    /// The bytes that the stream discarded, with no read: their credit goes back at once.
    discarded: u64,
    /// The bytes whose credit went back to the peer.
    credited: u64,
}

impl Inflow {
    /// Takes `data`, the next bytes of the body. Refuses with [`Kind::Overload`] when the budget
    /// cannot pay for the copy of a part that has no view: reset the stream.
    pub(crate) fn data(&mut self, data: Lease, budget: &Budget) -> Result<(), Error> {
        let len = data.initialized();
        if len == 0 {
            return Ok(());
        }
        if self.spill.is_none() && self.count < VIEWS {
            self.views[(self.first + self.count) % VIEWS] = Some(data);
            self.count += 1;
        } else {
            let (mut bytes, charge) = match self.spill.take() {
                Some((bytes, charge)) => (bytes, Some(charge)),
                None => (Vec::new(), None),
            };
            let need = bytes.len().saturating_add(len);
            let charge = match charge {
                Some(charge) if need <= bytes.capacity() => charge,
                _ => {
                    let capacity = need.max(bytes.capacity().saturating_mul(2));
                    let more = budget.reserve(capacity as u64).map_err(|_| overload())?;
                    bytes
                        .try_reserve_exact(capacity - bytes.len())
                        .map_err(|_| overload())?;
                    more
                }
            };
            bytes.extend_from_slice(data.bytes());
            self.spill = Some((bytes, charge));
        }
        self.received = self.received.saturating_add(len as u64);
        self.feed();
        Ok(())
    }

    /// Discards `data`, which the stream does not keep because it ends: only its credit counts.
    pub(crate) fn discard(&mut self, data: Lease) {
        let len = data.initialized() as u64;
        self.received = self.received.saturating_add(len);
        self.discarded = self.discarded.saturating_add(len);
    }

    /// Whether no part and no end wait for a read.
    pub(crate) fn waits(&self) -> bool {
        self.consumer.wants_data() && self.count == 0 && self.spill.is_none() && self.outcome.is_none()
    }

    /// Takes the end of the body. The first end stays.
    pub(crate) fn end(&mut self, outcome: Outcome) {
        self.outcome.get_or_insert(outcome);
        self.feed();
    }

    /// The bytes that the peer sent.
    pub(crate) fn received(&self) -> u64 {
        self.received
    }

    /// Whether the end of the body came, also if bytes still wait for a read.
    pub(crate) fn ended(&self) -> bool {
        self.outcome.is_some() || self.consumer.outcome().is_some()
    }

    /// The consumer, for the reads of the application. Call [`feed`](Self::feed) after each read.
    pub(crate) fn consumer(&mut self) -> &mut Consumer {
        &mut self.consumer
    }

    /// Gives the consumer the next part when it takes one, and the outcome after the last part.
    pub(crate) fn feed(&mut self) {
        if !self.consumer.wants_data() {
            return;
        }
        let part = if self.count > 0 {
            let view = self.views[self.first].take();
            self.first = (self.first + 1) % VIEWS;
            self.count -= 1;
            view
        } else {
            self.spill.take().map(|(bytes, charge)| message::charged(bytes, charge))
        };
        match part {
            Some(part) => {
                let taken = self.consumer.data(part);
                assert!(taken.is_ok(), "the consumer wants data");
            }
            None => {
                if let Some(outcome) = self.outcome.take() {
                    self.consumer.end(outcome);
                }
            }
        }
    }

    /// The bytes that the application read since the last call, whose credit goes back to the
    /// peer.
    pub(crate) fn take_credit(&mut self) -> u32 {
        let consumed = self.consumer.delivered().saturating_add(self.discarded);
        let due = consumed.saturating_sub(self.credited);
        let due = u32::try_from(due).unwrap_or(u32::MAX);
        self.credited += u64::from(due);
        due
    }

    /// Gives back the credit `bytes` that the peer did not get, for the next call.
    pub(crate) fn untake_credit(&mut self, bytes: u32) {
        self.credited = self.credited.saturating_sub(u64::from(bytes));
    }

    /// Drops the bytes that wait, because the stream ends, and gives the credit of each byte that
    /// the peer did not get back.
    pub(crate) fn drop_rest(&mut self) -> u32 {
        self.views = Default::default();
        self.count = 0;
        self.spill = None;
        self.consumer = Consumer::new();
        let due = self.received.saturating_sub(self.credited);
        self.credited = self.received;
        u32::try_from(due).unwrap_or(u32::MAX)
    }
}

fn overload() -> Error {
    Error::new(Kind::Overload, "the budget refused the copy of a part of a body")
}
