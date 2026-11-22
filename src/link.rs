//! The transport of one connection of the application API: TCP, or TLS over TCP. The HTTP/1.1
//! client and server drive their engine through it, and the host moves its bytes with the same
//! calls as a [`Connection`].

use core::num::NonZeroUsize;

use rstypes::buffer::Backing;
use rstypes::capacity::Budget;
use rstypes::time::{Deadline, Instant};

#[cfg(feature = "tls")]
use crate::drive::Kind;
use crate::drive::{Accepted, AckError, ActionId, Endpoint, Error, Inbound, Outbound, Output, Outstanding, Received};
use crate::host::{Connection, Engine, Io, Wait};
#[cfg(feature = "tls")]
use crate::tls::{Closure, ExportError, Negotiated, Tls};

/// The transport of a connection.
#[derive(Debug)]
#[cfg_attr(
    feature = "tls",
    expect(
        clippy::large_enum_variant,
        reason = "a connection holds its one transport in place, and a box would add an allocation to each TLS connection"
    )
)]
pub(crate) enum Link<E> {
    Plain(Connection<E>),
    #[cfg(feature = "tls")]
    Tls(Connection<Tls<E>>),
}

/// Runs `$body` with `$connection` bound to the connection of each transport.
macro_rules! each {
    ($link:expr, $connection:ident => $body:expr) => {
        match $link {
            Link::Plain($connection) => $body,
            #[cfg(feature = "tls")]
            Link::Tls($connection) => $body,
        }
    };
}

impl<E: Engine> Link<E> {
    /// The engine and its plaintext output queue.
    pub(crate) fn engine(&mut self) -> (&mut E, &mut Outbound) {
        match self {
            Self::Plain(connection) => connection.parts(),
            #[cfg(feature = "tls")]
            Self::Tls(connection) => connection.parts().0.parts(),
        }
    }

    /// Drives the connection one time at `now`.
    pub(crate) fn drive(&mut self, now: Instant) -> Result<Option<E::Event>, Error> {
        each!(self, connection => connection.drive(Some(now)))
    }

    /// The refusal, with `reason`, of a TLS connection on which ALPN selected a protocol other
    /// than HTTP/1.1.
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            unused_variables,
            reason = "a connection with no TLS has no ALPN, so it never refuses"
        )
    )]
    pub(crate) fn refused(&mut self, reason: &'static str) -> Option<Error> {
        #[cfg(feature = "tls")]
        if let Some(Negotiated {
            protocol: Some(protocol),
            ..
        }) = self.negotiated()
            && protocol != b"http/1.1"
        {
            return Some(Error::new(Kind::Unsupported, reason));
        }
        None
    }

    pub(crate) fn wait(&self) -> Wait {
        each!(self, connection => connection.wait())
    }

    #[expect(
        clippy::result_large_err,
        reason = "a refusal gives the caller back its region and facts, and a box would make each refusal allocate"
    )]
    pub(crate) fn receive(&mut self, received: Received) -> Result<(), Received> {
        each!(self, connection => connection.receive(received))
    }

    pub(crate) fn region(&mut self) -> Result<Option<Backing>, Error> {
        each!(self, connection => connection.region())
    }

    pub(crate) fn received(&mut self, region: Backing, endpoint: Endpoint, capacity: u64) -> Result<(), Backing> {
        each!(self, connection => connection.received(region, endpoint, capacity))
    }

    pub(crate) fn end_input(&mut self) {
        each!(self, connection => connection.end_input());
    }

    pub(crate) fn reset(&mut self) {
        each!(self, connection => connection.reset());
    }

    /// Whether the transport failed.
    pub(crate) fn is_reset(&self) -> bool {
        each!(self, connection => connection.is_reset())
    }

    pub(crate) fn output_region(&mut self, region: Backing) -> Result<(), (Error, Backing)> {
        each!(self, connection => connection.output_region(region))
    }

    pub(crate) fn take_output_region(&mut self) -> Option<Backing> {
        each!(self, connection => connection.take_output_region())
    }

    pub(crate) fn output(&mut self) -> Option<Output> {
        each!(self, connection => connection.output())
    }

    pub(crate) fn ack(&mut self, id: ActionId, accepted: usize) -> Result<(), AckError> {
        each!(self, connection => connection.ack(id, accepted))
    }

    pub(crate) fn outstanding(&self) -> Outstanding {
        each!(self, connection => connection.outstanding())
    }

    pub(crate) fn release(&self) -> Option<Result<(), Error>> {
        each!(self, connection => connection.release())
    }

    /// The bytes of the plaintext output that the transport accepted: exact over TCP, and in
    /// whole records over TLS.
    pub(crate) fn accepted(&self) -> Accepted {
        match self {
            Self::Plain(connection) => connection.queue().accepted(),
            #[cfg(feature = "tls")]
            Self::Tls(connection) => connection.engine().sent(connection.queue().accepted().bytes),
        }
    }

    /// The bytes of the plaintext output that the engine queued.
    pub(crate) fn pushed(&mut self) -> u64 {
        self.engine().1.pushed()
    }

    /// What the TLS handshake negotiated, or `None` before it completed and over TCP.
    #[cfg(feature = "tls")]
    pub(crate) fn negotiated(&mut self) -> Option<Negotiated<'_>> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(connection) => connection.parts().0.negotiated(),
        }
    }

    /// Derives exporter material of a TLS connection, as [`Tls::export`] does. Over TCP, refuses
    /// with [`ExportError::Unavailable`].
    #[cfg(feature = "tls")]
    pub(crate) fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        match self {
            Self::Plain(_) => {
                output.fill(0);
                Err(ExportError::Unavailable)
            }
            Self::Tls(connection) => connection.export(label, context, output),
        }
    }

    /// How the input of a TLS connection ended, or `None` before its end and over TCP.
    #[cfg(feature = "tls")]
    pub(crate) fn closure(&mut self) -> Option<Closure> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(connection) => connection.parts().0.closure(),
        }
    }
}

/// The two queues of one connection, each for at most `limit` regions.
pub(crate) fn queues(limit: NonZeroUsize, budget: &Budget) -> Result<(Inbound, Outbound), Error> {
    Ok((Inbound::new(limit, budget)?, Outbound::new(limit, budget)?))
}

/// The earlier of two deadlines.
pub(crate) fn earliest(a: Option<Deadline>, b: Option<Deadline>) -> Option<Deadline> {
    match (a, b) {
        (Some(a), Some(b)) => Some(match a.instant().compare(b.instant()) {
            Ok(core::cmp::Ordering::Greater) => b,
            _ => a,
        }),
        (a, b) => a.or(b),
    }
}
