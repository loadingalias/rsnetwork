//! One connection of the core on one Tokio TCP socket.

use core::future::poll_fn;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, ready};
use std::io;

use rsnetwork::buffer::Pool;
use rsnetwork::drive::{Error, Kind, Outstanding};
use rsnetwork::host::{Io, Next, Tcp};
use rsnetwork::time::{Deadline, Instant};
use tokio::net::TcpStream;
use tokio::task::coop;
use tokio::time::Sleep;

use crate::Clock;
use crate::stream::Stream;

/// The refusal of a wait that no event of the socket or the clock can end.
const CAPACITY: Error = Error::new(
    Kind::Overload,
    "the connection waits for capacity: drop the views of its received bytes, and call again",
);

/// One connection of the core on one Tokio TCP socket, with the [`Clock`]: the step of each call
/// of the binding.
///
/// [`until`](Self::until) calls the connection, moves its bytes with the rules of
/// [`host::Tcp`](rsnetwork::host::Tcp), and waits until the socket or a deadline can help. Thus
/// it drives each vocabulary of the core, also a [`Connection`](rsnetwork::host::Connection) of
/// your own engine. [`client::Http1`](crate::client::Http1),
/// [`client::Http2`](crate::client::Http2), [`server::Http`](crate::server::Http), and
/// [`tls::Stream`](crate::tls::Stream) are calls over it.
///
/// A socket that drops before the release of its connection, or with output that did not go,
/// resets the connection, as [`close`](Self::close) does.
#[derive(Debug)]
pub struct Socket<C: Io> {
    connection: C,
    /// The socket, until the close.
    tcp: Option<Tcp<Stream>>,
    clock: Clock,
}

/// What one turn of a call gave.
pub(crate) enum Turn<T> {
    /// The call gave its value, or `None` after the release.
    Done(Option<T>),
    /// Call again now: bytes moved, or the connection has more work.
    Now,
    /// Call again when the socket can read (`read`) or write (`write`), or at `deadline`.
    Wait {
        read: bool,
        write: bool,
        deadline: Option<Deadline>,
    },
}

impl<C: Io> Socket<C> {
    /// Binds `connection`, a connection of the core on the domain of the [`Clock`], to `stream`, a
    /// connected Tokio TCP socket, with `TCP_NODELAY`.
    ///
    /// `pool` gives the receive regions when the connection lends none: over TCP, and during the
    /// linger of a server. Charge it to the budget of the connection. A TLS connection lends its
    /// own input region, so one small slot is enough for it. Refuses with the error of the socket
    /// when it cannot set the option or read the two addresses.
    pub fn new(connection: C, stream: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self {
            connection,
            tcp: Some(Tcp::new(Stream(stream), pool)?),
            clock: Clock,
        })
    }

    /// The connection, for its calls that do not wait, for example its state.
    pub fn connection(&self) -> &C {
        &self.connection
    }

    /// The connection, for its calls that do not wait, for example a cancel.
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection
    }

    /// Calls `call` with the time now until it gives a value, and gives that value. After each
    /// call that gives `None`, it moves the bytes of the connection and waits as they say: until
    /// the socket can read or write what the connection waits for, or until its next deadline.
    /// Gives `None` when the connection released, and a call after the release gave `None` too.
    ///
    /// After the call that gives the value, it writes the output of that call, with no wait.
    /// Each turn that does not wait takes from the cooperative budget of the task, so a busy
    /// connection lets the other tasks of its thread run. Refuses with the error of `call` or of
    /// the socket, and with [`Kind::Overload`] when the connection waits only for capacity, which
    /// no event of the socket gives back: drop the views of its received bytes, and call again.
    ///
    /// Drop the future to stop waiting: the connection keeps its state, and the next call goes
    /// on from it.
    pub async fn until<T>(
        &mut self,
        mut call: impl FnMut(&mut C, Instant) -> Result<Option<T>, Error>,
    ) -> Result<Option<T>, Error> {
        let mut sleep = pin!(None);
        poll_fn(|cx| {
            loop {
                match self.turn(&mut call)? {
                    Turn::Done(value) => return Poll::Ready(Ok(value)),
                    Turn::Now => ready!(coop::poll_proceed(cx)).made_progress(),
                    Turn::Wait { read, write, deadline } => {
                        if !self.ready(cx, (read, write, deadline), sleep.as_mut()) {
                            return Poll::Pending;
                        }
                    }
                }
            }
        })
        .await
    }

    /// Calls `call` one time with the time now, and moves the bytes of the connection. After the
    /// call that gives a value, it writes the output of that call, with no wait. Refuses as
    /// [`until`](Self::until) says.
    pub(crate) fn turn<T>(
        &mut self,
        call: &mut impl FnMut(&mut C, Instant) -> Result<Option<T>, Error>,
    ) -> Result<Turn<T>, Error> {
        let tcp = self.tcp.as_mut().expect("the socket is there until the close");
        if let Some(value) = call(&mut self.connection, self.clock.now())? {
            // The output of the call goes now, also when the next call comes late. A pump
            // refuses only an input region, after its writes, and the next call meets that.
            let _pumped = tcp.pump(&mut self.connection);
            return Ok(Turn::Done(Some(value)));
        }
        Ok(match tcp.pump(&mut self.connection)? {
            Next::Now => Turn::Now,
            Next::Wait {
                read: false,
                write: false,
                deadline: None,
            } => return Err(CAPACITY),
            Next::Wait { read, write, deadline } => Turn::Wait { read, write, deadline },
            Next::Released => Turn::Done(call(&mut self.connection, self.clock.now())?),
        })
    }

    /// Makes `cx` wake when the socket can read (`read`) or write (`write`), or at `deadline`, on
    /// `sleep`. Gives whether one of them is ready now: then turn again.
    pub(crate) fn ready(
        &self,
        cx: &mut Context<'_>,
        (read, write, deadline): (bool, bool, Option<Deadline>),
        mut sleep: Pin<&mut Option<Sleep>>,
    ) -> bool {
        let stream = &self
            .tcp
            .as_ref()
            .expect("the socket is there until the close")
            .socket()
            .0;
        if (read && stream.poll_read_ready(cx).is_ready()) || (write && stream.poll_write_ready(cx).is_ready()) {
            return true;
        }
        let Some(deadline) = deadline else {
            return false;
        };
        let at = self.clock.tokio(deadline);
        match sleep.as_mut().as_pin_mut() {
            Some(timer) if timer.deadline() == at => {}
            Some(timer) => timer.reset(at),
            None => sleep.set(Some(tokio::time::sleep_until(at))),
        }
        sleep.as_pin_mut().is_some_and(|timer| timer.poll(cx).is_ready())
    }

    /// Moves the bytes of the connection until its release: its end, after the transport
    /// accepted each output. Gives the end of the connection. It gives the connection no time,
    /// so it is only for a connection whose release waits for no deadline, for example a client
    /// after its close.
    pub(crate) async fn release(&mut self) -> Result<C::End, Error> {
        let released = self.until(|connection, _| Ok(connection.release())).await?;
        released.ok_or(Error::new(Kind::Misuse, "the connection released with no end"))
    }

    /// Closes the socket, and gives the output of the connection that the socket did not accept.
    /// After the release of a connection with no such output, the peer reads the end of the
    /// stream. Else the close resets the socket, so the peer cannot read the cut as an end.
    pub fn close(mut self) -> Outstanding {
        self.shut()
    }

    /// Closes the socket one time, as [`close`](Self::close) says.
    fn shut(&mut self) -> Outstanding {
        match self.tcp.take() {
            Some(tcp) => tcp.close(&self.connection),
            None => self.connection.outstanding(),
        }
    }
}

impl<C: Io> Drop for Socket<C> {
    fn drop(&mut self) {
        // The output that did not go is lost with the connection: the reset tells the peer.
        let _lost = self.shut();
    }
}
