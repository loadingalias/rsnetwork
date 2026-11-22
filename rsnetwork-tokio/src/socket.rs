//! One connection of the core on one Tokio TCP socket.

use core::future::poll_fn;
use core::pin::pin;
use core::task::Poll;
use std::io;

use rsnetwork::buffer::Pool;
use rsnetwork::drive::{Error, Kind, Outstanding};
use rsnetwork::host::{Io, Next, Tcp};
use rsnetwork::time::{Deadline, Instant};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::coop;

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
/// [`server::Http1`](crate::server::Http1), and [`tls::Stream`](crate::tls::Stream) are calls
/// over it.
///
/// A socket that drops before the release of its connection, or with output that did not go,
/// resets the connection, as [`close`](Self::close) does.
#[derive(Debug)]
pub struct Socket<C: Io> {
    connection: C,
    /// The socket, until the close.
    tcp: Option<Tcp<Stream>>,
    clock: Clock,
    close: Option<Close<C>>,
}

/// The close of a server, which a connection of its own sees in each wait.
#[derive(Debug)]
struct Close<C> {
    signal: watch::Receiver<Option<Deadline>>,
    /// Starts the close of the connection, for example its drain.
    start: fn(&mut C, Deadline, Instant) -> Result<(), Error>,
    started: bool,
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
            close: None,
        })
    }

    /// Makes each wait see the close of a server: then `start` begins the close of the
    /// connection, one time.
    pub(crate) fn with_close(
        mut self,
        signal: watch::Receiver<Option<Deadline>>,
        start: fn(&mut C, Deadline, Instant) -> Result<(), Error>,
    ) -> Self {
        self.close = Some(Close {
            signal,
            start,
            started: false,
        });
        self
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
        loop {
            self.closing()?;
            let tcp = self.tcp.as_mut().expect("the socket is there until the close");
            if let Some(value) = call(&mut self.connection, self.clock.now())? {
                // The output of the call goes now, also when the next call comes late. A pump
                // refuses only an input region, after its writes, and the next call meets that.
                let _pumped = tcp.pump(&mut self.connection);
                return Ok(Some(value));
            }
            match tcp.pump(&mut self.connection)? {
                Next::Now => coop::consume_budget().await,
                Next::Wait { read, write, deadline } => self.wait(read, write, deadline).await?,
                Next::Released => return call(&mut self.connection, self.clock.now()),
            }
        }
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

    /// Starts the close of the connection, one time, after the server signalled its close.
    fn closing(&mut self) -> Result<(), Error> {
        let Some(close) = &mut self.close else {
            return Ok(());
        };
        if close.started {
            return Ok(());
        }
        let Some(deadline) = *close.signal.borrow_and_update() else {
            return Ok(());
        };
        close.started = true;
        (close.start)(&mut self.connection, deadline, self.clock.now())
    }

    /// Waits until the socket can read (`read`) or write (`write`), until `deadline`, or until the
    /// server signals its close.
    async fn wait(&mut self, read: bool, write: bool, deadline: Option<Deadline>) -> Result<(), Error> {
        if !read && !write && deadline.is_none() {
            return Err(CAPACITY);
        }
        let signalled = {
            let stream = &self
                .tcp
                .as_ref()
                .expect("the socket is there until the close")
                .socket()
                .0;
            let mut sleep = pin!(deadline.map(|deadline| tokio::time::sleep_until(self.clock.tokio(deadline))));
            let signal = self.close.as_mut().filter(|close| !close.started);
            let mut changed = pin!(signal.map(|close| close.signal.changed()));
            poll_fn(|cx| {
                if let Some(Poll::Ready(changed)) = changed.as_mut().as_pin_mut().map(|changed| changed.poll(cx)) {
                    return Poll::Ready(changed.is_ok());
                }
                let ready = (read && stream.poll_read_ready(cx).is_ready())
                    || (write && stream.poll_write_ready(cx).is_ready())
                    || sleep
                        .as_mut()
                        .as_pin_mut()
                        .is_some_and(|sleep| sleep.poll(cx).is_ready());
                if ready { Poll::Ready(true) } else { Poll::Pending }
            })
            .await
        };
        // A server that dropped its signal closes no more connections.
        if !signalled {
            self.close = None;
        }
        Ok(())
    }
}

impl<C: Io> Drop for Socket<C> {
    fn drop(&mut self) {
        // The output that did not go is lost with the connection: the reset tells the peer.
        let _lost = self.shut();
    }
}
