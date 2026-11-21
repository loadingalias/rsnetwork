//! The binding of a caller-driven host to a nonblocking std TCP socket.

use core::time::Duration;
use std::io::{self, BorrowedBuf, ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpStream};

use rstypes::buffer::{Backing, Buffer as _, BufferMut as _, Pool, WriteLoan};
use rstypes::time::Deadline;

use super::{Io, Wait};
use crate::drive::{Blocked, Ecn, Endpoint, Error, Outstanding, Received};

/// One nonblocking std TCP socket, which moves the bytes of one connection of a caller-driven
/// host: a [`Connection`](super::Connection), a `client::Http1`, a `server::Http1`, or a
/// `tls::Stream`.
///
/// The application owns the event loop, its poller, and its clock. In each turn, it calls the
/// connection, for example `client.response(now)`, then [`pump`](Self::pump), and does what
/// [`Next`] says. The socket spawns no task, starts no thread, and needs no runtime.
///
/// - **Receive.** A pump reads one time when the connection waits for input or lingers. It reads
///   into the region that the connection lends, which a TLS connection decrypts in place, or else
///   into a slot of its pool. Its reads fill each slot one after the other, so a short read keeps
///   no slot for itself. The end of input goes to [`Io::end_input`], and a failure of the socket
///   goes to [`Io::reset`].
/// - **Send.** A pump writes each output until the socket takes only part of one, and acknowledges
///   the exact bytes. [`new`](Self::new) sets `TCP_NODELAY`, because each output region is its own
///   write.
/// - **Linger.** At [`Wait::Linger`], after the last output, a pump shuts down the write side of
///   the socket one time.
/// - **Close.** At the release of the connection, a pump shuts down the write side after the
///   last output. [`close`](Self::close) closes the socket. Before the release, or with output
///   that did not go, it resets the connection, so the peer cannot read the close as the end of
///   the data.
///
/// A client and a server exchange one request over loopback. This loop does not wait: a real loop
/// waits in its poller as each [`Next::Wait`] says.
///
/// ```
/// use core::alloc::Layout;
/// use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
/// use core::time::Duration;
/// use std::net::{TcpListener, TcpStream};
///
/// use rsnetwork::body::Part;
/// use rsnetwork::buffer::{Buffer as _, Lease, Pool};
/// use rsnetwork::capacity::Budget;
/// use rsnetwork::client::{self, Request};
/// use rsnetwork::drive::TurnLimits;
/// use rsnetwork::h1::{self, BodyLimits, Framing};
/// use rsnetwork::host::{Io as _, Next, Tcp};
/// use rsnetwork::server::{self, Linger, Response};
/// use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
/// use rsnetwork::value::{Authority, Method, Status, Target};
///
/// let head = h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
/// let body = BodyLimits {
///     body_bytes: 1 << 20,
///     drain_bytes: 64 * 1024,
///     extension_bytes: 256,
///     trailer_bytes: 4 * 1024,
///     trailer_fields: 16,
/// };
/// let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
/// let queue = NonZeroUsize::new(16).expect("not zero");
/// let linger = Linger { time: Duration::from_secs(5), bytes: 64 * 1024 };
/// let budget = Budget::new(NonZeroU64::new(1 << 22).expect("not zero"));
///
/// // The monotonic clock of the host.
/// let clock = ClockDomain::new(1, Suspend::Pauses);
/// let start = std::time::Instant::now();
/// let now = || Instant::new(clock, u64::try_from(start.elapsed().as_nanos()).expect("in range"));
///
/// // Each socket has 4 receive regions of 16 KiB, charged to the budget.
/// let slot = Layout::array::<u8>(16 * 1024)?;
/// let pool = || Pool::new(&budget, NonZeroU32::new(4).expect("not zero"), slot);
/// let listener = TcpListener::bind("127.0.0.1:0")?;
/// let mut near = Tcp::new(TcpStream::connect(listener.local_addr()?)?, pool()?)?;
/// let mut far = Tcp::new(listener.accept()?.0, pool()?)?;
///
/// let mut client = client::Http1::plain(client::Limits { head, body, turn, queue }, clock, &budget)?;
/// let limits = server::Limits { head, body, turn, queue, head_timeout: Some(Duration::from_secs(30)), linger };
/// let mut server = server::Http1::plain(limits, clock, &budget)?;
///
/// let request = Request {
///     method: Method::GET,
///     target: Target::new(b"/hello")?,
///     authority: Authority::new(b"127.0.0.1")?,
///     fields: &[],
///     body: Framing::Length(0),
/// };
/// let deadline = Deadline::at(Instant::new(clock, 30_000_000_000));
/// client.send(&request, deadline, now())?;
/// let (mut answered, mut response, mut received, mut closed) = (false, None, Vec::new(), false);
/// loop {
///     // Call each connection: only its calls drive it.
///     if server.request(now())?.is_some() {
///         let hello = Response { status: Status::new(200)?, fields: &[], body: Framing::Length(5) };
///         answered = server.respond(&hello, now())?;
///         server.write(&Lease::from(b"hello".to_vec()), now())?;
///         server.finish(now())?;
///     }
///     if response.is_none() {
///         response = client.response(now())?;
///     }
///     while response.is_some() && !closed && let Some(part) = client.next(now())? {
///         match part {
///             Part::Data(data) => received.extend_from_slice(data.bytes()),
///             Part::End(_) => {
///                 client.close(now())?;
///                 closed = true;
///             }
///         }
///     }
///     // Then pump each socket.
///     if (near.pump(&mut client)?, far.pump(&mut server)?) == (Next::Released, Next::Released) {
///         break;
///     }
/// }
/// assert!(answered);
/// assert_eq!(received, b"hello");
/// assert_eq!(client.release(), Some(Ok(())));
/// assert_eq!(server.release().map(|closed| closed.result), Some(Ok(())));
/// assert!(near.close(&client).is_empty() && far.close(&server).is_empty());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Tcp {
    socket: TcpStream,
    endpoint: Endpoint,
    /// The receive regions of a connection that lends none.
    pool: Pool,
    /// The rest of the current slot of the pool, which the next read fills.
    rest: Option<Backing>,
    /// A received region that the connection gave back. The next pump gives it first.
    held: Option<Held>,
    /// The socket can give more bytes: it gave no end of input and did not fail.
    reading: bool,
    /// The socket failed: no byte comes or goes.
    failed: bool,
    /// The write side of the socket is shut down.
    shut: bool,
    /// The socket took only part of the last output.
    short: bool,
}

/// What the loop does after a [`Tcp::pump`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Call the connection now, and then pump: bytes moved, or the connection has more work.
    Now,
    /// Call the connection, and then pump, when the socket can read (`read`) or write (`write`),
    /// or at `deadline`. With neither, no event of the socket can help: the connection waits for
    /// capacity, for example for your code to drop the views of received bytes. Call again after
    /// that.
    Wait {
        /// Wait until the socket can read.
        read: bool,
        /// Wait until the socket can write.
        write: bool,
        /// The next deadline of the connection, or `None` when it has none.
        deadline: Option<Deadline>,
    },
    /// The connection can drop: give it to [`Tcp::close`].
    Released,
}

/// A received region that the connection could not take yet.
#[derive(Debug)]
enum Held {
    /// The bytes of a slot of the pool.
    Pool(Received),
    /// The region that the connection lent, with the bytes that the read added, and the room after
    /// them.
    Lent(Backing, u64),
}

/// The result of one read.
enum Read {
    /// The read gave bytes, the end of input, or a failure, so the connection has work.
    Moved,
    /// The socket has no bytes now.
    Blocked,
    /// The read did not run: a signal interrupted it, or the lent region has no room. Pump again.
    Again,
    /// Each slot of the pool is in use.
    Starved,
}

impl Tcp {
    /// Takes a connected socket, and sets it to nonblocking mode with `TCP_NODELAY`.
    ///
    /// `pool` gives the receive regions when the connection lends none: over TCP, and during the
    /// linger of a server, which discards the bytes. Charge it to the budget of the connection. A
    /// TLS connection lends its own input region, so one small slot is enough for it. Refuses with
    /// the error of the socket when it cannot set the mode or read the two addresses.
    pub fn new(socket: TcpStream, pool: Pool) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        socket.set_nodelay(true)?;
        let endpoint = Endpoint {
            peer: socket.peer_addr()?,
            local: socket.local_addr()?,
            ecn: Ecn::NotEct,
            segment: None,
        };
        Ok(Self {
            socket,
            endpoint,
            pool,
            rest: None,
            held: None,
            reading: true,
            failed: false,
            shut: false,
            short: false,
        })
    }

    /// The socket, for example to register it with the poller of the application. Do not read or
    /// write it.
    pub fn socket(&self) -> &TcpStream {
        &self.socket
    }

    /// Moves the bytes between the socket and `connection`, and tells what to do next.
    ///
    /// A pump gives the connection a region that it gave back, or reads one time when it waits
    /// for input. Then it writes each output, and shuts down the write side at the linger. A
    /// failure of the socket resets the connection, so the connection reports it. Call the
    /// connection after each pump: only its calls drive it.
    ///
    /// Refuses with [`Kind::Overload`](crate::drive::Kind::Overload) when the connection cannot
    /// pay for its input region, after it wrote the output: release capacity, and pump again.
    pub fn pump<C: Io>(&mut self, connection: &mut C) -> Result<Next, Error> {
        if let Some(released) = self.released(connection) {
            return Ok(released);
        }
        let mut moved = false;
        if let Some(held) = self.held.take() {
            self.give(connection, held);
            moved = self.held.is_none();
        }
        let input = matches!(
            connection.wait(),
            Wait::Until {
                blocked: Blocked::Input,
                ..
            } | Wait::Linger { .. }
        );
        let (mut again, mut starved) = (false, false);
        let read = (input && self.reading && self.held.is_none()).then(|| self.read(connection));
        // The output goes also when the connection refused its input region: a sent output can
        // give its capacity back.
        if !self.failed {
            let (wrote, interrupted) = self.write(connection);
            moved |= wrote;
            again |= interrupted;
        }
        match read.transpose()? {
            Some(Read::Moved) => moved = true,
            Some(Read::Again) => again = true,
            Some(Read::Starved) => starved = true,
            Some(Read::Blocked) | None => {}
        }
        if !self.failed && !self.shut && matches!(connection.wait(), Wait::Linger { .. }) {
            moved |= self.half_close(connection);
        }

        if let Some(released) = self.released(connection) {
            return Ok(released);
        }
        if moved || again || self.held.is_some() {
            return Ok(Next::Now);
        }
        let (input, deadline) = match connection.wait() {
            Wait::Now => return Ok(Next::Now),
            Wait::Until { blocked, deadline } => (blocked == Blocked::Input, deadline),
            Wait::Linger { deadline } => (true, Some(deadline)),
            Wait::Ended(_) => (false, None),
        };
        Ok(Next::Wait {
            read: input && self.reading && !starved,
            write: self.short,
            deadline,
        })
    }

    /// Closes the socket, and gives the output of `connection` that the socket did not accept.
    ///
    /// After the release of a connection with no such output, the peer reads the end of the
    /// stream. Else the close resets the connection: the peer cannot read the bytes that did not
    /// go as a complete message, for example a body that the close delimits.
    pub fn close<C: Io>(self, connection: &C) -> Outstanding {
        let outstanding = connection.outstanding();
        if connection.release().is_none() || !outstanding.is_empty() {
            // A socket that refuses the option failed already, so its close sends no end either.
            drop(self.socket.set_linger(Some(Duration::ZERO)));
        }
        outstanding
    }

    /// Gives [`Next::Released`] when the connection can drop. Then the output ended, so the socket
    /// shuts down its write side after the last output: the peer reads each byte and the end of
    /// the stream, also when a later close resets the connection.
    fn released<C: Io>(&mut self, connection: &C) -> Option<Next> {
        connection.release()?;
        if !self.failed && !self.shut && connection.outstanding().is_empty() {
            // The connection ended, so a failure of the socket now changes no outcome.
            self.shut = self.socket.shutdown(Shutdown::Write).is_ok();
        }
        Some(Next::Released)
    }

    /// Reads one time into the region that the connection lends, or into the pool.
    fn read<C: Io>(&mut self, connection: &mut C) -> Result<Read, Error> {
        let (region, lent) = match connection.region()? {
            Some(region) => (region, true),
            None => match self.slot() {
                Some(region) => (region, false),
                None => return Ok(Read::Starved),
            },
        };
        let mut loan = WriteLoan::new(region);
        let room = loan.capacity();
        let mut result = Ok(());
        // A loan with no room reads no byte, which would look like the end of input: drive first.
        let count = if room == 0 {
            result = Err(ErrorKind::Interrupted.into());
            0
        } else {
            loan.fill_with(|spare| {
                let mut buffer = BorrowedBuf::from(spare);
                result = self.socket.read_buf(buffer.unfilled());
                buffer.into_filled_mut()
            })
        };
        let region = loan.into_inner();
        let (read, end, failed) = match result {
            Ok(()) => (Read::Moved, count == 0, false),
            Err(error) if error.kind() == ErrorKind::WouldBlock => (Read::Blocked, false, false),
            Err(error) if error.kind() == ErrorKind::Interrupted => (Read::Again, false, false),
            Err(_) => (Read::Moved, false, true),
        };
        let capacity = u64::try_from(room - count).unwrap_or(u64::MAX);
        if lent {
            // The connection waits for its region also when the read gave no byte.
            self.give(connection, Held::Lent(region, capacity));
        } else if count > 0 {
            let (lease, rest) = region
                .freeze_prefix(count)
                .expect("a read initialized the bytes that it counts");
            self.rest = Some(rest);
            let received = Received {
                region: lease,
                endpoint: self.endpoint,
                capacity,
            };
            self.give(connection, Held::Pool(received));
        } else {
            self.rest = Some(region);
        }
        if end {
            self.reading = false;
            connection.end_input();
        }
        if failed {
            self.fail(connection);
        }
        Ok(read)
    }

    /// The rest of the current slot of the pool, or the next free slot. Gives `None` when each slot
    /// is in use.
    fn slot(&mut self) -> Option<Backing> {
        if let Some(rest) = self.rest.take() {
            if rest.capacity() > rest.initialized() {
                return Some(rest);
            }
            // A full rest keeps its slot in use: drop it, so that the slot can come back.
            drop(rest);
        }
        self.pool.acquire().ok()
    }

    /// Gives `held` to the connection, or keeps it when the connection cannot take it now.
    fn give<C: Io>(&mut self, connection: &mut C, held: Held) {
        self.held = match held {
            Held::Pool(received) => connection.receive(received).err().map(Held::Pool),
            Held::Lent(region, capacity) => connection
                .received(region, self.endpoint, capacity)
                .err()
                .map(|region| Held::Lent(region, capacity)),
        };
    }

    /// Writes each output until the socket takes only part of one. The output queue bounds the
    /// writes. Gives whether the socket took a byte or failed, and whether a signal interrupted a
    /// write.
    fn write<C: Io>(&mut self, connection: &mut C) -> (bool, bool) {
        self.short = false;
        let (mut moved, mut interrupted) = (false, false);
        while let Some(output) = connection.output() {
            let bytes = output.region.bytes();
            let (accepted, failed) = match self.socket.write(bytes) {
                Ok(0) if !bytes.is_empty() => (0, true),
                Ok(accepted) => (accepted, false),
                Err(error) if error.kind() == ErrorKind::WouldBlock => (0, false),
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    interrupted = true;
                    (0, false)
                }
                Err(_) => (0, true),
            };
            connection
                .ack(output.id, accepted)
                .expect("the socket accepts at most the bytes of the output that it took");
            moved |= accepted > 0 || failed;
            if failed {
                self.fail(connection);
                break;
            }
            if accepted < bytes.len() {
                self.short = !interrupted;
                break;
            }
        }
        (moved, interrupted)
    }

    /// Shuts down the write side after the last output. Gives whether the socket failed.
    fn half_close<C: Io>(&mut self, connection: &mut C) -> bool {
        if !connection.outstanding().is_empty() {
            return false;
        }
        match self.socket.shutdown(Shutdown::Write) {
            Ok(()) => {
                self.shut = true;
                false
            }
            Err(_) => {
                self.fail(connection);
                true
            }
        }
    }

    /// Records that the socket failed: the connection resets, and no byte comes or goes after it.
    fn fail<C: Io>(&mut self, connection: &mut C) {
        self.failed = true;
        self.reading = false;
        connection.reset();
    }
}
