//! The server on Tokio: the calls of [`rsnetwork::server::Http`], each of which awaits the
//! progress that it needs, and a [`Server`] that accepts connections and owns their tasks.

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::io;
use std::panic;
use std::sync::{Arc, Mutex, PoisonError};

use rsnetwork::body::{Collect, Part, Read};
use rsnetwork::buffer::{BufferMut, Lease, Pool, WriteLoan};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::host::{Io as _, Wait};
use rsnetwork::message::{RequestHead, Stream};
use rsnetwork::server::{Closed, Delivery, Http as Core, Response};
use rsnetwork::time::Deadline;
use rsnetwork::tls::Negotiated;
use rsnetwork::value::Field;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};

use crate::{Clock, Socket, Step, queued};

/// The refusal of a call after the connection ended.
const ENDED: Error = Error::new(Kind::Misuse, "the connection ended");

/// The refusal of a call of the exchange before a request.
const NO_REQUEST: Error = Error::new(Kind::Misuse, "no request waits for a response");

/// The pause after an accept that the listener refused, for example at the limit of open files:
/// the next accept would refuse at once.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// The place where a connection of a [`Server`] goes back to its task when the handler drops it.
type Back = Arc<Mutex<Option<Http>>>;

/// One server connection on a Tokio TCP socket, for HTTP/1.1 and HTTP/2.
///
/// It has the calls of [`rsnetwork::server::Http`], with its rules, one exchange at a time: a
/// delivery goes on after the handler finished its response, and the next
/// [`request`](Self::request) closes the stream before it. Each call awaits its own progress. A
/// future that you drop changes nothing: the next call goes on from the state of the
/// connection.
///
/// A connection of a [`Server`] goes back to its task when the handler drops it, and the task
/// drives the rest of its delivery and its close. A connection that you made with
/// [`new`](Self::new) needs [`close`](Self::close): a drop before its release resets it.
#[derive(Debug)]
pub struct Http {
    /// The connection, until the drop.
    socket: Option<Socket<Core>>,
    /// The stream of the last request.
    stream: Option<Stream>,
    /// The handler has a request whose response is not finished.
    open: bool,
    back: Option<Back>,
}

impl Http {
    /// Binds `server`, a server of the core made with [`Clock::domain`], to `stream`, an accepted
    /// TCP socket. `pool` gives the receive regions over TCP and during the linger: charge it to
    /// the budget of the server. Refuses with the error of the socket, as [`Socket::new`] does.
    pub fn new(server: Core, stream: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self {
            socket: Some(Socket::new(server, stream, pool)?),
            stream: None,
            open: false,
            back: None,
        })
    }

    /// The connection. It is there until the drop.
    fn socket(&mut self) -> &mut Socket<Core> {
        self.socket.as_mut().expect("the connection is there until the drop")
    }

    /// The stream of the last request.
    fn current(&self) -> Result<Stream, Error> {
        self.stream.ok_or(NO_REQUEST)
    }

    /// Closes the stream of the last request, and gives the next request head when it arrives,
    /// or `None` when the connection takes no more requests: the client closed, the connection
    /// closes, or it ended. Refuses as [`Http::request`](rsnetwork::server::Http::request) does.
    pub async fn request(&mut self) -> Result<Option<RequestHead>, Error> {
        if let Some(stream) = self.stream {
            self.socket().connection_mut().close(stream);
            self.open = false;
        }
        let request = self.socket().until(|server, now| {
            Ok(match server.request(now)? {
                Some(request) => Some(Some(request)),
                None if matches!(server.wait(), Wait::Linger { .. } | Wait::Ended(_)) => Some(None),
                None => None,
            })
        });
        let request = request.await?.flatten();
        self.open = request.is_some();
        Ok(request.map(|(stream, head)| {
            self.stream = Some(stream);
            head
        }))
    }

    /// Sends the head of `response` to the request in flight. It waits while the transport holds
    /// the heads before. Send a body with [`write`](Self::write), and end it with
    /// [`finish`](Self::finish).
    pub async fn respond(&mut self, response: &Response<'_>) -> Result<(), Error> {
        let stream = self.current()?;
        let responded = self
            .socket()
            .until(|server, now| Ok(server.respond(stream, response, now)?.then_some(())));
        responded.await?.ok_or(ENDED)?;
        // A response with no body is finished at once.
        self.open &= response.length != Some(0);
        Ok(())
    }

    /// Queues `data` as the next bytes of the response body, with no copy. It waits while the
    /// output queue is full.
    pub async fn write(&mut self, data: &Lease) -> Result<(), Error> {
        let stream = self.current()?;
        let written = self
            .socket()
            .until(|server, now| queued(server.write(stream, data, now)));
        written.await?.ok_or(ENDED)
    }

    /// Ends the response body: the handler is complete, and [`delivery`](Self::delivery) tracks
    /// the rest. It waits while the output queue is full.
    pub async fn finish(&mut self) -> Result<(), Error> {
        let stream = self.current()?;
        let finished = self.socket().until(|server, now| queued(server.finish(stream, now)));
        finished.await?.ok_or(ENDED)?;
        self.open = false;
        Ok(())
    }

    /// Ends a chunked response body with `trailers`, as [`finish`](Self::finish) does.
    pub async fn finish_with_trailers(&mut self, trailers: &[Field<'_>]) -> Result<(), Error> {
        let stream = self.current()?;
        let finished = self
            .socket()
            .until(|server, now| Ok(server.finish_with_trailers(stream, trailers, now)?.then_some(())));
        finished.await?.ok_or(ENDED)?;
        self.open = false;
        Ok(())
    }

    /// Gives the next part of the request body as a view of its received region, with no copy,
    /// or its end with its outcome.
    pub async fn next(&mut self) -> Result<Part, Error> {
        let stream = self.current()?;
        let part = self.socket().until(|server, now| server.next(stream, now));
        part.await?.ok_or(ENDED)
    }

    /// Copies the next bytes of the request body into the free capacity of `region`, or gives
    /// its outcome after its last byte. It waits until a byte arrives, so it never gives
    /// [`Read::Wait`].
    pub async fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        let stream = self.current()?;
        let step = self
            .socket()
            .until(|server, now| Ok(Step::of(&server.read_into(stream, now, region)?)));
        match step.await?.ok_or(ENDED)? {
            Step::Bytes(count) => Ok(Read::Bytes(count)),
            Step::Full => Ok(Read::Full),
            // The outcome stays in the server, so the read gives it again.
            Step::Done => self.socket().connection_mut().read_into(stream, Clock.now(), region),
        }
    }

    /// Collects the request body into `region`, whose free capacity bounds it. It waits until the
    /// body ends or no longer fits, so it never gives [`Collect::More`].
    pub async fn collect<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Collect, Error> {
        let stream = self.current()?;
        let collected = self.socket().until(|server, now| {
            Ok(match server.collect(stream, now, region)? {
                Collect::More => None,
                collect => Some(collect),
            })
        });
        collected.await?.ok_or(ENDED)
    }

    /// Cancels the exchange in flight, as
    /// [`Http::cancel`](rsnetwork::server::Http::cancel) does: the client sees an incomplete
    /// response, never a complete one.
    pub fn cancel(&mut self) {
        if let Some(stream) = self.stream {
            self.socket().connection_mut().cancel(stream);
        }
        self.open = false;
    }

    /// How much of the response of the last exchange the transport accepted.
    pub fn delivery(&self) -> Option<Delivery> {
        let socket = self.socket.as_ref().expect("the connection is there until the drop");
        socket.connection().delivery(self.stream?)
    }

    /// Closes the connection with `deadline`, as
    /// [`Http::shutdown`](rsnetwork::server::Http::shutdown) does: it drains the exchange in
    /// flight, and tells the client which requests the server did not process.
    pub fn shutdown(&mut self, deadline: Deadline) -> Result<(), Error> {
        self.socket().connection_mut().shutdown(deadline, Clock.now())
    }

    /// What the TLS handshake negotiated, or `None` before it completed and over TCP.
    pub fn negotiated(&mut self) -> Option<Negotiated<'_>> {
        self.socket().connection_mut().negotiated()
    }

    /// Ends the connection, and drives it until its release: the delivery of the last response,
    /// the close, and the linger. A response that is not finished is cancelled, so the client
    /// sees it incomplete. The client learns which later requests the server did not process,
    /// as [`shutdown`](Self::shutdown) says. The delivery and the linger bound the close, and a
    /// close of the [`Server`] adds its deadline. Gives the end of the connection, and
    /// [`delivery`](Self::delivery) then gives the final delivery of the last response.
    pub async fn release(&mut self) -> Result<Closed, Error> {
        if core::mem::take(&mut self.open) {
            self.cancel();
        }
        if let Some(stream) = self.stream {
            self.socket().connection_mut().close(stream);
        }
        let socket = self.socket();
        socket
            .connection_mut()
            .shutdown(Clock.deadline(Duration::MAX), Clock.now())?;
        // Each call gives the time to the server, so its linger and its deadlines end.
        let released = socket.until(|server, now| {
            server.request(now)?;
            Ok(server.release())
        });
        released.await?.ok_or(ENDED)
    }

    /// Drives the connection until its release, as [`release`](Self::release) does. Then it
    /// closes the socket, and gives the end of the connection.
    pub async fn close(mut self) -> Result<Closed, Error> {
        let closed = self.release().await?;
        let socket = self.socket.take().expect("the connection is there until the drop");
        let unsent = socket.close();
        assert!(unsent.is_empty(), "a released connection has no output that did not go");
        Ok(closed)
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        if let (Some(socket), Some(back)) = (self.socket.take(), self.back.take()) {
            let connection = Self {
                socket: Some(socket),
                stream: self.stream,
                open: self.open,
                back: None,
            };
            *back.lock().unwrap_or_else(PoisonError::into_inner) = Some(connection);
        }
    }
}

/// What the close of a [`Server`] reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The connections that the server accepted and served.
    pub accepted: u64,
    /// The accepts that failed, or whose connection could not start: the listener refused, the
    /// socket could not be set up, or `make` refused, for example with
    /// [`Kind::Overload`].
    pub refused: u64,
    /// The connections that ended with an error, whose handler gave an error, or whose handler
    /// panicked.
    pub failed: u64,
    /// The connections whose task the close stopped at its deadline.
    pub aborted: u64,
}

/// A server on a Tokio listener: it accepts each connection, and runs the handler for it in a
/// task of its own, on the runtime of the caller.
///
/// The server owns each task that it spawns: its accept task, and one task for each connection,
/// at most `connections_max` at a time. [`close`](Self::close) stops the accepts, drains each
/// connection, and joins each task. A server that drops before its close aborts each task, and
/// each connection resets.
#[derive(Debug)]
pub struct Server {
    task: Option<JoinHandle<Report>>,
    close: watch::Sender<Option<Deadline>>,
}

impl Server {
    /// Serves the connections of `listener` in tasks of the runtime of the caller, at most
    /// `connections_max` at a time. A connection over that waits in the backlog of the listener.
    ///
    /// For each accepted socket, `make` gives a server of the core, made with
    /// [`Clock::domain`], and the pool of its receive regions: over TCP or over TLS, charged to the
    /// budget that you select. Then `handler` serves the connection, and the task drives the rest
    /// of its delivery after the handler returns. Call it in a task of the runtime.
    pub fn serve<M, H, F>(listener: TcpListener, connections_max: NonZeroUsize, make: M, handler: H) -> Self
    where
        M: FnMut() -> Result<(Core, Pool), Error> + Send + 'static,
        H: Fn(Http) -> F + Send + Sync + 'static,
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let (close, signal) = watch::channel(None);
        let task = tokio::spawn(accept(listener, connections_max, make, Arc::new(handler), signal));
        Self {
            task: Some(task),
            close,
        }
    }

    /// Closes the server: it stops the accepts, and each connection drains with `deadline`, as
    /// [`Http::shutdown`] says. Then it joins each task. At `deadline`, it aborts the tasks that
    /// did not end, for example a handler that waits for another future. Gives what the server did.
    pub async fn close(mut self, deadline: Deadline) -> Report {
        self.close.send_replace(Some(deadline));
        let task = self.task.take().expect("the accept task is there until the close");
        match task.await {
            Ok(report) => report,
            Err(error) => panic::resume_unwind(error.into_panic()),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // The accept task owns the tasks of the connections, so they abort with it.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// An event of the accept task.
enum Event {
    Accepted(io::Result<(TcpStream, core::net::SocketAddr)>),
    Ended(Result<bool, JoinError>),
    /// The signal changed, or its server dropped (`false`).
    Close(bool),
}

/// Accepts the connections of `listener` until the close, and then drains and joins them.
async fn accept<M, H, F>(
    listener: TcpListener,
    connections_max: NonZeroUsize,
    mut make: M,
    handler: Arc<H>,
    mut signal: watch::Receiver<Option<Deadline>>,
) -> Report
where
    M: FnMut() -> Result<(Core, Pool), Error> + Send + 'static,
    H: Fn(Http) -> F + Send + Sync + 'static,
    F: Future<Output = Result<(), Error>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut report = Report::default();
    let mut pause: Option<tokio::time::Instant> = None;
    let deadline = loop {
        let event = {
            let mut changed = pin!(signal.changed());
            let mut paused = pin!(pause.map(tokio::time::sleep_until));
            poll_fn(|cx| {
                if let Poll::Ready(changed) = changed.as_mut().poll(cx) {
                    return Poll::Ready(Event::Close(changed.is_ok()));
                }
                if let Poll::Ready(Some(ended)) = tasks.poll_join_next(cx) {
                    return Poll::Ready(Event::Ended(ended));
                }
                if paused
                    .as_mut()
                    .as_pin_mut()
                    .is_some_and(|paused| paused.poll(cx).is_pending())
                {
                    return Poll::Pending;
                }
                if tasks.len() < connections_max.get()
                    && let Poll::Ready(accepted) = listener.poll_accept(cx)
                {
                    return Poll::Ready(Event::Accepted(accepted));
                }
                Poll::Pending
            })
            .await
        };
        pause = None;
        match event {
            Event::Close(true) => {
                let deadline = *signal.borrow();
                if let Some(deadline) = deadline {
                    break deadline;
                }
            }
            // A dropped server aborts this task: its tasks abort with the set.
            Event::Close(false) => return report,
            Event::Ended(ended) => record(&mut report, ended),
            Event::Accepted(Ok((stream, _))) => match start(stream, &mut make, signal.clone()) {
                Some(socket) => {
                    report.accepted = report.accepted.saturating_add(1);
                    tasks.spawn(run(socket, Arc::clone(&handler)));
                }
                None => report.refused = report.refused.saturating_add(1),
            },
            Event::Accepted(Err(_)) => {
                report.refused = report.refused.saturating_add(1);
                pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
            }
        }
    };
    // No more accepts: the listener closes, and each connection saw the signal in its wait.
    drop(listener);
    let mut ends = pin!(tokio::time::sleep_until(Clock.tokio(deadline)));
    loop {
        let ended = poll_fn(|cx| match tasks.poll_join_next(cx) {
            Poll::Ready(ended) => Poll::Ready(Some(ended)),
            Poll::Pending => ends.as_mut().poll(cx).map(|()| None),
        })
        .await;
        match ended {
            Some(Some(ended)) => record(&mut report, ended),
            Some(None) => return report,
            None => {
                tasks.abort_all();
                while let Some(ended) = tasks.join_next().await {
                    record(&mut report, ended);
                }
                return report;
            }
        }
    }
}

/// The connection of `stream`, with a server of `make`, which sees the close in each wait. Gives
/// `None` when the socket or `make` refused.
fn start<M>(stream: TcpStream, make: &mut M, signal: watch::Receiver<Option<Deadline>>) -> Option<Socket<Core>>
where
    M: FnMut() -> Result<(Core, Pool), Error>,
{
    let (server, pool) = make().ok()?;
    let socket = Socket::new(server, stream, pool).ok()?;
    Some(socket.with_close(signal, Core::shutdown))
}

/// Runs `handler` on the connection of `socket`, and then drives the rest of the connection.
/// Gives whether the connection and the handler ended with no error.
async fn run<H, F>(socket: Socket<Core>, handler: Arc<H>) -> bool
where
    H: Fn(Http) -> F,
    F: Future<Output = Result<(), Error>>,
{
    let back = Back::default();
    let connection = Http {
        socket: Some(socket),
        stream: None,
        open: false,
        back: Some(Arc::clone(&back)),
    };
    let handled = handler(connection).await;
    let connection = back.lock().unwrap_or_else(PoisonError::into_inner).take();
    // A handler that kept the connection, for example in another task, has its close.
    let Some(connection) = connection else {
        return handled.is_ok();
    };
    let closed = connection.close().await;
    handled.is_ok() && closed.is_ok_and(|closed| closed.result.is_ok())
}

/// Adds the end of a connection task to `report`.
fn record(report: &mut Report, ended: Result<bool, JoinError>) {
    match ended {
        Ok(true) => {}
        Ok(false) => report.failed = report.failed.saturating_add(1),
        Err(error) if error.is_cancelled() => report.aborted = report.aborted.saturating_add(1),
        Err(_) => report.failed = report.failed.saturating_add(1),
    }
}
