//! The server on Tokio: the calls of [`rsnetwork::server::Http`], each of which awaits the
//! progress that it needs, and a [`Server`] that accepts connections and owns their tasks.

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::io;
use std::panic;
use std::sync::Arc;

use rsnetwork::body::{Collect, Outcome, Part, Read};
use rsnetwork::buffer::{BufferMut, Lease, Pool, WriteLoan};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::host::{Io as _, Wait};
use rsnetwork::message::{RequestHead, Stream, Version};
use rsnetwork::server::{Closed, Delivery, Http as Core, Response};
use rsnetwork::time::Deadline;
use rsnetwork::tls::{ExportError, Negotiated};
use rsnetwork::value::Field;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};

use crate::shared::{Shared, Waits};
use crate::{Clock, Socket, Step, queued};

/// The refusal of a call after the connection ended.
const ENDED: Error = Error::new(Kind::Misuse, "the connection ended");

/// The pause after an accept that the listener refused, for example at the limit of open files:
/// the next accept would refuse at once.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// One server connection on a Tokio TCP socket, for HTTP/1.1 and HTTP/2.
///
/// It has the calls of [`rsnetwork::server::Http`], with its rules. [`request`](Self::request)
/// gives each request on its own [`Exchange`], which can go to a task of its own. The handle
/// that awaits drives the connection for each exchange, under a short lock, and wakes only the
/// handles whose streams changed: no task, no channel, and no copy. On HTTP/1.1, the next request
/// comes after the exchange before it dropped and the transport accepted its response. On
/// HTTP/2, requests come while the exchanges before them go on, at most
/// `SETTINGS_MAX_CONCURRENT_STREAMS`.
///
/// A connection needs [`close`](Self::close): when its last handle drops before its release, it
/// resets.
#[derive(Debug)]
pub struct Http {
    shared: Arc<Shared<Core>>,
}

impl Http {
    /// Binds `server`, a server of the core made with [`Clock::domain`], to `stream`, an accepted
    /// TCP socket. `pool` gives the receive regions over TCP and during the linger: charge it to
    /// the budget of the server. Refuses with the error of the socket, as [`Socket::new`] does.
    pub fn new(server: Core, stream: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self::bind(Socket::new(server, stream, pool)?))
    }

    fn bind(socket: Socket<Core>) -> Self {
        Self {
            shared: Arc::new(Shared::new(socket)),
        }
    }

    /// Gives the next request on its own exchange when it arrives, or `None` when the connection
    /// takes no more requests: the client closed, the connection closes, or it ended. Refuses as
    /// [`Http::request`](rsnetwork::server::Http::request) does.
    pub async fn request(&mut self) -> Result<Option<Exchange>, Error> {
        let request = self.shared.until(Waits::Connection, |server, now| {
            Ok(match server.request(now)? {
                Some(request) => Some(Some(request)),
                None if matches!(server.wait(), Wait::Linger { .. } | Wait::Ended(_)) => Some(None),
                None => None,
            })
        });
        let request = request.await?.flatten();
        Ok(request.map(|(stream, head)| Exchange {
            shared: Arc::clone(&self.shared),
            stream,
            head,
            end: None,
        }))
    }

    /// Closes the connection with `deadline`, as
    /// [`Http::shutdown`](rsnetwork::server::Http::shutdown) does: it drains the exchanges in
    /// flight, and tells the client which requests the server did not process.
    pub fn shutdown(&self, deadline: Deadline) -> Result<(), Error> {
        self.shared.change(|server| server.shutdown(deadline, Clock.now()))
    }

    /// Ends the connection, and drives it until its release: the delivery of each response, the
    /// close, and the linger. The client learns which later requests the server did not process,
    /// as [`shutdown`](Self::shutdown) says. The drain waits for each exchange in flight, so drop
    /// or finish them first. The delivery and the linger bound the close, and a close of the
    /// [`Server`] adds its deadline. Gives the end of the connection.
    pub async fn close(self) -> Result<Closed, Error> {
        self.shared
            .change(|server| server.shutdown(Clock.deadline(Duration::MAX), Clock.now()))?;
        // Each call gives the time to the server, so its linger and its deadlines end.
        let released = self.shared.until(Waits::Connection, |server, now| {
            server.request(now)?;
            Ok(server.release())
        });
        released.await?.ok_or(ENDED)
    }
}

/// One exchange of a server connection: a request and its response, on one stream.
///
/// It has the calls of [`rsnetwork::server::Http`] for its stream, with its rules: a delivery
/// goes on after the handler finished its response. Each call awaits its own progress, and a
/// future that you drop changes nothing. An exchange that drops ends its handler, as
/// [`Http::close`](rsnetwork::server::Http::close) says: a response that is not finished is
/// cancelled, so the client sees it incomplete.
#[derive(Debug)]
pub struct Exchange {
    shared: Arc<Shared<Core>>,
    stream: Stream,
    head: RequestHead,
    /// The outcome of the request body, after the read that gave it.
    end: Option<Outcome>,
}

impl Exchange {
    /// The head of the request.
    pub fn head(&self) -> &RequestHead {
        &self.head
    }

    /// What a call that sends waits for: on HTTP/1.1 also room in the output, which the
    /// connection gives in turn.
    fn sending(&self) -> Waits {
        match self.head.version() {
            Version::Http2 => Waits::Stream(self.stream),
            Version::Http10 | Version::Http11 => Waits::Place(Some(self.stream)),
        }
    }

    /// Sends the head of `response`. It waits while the transport holds the heads before, in the
    /// order of the exchanges that wait. Send a body with [`write`](Self::write), and end it with
    /// [`finish`](Self::finish).
    pub async fn respond(&mut self, response: &Response<'_>) -> Result<(), Error> {
        let stream = self.stream;
        let responded = self.shared.until(Waits::Place(Some(stream)), |server, now| {
            Ok(server.respond(stream, response, now)?.then_some(()))
        });
        responded.await?.ok_or(ENDED)
    }

    /// Queues `data` as the next bytes of the response body, with no copy. It waits while the
    /// output has no room for it.
    pub async fn write(&mut self, data: &Lease) -> Result<(), Error> {
        let stream = self.stream;
        let written = self
            .shared
            .until(self.sending(), |server, now| queued(server.write(stream, data, now)));
        written.await?.ok_or(ENDED)
    }

    /// Ends the response body: the handler is complete, and [`delivery`](Self::delivery) tracks
    /// the rest. It waits while the output has no room.
    pub async fn finish(&mut self) -> Result<(), Error> {
        let stream = self.stream;
        let finished = self
            .shared
            .until(self.sending(), |server, now| queued(server.finish(stream, now)));
        finished.await?.ok_or(ENDED)
    }

    /// Ends the response body with `trailers`, as [`finish`](Self::finish) does. On HTTP/1.1,
    /// only a chunked body carries them.
    pub async fn finish_with_trailers(&mut self, trailers: &[Field<'_>]) -> Result<(), Error> {
        let stream = self.stream;
        let finished = self.shared.until(Waits::Place(Some(stream)), |server, now| {
            Ok(server.finish_with_trailers(stream, trailers, now)?.then_some(()))
        });
        finished.await?.ok_or(ENDED)
    }

    /// Gives the next part of the request body as a view of its received region, with no copy,
    /// or its end with its outcome.
    pub async fn next(&mut self) -> Result<Part, Error> {
        let stream = self.stream;
        let part = self
            .shared
            .until(Waits::Stream(stream), |server, now| server.next(stream, now));
        part.await?.ok_or(ENDED)
    }

    /// Copies the next bytes of the request body into the free capacity of `region`, or gives
    /// its outcome after its last byte. It waits until a byte arrives, so it never gives
    /// [`Read::Wait`].
    pub async fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        let (stream, end) = (self.stream, &mut self.end);
        let step = self.shared.until(Waits::Stream(stream), |server, now| {
            let read = server.read_into(stream, now, region)?;
            if let Read::Done(outcome) = read {
                *end = Some(outcome.clone());
            }
            Ok(Step::of(&read))
        });
        Ok(match step.await?.ok_or(ENDED)? {
            Step::Bytes(count) => Read::Bytes(count),
            Step::Full => Read::Full,
            Step::Done => Read::Done(self.end.as_ref().expect("the read that ended kept the outcome")),
        })
    }

    /// Collects the request body into `region`, whose free capacity bounds it. It waits until the
    /// body ends or no longer fits, so it never gives [`Collect::More`].
    pub async fn collect<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Collect, Error> {
        let stream = self.stream;
        let collected = self.shared.until(Waits::Stream(stream), |server, now| {
            Ok(match server.collect(stream, now, region)? {
                Collect::More => None,
                collect => Some(collect),
            })
        });
        collected.await?.ok_or(ENDED)
    }

    /// Cancels the exchange, as [`Http::cancel`](rsnetwork::server::Http::cancel) does: the
    /// client sees an incomplete response, never a complete one.
    pub fn cancel(&mut self) {
        let stream = self.stream;
        self.shared.change(|server| server.cancel(stream));
    }

    /// How much of the response the transport accepted, or `None` before the response.
    pub fn delivery(&self) -> Option<Delivery> {
        self.shared.lock().socket.connection().delivery(self.stream)
    }

    /// Gives `read` what the TLS handshake negotiated, or `None` over TCP, and gives what `read`
    /// gives. `read` runs under the lock of the connection, so it must not call the connection or
    /// one of its exchanges.
    pub fn negotiated<T>(&self, read: impl FnOnce(Option<Negotiated<'_>>) -> T) -> T {
        read(self.shared.lock().socket.connection_mut().negotiated())
    }

    /// Derives `output.len()` bytes of keying material with `label` and `context` from the regular
    /// exporter of the connection of the exchange, as
    /// [`Http::export`](rsnetwork::server::Http::export) does.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        self.shared.lock().socket.connection().export(label, context, output)
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        let stream = self.stream;
        self.shared.change(|server| server.close(stream));
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

/// A server on a Tokio listener: it accepts each connection, drives it in a task of its own, on
/// the runtime of the caller, and runs the handler once for each request.
///
/// On HTTP/1.1, the handler runs in the task of its connection, one request at a time. On
/// HTTP/2, each request gets a handler task of its own, at most `SETTINGS_MAX_CONCURRENT_STREAMS`
/// for each connection, because a stream keeps its place until its exchange drops.
///
/// The server owns each task that it spawns: its accept task, one task for each connection, at
/// most `connections_max` at a time, and the handler tasks of each connection.
/// [`close`](Self::close) stops the accepts, drains each connection, and joins each task. A
/// server that drops before its close aborts each task, and each connection resets.
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
    /// budget that you select. Then `handler` serves each request on its [`Exchange`], and the
    /// connection drives the rest of its delivery after the exchange drops. Call it in a task of
    /// the runtime.
    pub fn serve<M, H, F>(listener: TcpListener, connections_max: NonZeroUsize, make: M, handler: H) -> Self
    where
        M: FnMut() -> Result<(Core, Pool), Error> + Send + 'static,
        H: Fn(Exchange) -> F + Send + Sync + 'static,
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
    /// did not end, for example a handler that waits for another future, and joins them too. So
    /// when the close returns, no task of the server holds its state. A close that drops before
    /// it returns aborts each task, as a drop of the server does. Gives what the server did.
    pub async fn close(mut self, deadline: Deadline) -> Report {
        self.close.send_replace(Some(deadline));
        let task = self.task.as_mut().expect("the accept task is there until the close");
        // The handle stays in the server until the join, so a drop of this future aborts the task.
        let joined = task.await;
        self.task = None;
        match joined {
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
    Ended(Result<Ended, JoinError>),
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
    H: Fn(Exchange) -> F + Send + Sync + 'static,
    F: Future<Output = Result<(), Error>> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    let mut report = Report::default();
    let mut pause: Option<tokio::time::Instant> = None;
    loop {
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
                if signal.borrow().is_some() {
                    break;
                }
            }
            // A dropped server aborts this task: its tasks abort with the set.
            Event::Close(false) => return report,
            Event::Ended(ended) => record(&mut report, ended),
            Event::Accepted(Ok((stream, _))) => match start(stream, &mut make) {
                Some(socket) => {
                    report.accepted = report.accepted.saturating_add(1);
                    tasks.spawn(run(socket, Arc::clone(&handler), signal.clone()));
                }
                None => report.refused = report.refused.saturating_add(1),
            },
            Event::Accepted(Err(_)) => {
                report.refused = report.refused.saturating_add(1);
                pause = tokio::time::Instant::now().checked_add(ACCEPT_PAUSE);
            }
        }
    }
    // No more accepts: the listener closes, and each connection saw the signal in its wait. Each
    // connection ends by the deadline, after its handlers.
    drop(listener);
    while let Some(ended) = tasks.join_next().await {
        record(&mut report, ended);
    }
    report
}

/// The connection of `stream`, with a server of `make`. Gives `None` when the socket or `make`
/// refused.
fn start<M>(stream: TcpStream, make: &mut M) -> Option<Socket<Core>>
where
    M: FnMut() -> Result<(Core, Pool), Error>,
{
    let (server, pool) = make().ok()?;
    Socket::new(server, stream, pool).ok()
}

/// What the task of a connection waits for.
enum Next {
    Request(Result<Option<Exchange>, Error>),
    Handled(Result<Result<(), Error>, JoinError>),
    /// The signal changed, or its server dropped (`false`).
    Close(bool),
}

/// How the task of a connection ended.
enum Ended {
    /// The connection and each of its handlers ended with no error.
    Served,
    /// The connection or a handler ended with an error, or a handler panicked.
    Failed,
    /// The deadline of the close of the server came first.
    Aborted,
}

/// Serves the connection of `socket` until the deadline of the close of the server. At that
/// deadline, the connection drops with its HTTP/1.1 handler, and each HTTP/2 handler aborts.
/// The task ends after each handler ended, so no handler outlives the close.
async fn run<H, F>(socket: Socket<Core>, handler: Arc<H>, signal: watch::Receiver<Option<Deadline>>) -> Ended
where
    H: Fn(Exchange) -> F,
    F: Future<Output = Result<(), Error>> + Send + 'static,
{
    let mut handlers = JoinSet::new();
    let served = {
        let mut served = pin!(serve(socket, handler, signal.clone(), &mut handlers));
        let mut expired = pin!(expiry(signal));
        poll_fn(|cx| {
            if let Poll::Ready(clean) = served.as_mut().poll(cx) {
                return Poll::Ready(Some(clean));
            }
            expired.as_mut().poll(cx).map(|()| None)
        })
        .await
    };
    match served {
        Some(true) => Ended::Served,
        Some(false) => Ended::Failed,
        None => {
            handlers.abort_all();
            while handlers.join_next().await.is_some() {}
            Ended::Aborted
        }
    }
}

/// Waits for the deadline of the close of the server, which `signal` gives. A server that drops
/// gives no deadline: its accept task then aborts this task.
async fn expiry(mut signal: watch::Receiver<Option<Deadline>>) {
    let deadline = signal
        .wait_for(Option::is_some)
        .await
        .ok()
        .and_then(|deadline| *deadline);
    match deadline {
        Some(deadline) => tokio::time::sleep_until(Clock.tokio(deadline)).await,
        None => core::future::pending().await,
    }
}

/// Serves the connection of `socket`: it runs `handler` for each request, and then drives the
/// rest of the connection. Each HTTP/2 handler is a task of `handlers`. The close of the server,
/// which `signal` gives, starts its shutdown. Gives whether the connection and each handler ended
/// with no error.
async fn serve<H, F>(
    socket: Socket<Core>,
    handler: Arc<H>,
    mut signal: watch::Receiver<Option<Deadline>>,
    handlers: &mut JoinSet<Result<(), Error>>,
) -> bool
where
    H: Fn(Exchange) -> F,
    F: Future<Output = Result<(), Error>> + Send + 'static,
{
    let mut connection = Http::bind(socket);
    let (mut failed, mut closing) = (false, false);
    loop {
        let next = {
            let mut request = pin!(connection.request());
            let mut changed = pin!(signal.changed());
            poll_fn(|cx| {
                if !closing && let Poll::Ready(changed) = changed.as_mut().poll(cx) {
                    return Poll::Ready(Next::Close(changed.is_ok()));
                }
                if let Poll::Ready(Some(handled)) = handlers.poll_join_next(cx) {
                    return Poll::Ready(Next::Handled(handled));
                }
                request.as_mut().poll(cx).map(Next::Request)
            })
            .await
        };
        match next {
            Next::Close(signalled) => {
                closing = true;
                shutdown(&connection, signalled.then(|| *signal.borrow()).flatten());
            }
            Next::Handled(handled) => failed |= !matches!(handled, Ok(Ok(()))),
            Next::Request(Ok(Some(exchange))) if exchange.head().version() == Version::Http2 => {
                handlers.spawn(handler(exchange));
            }
            Next::Request(Ok(Some(exchange))) => {
                // An HTTP/1.1 handler runs in this task, and the close of the server reaches it.
                let mut handled = pin!(handler(exchange));
                let mut watch = signal.clone();
                let mut changed = pin!(watch.changed());
                let handled = poll_fn(|cx| {
                    if !closing && let Poll::Ready(changed) = changed.as_mut().poll(cx) {
                        closing = true;
                        shutdown(&connection, changed.is_ok().then(|| *signal.borrow()).flatten());
                    }
                    handled.as_mut().poll(cx)
                })
                .await;
                failed |= handled.is_err();
            }
            Next::Request(Ok(None)) => break,
            Next::Request(Err(_)) => {
                failed = true;
                break;
            }
        }
    }
    // The connection takes no more requests: each handler ends, and then the connection releases.
    while let Some(handled) = handlers.join_next().await {
        failed |= !matches!(handled, Ok(Ok(())));
    }
    let closed = connection.close().await;
    !failed && closed.is_ok_and(|closed| closed.result.is_ok())
}

/// Starts the shutdown of `connection` at the close of the server, with its `deadline`: `None`
/// when the server dropped its signal, which then aborts the task.
fn shutdown(connection: &Http, deadline: Option<Deadline>) {
    if let Some(deadline) = deadline {
        // A connection that ended refuses the shutdown, and its next request gives the end.
        let _refused = connection.shutdown(deadline);
    }
}

/// Adds the end of a connection task to `report`. A task that panicked failed.
fn record(report: &mut Report, ended: Result<Ended, JoinError>) {
    match ended {
        Ok(Ended::Served) => {}
        Ok(Ended::Aborted) => report.aborted = report.aborted.saturating_add(1),
        Ok(Ended::Failed) | Err(_) => report.failed = report.failed.saturating_add(1),
    }
}
