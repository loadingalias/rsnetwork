//! The clients on Tokio: the calls of [`rsnetwork::client::Http1`] and
//! [`rsnetwork::client::Http2`], each of which awaits the progress that it needs.

use std::io;
use std::sync::Arc;

use rsnetwork::body::{Collect, Outcome, Part, Read};
use rsnetwork::buffer::{BufferMut, Lease, Pool, WriteLoan};
use rsnetwork::client::{Http1 as Core, Http2 as Core2, Request};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::host::Io as _;
use rsnetwork::message::{ResponseHead, Stream};
use rsnetwork::time::Deadline;
use rsnetwork::tls::{ExportError, Negotiated};
use tokio::net::TcpStream;

use crate::shared::{Shared, Waits};
use crate::{Clock, Socket, Step, queued};

/// The refusal of a call after the connection ended.
const ENDED: Error = Error::new(Kind::Misuse, "the connection ended: make a new client");

/// One HTTP/1.1 client connection on a Tokio TCP socket.
///
/// It has the calls of [`rsnetwork::client::Http1`], with its rules: one deadline covers the
/// TLS handshake, the response head, and each byte of the body, and an unread body drains before
/// the next request or the connection closes. Each call awaits its own progress, so a body read
/// moves its own bytes. A future that you drop changes nothing: the next call goes on from the
/// state of the connection. A client that drops before its close resets the connection.
#[derive(Debug)]
pub struct Http1 {
    socket: Socket<Core>,
}

impl Http1 {
    /// Binds `client`, a client of the core made with [`Clock::domain`], to `stream`, a TCP
    /// socket connected to the server. `pool` gives the receive regions over TCP: charge it to
    /// the budget of the client. Over TLS, one small slot is enough. Refuses with the error of the
    /// socket, as [`Socket::new`] does.
    pub fn new(client: Core, stream: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self {
            socket: Socket::new(client, stream, pool)?,
        })
    }

    /// Sends `request`, with `deadline` for the whole exchange, as
    /// [`Http1::send`](rsnetwork::client::Http1::send) does. It waits while the body before
    /// drains and while the transport holds the last request head. Send a body with
    /// [`write`](Self::write), and end it with [`finish`](Self::finish).
    pub async fn send(&mut self, request: &Request<'_>, deadline: Deadline) -> Result<(), Error> {
        let sent = self
            .socket
            .until(|client, now| Ok(client.send(request, deadline, now)?.then_some(())));
        sent.await?.ok_or(ENDED)
    }

    /// Queues `data` as the next bytes of the request body, with no copy. It waits while the
    /// output queue is full.
    pub async fn write(&mut self, data: &Lease) -> Result<(), Error> {
        let written = self.socket.until(|client, now| queued(client.write(data, now)));
        written.await?.ok_or(ENDED)
    }

    /// Ends the request body. It waits while the output queue is full.
    pub async fn finish(&mut self) -> Result<(), Error> {
        let finished = self.socket.until(|client, now| queued(client.finish(now)));
        finished.await?.ok_or(ENDED)
    }

    /// Gives the response head of the request in flight, when it arrives. Refuses as
    /// [`Http1::response`](rsnetwork::client::Http1::response) does, for example with
    /// [`Kind::Deadline`] at the deadline.
    pub async fn response(&mut self) -> Result<ResponseHead, Error> {
        let response = self.socket.until(Core::response);
        response.await?.ok_or(ENDED)
    }

    /// Gives the next part of the response body as a view of its received region, with no copy,
    /// or its end with its outcome. Only `Outcome::Complete` makes the body complete.
    pub async fn next(&mut self) -> Result<Part, Error> {
        let part = self.socket.until(Core::next);
        part.await?.ok_or(ENDED)
    }

    /// Copies the next bytes of the response body into the free capacity of `region`, or gives
    /// its outcome after its last byte. It waits until a byte arrives, so it never gives
    /// [`Read::Wait`].
    pub async fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        let step = self
            .socket
            .until(|client, now| Ok(Step::of(&client.read_into(now, region)?)));
        match step.await?.ok_or(ENDED)? {
            Step::Bytes(count) => Ok(Read::Bytes(count)),
            Step::Full => Ok(Read::Full),
            // The outcome stays in the client, so the read gives it again.
            Step::Done => self.socket.connection_mut().read_into(Clock.now(), region),
        }
    }

    /// Collects the response body into `region`, whose free capacity bounds it. It waits until
    /// the body ends or no longer fits, so it never gives [`Collect::More`]. Only
    /// [`Collect::Complete`] holds a complete body.
    pub async fn collect<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Collect, Error> {
        let collected = self.socket.until(|client, now| {
            Ok(match client.collect(now, region)? {
                Collect::More => None,
                collect => Some(collect),
            })
        });
        collected.await?.ok_or(ENDED)
    }

    /// The bytes of the response body that the client gave so far. After a deadline, this is the
    /// part that arrived.
    pub fn delivered(&self) -> u64 {
        self.socket.connection().delivered()
    }

    /// Leaves the rest of the response body unread, as
    /// [`Http1::cancel`](rsnetwork::client::Http1::cancel) does: it drains before the next request,
    /// or the connection closes.
    pub fn cancel(&mut self) {
        self.socket.connection_mut().cancel();
    }

    /// What the TLS handshake negotiated, or `None` before it completed and over TCP.
    pub fn negotiated(&mut self) -> Option<Negotiated<'_>> {
        self.socket.connection_mut().negotiated()
    }

    /// Derives `output.len()` bytes of keying material with `label` and `context` from the regular
    /// exporter of the connection, as [`Http1::export`](rsnetwork::client::Http1::export) does.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        self.socket.connection().export(label, context, output)
    }

    /// Ends the connection: the exchange in flight ends with it, and over TLS the client sends
    /// `close_notify`. It waits until the transport accepted each output, and then closes the
    /// socket. Gives the end of the connection.
    pub async fn close(mut self) -> Result<(), Error> {
        self.socket.connection_mut().close(Clock.now())?;
        let end = self.socket.release().await?;
        let unsent = self.socket.close();
        assert!(unsent.is_empty(), "a released connection has no output that did not go");
        end
    }
}

/// One HTTP/2 client connection on a Tokio TCP socket, which many tasks share.
///
/// It has the calls of [`rsnetwork::client::Http2`], with its rules. A clone is one more handle of
/// the same connection. [`send`](Self::send) gives an [`Exchange`], the handle of one stream,
/// which can go to a task of its own. The handle that awaits drives the connection for each
/// stream, under a short lock, and wakes only the handles whose streams changed: no task, no
/// channel, and no copy. Thus a stalled body holds back only its own stream.
///
/// Only an awaited call drives the connection. While no exchange awaits, await
/// [`drive`](Self::drive), so the client answers the control frames of the server. A connection
/// whose last handle drops before its close resets.
#[derive(Clone, Debug)]
pub struct Http2 {
    shared: Arc<Shared<Core2>>,
}

impl Http2 {
    /// Binds `client`, a client of the core made with [`Clock::domain`], to `stream`, a TCP
    /// socket connected to the server. `pool` gives the receive regions over TCP: charge it to
    /// the budget of the client. Over TLS, one small slot is enough. Refuses with the error of the
    /// socket, as [`Socket::new`] does.
    pub fn new(client: Core2, stream: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self {
            shared: Arc::new(Shared::new(Socket::new(client, stream, pool)?)),
        })
    }

    /// Sends `request` on a new stream, with `deadline` for its exchange, as
    /// [`Http2::send`](rsnetwork::client::Http2::send) does, and gives the handle of the stream.
    /// It waits while each stream is in use, in the order of the calls that wait. Send a body
    /// with [`Exchange::write`], and end it with [`Exchange::finish`].
    pub async fn send(&self, request: &Request<'_>, deadline: Deadline) -> Result<Exchange, Error> {
        let sent = self
            .shared
            .until(Waits::Place(None), |client, now| client.send(request, deadline, now));
        let stream = sent.await?.ok_or(ENDED)?;
        Ok(Exchange {
            shared: Arc::clone(&self.shared),
            stream,
            end: None,
        })
    }

    /// Drives the connection until it ends: it answers the control frames of the server, such as
    /// SETTINGS and PING, and reads a GOAWAY. Await it while no exchange awaits, for example
    /// beside the other work of the task. Refuses with the error that ended the client.
    pub async fn drive(&self) -> Result<(), Error> {
        let driven = self
            .shared
            .until(Waits::Connection, |client, now| client.drive(now).map(|()| None::<()>));
        driven.await.map(drop)
    }

    /// Gives `read` what the TLS handshake negotiated, or `None` before it completed and over
    /// TCP, and gives what `read` gives. `read` runs under the lock of the connection, so it must
    /// not call the connection or one of its exchanges.
    pub fn negotiated<T>(&self, read: impl FnOnce(Option<Negotiated<'_>>) -> T) -> T {
        read(self.shared.lock().socket.connection_mut().negotiated())
    }

    /// Derives `output.len()` bytes of keying material with `label` and `context` from the regular
    /// exporter of the connection, as [`Http2::export`](rsnetwork::client::Http2::export) does.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        self.shared.lock().socket.connection().export(label, context, output)
    }

    /// Ends the connection: each exchange in flight ends with it, the client sends GOAWAY, and over
    /// TLS `close_notify`. It waits until the transport accepted each output. Gives the end of the
    /// connection. The socket closes when the last handle drops.
    pub async fn close(self) -> Result<(), Error> {
        self.shared.change(|client| client.close(Clock.now()))?;
        let released = self.shared.until(Waits::Connection, |client, _| Ok(client.release()));
        released.await?.ok_or(ENDED)?
    }
}

/// One exchange of an [`Http2`] connection: a request and its response on one stream.
///
/// It has the calls of [`rsnetwork::client::Http2`] for its stream. Each call awaits its own
/// progress, and a future that you drop changes nothing. An exchange that drops leaves its
/// stream, as [`Http2::cancel`](rsnetwork::client::Http2::cancel) says: when its exchange did not
/// end, the stream resets with `CANCEL`, and the connection goes on.
#[derive(Debug)]
pub struct Exchange {
    shared: Arc<Shared<Core2>>,
    stream: Stream,
    /// The outcome of the response body, after the read that gave it.
    end: Option<Outcome>,
}

impl Exchange {
    /// Queues `data` as the next bytes of the request body, with no copy. It waits while the chunk
    /// before waits for the output.
    pub async fn write(&mut self, data: &Lease) -> Result<(), Error> {
        let stream = self.stream;
        let written = self.shared.until(Waits::Stream(stream), |client, now| {
            queued(client.write(stream, data, now))
        });
        written.await?.ok_or(ENDED)
    }

    /// Ends the request body.
    pub async fn finish(&mut self) -> Result<(), Error> {
        let stream = self.stream;
        let finished = self
            .shared
            .until(Waits::Stream(stream), |client, now| queued(client.finish(stream, now)));
        finished.await?.ok_or(ENDED)
    }

    /// Gives the response head when it arrives. Refuses as
    /// [`Http2::response`](rsnetwork::client::Http2::response) does, for example with
    /// [`Kind::Deadline`] at the deadline.
    pub async fn response(&mut self) -> Result<ResponseHead, Error> {
        let stream = self.stream;
        let response = self
            .shared
            .until(Waits::Stream(stream), |client, now| client.response(stream, now));
        response.await?.ok_or(ENDED)
    }

    /// Gives the next part of the response body as a view of its received region, with no copy,
    /// or its end with its outcome. Only `Outcome::Complete` makes the body complete.
    pub async fn next(&mut self) -> Result<Part, Error> {
        let stream = self.stream;
        let part = self
            .shared
            .until(Waits::Stream(stream), |client, now| client.next(stream, now));
        part.await?.ok_or(ENDED)
    }

    /// Copies the next bytes of the response body into the free capacity of `region`, or gives
    /// its outcome after its last byte. It waits until a byte arrives, so it never gives
    /// [`Read::Wait`].
    pub async fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        let (stream, end) = (self.stream, &mut self.end);
        let step = self.shared.until(Waits::Stream(stream), |client, now| {
            let read = client.read_into(stream, now, region)?;
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

    /// Collects the response body into `region`, whose free capacity bounds it. It waits until
    /// the body ends or no longer fits, so it never gives [`Collect::More`]. Only
    /// [`Collect::Complete`] holds a complete body.
    pub async fn collect<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Collect, Error> {
        let stream = self.stream;
        let collected = self.shared.until(Waits::Stream(stream), |client, now| {
            Ok(match client.collect(stream, now, region)? {
                Collect::More => None,
                collect => Some(collect),
            })
        });
        collected.await?.ok_or(ENDED)
    }

    /// The bytes of the response body that the exchange gave so far. After a deadline, this is
    /// the part that arrived.
    pub fn delivered(&self) -> u64 {
        self.shared.lock().socket.connection_mut().delivered(self.stream)
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        let stream = self.stream;
        self.shared.change(|client| client.cancel(stream));
    }
}
