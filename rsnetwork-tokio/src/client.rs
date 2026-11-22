//! The HTTP/1.1 client on Tokio: the calls of [`rsnetwork::client::Http1`], each of which awaits
//! the progress that it needs.

use std::io;

use rsnetwork::body::{Collect, Part, Read};
use rsnetwork::buffer::{BufferMut, Lease, Pool, WriteLoan};
use rsnetwork::client::{Http1 as Core, Request};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::h1::RetainedResponse;
use rsnetwork::time::Deadline;
use rsnetwork::tls::Negotiated;
use tokio::net::TcpStream;

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
    pub async fn response(&mut self) -> Result<RetainedResponse, Error> {
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
