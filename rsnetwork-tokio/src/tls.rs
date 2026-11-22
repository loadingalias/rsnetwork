//! The TLS stream on Tokio: the calls of [`rsnetwork::tls::Stream`], each of which awaits the
//! progress that it needs, for a protocol other than HTTP over TLS.

use std::io;

use rsnetwork::body::{Part, Read};
use rsnetwork::buffer::{BufferMut, Lease, Pool, WriteLoan};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::tls::{Closure, ExportError, Negotiated, Stream as Core};
use tokio::net::TcpStream;

use crate::{Clock, Socket, Step, queued};

/// The refusal of a call after the stream ended.
const ENDED: Error = Error::new(Kind::Misuse, "the stream ended");

/// One TLS stream on a Tokio TCP socket: an encrypted, authenticated byte stream.
///
/// It has the calls of [`rsnetwork::tls::Stream`], with its rules. Each call awaits its own
/// progress. A future that you drop changes nothing: the next call goes on from the state of the
/// stream. A stream that drops before its close resets the connection.
#[derive(Debug)]
pub struct Stream {
    socket: Socket<Core>,
}

impl Stream {
    /// Binds `stream`, a TLS stream of the core made with [`Clock::domain`], to `tcp`, a
    /// connected TCP socket. The stream lends its own input region, so `pool` needs only one
    /// small slot, charged to the budget of the stream. Refuses with the error of the socket, as
    /// [`Socket::new`] does.
    pub fn new(stream: Core, tcp: TcpStream, pool: Pool) -> io::Result<Self> {
        Ok(Self {
            socket: Socket::new(stream, tcp, pool)?,
        })
    }

    /// Waits until the handshake completed, and gives what it negotiated. Refuses as
    /// [`Stream::drive`](rsnetwork::tls::Stream::drive) does, for example with
    /// [`Kind::Trust`] or with [`Kind::Deadline`] at the deadline of the handshake.
    pub async fn handshake(&mut self) -> Result<Negotiated<'_>, Error> {
        let completed = self.socket.until(|stream, now| {
            stream.drive(now)?;
            Ok(stream.negotiated().map(|_| ()))
        });
        completed.await?.ok_or(ENDED)?;
        self.socket.connection().negotiated().ok_or(ENDED)
    }

    /// Copies the next received bytes into the free capacity of `region`, or gives the outcome of
    /// the stream after its last byte. It waits until a byte arrives, so it never gives
    /// [`Read::Wait`].
    pub async fn read_into<B: BufferMut>(&mut self, region: &mut WriteLoan<B>) -> Result<Read<'_>, Error> {
        let step = self
            .socket
            .until(|stream, now| Ok(Step::of(&stream.read_into(now, region)?)));
        match step.await?.ok_or(ENDED)? {
            Step::Bytes(count) => Ok(Read::Bytes(count)),
            Step::Full => Ok(Read::Full),
            // The outcome stays in the stream, so the read gives it again.
            Step::Done => self.socket.connection_mut().read_into(Clock.now(), region),
        }
    }

    /// Gives the next received bytes as a view of their received region, with no copy, or the
    /// end of the stream with its outcome.
    pub async fn next(&mut self) -> Result<Part, Error> {
        let part = self.socket.until(Core::next);
        part.await?.ok_or(ENDED)
    }

    /// Queues `data` as the next bytes of the stream, with no copy. It waits while the queue is
    /// full.
    pub async fn write(&mut self, data: &Lease) -> Result<(), Error> {
        let written = self.socket.until(|stream, now| queued(stream.write(data, now)));
        written.await?.ok_or(ENDED)
    }

    /// The bytes that [`write`](Self::write) took.
    pub fn written(&self) -> u64 {
        self.socket.connection().written()
    }

    /// The bytes of the stream whose records the transport accepted, exact to whole records.
    pub fn sent(&self) -> u64 {
        self.socket.connection().sent()
    }

    /// How the input of the peer ended, or `None` before its end.
    pub fn closure(&self) -> Option<Closure> {
        self.socket.connection().closure()
    }

    /// Derives `output.len()` bytes of keying material with `label` and `context` from the regular
    /// exporter of the stream, as [`Stream::export`](rsnetwork::tls::Stream::export) does.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        self.socket.connection().export(label, context, output)
    }

    /// Ends the stream: it sends `close_notify` after the bytes that it took, waits until the
    /// transport accepted each output, and closes the socket. Gives the end of the stream.
    pub async fn close(mut self) -> Result<(), Error> {
        self.socket.connection_mut().close(Clock.now())?;
        let end = self.socket.release().await?;
        let unsent = self.socket.close();
        assert!(unsent.is_empty(), "a released connection has no output that did not go");
        end
    }
}
