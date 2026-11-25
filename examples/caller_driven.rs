//! The caller-driven protocol loop: an HTTP/1.1 client and server, each one a
//! `rsnetwork::host::Connection` that this program drives from its own loop, over loopback TCP
//! sockets in nonblocking mode.
//!
//! Run it with `cargo run --example caller_driven`. Each case checks its outcome and prints one
//! line. The page `docs/content/caller-driven-example.md` tells what each case shows.

use core::error::Error as StdError;
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::io::{self, ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

use rsnetwork::body::{Body, Outcome};
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::value::{Authority, Field, Method, Status, Target};

type Result<T> = core::result::Result<T, Box<dyn StdError>>;

/// The clock domain of this host: one monotonic clock.
const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

const LIMITS: Limits = Limits {
    head_bytes: 8 * 1024,
    fields: 64,
    name_bytes: 64,
    value_bytes: 4 * 1024,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 64 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 256 * 1024,
    frames: 1024,
    visits: 4096,
};

/// The bytes of one part of a large body. Each send queues a view of one part, with no copy.
const PART: usize = 64 * 1024;

/// The parts of a large body: 32 MiB, more than the socket buffers of a loopback connection hold.
const PARTS: usize = 512;

/// The longest wait between two turns. The standard library has no readiness poller: a real loop
/// waits in epoll or kqueue for the socket, or for the deadline of the connection.
const POLL: Duration = Duration::from_millis(1);

/// The longest time that one case can run before it fails.
const GUARD: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    let cases: [fn() -> Result<&'static str>; 5] = [partial_io, backpressure, timeout, cancellation, shutdown];
    for case in cases {
        report(case()?);
    }
    Ok(())
}

#[expect(clippy::print_stdout, reason = "an example prints the outcome of each case")]
fn report(line: &str) {
    println!("{line}");
}

/// A request with a buffered body, which each side reads in 7-byte regions: the heads and the
/// bodies come in parts. The server reads the head as an immediate borrow, keeps each part of the
/// body as an owned view, and echoes the views back with no copy. Both connections then end, and
/// they release after the transport accepted each output.
fn partial_io() -> Result<&'static str> {
    let clock = Clock::new();
    let (near, far) = sockets()?;
    let mut client = Peer::client(near, 7)?;
    let mut server = Peer::server(far, 16, 7, None)?;

    // A buffered body: each byte is here now, so its length frames it.
    let sent = Lease::from(b"partial reads, one region at a time".to_vec());
    let framing = Framing::from(&Body::Buffered(sent.clone()));
    let (engine, outbound) = client.connection.parts();
    let close = Field::new(b"connection", b"close")?;
    let (target, authority) = (Target::new(b"/echo")?, Authority::new(b"127.0.0.1")?);
    engine.request(outbound, Method::POST, target, authority, &[close], framing, head())?;
    engine.send(outbound, &sent)?;
    engine.finish(outbound)?;

    let mut kept: Vec<Lease> = Vec::new();
    let (mut status, mut echo, mut end) = (0, Vec::new(), None);
    let ends = loop {
        clock.guard()?;
        client.pump()?;
        server.pump()?;
        server.drive(clock.now(), |engine, outbound, event| {
            match event {
                // An immediate borrow: the head is valid during this call.
                ServerEvent::Request(request) => {
                    let head = request.head();
                    if head.method().as_bytes() != b"POST" || head.target().as_bytes() != b"/echo" {
                        return Err("the server read another request".into());
                    }
                }
                // An owned view of a received region: it stays valid after the drive, with no copy.
                ServerEvent::Data(data) => kept.push(data),
                ServerEvent::End(Outcome::Complete(None)) => {
                    let length = kept.iter().map(|data| data.bytes().len()).sum::<usize>();
                    let framing = Framing::Length(u64::try_from(length)?);
                    engine.respond(outbound, Status::new(200)?, &[], framing, head())?;
                    for data in &kept {
                        engine.send(outbound, data)?;
                    }
                    engine.finish(outbound)?;
                }
                other => return Err(format!("the server got {other:?}").into()),
            }
            Ok(())
        })?;
        client.drive(clock.now(), |_, _, event| {
            match event {
                ClientEvent::Response(response) => status = response.head().status().code(),
                ClientEvent::Data(data) => echo.extend_from_slice(data.bytes()),
                ClientEvent::End(outcome) => end = Some(outcome),
                other => return Err(format!("the client got {other:?}").into()),
            }
            Ok(())
        })?;
        client.pump()?;
        server.pump()?;
        // Terminal release: each engine ended, and the transport accepted each output.
        if let (Some(client), Some(server)) = (client.connection.release(), server.connection.release()) {
            break (client, server);
        }
        idle(clock.now(), &[client.connection.wait(), server.connection.wait()]);
    };

    check(server.reads > 2, "the request did not come in parts")?;
    check(status == 200 && echo == sent.bytes(), "the echo differs")?;
    check(
        matches!(end, Some(Outcome::Complete(None))),
        &format!("the echo ended {end:?}"),
    )?;
    check(
        matches!(ends, (Ok(()), Ok(()))),
        &format!("the connections ended {ends:?}"),
    )?;
    Ok("partial I/O: each side read 7-byte parts, both bodies are complete, and both ends released")
}

/// A one-shot body of 32 MiB, which the server produces as views of one part into an output queue
/// of 4 regions. The client reads nothing until the socket of the server accepts only part of an
/// output. Until then, the server waits for the socket, and its queue refuses each send. The client
/// then counts the bytes of each part as it comes, with no collection.
fn backpressure() -> Result<&'static str> {
    let clock = Clock::new();
    let (near, far) = sockets()?;
    let mut client = Peer::client(near, 64 * 1024)?;
    client.reading = false;
    let mut server = Peer::server(far, 4, 4 * 1024, None)?;
    request(&mut client, b"/large")?;

    let part = Lease::from(vec![b'x'; PART]);
    let total = u64::try_from(PART * PARTS)?;
    let (mut responding, mut produced, mut finished, mut refused) = (false, 0, false, 0);
    let (mut received, mut end) = (0, None);
    let ends = loop {
        clock.guard()?;
        client.pump()?;
        server.pump()?;
        // The client starts to read only when the socket of the server is full.
        client.reading |= server.short_writes > 0;
        server.drive(clock.now(), |engine, outbound, event| {
            if let ServerEvent::Request(_) = event {
                // A one-shot body: the application produces its bytes once, in order.
                let framing = Framing::from(&Body::OneShot { length: Some(total) });
                engine.respond(outbound, Status::new(200)?, &[], framing, head())?;
                responding = true;
            }
            Ok(())
        })?;
        if responding && !finished {
            let (engine, outbound) = server.connection.parts();
            while produced < PARTS {
                match engine.send(outbound, &part) {
                    Ok(()) => produced += 1,
                    // The queue is full: send again after the transport accepts output.
                    Err(error) if error.kind() == Kind::Overload => {
                        refused += 1;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if produced == PARTS {
                match engine.finish(outbound) {
                    Ok(()) => finished = true,
                    Err(error) if error.kind() == Kind::Overload => refused += 1,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        client.drive(clock.now(), |_, _, event| {
            match event {
                // The client uses each part in the call, and keeps no byte.
                ClientEvent::Data(data) => received += data.bytes().len(),
                ClientEvent::End(outcome) => end = Some(outcome),
                ClientEvent::Response(_) => {}
                other => return Err(format!("the client got {other:?}").into()),
            }
            Ok(())
        })?;
        client.pump()?;
        server.pump()?;
        if let (Some(client), Some(server)) = (client.connection.release(), server.connection.release()) {
            break (client, server);
        }
        idle(clock.now(), &[client.connection.wait(), server.connection.wait()]);
    };

    check(server.short_writes > 0 && refused > 0, "the server did not wait")?;
    check(u64::try_from(received)? == total, "the client got another length")?;
    check(
        matches!(end, Some(Outcome::Complete(None))),
        &format!("the body ended {end:?}"),
    )?;
    check(
        matches!(ends, (Ok(()), Ok(()))),
        &format!("the connections ended {ends:?}"),
    )?;
    Ok("backpressure: the server waited for the socket and for its queue, and the client got 33554432 bytes")
}

/// A client that sends part of a request head and stops. The loop sleeps until the deadline that
/// the wait of the server gives. The server then answers 408 and ends with a deadline error.
fn timeout() -> Result<&'static str> {
    let clock = Clock::new();
    let (mut near, far) = sockets()?;
    let mut server = Peer::server(far, 16, 4 * 1024, Some(Duration::from_millis(100)))?;
    near.write_all(b"GET / HTTP/1.1\r\nHo")?;

    let end = loop {
        clock.guard()?;
        server.pump()?;
        server.drive(clock.now(), |_, _, event| {
            Err(format!("the server got {event:?}").into())
        })?;
        server.pump()?;
        if let Some(end) = server.connection.release() {
            break end;
        }
        idle(clock.now(), &[server.connection.wait()]);
    };
    // The end of the connection: close the socket.
    drop(server);
    let mut answer = Vec::new();
    near.set_nonblocking(false)?;
    near.read_to_end(&mut answer)?;

    check(
        matches!(end, Err(error) if error.kind() == Kind::Deadline),
        &format!("the server ended {end:?}"),
    )?;
    check(answer.starts_with(b"HTTP/1.1 408 "), "the client got no 408")?;
    Ok("timeout: the server answered the slow head with 408 and ended with a deadline error")
}

/// The client cancels a long one-shot body after its first part. The body then ends `Cancelled`,
/// with no more of its bytes. The connection closes after this response, so the client engine
/// discards nothing to reuse it, and it ends. The client closes its socket after the terminal
/// release. The server then reads the end of the input, or its socket fails.
fn cancellation() -> Result<&'static str> {
    let clock = Clock::new();
    let (near, far) = sockets()?;
    let mut client = Some(Peer::client(near, 4 * 1024)?);
    let mut server = Peer::server(far, 4, 4 * 1024, None)?;
    if let Some(client) = client.as_mut() {
        request(client, b"/stream")?;
    }

    let part = Lease::from(vec![b'x'; PART]);
    let (mut responding, mut cancelled, mut after, mut end, mut client_end) = (false, false, 0, None, None);
    loop {
        clock.guard()?;
        if let Some(peer) = client.as_mut() {
            peer.pump()?;
            peer.drive(clock.now(), |engine, _, event| {
                match event {
                    ClientEvent::Data(_) if !cancelled => {
                        // Early cancellation: the client wants no more of the body.
                        engine.cancel_response();
                        cancelled = true;
                    }
                    ClientEvent::Data(_) => after += 1,
                    ClientEvent::End(outcome) => end = Some(outcome),
                    ClientEvent::Response(_) => {}
                    other => return Err(format!("the client got {other:?}").into()),
                }
                Ok(())
            })?;
            peer.pump()?;
            if let Some(end) = peer.connection.release() {
                // Terminal release: close the socket.
                client_end = Some(end);
                client = None;
            }
        }
        // The server sends until the client closed. Then its socket fails, or it reads the end.
        if server.pump().is_err() {
            break;
        }
        server.drive(clock.now(), |engine, outbound, event| {
            if let ServerEvent::Request(_) = event {
                // A one-shot body of unknown length goes in chunks.
                let framing = Framing::from(&Body::OneShot { length: None });
                engine.respond(outbound, Status::new(200)?, &[], framing, head())?;
                responding = true;
            }
            Ok(())
        })?;
        if responding {
            let (engine, outbound) = server.connection.parts();
            while engine.send(outbound, &part).is_ok() {}
        }
        if server.pump().is_err() || (client.is_none() && server.connection.release().is_some()) {
            break;
        }
        let client_wait = client
            .as_ref()
            .map_or(Wait::Ended(Ok(())), |peer| peer.connection.wait());
        idle(clock.now(), &[client_wait, server.connection.wait()]);
    }
    // A failed socket ends the server before its terminal release: abandon its connection.
    let _ = server.connection.abandon();

    check(
        cancelled && after == 0,
        "the client got more of the body after the cancel",
    )?;
    check(
        matches!(end, Some(Outcome::Cancelled)),
        &format!("the body ended {end:?}"),
    )?;
    check(
        matches!(client_end, Some(Ok(()))),
        &format!("the client ended {client_end:?}"),
    )?;
    Ok(
        "early cancellation: the client cancelled the body after its first part, the body ended Cancelled, and the client released",
    )
}

/// The server sends a long body to a client that reads nothing, until its socket accepts only part
/// of an output. Then the application shuts down before the terminal release: `abandon` reports
/// the output that the socket did not accept. A completion transport keeps its own view of that
/// output until its terminal event.
fn shutdown() -> Result<&'static str> {
    let clock = Clock::new();
    let (near, far) = sockets()?;
    let mut client = Peer::client(near, 4 * 1024)?;
    client.reading = false;
    let mut server = Peer::server(far, 4, 4 * 1024, None)?;
    request(&mut client, b"/large")?;

    let part = Lease::from(vec![b'x'; PART]);
    let mut responding = false;
    while server.short_writes == 0 {
        clock.guard()?;
        client.pump()?;
        server.pump()?;
        server.drive(clock.now(), |engine, outbound, event| {
            if let ServerEvent::Request(_) = event {
                let framing = Framing::from(&Body::OneShot { length: None });
                engine.respond(outbound, Status::new(200)?, &[], framing, head())?;
                responding = true;
            }
            Ok(())
        })?;
        if responding {
            let (engine, outbound) = server.connection.parts();
            while engine.send(outbound, &part).is_ok() {}
        }
        server.pump()?;
        idle(clock.now(), &[client.connection.wait(), server.connection.wait()]);
    }
    let outstanding = server.connection.abandon();
    let requested = client.connection.abandon();

    check(
        outstanding.regions > 0 && outstanding.bytes > 0,
        &format!("the server abandoned {outstanding:?}"),
    )?;
    check(requested.is_empty(), "the socket did not accept the request")?;
    Ok("shutdown: the server abandoned its connection with output that the socket did not accept")
}

/// A GET request for `target` that asks the server to close the connection after its response.
fn request(client: &mut Peer<Client>, target: &[u8]) -> Result<()> {
    let (engine, outbound) = client.connection.parts();
    let close = Field::new(b"connection", b"close")?;
    let (target, authority) = (Target::new(target)?, Authority::new(b"127.0.0.1")?);
    engine.request(
        outbound,
        Method::GET,
        target,
        authority,
        &[close],
        Framing::Length(0),
        head(),
    )?;
    engine.finish(outbound)?;
    Ok(())
}

/// Fails with `what` when the outcome of a case does not hold.
fn check(holds: bool, what: &str) -> Result<()> {
    if holds { Ok(()) } else { Err(what.into()) }
}

/// A region for a head that an engine writes.
fn head() -> Backing {
    Backing::from(Vec::with_capacity(256))
}

/// The two ends of a new loopback TCP connection, in nonblocking mode.
fn sockets() -> Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let near = TcpStream::connect(listener.local_addr()?)?;
    let (far, _) = listener.accept()?;
    near.set_nonblocking(true)?;
    far.set_nonblocking(true)?;
    Ok((near, far))
}

/// Waits before the next turn: not at all when a connection has work now, and else until the
/// earliest deadline, for at most [`POLL`].
fn idle(now: Instant, waits: &[Wait]) {
    let mut sleep = POLL;
    for wait in waits {
        match wait {
            Wait::Now => return,
            Wait::Until {
                deadline: Some(deadline),
                ..
            }
            | Wait::Linger { deadline } => {
                let left = deadline.instant().as_nanos().saturating_sub(now.as_nanos());
                sleep = sleep.min(Duration::from_nanos(left));
            }
            Wait::Until { deadline: None, .. } | Wait::Ended(_) => {}
        }
    }
    std::thread::sleep(sleep);
}

/// The monotonic clock of this host, on [`CLOCK`].
struct Clock(std::time::Instant);

impl Clock {
    fn new() -> Self {
        Self(std::time::Instant::now())
    }

    fn now(&self) -> Instant {
        let nanos = u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Instant::new(CLOCK, nanos)
    }

    /// Fails when the case runs longer than [`GUARD`].
    fn guard(&self) -> Result<()> {
        if self.0.elapsed() > GUARD {
            return Err("the case did not end".into());
        }
        Ok(())
    }
}

/// One end of a TCP connection: its socket, and the connection that drives its engine.
struct Peer<E> {
    socket: TcpStream,
    connection: Connection<E>,
    endpoint: Endpoint,
    /// The bytes of each read.
    read_size: usize,
    /// Whether the loop reads the socket.
    reading: bool,
    /// A received region that the full input queue gave back. The next turn gives it again.
    held: Option<Received>,
    /// The reads that gave bytes.
    reads: usize,
    /// The writes that the socket accepted only in part, or not at all.
    short_writes: usize,
}

impl Peer<Client> {
    fn client(socket: TcpStream, read_size: usize) -> Result<Self> {
        let budget = budget()?;
        let (inbound, outbound) = queues(4, &budget)?;
        let engine = Client::new(LIMITS, BODY, TURN, &outbound, &budget)?;
        Peer::new(socket, engine, inbound, outbound, read_size)
    }
}

impl Peer<Server> {
    fn server(socket: TcpStream, outputs: usize, read_size: usize, timeout: Option<Duration>) -> Result<Self> {
        let budget = budget()?;
        let (inbound, outbound) = queues(outputs, &budget)?;
        let engine = Server::new(LIMITS, BODY, TURN, &outbound, &budget)?.head_timeout(timeout);
        Peer::new(socket, engine, inbound, outbound, read_size)
    }
}

impl<E: Engine> Peer<E> {
    fn new(socket: TcpStream, engine: E, inbound: Inbound, outbound: Outbound, read_size: usize) -> Result<Self> {
        let endpoint = Endpoint {
            peer: socket.peer_addr()?,
            local: socket.local_addr()?,
            ecn: Ecn::NotEct,
            segment: None,
        };
        Ok(Self {
            socket,
            connection: Connection::new(engine, inbound, outbound, Some(CLOCK))?,
            endpoint,
            read_size,
            reading: true,
            held: None,
            reads: 0,
            short_writes: 0,
        })
    }

    /// Moves bytes between the socket and the connection: one read when the engine waits for
    /// input, then each output until the socket accepts only part of one.
    fn pump(&mut self) -> io::Result<()> {
        if let Some(received) = self.held.take() {
            self.held = self.connection.receive(received).err();
        } else if self.reading
            && matches!(
                self.connection.wait(),
                Wait::Until {
                    blocked: Blocked::Input,
                    ..
                }
            )
        {
            let mut region = vec![0; self.read_size];
            match self.socket.read(&mut region) {
                Ok(0) => self.connection.end_input(),
                Ok(len) => {
                    region.truncate(len);
                    self.reads += 1;
                    let received = Received {
                        region: Lease::from(region),
                        endpoint: self.endpoint,
                        capacity: u64::try_from(self.read_size).unwrap_or(u64::MAX),
                    };
                    // A full input queue gives the region back: drive first.
                    self.held = self.connection.receive(received).err();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        while let Some(output) = self.connection.output() {
            let accepted = match self.socket.write(output.region.bytes()) {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == ErrorKind::WouldBlock => 0,
                Err(error) => return Err(error),
            };
            // The exact bytes that the socket accepted. The rest stays in the queue, at its address.
            self.connection.ack(output.id, accepted).map_err(io::Error::other)?;
            if accepted < output.region.initialized() {
                self.short_writes += 1;
                break;
            }
        }
        Ok(())
    }

    /// Drives the connection at `now` until it gives no event, and gives each event to `answer`
    /// with the engine and its output queue.
    fn drive(
        &mut self,
        now: Instant,
        mut answer: impl FnMut(&mut E, &mut Outbound, E::Event) -> Result<()>,
    ) -> Result<()> {
        while let Some(event) = self.connection.drive(Some(now))? {
            let (engine, outbound) = self.connection.parts();
            answer(engine, outbound, event)?;
        }
        Ok(())
    }
}

/// The budget of one connection, which pays for its queues and its engine.
fn budget() -> Result<Budget> {
    Ok(Budget::new(NonZeroU64::new(1 << 20).ok_or("zero budget")?))
}

/// The input queue of 16 regions, and an output queue of `outputs` regions.
fn queues(outputs: usize, budget: &Budget) -> Result<(Inbound, Outbound)> {
    let inputs = NonZeroUsize::new(16).ok_or("zero inputs")?;
    let outputs = NonZeroUsize::new(outputs).ok_or("zero outputs")?;
    Ok((Inbound::new(inputs, budget)?, Outbound::new(outputs, budget)?))
}

#[cfg(test)]
mod tests {
    /// Each case of the example gives its expected outcome.
    #[test]
    fn each_case_gives_its_outcome() {
        super::main().unwrap();
    }
}
