# Drive a connection from your own event loop

The `rsnetwork::host` module is the caller-driven host: one connection that your application
drives from its own event loop, with no runtime. Your loop owns the socket, or any other byte
source, and the clock. The connection spawns no task, starts no thread, and does not need `Send`.

rsnetwork is in development and has no release. To move the bytes of a std TCP socket, use
[`host::Tcp`](#bind-a-tcp-socket). To run the engines on Tokio, see
[run the engines on Tokio](tokio.md). To connect them to another runtime, see
[Write a binding](adapters.md). To run the same connection over TLS 1.3, see
[Run a connection over TLS 1.3](tls.md).

## The loop

A `Connection` holds one engine, `h1::Server` or `h1::Client`, and its two queues. The calls that
move its bytes, for example `receive`, `output`, `ack`, `wait`, and `release`, are the calls of the
trait `host::Io`: import it with `use rsnetwork::host::Io as _;`. In each turn of your loop:

1. Read the bytes that the socket received, and give each region to `connection.receive`. When the
   socket reports that the peer closed its side, call `connection.end_input()`. When the socket
   reports a reset, or a write fails, call `connection.reset()`.
2. Call `connection.drive(now)` until it gives no event, with the time of your host as `now`.
   Answer each event, for example a request, with the engine and the output queue that
   `connection.parts()` gives.
3. Write each output that `connection.output()` gives to the socket, and acknowledge the bytes
   that the socket accepted with `connection.ack(id, accepted)`. Give `0` when the socket accepted
   no byte.
4. Wait as `connection.wait()` tells, then go to step 1.

| `Wait` | Next action |
| --- | --- |
| `Now` | Drive again now: the engine has an event or more work |
| `Until { blocked, deadline }` | Drive when your host gives what `blocked` names, or at `deadline`, whichever comes first. `None` has no deadline |
| `Linger { deadline }` | Only the [server](server.md#linger) gives it: half-close the socket once, give each received byte as before, and call again at `deadline` |
| `Ended(result)` | Do not drive again. Send the rest of the output, then release the connection |

| `blocked` | The engine waits for |
| --- | --- |
| `Blocked::Input` | Received bytes, or the end of the input |
| `Blocked::Output` | The socket to accept output: the engine has output that must go first |
| `Blocked::Capacity(n)` | `n` more bytes of capacity, for example after your code consumes a body |
| `Blocked::Streams` | HTTP/2 only: a free stream slot. Your code closes a stream when its handler ends: with `server::Http::close`, or with `h2::Connection::close` after a reset. The HTTP/1.1 engines never give it |

Wait only for the cause that `blocked` names. A socket can almost always take output, so a loop
that also waits for that while the engine waits for input wakes at once, again and again. Write
each output that `connection.output()` gives in any wait. Wait for the socket to take more output
only when it accepted part of an output.

The wait comes from the last turn. A deadline that the engine starts on a turn, also with no new
input, is in the wait of that turn, so set your timer after each drive, not only after a receive.

## Time and clocks

Give `Connection::new` the clock of your host, a `ClockDomain`, and give each drive an `Instant`
on that clock. A host with no clock gives `None` for both. The server engine has a head timeout,
30 seconds by default, which needs a clock:

- A host with no clock refuses an engine with a timer: `Connection::new` gives `Kind::Unsupported`.
  Turn the timer off with `Server::head_timeout(None)`, or give a clock.
- A drive with a time on another clock, or with no time when the connection has a clock, refuses
  with `Kind::Misuse`.

## Close and release

A connection must stay driven until its terminal release: the engine ended, and the socket
accepted each output. `connection.release()` gives the result of the connection then, and `None`
before it. Then drop the connection and close the socket.

After `connection.reset()`, the output that waits can never go, so `release()` does not wait for
it, and `outstanding()` reports it.

To drop a connection before release, call `connection.abandon()`. Its report gives the pending regions and bytes and the current offer ID.
The totals include regions that an ordered driver owns. The report gives their counts in `admitted_regions` and `admitted_bytes`.
The driver keeps its views until its final use. [Give output to an ordered driver](adapters.md#give-output-to-an-ordered-driver)

## Example

A server connection answers one request. The code runs in a function that returns
`Result<(), Box<dyn std::error::Error>>`. The module documentation of `rsnetwork::host` runs the
same example as a test. [The caller-driven protocol loop](caller-driven-example.md) is a complete
program over loopback sockets, with partial I/O, backpressure, a timeout, cancellation, and
shutdown.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::value::Status;

let limits = Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
let body = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024, visits: 4096 };
let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let queue = NonZeroUsize::new(16).expect("not zero");
let (inbound, outbound) = (Inbound::new(queue, &budget)?, Outbound::new(queue, &budget)?);
let server = Server::new(limits, body, turn, &outbound, &budget)?;

// The clock of the host. A real host reads its monotonic clock at each drive.
let clock = ClockDomain::new(1, Suspend::Pauses);
let now = Some(Instant::new(clock, 0));
let mut connection = Connection::new(server, inbound, outbound, Some(clock))?;

// The socket received a request.
let endpoint = Endpoint {
    peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
    local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
    ecn: Ecn::NotEct,
    segment: None,
};
let region = Lease::from(b"GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec());
connection.receive(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");

// Drive until the connection waits, and answer the request.
while let Some(event) = connection.drive(now)? {
    if let ServerEvent::Request(_) = event {
        let (server, outbound) = connection.parts();
        let head = Backing::from(Vec::with_capacity(256));
        server.respond(outbound, Status::new(200)?, &[], Framing::Length(5), head)?;
        server.send(outbound, &Lease::from(b"hello".to_vec()))?;
        server.finish(outbound)?;
    }
}
assert_eq!(connection.wait(), Wait::Ended(Ok(())));

// Write each output to the socket, and acknowledge the bytes that it accepted.
let mut sent = Vec::new();
while let Some(output) = connection.output() {
    sent.extend_from_slice(output.region.bytes());
    connection.ack(output.id, output.region.initialized())?;
}
assert_eq!(sent, b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 5\r\n\r\nhello");
assert_eq!(connection.release(), Some(Ok(())));
```

## Bind a TCP socket

With the `tcp` feature, `host::Tcp` moves the bytes between one nonblocking `std::net::TcpStream`
and one connection: a `Connection`, a `client::Http1`, a `client::Http2`, a `server::Http`, or a
`tls::Stream`. Your
loop keeps the poller and the clock. The socket spawns no task and starts no thread. `Tcp` also
takes another socket through the trait `host::Socket`, for example the socket of a runtime: see
[readiness hosts](adapters.md#readiness-hosts).

Prerequisites:

- The `tcp` feature. It is off by default, and it adds no dependency. Until `Read::read_buf` and
  `TcpStream::set_linger` are stable in std, it needs the nightly toolchain that rsnetwork pins.
- A connected `TcpStream`, for example from `TcpStream::connect` or `TcpListener::accept`.
- A `Pool` of receive regions, charged to the budget of the connection: see [receive regions](#receive-regions).

To run a connection over the socket:

1. Make the socket with `Tcp::new(stream, pool)`. It sets the stream to nonblocking mode and sets
   `TCP_NODELAY`, because each output region is its own write. It refuses with the `io::Error` of
   the stream.
2. In each turn, call the connection, for example `client.response(now)` or `server.request(now)`.
   Only these calls drive it.
3. Call `tcp.pump(&mut connection)`, and do what its `Next` says.
4. At `Next::Released`, read the end of the connection with `connection.release()`. Then call
   `tcp.close(&connection)`.

| `Next` | Next action |
| --- | --- |
| `Now` | Call the connection again, and pump again: bytes moved, or the connection has more work |
| `Wait { read, write, deadline }` | Wait in your poller until the socket can read (`read`) or write (`write`), or until `deadline`. With neither, no event of the socket can help: the connection waits for capacity, for example for your code to drop the views of received bytes. Call it again after that |
| `Released` | The connection can drop: close the socket |

Register `tcp.socket()` with your poller. Do not read or write it yourself.

### What a pump does

A pump reads one time when the connection waits for input or lingers, and then writes each output
until the socket takes only part of one. It gives each result of the socket to the connection:

| The socket gives | The pump |
| --- | --- |
| Bytes | Gives them to the connection, with no copy |
| The end of the stream | Calls `end_input`: a body with a length that did not end ends `Outcome::Truncated` |
| An error, for example a reset or a refused write | Calls `reset`: a body that did not end ends `Outcome::Reset(None)` |
| `WouldBlock` on a read | Gives `Wait` with `read` |
| Part of an output, or `WouldBlock` on a write | Acknowledges the exact bytes, and gives `Wait` with `write` |
| `Interrupted` | Gives `Now` |

At `Wait::Linger` of a [server](server.md#linger), after the last output, the pump shuts down the
write side of the socket one time. At the release of the connection, it does the same, so the
peer reads each byte and then the end of the stream.

`pump` refuses with `Kind::Overload` when the connection cannot pay for its input region. It
writes the output first. Release capacity, and pump again.

### Receive regions

A connection over TCP lends no input region, so the pump reads into a slot of the pool. The reads
fill each slot one after the other, so a short read keeps no slot for itself. A slot comes back
when the last view of its bytes drops. When each slot is in use, the pump gives `Wait` with
neither `read` nor `write`.

A TLS connection lends its own input region, and the pump reads into it: see
[TLS over the socket](#tls-over-the-socket). Its pool serves only the linger of a server, which
discards the bytes, so one slot of a few KiB is enough.

### Close

`tcp.close(&connection)` closes the socket and gives the output that the socket did not accept,
as an `Outstanding`:

- After `Next::Released`, with no output left, the peer read each byte and then the end of the
  stream. `close` gives an empty `Outstanding`.
- Before the release, or with output left, for example at a shutdown of your process, `close`
  resets the connection. Thus the peer cannot read the close as the end of the data, for example
  of a body that the close delimits. The `Outstanding` tells what did not go.

### Example

A client and a server exchange one request over loopback sockets. The code runs in a function that
returns `Result<(), Box<dyn std::error::Error>>`. The documentation of `rsnetwork::host::Tcp` runs
the same example as a test. This loop does not wait: a real loop waits in its poller as each
`Next::Wait` says.

```rust
use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::net::{TcpListener, TcpStream};

use rsnetwork::body::Part;
use rsnetwork::buffer::{Buffer as _, Lease, Pool};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::host::{Io as _, Next, Tcp};
use rsnetwork::server::{self, Cleartext, Linger, Response};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::value::{Authority, Method, Status, Target};

let head = h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
let body = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};
let settings = h2::Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..h2::Settings::INITIAL };
let h2 = h2::Limits { settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 };
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024, visits: 4096 };
let queue = NonZeroUsize::new(16).expect("not zero");
let linger = Linger { time: Duration::from_secs(5), bytes: 64 * 1024 };
let budget = Budget::new(NonZeroU64::new(1 << 22).expect("not zero"));

// The monotonic clock of the host.
let clock = ClockDomain::new(1, Suspend::Pauses);
let start = std::time::Instant::now();
let now = || Instant::new(clock, u64::try_from(start.elapsed().as_nanos()).expect("in range"));

// Each socket has 4 receive regions of 16 KiB, charged to the budget.
let slot = Layout::array::<u8>(16 * 1024)?;
let pool = || Pool::new(&budget, NonZeroU32::new(4).expect("not zero"), slot);
let listener = TcpListener::bind("127.0.0.1:0")?;
let mut near = Tcp::new(TcpStream::connect(listener.local_addr()?)?, pool()?)?;
let mut far = Tcp::new(listener.accept()?.0, pool()?)?;

let mut client = client::Http1::plain(client::Limits { head, h2, body, turn, queue }, clock, &budget)?;
let head_timeout = Some(Duration::from_secs(30));
let cleartext = Cleartext::Http1;
let limits = server::Limits { head, h2, body, turn, queue, head_timeout, linger, cleartext };
let mut server = server::Http::plain(limits, clock, &budget)?;

let request = Request {
    method: Method::GET,
    target: Target::new(b"/hello")?,
    authority: Authority::new(b"127.0.0.1")?,
    fields: &[],
    length: Some(0),
};
let deadline = Deadline::at(Instant::new(clock, 30_000_000_000));
client.send(&request, deadline, now())?;
let (mut answered, mut response, mut received, mut closed) = (false, None, Vec::new(), false);
loop {
    // Call each connection: only its calls drive it.
    if let Some((stream, _head)) = server.request(now())? {
        let hello = Response { status: Status::new(200)?, fields: &[], length: Some(5) };
        answered = server.respond(stream, &hello, now())?;
        server.write(stream, &Lease::from(b"hello".to_vec()), now())?;
        server.finish(stream, now())?;
        server.close(stream);
    }
    if response.is_none() {
        response = client.response(now())?;
    }
    while response.is_some() && !closed && let Some(part) = client.next(now())? {
        match part {
            Part::Data(data) => received.extend_from_slice(data.bytes()),
            Part::End(_) => {
                client.close(now())?;
                closed = true;
            }
        }
    }
    // Then pump each socket.
    if (near.pump(&mut client)?, far.pump(&mut server)?) == (Next::Released, Next::Released) {
        break;
    }
}
assert!(answered);
assert_eq!(received, b"hello");
assert_eq!(client.release(), Some(Ok(())));
assert_eq!(server.release().map(|closed| closed.result), Some(Ok(())));
assert!(near.close(&client).is_empty() && far.close(&server).is_empty());
```

## TLS over the socket

A TLS connection runs over `host::Tcp` with the same loop. Make it with `client::Http1::tls`,
`client::Http2::tls`, `server::Http::tls`, `tls::Stream::connect`, or `tls::Stream::accept`, and
give its socket a pool of one small slot. In the example, the client over TLS is:

```rust
// `config` is a `tls::ClientConfig`, and `tls` is the `tls::Limits` of the connection.
let slot = Layout::array::<u8>(4096)?;
let mut near = Tcp::new(TcpStream::connect(address)?, Pool::new(&budget, NonZeroU32::MIN, slot)?)?;
let limits = client::Limits { head, h2, body, turn, queue };
let mut client = client::Http1::tls(&config, "example.com", (limits, tls), clock, &budget)?;
```

- The pump reads into the tail of the input region that the connection lends, and TLS decrypts
  each record there. No received byte is copied: `Copies::received` stays 0.
- The connection runs the handshake, sends `close_notify`, and tells a `close_notify` of the peer
  from an end of the stream with no `close_notify`. The pump moves only ciphertext.
- A write of the application that meets a full plaintext queue drives the connection one time,
  because only a drive seals plaintext into records. When the queue is still full, the write
  refuses with `Kind::Overload`: pump, and write again.

[Run a connection over TLS 1.3](tls.md) gives the configuration of each end, and
[Send a byte stream over TLS](tls-stream.md) gives the stream.
