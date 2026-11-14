# Drive a connection from your own event loop

The `rsnetwork::host` module is the caller-driven host: one connection that your application
drives from its own event loop, with no runtime. Your loop owns the socket, or any other byte
source, and the clock. The connection spawns no task, starts no thread, and does not need `Send`.

rsnetwork is in development and has no release. To connect the engines to a runtime instead, see
[Write a binding](adapters.md).

## The loop

A `Connection` holds one engine, `h1::Server` or `h1::Client`, and its two queues. In each turn of
your loop:

1. Read the bytes that the socket received, and give each region to `connection.receive`. When the
   socket reports that the peer closed its side, call `connection.end_input()`.
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
| `Ended(result)` | Do not drive again. Send the rest of the output, then release the connection |

| `blocked` | The engine waits for |
| --- | --- |
| `Blocked::Input` | Received bytes, or the end of the input |
| `Blocked::Output` | The socket to accept output: the engine has output that must go first |
| `Blocked::Capacity(n)` | `n` more bytes of capacity, for example after your code consumes a body |

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

To drop a connection before its release, for example at shutdown, call `connection.abandon()`. It
reports the output that the socket has not accepted: its regions, its bytes, and the output that
waits for its acknowledgement. The socket keeps its own view of that output until its terminal
event.

## Example

A server connection answers one request. The code runs in a function that returns
`Result<(), Box<dyn std::error::Error>>`. The module documentation of `rsnetwork::host` runs the
same example as a test.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Wait};
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
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
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

## A nonblocking socket

For a `std::net::TcpStream` in nonblocking mode, one turn of the loop is:

1. Read into a new region. `Ok(0)` is the end of input. `Ok(n)` gives a region of `n` bytes for
   `receive`. `WouldBlock` means that no byte waits.
2. Drive, as above.
3. For each output, write its bytes. `Ok(n)` is an acknowledgement of `n` bytes. `WouldBlock` is
   an acknowledgement of `0`, and the next output waits until the socket can take more.

The test `tests/host.rs` of rsnetwork runs a client and a server connection this way over loopback
sockets.
