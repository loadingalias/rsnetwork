# Run the engines on Tokio

The package `rsnetwork-tokio` runs the HTTP/1.1 client, the HTTP/1.1 server, and the TLS stream of
rsnetwork on the Tokio runtime of your application. Each call awaits the progress that it needs,
so a body read moves its own bytes. You poll no second object, and the client spawns no task. A
server spawns one task for each connection, owns it, and joins it at its close.

rsnetwork is in development and has no release. `rsnetwork-tokio` is a package of the rsnetwork
repository. It has run evidence on macOS (aarch64), on the current-thread runtime and the
multi-thread runtime of Tokio.

## Prerequisites

- A Tokio 1.54 runtime whose I/O driver and timer are on, for example a runtime that
  `Builder::enable_all` or `#[tokio::main]` made. The binding starts no runtime and no thread.
  Call it in a task of that runtime.
- The nightly toolchain that rsnetwork pins: the binding uses the socket rules of
  [`host::Tcp`](caller-driven.md#bind-a-tcp-socket), which need the `tcp` feature.
- The limits and the budget of each connection, as for the core [client](client.md) and
  [server](server.md). Over TLS, also a configuration, as on the [TLS page](tls.md).

## The clock

`rsnetwork_tokio::Clock` is the monotonic clock of Tokio as the time of the core. Make each
connection of the core with `Clock.domain()`, and each deadline with `Clock.deadline(after)`. A
connection on another clock domain refuses its first call with `Kind::Misuse`. Each `Clock` of a
process has the same start, so their times compare. The clock stops while the system is suspended,
as the monotonic clock of the target does. On Windows it goes on.

## Serve requests and send one

A server answers each request with `hello`, and a client sends one request over loopback. The code
runs in a function that returns `Result<(), Box<dyn std::error::Error>>`. The documentation of the
crate `rsnetwork_tokio` runs the same example as a test.

```rust
use core::alloc::Layout;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rsnetwork::body::Collect;
use rsnetwork::buffer::{Lease, Pool, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::{Error, Kind, TurnLimits};
use rsnetwork::h1::{self, BodyLimits, Framing};
use rsnetwork::server::{self, Linger, Response};
use rsnetwork::value::{Authority, Method, Status, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::Server;

let head = h1::Limits { head_bytes: 8 * 1024, fields: 64, name_bytes: 64, value_bytes: 4 * 1024 };
let body = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024 };
let queue = NonZeroUsize::new(16).expect("not zero");
let linger = Linger { time: Duration::from_secs(5), bytes: 64 * 1024 };
let head_timeout = Some(Duration::from_secs(30));
let server_limits = server::Limits { head, body, turn, queue, head_timeout, linger };
let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
// Each socket has 4 receive regions of 16 KiB, charged to the budget.
let slot = Layout::array::<u8>(16 * 1024)?;
let pool = {
    let budget = budget.clone();
    move || Pool::new(&budget, NonZeroU32::new(4).expect("not zero"), slot)
};
let ok = Status::new(200)?;

let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
runtime.block_on(async {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    // Each accepted connection gets a server of the core and its receive regions.
    let make = {
        let (budget, pool) = (budget.clone(), pool.clone());
        move || {
            let refused = |_| Error::new(Kind::Overload, "the budget refused the receive regions");
            let pool = pool().map_err(refused)?;
            Ok((server::Http1::plain(server_limits, Clock.domain(), &budget)?, pool))
        }
    };
    let connections = NonZeroUsize::new(1024).expect("not zero");
    let server = Server::serve(listener, connections, make, move |mut connection| async move {
        while connection.request().await?.is_some() {
            let hello = Response { status: ok, fields: &[], body: Framing::Length(5) };
            connection.respond(&hello).await?;
            connection.write(&Lease::from(&b"hello"[..])).await?;
            connection.finish().await?;
        }
        Ok(())
    });

    let core = client::Http1::plain(client::Limits { head, body, turn, queue }, Clock.domain(), &budget)?;
    let stream = tokio::net::TcpStream::connect(address).await?;
    let mut client = rsnetwork_tokio::client::Http1::new(core, stream, pool()?)?;
    let request = Request {
        method: Method::GET,
        target: Target::new(b"/hello")?,
        authority: Authority::new(b"127.0.0.1")?,
        fields: &[],
        body: Framing::Length(0),
    };
    // One deadline covers the response head and each byte of the body.
    client.send(&request, Clock.deadline(Duration::from_secs(5))).await?;
    assert_eq!(client.response().await?.head().status(), ok);
    let mut region = WriteLoan::new(Vec::with_capacity(64));
    assert!(matches!(client.collect(&mut region).await?, Collect::Complete(None)));
    assert_eq!(region.filled(), b"hello");
    client.close().await?;

    // The close drains each connection, and joins each task of the server.
    let report = server.close(Clock.deadline(Duration::from_secs(5))).await;
    assert_eq!((report.accepted, report.failed, report.aborted), (1, 0, 0));
    Ok::<(), Box<dyn std::error::Error>>(())
})?;
```

Over TLS, make the core connection with `client::Http1::tls` or `server::Http1::tls`. The rest
does not change. A TLS connection lends its own input region, so one small slot in its pool is
enough: see [receive regions](caller-driven.md#receive-regions).

## The calls

Each type binds one connection of the core to one Tokio `TcpStream`, with `new(connection, stream,
pool)`. `new` sets `TCP_NODELAY`, and refuses with the `io::Error` of the socket. Each call has the
rules of its call in the core, and awaits what the core call says to wait for:

| Type | Calls that await | Calls that do not wait |
| --- | --- | --- |
| `client::Http1` | `send`, `write`, `finish`, `response`, `next`, `read_into`, `collect`, `close` | `delivered`, `cancel`, `negotiated` |
| `server::Http1` | `request`, `respond`, `write`, `finish`, `finish_with_trailers`, `next`, `read_into`, `collect`, `release`, `close` | `cancel`, `delivery`, `shutdown`, `negotiated` |
| `tls::Stream` | `handshake`, `read_into`, `next`, `write`, `close` | `written`, `sent`, `closure` |

- A call gives its value when the core gives one. `read_into` never gives `Read::Wait`, and
  `collect` never gives `Collect::More`.
- `write` and `finish` wait while the output queue is full.
- After a call gives its value, the binding writes its output at once, with no wait.
- `server::Http1::request` gives `None` when the connection takes no more requests: the client
  closed, the connection closes, or it ended.
- `tls::Stream::handshake` waits until the handshake completed, and gives what it negotiated.
- `close` ends the connection, waits until the transport accepted each output, and closes the
  socket. Over TLS, the end sends `close_notify`.

The rules of each core call are on the pages of the [client](client.md), the [server](server.md),
and the [TLS stream](tls-stream.md).

## A server and its tasks

`Server::serve(listener, connections_max, make, handler)` accepts the connections of a Tokio
`TcpListener` and serves each one in a task of the runtime of the caller. Call it in a task of
that runtime.

- At most `connections_max` connections run at a time. Another connection waits in the backlog of
  the listener.
- For each accepted socket, `make` gives a server of the core, made with `Clock.domain()`, and the
  pool of its receive regions. A refusal of `make` drops that connection, and `Report::refused`
  counts it.
- `handler` takes the connection, a `server::Http1`, and serves its requests in order. When the
  handler returns or drops the connection, the task drives the rest: the delivery of the last
  response, the close, and the linger. A response that the handler did not finish is cancelled, so
  the client sees it incomplete. A request that comes after the handler gets `503`.
- `server.close(deadline)` stops the accepts. Each connection drains with `deadline`, as
  `server::Http1::shutdown` says: the exchange in flight completes, and a request that the handler
  did not see gets `503` with `connection: close`. Then the close joins each task. At `deadline`,
  it aborts each task that did not end, for example a handler that waits for another future.
- A server that drops before its close aborts each of its tasks, and each connection resets.

`close` gives a `Report`:

| Field | Count |
| --- | --- |
| `accepted` | The connections that the server accepted and served |
| `refused` | The accepts that failed, or whose connection could not start |
| `failed` | The connections that ended with an error, whose handler gave an error, or whose handler panicked |
| `aborted` | The connections whose task the close stopped at its deadline |

A handler that moves its connection to another task keeps it: the task of the server then does not
drive the rest of that connection. Keep the connection in the handler.

`server::Http1::release` gives the end of a connection as a `server::Closed`, and then `delivery`
gives the final delivery of its last response. Thus the end of the handler and the delivery of its
response are two results. Without a `Server`, make a connection with `server::Http1::new` on a
socket that you accepted, and call `close` when you are done with it.

## Cancellation and drop

A future that you drop changes nothing: the connection keeps its state, and the next call goes on
from it. To bound a wait, give the exchange a deadline, or drop the future of the call.

A client, a server connection, or a TLS stream that drops before its close resets the connection,
so the peer cannot read the cut as the end of the data. Its output that did not go is lost.

## Blocking jobs and host lookups

Tokio's blocking pool has no bound on its queue. `Blocking::new(jobs_max)` admits at most
`jobs_max` blocking jobs at a time, and its clones share the places:

- `blocking.run(job).await` runs `job` on the blocking pool, and gives its result. It refuses with
  `Kind::Overload`, and runs nothing, when each place is in use.
- `blocking.lookup(host, port, addresses_max).await` looks up `host` with the resolver of the
  system as one job. The outer result is the admission. The inner result is the answer of the
  resolver, as an `io::Result` with at most `addresses_max` addresses, each with `port`.
- A job keeps its place until it returns, also when its caller drops the future. The blocking pool
  cannot stop a job that runs, so a lookup that its caller abandoned stays occupied until the
  resolver answers. A lookup has no timeout of its own.

## Errors

The calls refuse with the `rsnetwork::drive::Error` of the core call, and with these:

| Kind | Reason | Recovery |
| --- | --- | --- |
| `Overload` | `the connection waits for capacity: drop the views of its received bytes, and call again` | The connection waits for capacity that no event of the socket gives back. Drop the views of received bytes, for example the parts of a body, and call again |
| `Overload` | `each place for a blocking job is in use` | Retry the job later, or give `Blocking` more places |
| `Misuse` | `the connection ended: make a new client`, `the connection ended`, or `the stream ended` | The connection or the stream ended before the call gave its value. Make a new one |
| `Cancelled` | `the runtime shut down before the blocking job ended` | None: the runtime stopped |

See [errors](errors.md) for each kind.

## Drive another vocabulary

`rsnetwork_tokio::Socket` is the step of each call: a connection of the core, its socket, and the
clock. `socket.until(call)` calls `call(&mut connection, now)` until it gives a value. After each
call that gives `None`, it moves the bytes with the rules of `host::Tcp`, and waits until the
socket can read or write what the connection waits for, or until its next deadline. Each turn that
does not wait takes from the cooperative budget of the task, so a busy connection lets the other
tasks of its thread run. Use it to drive a `host::Connection` of your own engine: call
`connection.drive(now)` in `call`. `socket.close()` closes the socket and gives the output that did
not go, as `host::Tcp::close` does.

The binding reads the socket with Tokio's own calls, so Tokio sees each read and write and wakes
the task when the socket is ready again: see [readiness hosts](adapters.md#readiness-hosts).
