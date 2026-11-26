# Run the engines on Tokio

The package `rsnetwork-tokio` runs the HTTP/1.1 and HTTP/2 clients, the server of both versions,
and the TLS stream of rsnetwork on the Tokio runtime of your application. Each call awaits the
progress that it needs, so a body read moves its own bytes. You poll no second object, and the
client spawns no task. On HTTP/2, each stream has its own handle, which can go to a task of its
own. A server spawns one task for each connection, and on HTTP/2 one task for each stream. It owns
each task, and joins it at its close.

rsnetwork is in development and has no release. `rsnetwork-tokio` is a package of the rsnetwork
repository. It has run evidence on macOS (aarch64), on the current-thread runtime and the
multi-thread runtime of Tokio: HTTP/1.1, HTTP/2 over TCP with prior knowledge and over TLS with
ALPN `h2`, and TLS streams.

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
use rsnetwork::drive::TurnLimits;
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::server::{self, Cleartext, Linger, Response};
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
let turn = TurnLimits { bytes: 256 * 1024, frames: 1024, visits: 4096 };
let queue = NonZeroUsize::new(16).expect("not zero");
let linger = Linger { time: Duration::from_secs(5), bytes: 64 * 1024 };
let head_timeout = Some(Duration::from_secs(30));
// The HTTP/2 connection, which a server over TLS can select with ALPN `h2`.
let h2_settings = h2::Settings { max_concurrent_streams: 100, max_header_list_size: 16 * 1024, ..h2::Settings::INITIAL };
let h2 = h2::Limits { settings: h2_settings, work: 64 * 1024, encoder_table_bytes: 4096, connection_window: 1 << 20 };
let cleartext = Cleartext::Http1;
let server_limits = server::Limits { head, h2, body, turn, queue, head_timeout, linger, cleartext };
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
        move || Ok((server::Http::plain(server_limits, Clock.domain(), &budget)?, pool()?))
    };
    let connections = NonZeroUsize::new(1024).expect("not zero");
    // The handler runs once for each request, with its exchange.
    let server = Server::serve(listener, connections, make, move |mut exchange| async move {
        let hello = Response { status: ok, fields: &[], length: Some(5) };
        exchange.respond(&hello).await?;
        exchange.write(&Lease::from(&b"hello"[..])).await?;
        exchange.finish().await
    });

    let core = client::Http1::plain(client::Limits { head, h2, body, turn, queue }, Clock.domain(), &budget)?;
    let stream = tokio::net::TcpStream::connect(address).await?;
    let mut client = rsnetwork_tokio::client::Http1::new(core, stream, pool()?)?;
    let request = Request {
        method: Method::GET,
        target: Target::new(b"/hello")?,
        authority: Authority::new(b"127.0.0.1")?,
        fields: &[],
        length: Some(0),
    };
    // One deadline covers the response head and each byte of the body.
    client.send(&request, Clock.deadline(Duration::from_secs(5))).await?;
    assert_eq!(client.response().await?.status(), ok);
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

Over TLS, make the core connection with `client::Http1::tls` or `server::Http::tls`. The rest
does not change. A TLS connection lends its own input region, so one small slot in its pool is
enough: see [receive regions](caller-driven.md#receive-regions).

## The calls

`client::Http1`, `client::Http2`, `server::Http`, and `tls::Stream` each bind one connection of the
core to one Tokio `TcpStream`, with `new(connection, stream, pool)`. `new` sets `TCP_NODELAY`, and
refuses with the `io::Error` of the socket. An exchange is the handle of one stream: a request and
its response. Each call has the rules of its call in the core, and awaits what the core call says
to wait for:

| Type | Calls that await | Calls that do not wait |
| --- | --- | --- |
| `client::Http1` | `send`, `write`, `finish`, `finish_with_trailers`, `response`, `next`, `read_into`, `collect`, `close` | `delivered`, `cancel`, `negotiated`, `export` |
| `client::Http2` | `send`, `drive`, `close` | `negotiated`, `export` |
| `client::Exchange` | `write`, `finish`, `finish_with_trailers`, `response`, `next`, `read_into`, `collect`, `prioritize` | `delivered` |
| `server::Http` | `request`, `close` | `shutdown` |
| `server::Exchange` | `respond`, `write`, `finish`, `finish_with_trailers`, `next`, `read_into`, `collect` | `head`, `cancel`, `prioritize`, `delivery`, `negotiated`, `export` |
| `tls::Stream` | `handshake`, `read_into`, `next`, `write`, `close` | `written`, `sent`, `closure`, `export` |

- A call gives its value when the core gives one. `read_into` never gives `Read::Wait`, and
  `collect` never gives `Collect::More`.
- `write`, `finish`, and `finish_with_trailers` wait while the output has no room. On HTTP/2,
  `write` and `finish_with_trailers` also wait while the chunk before waits for the output. A
  trailer section larger than `head.head_bytes` refuses at once with `Kind::Overload`.
- `prioritize(priority)` sets the priority of a response (RFC 9218): on a client exchange it sends
  a PRIORITY_UPDATE, and waits while the output has no room. On a server exchange it does not
  wait. See [multiplexing](multiplexing.md#set-the-priority-of-a-response).
- The bytes of a connection move only inside its calls. When you drive a `server::Http` yourself,
  a call of the connection after the finish of an exchange, such as the next `request`, moves the
  rest of the response. A `Server` makes that call in the task of each connection.
- After a call gives its value, the binding writes its output at once, with no wait.
- `server::Http::request` gives each request on its own `server::Exchange`, or `None` when the
  connection takes no more requests: the client closed, the connection closes, or it ended. On
  HTTP/1.1, the next request comes after the exchange before it dropped and the transport accepted
  its response. On HTTP/2, requests come while the exchanges before them go on.
- An exchange that drops ends its stream. A server exchange closes it, and cancels a response that
  is not finished, so the client sees it incomplete. A client exchange cancels it: when its
  exchange did not end, the stream resets with `CANCEL`, and the connection goes on.
- `negotiated(read)` of `client::Http2` and `server::Exchange` gives `read` what the TLS handshake
  negotiated, and gives what `read` gives. `read` runs under the lock of the connection, so it must
  not call the connection or one of its exchanges.
- `export(label, context, &mut output)` derives keying material from the regular exporter of the
  TLS connection: see [bind a proof to a TLS connection](exporter.md).
- `tls::Stream::handshake` waits until the handshake completed, and gives what it negotiated.
- `close` ends the connection, and waits until the transport accepted each output. Over TLS, the
  end sends `close_notify`. `client::Http1` and `tls::Stream` then close the socket. A connection
  with exchanges closes its socket when its last handle drops.

The rules of each core call are on the pages of the [client](client.md), the [server](server.md),
and the [TLS stream](tls-stream.md).

## HTTP/2: streams in tasks of their own

`client::Http2` is one HTTP/2 connection, which many tasks share: each clone is one more handle of
the same connection. `send` gives a `client::Exchange` for each request. Two tasks send on one
connection at the same time. This example continues the one above, against a server that serves
HTTP/2 over TCP with prior knowledge (`Cleartext::Http2`):

```rust
use rsnetwork::message::ResponseHead;

let core = client::Http2::plain(client::Limits { head, h2, body, turn, queue }, Clock.domain(), &budget)?;
let stream = tokio::net::TcpStream::connect(address).await?;
let client = rsnetwork_tokio::client::Http2::new(core, stream, pool()?)?;
let mut tasks = tokio::task::JoinSet::new();
for target in [&b"/a"[..], b"/b"] {
    let request = Request {
        method: Method::GET,
        target: Target::new(target)?,
        authority: Authority::new(b"127.0.0.1")?,
        fields: &[],
        length: Some(0),
    };
    let client = client.clone();
    tasks.spawn(async move {
        let mut exchange = client.send(&request, Clock.deadline(Duration::from_secs(5))).await?;
        let head: ResponseHead = exchange.response().await?;
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        let collected = exchange.collect(&mut region).await?;
        Ok::<_, rsnetwork::drive::Error>((head.status(), collected, region.into_inner()))
    });
}
while let Some(done) = tasks.join_next().await {
    let (status, collected, body) = done??;
    assert_eq!(status, ok);
    assert!(matches!(collected, Collect::Complete(None)));
    assert_eq!(body, b"hello");
}
client.close().await?;
```

- **Drive.** The connection has no task of its own. The handle that awaits drives the connection
  for each stream, under a short lock that no wait holds. After each turn, only the handles whose
  streams changed wake. Thus a stalled body holds back only its own stream.
- **Idle.** Only an awaited call drives the connection. While no exchange awaits, await
  `client.drive()`, for example in a task of your own, so the client answers the SETTINGS and PING
  of the server and reads a GOAWAY. `drive` gives the end of the connection.
- **Places.** At the stream limit, `send` waits until a stream frees its place. The calls that
  wait take the places in their order.
- **Deadline.** The deadline of a request ends only its stream, with `RST_STREAM` and `CANCEL`,
  also when no call of that stream runs. The calls of the stream then refuse with
  `Kind::Deadline`, and `delivered()` gives the part of the body that arrived.
- **Close.** `close()` ends each exchange in flight, sends GOAWAY, and over TLS `close_notify`. A
  connection whose last handle drops before its close resets.

The rules of each stream are those of the core [HTTP/2 client](client.md#http2). The
[multiplexed connection example](multiplexed-example.md) is a complete program with these rules
over TLS: an idle body, a cancel, a deadline, backpressure, and the close of the server.

## A server and its tasks

`Server::serve(listener, connections_max, make, handler)` accepts the connections of a Tokio
`TcpListener` and serves each one in a task of the runtime of the caller. Call it in a task of
that runtime.

- At most `connections_max` connections run at a time. Another connection waits in the backlog of
  the listener.
- For each accepted socket, `make` gives a server of the core, made with `Clock.domain()`, and the
  pool of its receive regions. A refusal of `make` drops that connection, and `Report::refused`
  counts it.
- `handler` runs once for each request, with its `server::Exchange`. On HTTP/1.1, it runs in the
  task of its connection, one request at a time. On HTTP/2, each request gets a handler task of its
  own, at most `SETTINGS_MAX_CONCURRENT_STREAMS` for each connection, because a stream keeps its
  place until its exchange drops.
- When the exchange drops, the task of the connection drives the rest: the delivery of the
  response, the next requests, the close, and the linger. A response that the handler did not
  finish is cancelled, so the client sees it incomplete.
- `server.close(deadline)` stops the accepts. Each connection drains with `deadline`, as
  `server::Http::shutdown` says: the exchanges in flight complete, and the client learns which
  requests the server did not process, as the [server](server.md#close) says. Then the close joins
  each task, also each handler task. At `deadline`, it aborts each task that did not end, for
  example a handler that waits for another future, and joins it too. When `close` returns, no
  handler runs and no task holds state of the server. A handler that blocks its thread delays
  the close until it returns.
- A server that drops before its close aborts each of its tasks, and each connection resets. A
  close whose future drops before it returns does the same.

`close` gives a `Report`:

| Field | Count |
| --- | --- |
| `accepted` | The connections that the server accepted and served |
| `refused` | The accepts that failed, or whose connection could not start |
| `failed` | The connections that ended with an error, or of which a handler gave an error or panicked |
| `aborted` | The connections whose task the close stopped at its deadline |

The end of the handler and the delivery of its response are two results: `exchange.delivery()`
gives how much of the response the transport accepted, also after the handler finished it. An
HTTP/1.1 handler that moves its exchange to another task holds the next request of its connection
until the exchange drops.

Without a `Server`, make a connection with `server::Http::new` on a socket that you accepted, take
each request with `request`, and call `close` when you are done with it. `close` gives the end of
the connection as a `server::Closed`. Its drain waits for each exchange in flight, so drop or
finish each exchange first.

## Cancellation and drop

A future that you drop changes nothing: the connection keeps its state, and the next call goes on
from it. To bound a wait, give the exchange a deadline, or drop the future of the call.

A client, a server connection, or a TLS stream that drops before its close resets the connection,
so the peer cannot read the cut as the end of the data. Its output that did not go is lost. A
connection with exchanges resets when its last handle drops before its close. An exchange that
drops ends only its own stream: see [the calls](#the-calls).

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
