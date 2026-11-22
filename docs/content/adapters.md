# Write a binding

A binding connects the rsnetwork protocol engines to a host: a runtime, or the event loop of your
application. It moves received bytes, output, time, and wakes between the host and each
connection: a `host::Connection`, a `client::Http1`, a `server::Http1`, or a `tls::Stream`. These
connections have the same calls, which the sealed trait `host::Io` names. Thus one binding takes
any `C: Io` and moves the bytes of each. The binding calls the connection directly. It implements
no trait of rsnetwork, and no dispatch layer is between the two.

This page is a first draft of the adapter guide. rsnetwork is in development and has no release.
It has two bindings: `host::Tcp` binds a caller-driven host to a nonblocking TCP socket (see
[bind a TCP socket](caller-driven.md#bind-a-tcp-socket)), and the package `rsnetwork-tokio` runs
the connections on Tokio (see [run the engines on Tokio](tokio.md)).
[Drive a connection from your own event loop](caller-driven.md) gives the connection calls and a
complete example.

## Packages

| Package | Contents | Dependencies |
| --- | --- | --- |
| `rsnetwork` | The protocol engines and the caller-driven host, `rsnetwork::host` | `rstypes`, the shared buffer, capacity, and time types of the runtime family, with no scheduler and no driver |
| `rsnetwork` with the `tls` feature, on by default | Also [TLS 1.3](tls.md), `rsnetwork::tls` | Also rustls and the `rscrypto-rustls` provider, with their dependencies: no C, and no cryptography other than rscrypto |
| `rsnetwork` with the `tcp` feature, off by default | Also `host::Tcp`, the binding of a caller-driven host to a nonblocking TCP socket, and `host::Socket`, the calls of that socket | No new crate. Until `Read::read_buf` and `TcpStream::set_linger` are stable in std, it needs the nightly toolchain that rsnetwork pins |
| `rsnetwork-tokio` | The [Tokio binding](tokio.md): the client, the server, and the TLS stream on Tokio, a `Server` that owns its tasks, and bounded blocking jobs | `rsnetwork` with `tcp`, Tokio 1.54 with `rt`, `net`, `sync`, and `time`, and socket2: no C |

A binding that needs a runtime is a package of its own, which depends on `rsnetwork` and on that
runtime. `rsnetwork` never depends on a binding. Thus:

- A protocol-only build is `rsnetwork` with `default-features = false`. It has no executor, no
  socket driver, no Tokio, and no TLS.
- The public API of `rsnetwork` cannot name a type of a runtime, because `rsnetwork` does not depend
  on one.
- A new major version of a runtime changes only its binding.

Socket code that needs no new dependency goes in `rsnetwork` behind a feature that is off by
default: `tcp`. Thus a protocol-only build also has no socket code.

`cargo xtask check` enforces the layout on each target. It fails when the protocol-only build holds
a crate other than `rsnetwork` and `rstypes`. It also fails when the default build, or a build
with all features, adds a crate outside the closure of the `tls` feature, and when
`rsnetwork-tokio` adds a crate outside its approved list.

## Host effects

Each call in this table is a call of `host::Io`, except `Connection::abandon`. Import the trait
with `use rsnetwork::host::Io as _;`.

| Effect | Interface | Contract |
| --- | --- | --- |
| Received bytes | `Io::receive(Received)`, `Io::end_input()`, `Io::reset()` | Any region: a buffer of the binding, a pool slot through `Lease::from_owner`, or a buffer that the kernel selected. The engine reads it in place, with no copy |
| Received bytes into a region of the engine | `Io::region()`, then `Io::received(region, endpoint, capacity)` | `region()` lends the input region of the engine, or gives `None` when the engine has none. A TLS engine also gives `None` while a region of the host waits after a partial record. Receive into its capacity after its initialized bytes, and give it back. `received` also takes a writable region of the host. A TLS engine decrypts in place only in a writable region: see [receive forms](tls.md#receive-forms-and-their-copies) |
| Output | `Io::output()`, `Io::ack(id, accepted)` | One output at a time. Give its region to the transport, and acknowledge the exact bytes that the transport accepted |
| Output into a region of the host | `Io::output_region(region)`, `Io::take_output_region()` | A TLS connection seals its next records into a writable region that the host selects, for example a registered buffer, and gives it back as an output. A region with no record comes back with `take_output_region`. See [output regions of the host](tls.md#output-regions-of-the-host) |
| Time | The `ClockDomain` of `Connection::new`, and an `Instant` at each drive | A monotonic clock. A host with no clock gives `None` |
| Transport failure | `Io::reset()` | A reset or a failed write: no byte comes or goes after it. A body that did not end ends `Outcome::Reset(None)`, and `release()` does not wait for the output |
| Wait and wake | `Io::wait()` | `Now`, `Until { blocked, deadline }`, `Linger { deadline }`, or `Ended(result)`, from the last turn |
| Half-close | `Wait::Linger { deadline }` | Only the [server](server.md#linger) gives it, after its last output: shut down the write side of the transport once, give each received byte, and call again at `deadline` |
| Cleanup | `Io::release()`, `Connection::abandon()` | Drive until the release. An abandon reports the output that the transport has not accepted |

A connection refuses at construction when the host does not have a capability that the engine
needs. An engine with a timer on a host with no clock gives `Kind::Unsupported`.

## The binding loop

Each turn of a binding:

1. Give the received regions to `receive`. Call `end_input` at the end of the input, and `reset`
   when the transport fails.
2. Call `drive(now)` until it gives no event, and answer each event.
3. Give each output to the transport, and acknowledge it.
4. Wait as `wait()` tells, and go to step 1.

Wait only for the cause that `Until` names:

| `blocked` | Wake the connection when |
| --- | --- |
| `Blocked::Input` | Bytes arrive, or the input ends |
| `Blocked::Output` | The transport accepts output |
| `Blocked::Capacity(n)` | `n` more bytes of capacity are free |
| `Blocked::Streams` | HTTP/2 only: your code closes a stream that a reset ended |

Also wake it at `deadline`. A socket can almost always take output, so a binding that waits for
that while the engine waits for input wakes again and again with no work.

### Readiness hosts

A readiness host, for example epoll, kqueue, or Tokio, tells when a socket can read or write:

- Read when the engine waits for input. When `region()` lends a region, read into it, and give it
  back to `received`. Otherwise read into a region of the binding, and give it to `receive`. When
  the engine cannot take a region now, `receive` and `received` give it back: drive first.
- Write each output when it comes. Wait for the socket to be writable only after it accepted a part
  of an output.

`host::Tcp` is this loop for a TCP socket: see [what a pump does](caller-driven.md#what-a-pump-does).
It takes a std `TcpStream` by default, or another `host::Socket`: a socket of a runtime that must see
each read and write. A runtime such as Tokio clears its readiness only when its own read or write
finds no byte, so the socket of the binding reads and writes through the runtime, and the binding
waits for readiness between pumps. The Tokio binding does so: see [run the engines on Tokio](tokio.md).

### Completion hosts

A completion host, for example io_uring, owns each buffer until its operation completes:

- Submit a receive into the region that `region()` lends, into an owned buffer, or a receive that
  selects a buffer of the kernel. At its completion, give a lent region or a writable buffer, as a
  `Backing`, to `received`. A TLS engine decrypts it in place. Give a read-only buffer, as a
  `Lease`, to `receive`.
- Submit a send of the region of an output. The transport keeps its own view of the region. At the
  completion, acknowledge the count that the send gives. To send from registered buffers, give a
  TLS connection one with `output_region` before the drive: its records are then in that buffer.

## Clients and servers

`client::Http1` and `server::Http1` are one HTTP/1.1 connection over TCP or TLS each, and a binding
moves their bytes with the calls of `host::Io`, as for a `Connection`. Their calls of the exchange are the
handler interface: see [send requests](client.md) and [serve requests](server.md). `tls::Stream` is
a byte stream over TLS for other protocols: see [send a byte stream over TLS](tls-stream.md). A binding adds
its own handler form over these calls, for example an async function, and owns the progress of the
connection while the handler runs. The server tells when the transport accepted a response, so a
binding reports the end of the handler and the delivery of its response as two results.

## Threads

A connection stays on the thread of its host, and it does not need `Send`. A binding that moves
connections between threads can do so: `Connection<Server>` and `Connection<Client>` are `Send`.

## Tasks and cleanup

A binding creates no executor and detaches no work. It spawns its tasks on the runtime of the
application, owns them, and joins them. It drives each connection until `release()` gives its
result. `release()` takes no time, so drive the connection with a call that takes `now`, for
example `server::Http1::request(now)`: else a linger or a deadline never ends. The
[Tokio server](tokio.md#a-server-and-its-tasks) does so after each handler. At a shutdown, it calls `abandon()` and keeps each output region that the transport holds
until the transport completes it. A socket that closes before the release resets the connection,
so the peer cannot read the close as the end of the data. `host::Tcp::close` does so, and reports
the output that did not go.

## Not yet in the interface

- A wake when capacity is free again. It needs a release listener in the shared capacity types. Until
  then, drive again after your code releases capacity, for example after it consumes a body.
- Name resolution and other blocking jobs, with a bound, in the core. The Tokio binding has
  `Blocking`: see [blocking jobs and host lookups](tokio.md#blocking-jobs-and-host-lookups).
- A send of several output regions in one call.
