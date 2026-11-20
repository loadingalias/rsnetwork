# Write a binding

A binding connects the rsnetwork protocol engines to a host: a runtime, or the event loop of your
application. It moves received bytes, output, time, and wakes between the host and one
`rsnetwork::host::Connection` for each connection. The binding calls the connection directly. It
implements no trait of rsnetwork, and no dispatch layer is between the two.

This page is a first draft of the adapter guide. rsnetwork is in development and has no release,
and it has no runtime binding yet. [Drive a connection from your own event loop](caller-driven.md)
gives the connection calls and a complete example.

## Packages

| Package | Contents | Dependencies |
| --- | --- | --- |
| `rsnetwork` | The protocol engines and the caller-driven host, `rsnetwork::host` | `rstypes`, the shared buffer, capacity, and time types of the runtime family, with no scheduler and no driver |
| `rsnetwork` with the `tls` feature, on by default | Also [TLS 1.3](tls.md), `rsnetwork::tls` | Also rustls and the `rscrypto-rustls` provider, with their dependencies: no C, and no cryptography other than rscrypto |

A binding that needs a runtime is a package of its own, which depends on `rsnetwork` and on that
runtime. `rsnetwork` never depends on a binding. Thus:

- A protocol-only build is `rsnetwork` with `default-features = false`. It has no executor, no
  socket driver, no Tokio, and no TLS.
- The public API of `rsnetwork` cannot name a type of a runtime, because `rsnetwork` does not depend
  on one.
- A new major version of a runtime changes only its binding.

Socket code that needs no new dependency, for example for the sockets of a caller-driven host,
goes in `rsnetwork` behind a feature that is off by default. Thus a protocol-only build also has no
socket code.

`cargo xtask check` enforces the layout on each target. It fails when the protocol-only build holds
a crate other than `rsnetwork` and `rstypes`. It also fails when the default build adds a crate
outside the closure of the `tls` feature.

## Host effects

| Effect | Interface | Contract |
| --- | --- | --- |
| Received bytes | `Connection::receive(Received)`, `Connection::end_input()` | Any region: a buffer of the binding, a pool slot through `Lease::from_owner`, or a buffer that the kernel selected. The engine reads it in place, with no copy |
| Received bytes into a region of the engine | `Connection::region()`, then `Connection::received(region, endpoint, capacity)` | `region()` lends the input region of the engine, or gives `None` when the engine has none. Receive into its capacity after its initialized bytes, and give it back. `received` also takes a writable region of the host. A TLS engine decrypts in place only in a writable region: see [receive forms](tls.md#receive-forms-and-their-copies) |
| Output | `Connection::output()`, `Connection::ack(id, accepted)` | One output at a time. Give its region to the transport, and acknowledge the exact bytes that the transport accepted |
| Time | The `ClockDomain` of `Connection::new`, and an `Instant` at each drive | A monotonic clock. A host with no clock gives `None` |
| Wait and wake | `Connection::wait()` | `Now`, `Until { blocked, deadline }`, or `Ended(result)`, from the last turn |
| Cleanup | `Connection::release()`, `Connection::abandon()` | Drive until the release. An abandon reports the output that the transport has not accepted |

A connection refuses at construction when the host does not have a capability that the engine
needs. An engine with a timer on a host with no clock gives `Kind::Unsupported`.

## The binding loop

Each turn of a binding:

1. Give the received regions to `receive`, and call `end_input` at the end of the input.
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

### Completion hosts

A completion host, for example io_uring, owns each buffer until its operation completes:

- Submit a receive into the region that `region()` lends, into an owned buffer, or a receive that
  selects a buffer of the kernel. At its completion, give a lent region or a writable buffer, as a
  `Backing`, to `received`. A TLS engine decrypts it in place. Give a read-only buffer, as a
  `Lease`, to `receive`.
- Submit a send of the region of an output. The transport keeps its own view of the region. At the
  completion, acknowledge the count that the send gives.

## Threads

A connection stays on the thread of its host, and it does not need `Send`. A binding that moves
connections between threads can do so: `Connection<Server>` and `Connection<Client>` are `Send`.

## Tasks and cleanup

A binding creates no executor and detaches no work. It spawns its tasks on the runtime of the
application, owns them, and joins them. It drives each connection until `release()` gives its
result. At a shutdown, it calls `abandon()` and keeps each output region that the transport holds
until the transport completes it.

## Not yet in the interface

- A wake when capacity is free again. It needs a release listener in the shared capacity types. Until
  then, drive again after your code releases capacity, for example after it consumes a body.
- Work that a connection owns outside a drive, for example the handler of a request.
- Name resolution and other blocking jobs, with a bound.
- A send of several output regions in one call.
