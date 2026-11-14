# Drive a protocol engine

The `rsnetwork::drive` module is the interface that each protocol engine of the core shares. A
host, such as a runtime binding or your own event loop, gives the engine its received bytes and
takes its output bytes. The engine does no I/O and keeps no socket or timer.

rsnetwork is in development and has no release. This module has the vocabulary and the queues of
the interface. The protocol engines that use it come in later releases.

## The model

An engine runs in drives. A drive is one bounded synchronous call. In each drive:

1. The host lends the engine its `Inbound` queue of received regions. The engine reads the bytes in
   place, with no copy.
2. The engine acknowledges the exact prefix that it consumed. Each byte after that prefix stays in
   the queue, at its address, for the next drive.
3. The engine pushes its output regions into its `Outbound` queue. The host takes each `Output`,
   gives its region to the transport, and acknowledges the exact number of bytes that the
   transport accepted.
4. The drive gives a `Turn`: what the engine needs next, and its next deadline.

A region is a `Lease` from `rsnetwork::buffer`. Each holder of a region keeps its own view of the
backing: the queue, the transport, and a consumer of a body. The backing stays alive and charged
one time while any view of it lives. The last view releases it. A cancellation, a deadline, or a
close ends interest, but it does not release a region that the transport still holds. The host
keeps each `Output` until the transport gives its terminal event.

An engine keeps a received byte after the drive only through a `Lease` view of its backing, never
through a reference. Thus a pipelined request, a body suffix, an informational response, and the
bytes after an upgrade keep their owner across drives.

## Example

The code runs in a function that returns `Result<(), Box<dyn std::error::Error>>`. The module
documentation of `rsnetwork::drive` runs the same example as a test.

```rust
use core::net::{Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Outbound, Received};

// One budget pays for each queue of the connection.
let budget = Budget::new(NonZeroU64::new(1 << 20).expect("not zero"));
let limit = NonZeroUsize::new(8).expect("not zero");

// The host receives a region and queues it for the engine.
let mut inbound = Inbound::new(limit, &budget)?;
let endpoint = Endpoint {
    peer: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 50_000)),
    local: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 8080)),
    ecn: Ecn::NotEct,
    segment: None,
};
let region = Lease::from(b"PING\r\nPI".to_vec());
inbound.push(Received { region, endpoint, capacity: 64 * 1024 }).expect("the queue has space");

// In a drive, the engine reads the bytes in place and consumes one complete line.
inbound.consume(6)?;
// The partial line stays, at its address in the same region, for the next drive.
assert_eq!(inbound.front().map(|received| received.region.bytes()), Some(&b"PI"[..]));

// The engine queues its output. The host sends it, and the transport accepts 3 bytes.
let mut outbound = Outbound::new(limit, &budget)?;
outbound.push(Lease::from(b"PONG\r\n".to_vec())).expect("the queue has space");
let output = outbound.submit().expect("an output is ready");
outbound.ack(output.id, 3)?;
// The next output is the rest of the same region, with no copy.
let rest = outbound.submit().expect("the rest is ready");
assert_eq!(rest.region.bytes(), b"G\r\n");
assert_eq!(rest.region.as_ptr(), output.region.as_ptr().wrapping_add(3));
```

## Received regions

A `Received` is one received region with its facts:

| Field | Meaning |
| --- | --- |
| `region` | The exact initialized bytes, as a `Lease`. A view of it keeps the backing alive |
| `endpoint` | An `Endpoint`: the `peer` address, the `local` address that the bytes came to, the `ecn` codepoint, and the `segment` size when one region holds several datagrams of one size (`None` for one datagram or a byte stream) |
| `capacity` | The bytes that the host can still admit after this region. The engine grants no more receive credit than this |

`Inbound` holds the received regions that no drive consumed, in their order:

| Operation | Result |
| --- | --- |
| `Inbound::new(limit, &budget)` | A queue for at most `limit` regions. It charges their memory to `budget` and reserves it now, so a push never allocates. `Err` with `Kind::Overload`, and no allocation, if the budget or the memory refuses |
| `push(received)` | Adds the region after the others. `Err(received)` gives it back when the queue is full. The queue drops an empty region |
| `front()` | The front region, with the bytes that no drive consumed |
| `consume(len)` | Acknowledges that the engine consumed the first `len` bytes of the front region. The queue keeps a view of the bytes after them and drops a region with no byte left. `Err(AckError::TooLarge)` if `len` is more than the front region has. The queue does not change |
| `take_front()` | Removes the front region and gives exactly its unconsumed bytes, for example the bytes after an upgrade or a CONNECT head, to their new owner |
| `end()`, `ended()` | Records, or tells, that the transport gives no more bytes after the queued regions: the peer closed its side. An engine reads the queued regions first, and then sees the end |

## Output regions

`Outbound` holds the output regions that the transport has not accepted, in their order:

| Operation | Result |
| --- | --- |
| `Outbound::new(limit, &budget)` | A queue for at most `limit` regions, with their memory charged to `budget` and reserved. `Err` with `Kind::Overload`, and no allocation, if the budget or the memory refuses |
| `push(region)` | Adds the region after the others. `Err(region)` gives it back when the queue is full. The queue drops an empty region |
| `limit()`, `free()` | The most regions that the queue holds, and the number that it can take now |
| `submit()` | The next `Output`: an `ActionId` and a view of the bytes of the front region that the transport has not accepted. `None` while an output has no acknowledgement, or when the queue is empty |
| `ack(id, accepted)` | Acknowledges that the transport accepted the first `accepted` bytes of output `id`. The next output gives the bytes after them, at the same address, with no copy |

Give `ack(id, 0)` when the transport refused the submission or accepted no byte. The bytes stay
in the queue for the next output.

An acknowledgement that names no outstanding bytes refuses with an `AckError`, and the queue does
not change:

| `AckError` | Cause |
| --- | --- |
| `Duplicate` | The output had its acknowledgement before |
| `Unknown` | This queue did not give the identifier, for example because it is from the queue of another connection |
| `TooLarge` | The acknowledgement names more bytes than the region has |

## The result of a drive

Each drive gives a `Turn`:

| Field | Meaning |
| --- | --- |
| `progress` | A `Progress`, below |
| `deadline` | The earliest deadline of the engine's timers, an `rsnetwork::time::Deadline`. Drive the engine again when it is reached, also if no input arrives. A new or earlier deadline replaces your wait on the same turn |

| `Progress` | Next action of the host |
| --- | --- |
| `Blocked(Blocked::Input)` | Receive more bytes, then drive again |
| `Blocked(Blocked::Output)` | Acknowledge the outstanding output, then drive again |
| `Blocked(Blocked::Capacity(n))` | Admit `n` more bytes of capacity, then drive again |
| `Pending` | The engine gave an event, or it stopped at a [turn limit](limits.md) with more work. Drive it again with no wait |
| `Terminal(Ok(()))` | The engine completed |
| `Terminal(Err(error))` | The engine failed. See [errors](errors.md) |

## Debug output

The `Debug` output of a `Received`, an `Inbound`, an `Outbound`, and an `Output` shows lengths,
counts, and identifiers. It shows no byte of a region, so a log line does not show a credential
or a body.
