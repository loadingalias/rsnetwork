# Connect over IPv4 or IPv6 within one deadline

Set the deadline before DNS lookup. If the first TCP address stalls, the other family gets a turn while the first connection is pending.
The first successful connection wins. Its HTTP exchange keeps the time left from lookup and connection establishment.

## Connect on Tokio

Use a Tokio runtime with I/O and time enabled. Share one `rsnetwork_tokio::Blocking` across lookups.
Use the same monotonic clock for the HTTP client and the operation. [Set up a Tokio client](tokio.md#prerequisites)

This example sends a request with an empty body. Supply the destination `host` and `port`, the shared `resolver`, and a memory budget.
Create the HTTP/1.1 `core` with `Clock.domain()` and the destination's TLS identity for HTTPS.
Supply its receive `pool` and the `request`. [Configure the HTTP client](client.md#make-the-client)

```rust
use core::num::NonZeroUsize;
use core::time::Duration;
use rsnetwork::client::{Operation, establish::Dial};
use rsnetwork_tokio::{Clock, client::{Http1, connect}};

let mut operation = Operation::new(
    Clock.deadline(Duration::from_secs(5)),
    NonZeroUsize::new(4).expect("four is positive"),
);
let socket = connect(host, port, resolver, Dial::default(), &mut operation, memory).await?;
let mut client = Http1::new(core, socket, pool)?;
client.send(request, &operation).await?;
let head = client.response().await?;
```

`head` contains the final response status and fields. Call `client.next().await` to read each body part.
Only `Part::End(Outcome::Complete(_))` confirms a complete body. HTTP/2 accepts the same `&operation` on each request. [Read the response body](client.md#send-a-request-and-read-its-body)

If you already have addresses, pass the resolver-ordered slice to `client::connect_addresses`.
Use `client::connect_with` when each connection needs a source-bound socket. Its future must own the socket and close it on drop.

## Address order and limits

`Dial::default()` accepts up to 16 addresses. The first family comes from the resolver.
The race alternates IPv6 and IPv4 and preserves the order within each family. Duplicate socket addresses count once. IPv6 scope IDs stay distinct.

The default delay between pending attempts is 250 ms. Set `Dial::delay` when you have a measured delay for the path.
A failed attempt allows the next address to start sooner. Starts stay at least 10 ms apart. [RFC 8305, section 5](https://www.rfc-editor.org/rfc/rfc8305.html#section-5)

Each admitted lookup and each TCP attempt spends one work unit, including failures. Four units allow one lookup and up to three TCP attempts.
An admitted attempt can still succeed after the last unit is spent. The winner closes all losing sockets that the host can cancel.

Keep the same `Operation` when your application permits a fallback, retry, or redirect.
Charge a new request attempt on an existing socket with `operation.attempt(now)` and hold its permit until that attempt ends.
Reading the current response spends no further attempt units.

## Drive the race from your event loop

1. Set the lifetime on your monotonic clock. Reserve a lookup on your blocking service. [Resolve a name](resolver.md#caller-driven-hosts)
2. Charge the lookup with `operation.attempt(now)`. Move its permit into the worker until the lookup ends.
3. Pass the addresses, `&mut operation`, the time, and the memory budget to `Dial::race`.
4. Call `race.advance(now, start, poll)`. Have `start` initiate a nonblocking connection and keep its permit with the attempt.
5. On `Step::Wait(time)`, wake on socket readiness or at `time`, whichever comes first. Drive the race again.
6. On `Step::Connected(socket)`, drop the race. Give the socket to the HTTP binding and pass `&operation` to `send`.

Dropping a race cancels its active handles. If the host cannot stop a job, its owner keeps the permit until completion.
`operation.occupied()` includes that work. On HTTP/2, a caller waiting for space to send must also wake at `operation.deadline()`.

## Long-lived responses and failures

Use `Operation::with_body_idle(duration)` to bound a pause in the response body.
The final response head starts the idle timer. Only nonempty body data renews it. The original lifetime always applies, including during an unfinished upload.

During establishment, `ConnectError::Operation` identifies deadline expiry, a capacity refusal, or invalid settings.
`ConnectError::Io` gives the resolver or socket error category. During HTTP, expiry gives `Kind::Deadline`.
Use `delivered()` to find how many body bytes the client already gave you. [HTTP client errors](client.md#errors)
