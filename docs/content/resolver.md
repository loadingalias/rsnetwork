# Resolve a name on the host

The operating system resolver returns socket addresses in its preferred order. Each address keeps its port and IPv6 scope.
Set two limits. One bounds queued and running jobs together. The other bounds the number of addresses that one lookup returns.
The operating system can produce a longer list internally. This interface returns addresses only. It supplies no DNS TTL or HTTPS records.

To open a connection, give the returned addresses to the TCP address race. It shares the request's time and work limits. [Connect within one deadline](establishment.md)

## Caller-driven hosts

Enable the `os-resolver` feature of `rsnetwork`. It works without TLS, TCP, or a runtime dependency.

1. Create one `host::Blocking` with the job limit. Share it with each user of the blocking service.
2. Call `reserve_lookup(addresses_max)`. This reserves one place before you queue the lookup.
3. Move the lookup into a job on your blocking worker. Call `lookup.run((host, port))` there.
4. Send the result back to the event loop. If submission fails, drop the unused job to return its place.

```rust
use core::num::NonZeroUsize;
use rsnetwork::host::Blocking;

let service = Blocking::new(NonZeroUsize::MIN);
let lookup = service.reserve_lookup(NonZeroUsize::MIN)?;
let job = move || lookup.run(("127.0.0.1", 443));
let addresses = std::thread::scope(|scope| scope.spawn(job).join().expect("the worker returned"))?;
assert_eq!(addresses, [std::net::SocketAddr::from(([127, 0, 0, 1], 443))]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

This example supplies one worker. An application with a blocking pool submits the same closure to that pool.
Use `Blocking::default()` on a host without a blocking service. An attempted lookup then returns `Kind::Unsupported`.

## Tokio

Create one `rsnetwork_tokio::Blocking`. Call `blocking.lookup(host, port, addresses_max).await` on your Tokio runtime.
Lookups and other calls to `blocking.run` share its job limit. The outer result reports admission or a runtime error.
The inner `io::Result` contains the addresses or the resolver error. [Tokio blocking jobs](tokio.md#blocking-jobs-and-host-lookups)

## Cancellation and overload

A full service returns `Kind::Overload` before it submits another job. Retry after a worker returns a place.
A deadline can end the caller's wait. The operating system lookup has no hard timeout through this interface.
An abandoned job keeps its place until it returns or the host removes it from the queue.
