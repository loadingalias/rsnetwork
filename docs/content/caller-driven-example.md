# The caller-driven protocol loop

The example `examples/caller_driven.rs` drives an HTTP/1.1 client and server from its own loop.
Each side is one `rsnetwork::host::Connection` over a loopback TCP socket in nonblocking mode, and
the program uses only the public API of `rsnetwork` and the standard library. It has no runtime
and starts no thread. [Drive a connection from your own event loop](caller-driven.md) gives each
call that it uses. The example moves the bytes of each socket with its own loop, so it shows each
call of `host::Io`. With the `tcp` feature, [`host::Tcp`](caller-driven.md#bind-a-tcp-socket) is
that loop.

rsnetwork is in development and has no release.

## Run it

```sh
cargo run --example caller_driven
```

Each case checks its outcome and prints one line. A case that does not get its outcome stops the
program with an error. The output is:

```text
partial I/O: each side read 7-byte parts, both bodies are complete, and both ends released
backpressure: the server waited for the socket and for its queue, and the client got 33554432 bytes
timeout: the server answered the slow head with 408 and ended with a deadline error
early cancellation: the client cancelled the body after its first part, the body ended Cancelled, and the client released
shutdown: the server abandoned its connection with output that the socket did not accept
```

`cargo xtask test` also runs the example, as the test `each_case_gives_its_outcome`.

## The loop

Each turn of the loop does these steps for each connection:

1. Read the socket once, but only when `wait()` is `Until { blocked: Blocked::Input, .. }`. Give
   the bytes to `receive`. When the input queue is full, `receive` gives the region back: keep it,
   and give it again in the next turn.
2. Call `drive(now)` until it gives no event, and answer each event with the engine and the output
   queue.
3. Write each output to the socket, and acknowledge the bytes that the socket accepted. Stop at the
   first output that the socket accepted only in part.
4. When no connection has work now, sleep until the earliest deadline of a wait, for at most 1 ms.

The standard library has no readiness poller, so the example sleeps for at most 1 ms between
turns. A real loop waits in epoll or kqueue for the socket, or until the deadline. No outcome of a
case depends on that time.

## The cases

| Case | What it shows |
| --- | --- |
| Partial I/O | Each side reads 7-byte regions, so each head and each body comes in parts. The request has a buffered body, `Body::Buffered`. The server reads the head as an immediate borrow in its `Request` event. It keeps each `Data` lease as an owned view after the drive, and it echoes those views with no copy. Both connections reach the terminal release |
| Backpressure | The server sends a one-shot body of 32 MiB, as 512 views of one 64 KiB region, into an output queue of 4 regions. The client starts to read only after the socket of the server accepted part of an output. Until then, `send` refuses with `Kind::Overload`, and the server sends again after an acknowledgement. The client counts the bytes of each part as it comes, and it collects none |
| Timeout | A client sends part of a request head and stops. The loop sleeps until the deadline of the wait. The server then sends a 408 response and ends with `Kind::Deadline` |
| Early cancellation | The client calls `cancel_response` at the first part of a long body with no length. The next drive gives `End(Outcome::Cancelled)` for the body, and no more of its bytes. The request asked the server to close the connection after the response, so the client engine discards nothing to reuse the connection, and it ends. `release()` gives `Ok(())`, and the client closes its socket |
| Shutdown | The server sends to a client that reads nothing, until the socket is full. The application then stops: `abandon()` reports the output that the socket did not accept |

## Borrows, views, and release

- An immediate borrow is valid only during the call that gives it: the head of a `Request` event,
  and the bytes of `data.bytes()`. Copy what you keep, or keep a view.
- An owned view, a `Lease`, keeps its backing alive after the drive, with no copy. The partial I/O
  case keeps the parts of the request body as views, and sends them as the response body.
- The terminal release comes after the engine ended and the socket accepted each output. Close the
  socket only then. Before it, `abandon()` reports the output that the socket has not accepted.

## Limits

- The host has no input for a reset of the transport. When the socket fails, the loop abandons
  the connection.
- The example has no TLS, so it has no trust failure case.
