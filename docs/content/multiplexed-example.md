# The multiplexed connection over HTTP/2

The example `rsnetwork-tokio/examples/multiplexed.rs` runs one HTTP/2 connection over TLS 1.3 on
the Tokio binding. The body of the stream `/idle` waits, and the other streams of the connection
go on meanwhile: a stream that the client cancels, a stream whose deadline comes, and a stream
that the consumer reads late. One thread runs the server, the client, each stream, and each
deadline: a current-thread runtime. The example uses only the public API of `rsnetwork`,
`rsnetwork-tokio`, and `tokio`. [Run the engines on Tokio](tokio.md) gives each call that it uses.

rsnetwork is in development and has no release.

## Prerequisites

- The nightly toolchain that rsnetwork pins, as for [the Tokio binding](tokio.md#prerequisites).
- A clone of the rsnetwork repository. The example takes its certificates from `tests/tls`: the
  root `ca.der`, the certificate of `server.test` that it signs, and the root `other-ca.der`,
  which signs neither. These certificates are valid from 2026-01-01 to 2036-01-01, and the
  example checks them with the clock of the system (`DefaultTimeProvider`).

## Run it

```sh
cargo run -p rsnetwork-tokio --example multiplexed
```

Each case checks its outcome and prints one line. A case that does not get its outcome stops the
program with an error, and the program stops after 30 seconds. The output is:

```text
trust failure: a client that trusts another root refused the server: the peer certificate chain reaches no trusted root
idle: TLS selected h2, /idle got its head and 4 bytes, and then its body waits
partial I/O: the server echoed the buffered body of /echo as views, and the client read its 25 bytes in 4 reads of at most 7 bytes
backpressure: /large waited for its window after 4 of 64 chunks, /quick completed meanwhile, and the client counted its 1048576 bytes with no collection
early cancellation: the client dropped /cancel after its first part, the server saw the reset, and /quick completed after it
timeout: the deadline reset /late while no call of /late ran, the server saw the reset, and the next call of /late gave Kind::Deadline
idle: the rest of /idle came after its release, and the client kept its 8 bytes as 2 views
shutdown: the close waited for /drain and refused a new request, the client released, and the report counts 2 accepted, 1 failed, 0 aborted
```

`cargo xtask test` also runs the example, as the test `each_case_gives_its_outcome`.

## The connection

A `rsnetwork_tokio::server::Server` serves HTTP/2 over TLS with ALPN `h2`, and runs the handler
of each request in a task of its own. One `rsnetwork_tokio::client::Http2` sends each request on
the same connection. The first line uses a second client, which refuses the server.

The client of `/idle` reads the head and the first part of the body. Then a task of its own
awaits the rest. That wait drives the connection while the other cases run, so no task calls
`client.drive()`. Before each later case, the example checks that the body of `/idle` still
waits. The server sends the rest of `/idle` only after the timeout case.

## The cases

| Case | What it shows |
| --- | --- |
| Trust failure | A client whose only root is `other-ca.der` refuses the certificate of the server with `Kind::Trust`. It sends no request. The server counts the connection as failed in its report |
| Idle | The server sends the head of `/idle` and 4 bytes, and then it waits. `client.negotiated` lends the negotiated protocol, `h2`, only during its call |
| Partial I/O | The client sends a buffered request body to `/echo`: `Body::Buffered`, one region that it could send again. The server sends each part of it back as the same view, with no copy. The client reads the echo with `read_into` into a region of 7 bytes, so each read gives a part of the body |
| Backpressure | At first the client reads nothing of the body of `/large`, a one-shot body (`Body::OneShot`) of 64 views of one 16 KiB region. The window of the stream starts at 65,535 bytes, so the fourth chunk waits for its last byte and the fifth write waits. Meanwhile `/quick` completes. Then the client reads each part with `next`, which gives the credit of its bytes back to the server. The client counts the bytes, drops each view at once, and collects none of the body |
| Early cancellation | The client drops the exchange of `/cancel` after its first part. The stream resets with `CANCEL`, and the next write of the server refuses with `Kind::Partial`. `/quick` completes on the same connection after it |
| Timeout | The client sends 4 bytes of the request body of `/late`, with a deadline of 200 ms, and then calls nothing on that stream. At the deadline, the connection resets the stream. The wait of `/idle` drives it, so the reset needs no call of `/late`. The server reads `Outcome::Reset` with the code of `CANCEL`, and the next call of `/late` refuses with `Kind::Deadline` |
| Idle | After the release, the rest of `/idle` arrives. The client kept each part as a view: 2 views, 8 bytes |
| Shutdown | `server.close(deadline)` starts while `/drain` is in flight. The example polls the close one time, so the server knows of the close before the next request. That request is not processed: it refuses with `Kind::Misuse` or `Kind::Overload`, and the client can send it again on a new connection. `/drain` completes, the client closes, and the close joins each task of the server |

## Borrows, views, and release

- An immediate borrow is valid only during its call: the negotiated protocol in the closure of
  `negotiated`, and the outcome of `Read::Done`. Copy what you keep.
- An owned view, a `Lease`, keeps its received region alive after the call, with no copy. The
  client keeps the parts of `/idle` as views, and the server sends the parts of the body of
  `/echo` back as views. A view that you keep holds the memory of its region, so drop each view
  when you are done with it, as the backpressure case does.
- The terminal release comes after the close. `client.close()` ends the connection, and waits
  until the transport accepted each output. `server.close(deadline)` gives its `Report` only
  after each task of the server ended.

## Limits

- The example serves HTTP/2 only. Its server sends ALPN `h2`, and its client asks for `h2` only.
- The certificates of `tests/tls` are for tests. Give your own identity and roots, as on the
  [TLS page](tls.md).
- On loopback, the window of the stream holds back `/large` before the socket does. The
  [caller-driven example](caller-driven-example.md) shows a socket that accepts no more bytes.
