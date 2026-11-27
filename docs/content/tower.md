# Serve a Tower service or an axum router

Enable `tower` on `rsnetwork-tokio` to pass a router to `Server::serve_tower`.
The application supplies the Tokio runtime. Its existing server tasks drive each request and response.
The native connection handles protocol selection, flow control, framing, and shutdown.

## Mount a router on Tokio

Use the listener, connection limit, and connection factory from the Tokio server example.
Create an `Adapter` with the same head limits and memory budget.
This example uses axum 0.8.9 with default features disabled. [Tokio server setup](tokio.md#serve-requests-and-send-one)

```rust
use core::num::NonZeroUsize;
use axum::{Router, routing::get};
use rsnetwork::buffer::Pool;
use rsnetwork::drive::Error;
use rsnetwork::http::Adapter;
use rsnetwork::server::Http;
use rsnetwork_tokio::server::Server;
use tokio::net::TcpListener;

fn routes() -> Router {
    Router::new().route("/health", get(|| async { "ready" }))
}

fn serve(
    listener: TcpListener,
    connections_max: NonZeroUsize,
    make: impl FnMut() -> Result<(Http, Pool), Error> + Send + 'static,
    adapter: Adapter,
    router: Router,
) -> Server {
    Server::serve_tower(listener, connections_max, make, adapter, router)
}
```

Pass `routes()` as the last argument. A GET to `/health` returns HTTP 200 and the five bytes `ready`.
Call `server.close(deadline).await` to drain the server and join its tasks.

A mounted Tokio service must implement `Clone + Send + Sync`. Its call future and response body must implement `Send`.
Each exchange clones the service once. It polls that clone for readiness and calls it once when ready.
A pending service stays within the server's connection and stream limits.
The exchange owns the returned body until its final frame. A handler panic on HTTP/2 resets its stream. Other streams can finish.

## Use your own event loop

Enable `tower` on `rsnetwork`. With `default-features = false`, the adapter needs only the shared family types and five ecosystem crates.
The two Tower-specific additions are `tower-service` and `http-body`. Both features named `tower` are off by default.
Caller-driven dispatch borrows the service. It accepts single-threaded services and services that own a unique resource.

1. Pass the received head and your stream's body reader to `Adapter::tower_request`.
2. Poll `rsnetwork::tower::dispatch(&mut service, request)` in your event loop. A pending reader must arrange a wake.
3. Pin the returned body. Pass it to `Adapter::tower_body` and feed each part to the native stream under its write limit.
4. Confirm `Outcome::Complete` before sending the bytes or head that finish the response. Forward any trailers. Cancel the exchange if the producer fails.

For HTTP/1.1 and HTTP/2, read request parts with `server::Http::next`.
When `Http::respond` sends a zero-length response, that call finishes it.
Hold the last region of a fixed-length HTTP/1.1 response until the producer confirms completion.
On HTTP/3, read `Event::Body` and release QUIC credit as the consumer takes the data.
Drive each queued HTTP/3 frame before submitting another on that stream. [HTTP/3 message delivery](http3.md#send-and-receive-a-message)

## Streaming costs and failures

| Operation | Behavior |
| --- | --- |
| Read request data | Each frame shares the received region through a `Bytes` owner. Retaining a frame retains that region and its charge. |
| Write a unique `Bytes` allocation | The adapter can reuse the allocation and charges its full capacity. If only the visible bytes fit, it copies those bytes. |
| Write a shared slice or segmented buffer | The adapter copies a shared slice into bounded storage. A segmented `Buf` can also need a copy to join its segments. |
| Read on Tokio | The first body poll allocates one pinned timer slot. Later frames reuse it. The handler drives the socket directly. |
| Finish with trailers | The adapter checks the fields and stores the trailer section in charged memory until the producer confirms completion. |
| Fail during a read | The request yields a `BodyError`. A peer reset retains its protocol code. Truncation, malformed framing, and cancellation have distinct outcomes. |
| Fail during dispatch or output | A readiness error gives `Overload`. A service or producer error gives `Partial`. Insufficient frame capacity gives `Overload`. |

On HTTP/1.1, stream trailers with an unknown body length. HTTP/2 permits trailers with a declared length.
Head conversions have their own allocation costs. [HTTP types and framing](http-conversions.md)

## Compatibility

The macOS tests exercise an axum router over caller-driven HTTP/1.1, HTTP/2, and HTTP/3 over QUIC.
The Tokio socket tests exercise HTTP/1.1 and HTTP/2 with both current-thread and multi-thread runtimes.
The readiness, memory, and terminal-outcome tests also passed on `wasm32-wasip1` under Wasmtime.
Middleware that calls Tokio timers needs a Tokio runtime with time enabled.

Axum's `WebSocketUpgrade` extractor requires a hyper connection extension.
On a valid HTTP/1.1 WebSocket handshake, the extractor returns `ConnectionNotUpgradable` and HTTP 426.
An application can handle that rejection through axum's usual error response.
