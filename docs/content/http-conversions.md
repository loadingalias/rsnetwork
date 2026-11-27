# Serve a handler that uses Rust `http` types

Enable the `http` feature on `rsnetwork-tokio` to mount a handler that accepts `http::Request` and returns `http::Response`.
For a caller-driven host, enable `http` on `rsnetwork`. Both features are off by default.
The module `rsnetwork::http` exports the same types as the `http` 1.x crate.
For a Tower service or axum router, enable the optional `tower` feature. [Serve a Tower service](tower.md)

## Mount the handler

Give the adapter your head limits and a memory budget. Use the listener and connection factory from your existing Tokio server.
This handler returns the incoming body. The client receives its bytes and any trailers even after the handler returns. [Tokio server setup](tokio.md#serve-requests-and-send-one)

```rust
use core::num::NonZeroUsize;
use rsnetwork::buffer::Pool;
use rsnetwork::drive::Error;
use rsnetwork::http::{Adapter, Response};
use rsnetwork::server::Http;
use rsnetwork_tokio::server::Server;
use tokio::net::TcpListener;

fn serve_echo(
    listener: TcpListener,
    connections_max: NonZeroUsize,
    make: impl FnMut() -> Result<(Http, Pool), Error> + Send + 'static,
    adapter: Adapter,
) -> Server {
    Server::serve_http(listener, connections_max, make, adapter, |request| async move {
        Ok(Response::new(request.into_body()))
    })
}
```

Create the adapter with `Adapter::new(limits.head, &budget)`. Call `server.close(deadline).await` to drain and join the server.
Return `()` for an empty response, `Some(lease)` for one region, or implement `rsnetwork::http::Body` for a producer.
Its `next` method yields a native `Part`. Only `Part::End(Outcome::Complete(...))` finishes a response.
A handler can read the original reset code from its incoming body. A failed outgoing body cancels its own exchange. [Body outcomes](body.md#outcomes)

The Tokio adapter checks the body outcome before it sends a zero-length response, a response to HEAD, or status 204 or 304.
A HEAD response can declare the size of the selected representation and return `()`.
For fixed-length HTTP/1 responses, the adapter holds the last region until the producer confirms completion.
Earlier regions stream as they arrive. This keeps a source reset from appearing as a complete response on the wire.
HTTP/2 can carry trailers with any declared length, including zero. On HTTP/1.1, return an unknown length to stream a body with trailers.

On a caller-driven HTTP/1.1 or HTTP/2 server, call `Http::handle_http`.
The request body holds the stream identifier. Read its parts through `Http::next`, then send the converted response under the same stream's backpressure.
On caller-driven HTTP/3, pass the head and stream from `Event::Request` to `Adapter::handle`.
Pass the handler's response to `Connection::respond_http`. Each DATA event keeps its QUIC flow-control credit until the consumer releases it. [HTTP/3 message delivery](http3.md#send-and-receive-a-message)

## Convert a message

| Input | Operation | Result |
| --- | --- | --- |
| Native request or response head and a body | `Adapter::request`, `Adapter::response` | An owned ecosystem message with the supplied body. The header values share the received head's backing. |
| Ecosystem request or response and an optional body length | `Adapter::native_request`, `Adapter::native_response` | A view. Pass its `head()` to the native client or server. Keep the view while the send is pending. |
| Native field slice or ecosystem header map | `Adapter::headers`, `Adapter::fields` | An owned map or a borrowed field list. Use `as_slice()` on the list. |
| Checked method or status | `try_into()` | The corresponding method or status. For conversion to a native method, borrow the ecosystem method. |
| Native target or ecosystem URI | `Uri::try_from(target)`, `Adapter::target(&uri)` | An exact URI or a view with `target()`. A standalone conversion refuses a spelling the URI would change. |

An HTTP/1 request keeps its target form. When the URI normalizes the spelling, the request stores an `OriginalTarget` extension.
For example, its `target()` returns the exact bytes of `HTTP://Example.test`. Reverse conversion restores those bytes while the presented URI has the same spelling.
Changing the URI makes the replacement authoritative. Removing the extension discards the original spelling.
HTTP/2 and HTTP/3 expose the scheme, authority, and path in the ecosystem URI. Reverse conversion uses the path and query, or the CONNECT authority.
Select a native connection that serves the URI's authority and scheme. [URI components](https://docs.rs/http/1.5.0/http/uri/struct.Uri.html)

Header values keep their bytes, including non-UTF-8 values. Repeated values keep their order within each name.
The map lowercases field names and groups their values. HTTP/1 name case and the interleaving of different names are lost.
The ecosystem message also omits the HTTP/1 reason phrase. Keep the native head when those details matter.
An ecosystem message's `Debug` output can contain the request target and header values.

Native conversion takes the authority from the URI or Host field. Conflicting authorities, conflicting lengths, and unsupported transfer encodings give an error.
Content-Length supplies the native length. HTTP/1.1 chunked framing gives an unknown length. With neither field, the caller supplies the length.
The Tokio server validates response framing against the negotiated protocol.
Native field validation rejects leading or trailing whitespace. A caller-set sensitive marker that native compression cannot preserve gives `Kind::Unsupported`.
The direct HTTP/3 response writer passes that marker to QPACK.

## Allocation and copy costs

These counts come from the macOS aarch64 allocation tests with `http` 1.5.0. They count heap allocations during conversion, including array growth.
Protocol encoding and application processing have their own costs.

| Conversion | Allocations and copies |
| --- | --- |
| Method or status | Status conversion takes zero allocations. A native method borrows the name. An ecosystem method stores up to 15 extension bytes inline. Longer extension names need one allocated copy. |
| URI to native target | Origin, authority, and asterisk forms borrow the URI with zero allocations. An absolute target joins its components into one charged allocation. |
| Native target to standalone URI | The URI constructor copies the input once. Origin, authority, and asterisk examples took one allocation each. The absolute URI took two allocations for its shared components. |
| Received request or response to ecosystem message | A tested HTTP/1 request with Host and two Accept values took four allocations. An HTTP/3 response with two Set-Cookie values also took four. Each needed one shared backing owner, two map arrays, and one array for repeated values. Neither copied header values or body bytes. Custom field names and the original-target extension can add allocations. |
| Borrowed field slice to map | Two Accept values took five allocations, including a copy of each value. This operation accepts fields with unrelated backing. |
| Ecosystem message or header map to native view | One descriptor array for a nonempty map. Names and values stay borrowed. A reconstructed absolute HTTP/1 target adds its one allocation. |
| Body | Passing the body moves its handle. Streaming transfers each `Lease` without a payload copy. A trailer section can need one native field descriptor array. |

Head limits bound the number of fields, the name and value sizes, and the total bytes examined.
The budget pays for native descriptor arrays and reconstructed targets. The caller owns the ecosystem map and its allocations.
Holding a converted value can retain the original receive region. Release the message or its last shared value when finished. [Receive backing and limits](limits.md)
