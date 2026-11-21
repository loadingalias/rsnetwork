# Read and send bodies

The `rsnetwork::body` module is the body model that each protocol of the core shares: the terminal
outcome of a body, its trailers, a consumer that reads a body into regions of the caller, bounded
collection, and the bodies that a sender gives.

rsnetwork is in development and has no release. Today the [HTTP/1.1 engines](http1.md) give and
take bodies with this model.

## Outcomes

An engine gives a received body as `Data` events, which are views of the received regions, and
then one `End(outcome)` event. Only `Outcome::Complete` makes the bytes a complete value. A body
that ends any other way is a part, never a complete value.

| `Outcome` | Cause |
| --- | --- |
| `Complete(trailers)` | The body ended as its framing says: at its length, after its last chunk and its trailers, or at the end of input when the end of input delimits it |
| `Truncated` | The input ended inside a body with a length or with chunks (EOF) |
| `Reset(code)` | The peer reset the stream or the connection, with the code of a protocol that has one. Over TCP, your host calls `reset` when the transport reports a reset, and the code is `None` |
| `Cancelled` | The application cancelled the body |
| `Malformed` | The framing of the body broke the rules of its protocol |

The end of input does not always cut a body. A response with no length, for example from an
HTTP/1.0 server, ends at the close of the connection, so that end is `Complete(None)`. A body with a
Content-Length or with chunks that ends early is `Truncated`. A reset never completes a body: after
a reset, each body that did not end is `Reset(None)`, also a body that the close delimits.

`Trailers::fields()` gives the trailer fields of a complete body, in their received order.

## Read a body into your regions

You can keep the `Data` views, which costs no copy. To put the bytes into regions that you admit,
for example a destination with a fixed size, use a `Consumer`:

1. Make one `Consumer` for each body with `Consumer::new()`.
2. Give it each `Data` view with `consumer.data(data)` and the outcome with `consumer.end(outcome)`.
3. Call `consumer.read_into(&mut region)` with a `WriteLoan` over your region. It copies the
   waiting bytes straight from the received region into yours, and the loan records the exact
   extent.

The consumer holds one waiting part. `data` gives a part back while the bytes of the part before
it wait, so read first: your regions pace the body. The outcome shows only after the last waiting
byte.

| `read_into` result | Meaning |
| --- | --- |
| `Read::Bytes(n)` | It copied `n` bytes into the region |
| `Read::Full` | Bytes wait, and the region has no free capacity: give another region |
| `Read::Wait` | No byte waits: give the next part |
| `Read::Done(outcome)` | The body ended with `outcome` after its last byte |

`consumer.wants_data()` tells when the consumer takes the next part: no byte waits, and the body
has not ended. `consumer.take()` gives the waiting bytes as a view, with no copy, and
`consumer.outcome()` gives the outcome after the last waiting byte. `consumer.delivered()` gives
the number of body bytes that the consumer copied or gave, also after an interrupted body.

The [client](client.md) runs a consumer for each response body, and the [server](server.md) for
each request body.

## Collect a body

Collection into one region is an explicit operation, and the free capacity of the region is its
bound. Call `consumer.collect(&mut region)` after each part:

| `Collect` | Meaning |
| --- | --- |
| `More` | The region holds each byte so far: give the next part |
| `Complete(trailers)` | The region holds the whole body, which is a complete value |
| `TooLarge { collected }` | The body is longer than the region. The region keeps its first `collected` bytes, and the rest waits in the consumer |
| `Interrupted(outcome)` | The body ended with an outcome that is not complete. The region holds the bytes that arrived, which are not a complete value |

## Example

The code runs as is. The module documentation of `rsnetwork::body` runs the same example as a
test.

```rust
use rsnetwork::body::{Collect, Consumer, Outcome};
use rsnetwork::buffer::{Lease, WriteLoan};

// The engine gave two parts of a body, and then its end.
let mut consumer = Consumer::new();
let mut region = WriteLoan::new(Vec::with_capacity(16));
consumer.data(Lease::from(b"hello, ".to_vec())).expect("no bytes wait");
assert!(matches!(consumer.collect(&mut region), Collect::More));
consumer.data(Lease::from(b"world".to_vec())).expect("no bytes wait");
consumer.end(Outcome::Complete(None));

// The body is complete only now: after its last byte and its outcome.
assert!(matches!(consumer.collect(&mut region), Collect::Complete(None)));
assert_eq!(region.filled(), b"hello, world");
```

## Send a body

A `Body` tells what a sender has:

| `Body` | Length | Can be sent again |
| --- | --- | --- |
| `Empty` | 0 | Yes |
| `Buffered(lease)` | The length of the lease | Yes, for example after a redirect or for a retry |
| `OneShot { length }` | `length`, if the application knows it before the first byte | No: the application produces the bytes once |

`body.length()` and `body.replayable()` give these facts. For HTTP/1.1, `Framing::from(&body)`
gives `Framing::Length(n)` for a known length and `Framing::Chunked` for an unknown one. Give it to
`respond` or `request`, then send the bytes with `send` and end the body with `finish`. No body
needs collection before it is sent.

## Debug output

The `Debug` output of an outcome, trailers, a consumer, and a body shows lengths and kinds. It shows
no byte of a body or a trailer.
