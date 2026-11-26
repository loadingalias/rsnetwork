# Send many HTTP/2 streams on one connection

The HTTP/2 engine, `h2::Connection`, sends the body of each stream from a send slot of that stream.
In each drive, its send scheduler shares the connection between the streams in turn. A slow
consumer at the peer holds back only its own stream, and a slow consumer of yours holds back only
its own stream when the connection window follows the rule on this page.

rsnetwork is in development and has no release. The [client](client.md#http2) and the
[server](server.md#streams) run this scheduler for each stream. This page is about the engine: see
[Run an HTTP/2 connection with no I/O](http2.md) for its model and its other calls. The
[multiplexed connection example](multiplexed-example.md) shows these rules on the Tokio binding.

## Send a body

1. Send the header section of the message: `open` for a request, or `headers` for a response.
2. Give the first chunk of the body with `data(&mut outbound, stream, chunk, end_stream)`. The
   chunk is a `Lease`. The engine keeps views of it and copies no byte. Set `end_stream` on the
   last chunk of the body.
3. Drive the connection. Each drive sends DATA frames of the chunk within the send windows.
4. At `Event::Sent { stream }`, give the next chunk. To end the body with a trailer section, send
   it with `headers(&mut outbound, stream, lines, true, region)` after the `Sent` event of the last
   chunk.

A stream holds one chunk at a time. From `data` to the `Sent` event of the chunk, `data` refuses
with `Kind::Misuse`, and `headers` refuses a trailer section. A chunk with `end_stream` gives no
`Sent` event, because the body ends with it. To end a body after its last `Sent` event with no
trailer section, give an empty chunk with `end_stream`. Its DATA frame needs no credit (RFC 9113,
section 6.9.1), so it goes into the output queue at once. An empty chunk with no `end_stream`
refuses with `Kind::Misuse`.

The example of [Run an HTTP/2 connection with no I/O](http2.md#example) sends a response body in one
chunk with `end_stream`, and a drive sends it.

## How the connection shares its streams

The streams whose chunk can go out are in a ring, in their order of arrival. The scheduler visits
the stream at the front of the ring and sends one DATA frame of at most 16,384 bytes, within the
stream window and the connection window. Then the stream goes to the end of the ring. Thus each
stream that can send gets one frame in each turn of the ring (round-robin). Each stream has the same
share.

- A stream whose send window has no credit leaves the ring, and its chunk waits in its slot. A
  WINDOW_UPDATE of the peer on the stream, or a larger `SETTINGS_INITIAL_WINDOW_SIZE`, puts it back
  at the end of the ring.
- When the connection window has no credit, no stream sends until a WINDOW_UPDATE of the peer on
  stream 0.
- The output queue holds only DATA frames that can go now, so no frame waits in it for credit.
- The scheduler sends after the drive reads frames, so the answers of the drive go first.
- DATA frames use at most half of the entries of the output queue. Thus the header sections,
  answers, WINDOW_UPDATE frames of `release`, and resets of your calls find room between drives.
  When DATA waits for room, the turn is `Blocked(Blocked::Output)`: acknowledge the output, then
  drive again.

16,384 bytes is the smallest `SETTINGS_MAX_FRAME_SIZE`, so each peer takes the frames.

## Isolate a slow consumer

A slow consumer at the peer: the peer gives no more credit to its stream, so the stream leaves the
ring. The other streams go on, and the stream keeps only its chunk, a view of your region. The
engine has no deadline for it. Bound its time with your own deadline, and then reset the stream.

A slow consumer of yours: it holds the bytes that it received until it calls `release`. The peer
can fill the window of a stream with no WINDOW_UPDATE, so a consumer that releases nothing holds
up to `settings.initial_window_size` bytes of `connection_window`. The other streams share the rest
of the connection window. The rule for `h2::Limits`:

> To isolate k stalled consumers (consumers that release nothing), choose
> `connection_window` ≥ (k + 1) × `settings.initial_window_size`.

With less, k stalled consumers can hold the whole connection window, and each other stream stops
until you release their bytes or reset their streams. The connection window is also the most
received data that the peer can make you hold on the connection, so the rule sets that memory too.

For example, the configuration of the [HTTP/2 example](http2.md#example) has an
`initial_window_size` of 65,535, the initial value of RFC 9113, and a `connection_window` of
1,048,576 (1 MiB). 1,048,576 / 65,535 is 16.0002, so k + 1 is at most 16. The connection isolates
15 stalled consumers. To isolate each of 100 streams, give 100 × 65,535 = 6,553,500 bytes.

A larger connection window also lets the peer send more before a WINDOW_UPDATE comes back, which a
path with a long round trip needs.

## Cancel a stream

Cancellation ends the affected stream, and the connection goes on:

| Who cancels | Call or event | What ends |
| --- | --- | --- |
| You | `reset(&mut outbound, stream, ErrorCode::CANCEL)` | The connection sends RST_STREAM. The chunk of the stream drops |
| The peer | `Event::Reset { stream, code }` | The chunk of the stream drops. Call `close(stream)` when the handler of the stream ends: see [handler slots](http2.md#handler-slots) |

The DATA frames of the stream that are in the output queue stay until the transport takes them,
because they are a part of the byte stream of the connection. After the reset, release the bytes
that the consumer of the stream holds: their connection credit goes back to the peer, and the
other streams can use it.
