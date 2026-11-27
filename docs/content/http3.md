# Read HTTP/3 frames

Use `rsnetwork::h3::frame` to read or write HTTP/3 framing without a socket.
The module works with `default-features = false`.
It exposes the frame boundaries, stream placement rules, and payload bytes. The application owns its connection state.

## Read a stream

1. On a unidirectional stream, pass its first bytes to `StreamType::read`. Retain an incomplete prefix until more bytes arrive.
2. On a control stream, create a `Decoder` with `Stream::ClientControl` or `Stream::ServerControl` according to the sender.
3. On a request stream, use `Stream::Request` for the request and `Stream::Response` for the response.
4. Pass a slice of the current region to `Decoder::next`. Limit the slice to the byte budget for this turn.
5. Process the returned `Part`. Call again with the remaining slice. Supply the next region after `Ok(None)`.
6. Call `finish` on a clean QUIC FIN. On a reset, discard this stream's decoder and report the reset separately.

The first part of each frame is its header. Check its length against the relevant limit before reserving any memory.
A DATA or HEADERS payload can arrive in pieces. `Part::Bytes` borrows the current region.
Its `end` flag marks the end of that frame. HTTP body completion also requires the message state and the stream FIN.
The decoder keeps up to seven bytes of an incomplete integer. An unknown frame consumes only the bytes supplied to the current call.

Use one QPACK decoder per connection. Give it complete HEADERS field sections and the bytes of the peer's QPACK encoder stream.
A `103 Early Hints` response and the final response have separate HEADERS frames on the same request stream.
The connection decides whether a decoded status is informational, final, or invalid. [QPACK field sections](qpack.md)

## Write a frame header

Use `Header::write` to write the frame type and payload length into caller storage. A 16-byte region holds any legal header.
Send the initialized prefix followed by the payload on the same QUIC stream.
`WriteError::Space` reports insufficient room. `WriteError::Value` reports a length above the 62-bit wire range.
Either refusal preserves the output buffer.

## Handle wire errors

| Event | Result |
| --- | --- |
| First frame on a control stream differs from SETTINGS | `H3_MISSING_SETTINGS` |
| A second SETTINGS arrives, or a frame appears on a forbidden stream | `H3_FRAME_UNEXPECTED` |
| A SETTINGS identifier is reserved for HTTP/2 | `H3_SETTINGS_ERROR` |
| A server GOAWAY names a stream other than a client request | `H3_ID_ERROR` |
| A frame contains an incomplete integer, extra identifier bytes, or a truncated payload | `H3_FRAME_ERROR` |
| A control stream ends at a frame boundary | `H3_CLOSED_CRITICAL_STREAM` |

The frame decoder returns the first framing error on later reads. The connection owner applies it as a connection error.
A push stream starts with a push ID. The connection checks authorization before it passes the response frames to a `Stream::Push` decoder.
An unknown unidirectional stream can be stopped or drained. Its contents have no HTTP/3 frame format.
The RFC gives the stream and frame rules. [RFC 9114, sections 6 and 7](https://www.rfc-editor.org/rfc/rfc9114.html#section-6)
