# Drive an HTTP/3 connection

Use `rsnetwork::h3::Connection` with the default `tls` feature to serve or request resources over QUIC.
The host supplies datagrams and time. The engine owns HTTP message order, the control streams, and both QPACK tables.

## Start and drive the connection

1. Offer the ALPN name `h3` in the client and server TLS configurations.
2. Set `quic::Limits` before creating the QUIC connection. Allow at least three unidirectional streams and positive stream, connection, and send byte limits.
3. Create the engine with `h3::Connection::new(&quic, limits, &budget)`. Use this QUIC connection for every operation on the engine.
4. Call `drive(&mut quic, &mut input, now)` with each event from QUIC. Drive with `None` after transport progress or an application write. A credit grant can arrive without a QUIC event.
5. On `Step::Again`, drive again. On `Step::Event`, handle the event and resume. On `Step::Wait`, resume at the next transport or application event.
6. Continue to service QUIC transmission and its deadlines. On `Event::Closed`, finish pending exchanges with the transport outcome.

After negotiation, each endpoint opens a control stream and two QPACK streams. SETTINGS is the first control frame.
Reserve these streams for the engine. It can receive a request before the peer’s SETTINGS arrives. [RFC 9114, section 6](https://www.rfc-editor.org/rfc/rfc9114.html#section-6)

## Send and receive a message

A client calls `open` for a request stream. A server receives its identifier in `Event::Request`.
Pass the pseudo-header fields first in `headers`. For example, an HTTPS GET uses `:method`, `:scheme`, `:authority`, and `:path`.
Use `data` to admit a body region. Set the last frame’s `end` flag, or call `finish` after the last frame advances.
Each stream admits one pending frame. If that slot is full, drive the connection before retrying with the same input.

The client receives each informational response with its fields, then the final response.
A `103 Early Hints` event lets the application decide whether its cache, authority policy, and byte budget permit a fetch.
The client grants no push IDs. The server continues to serve requests when a peer offers push credit. [Early Hints](https://www.rfc-editor.org/rfc/rfc8297.html)

A DATA event carries a view of the received bytes. Call `release` with the consumed byte count to restore flow credit.
A clean FIN yields `Outcome::Complete` with any trailers. A reset carries its stream code and releases that stream’s blocked QPACK section.
Call `cancel` to abandon a request. Call `retire` when both directions end. A pending send acknowledgement gives `Ok(false)`.

## Limits and shutdown

A slow body reader can hold request bytes. HTTP/3 reserves local send storage and peer connection credit for its three critical streams.
The reserve grows to a quarter of the available window, up to `control_bytes`. A window of two or three bytes reserves one byte.
The peer must grant stream credit for the critical bytes to advance.
An encoder queues an insertion only when its complete instruction fits both stream and connection credit.
Otherwise, it can send the field as a literal. Split large outgoing bodies into DATA frames within the send limit. [RFC 9204, section 2.1.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.3)

| Limit | Default | What it bounds |
| --- | --- | --- |
| `h3::Limits::control_bytes` | 4 KiB | The incoming SETTINGS payload and each outgoing critical-stream buffer. Each critical stream also has one funded send region of this size. |
| `h3::Limits::blocked_bytes` | 256 KiB | The combined capacity of blocked field sections and bytes held behind them. Both buffers count while a buffer grows. |
| `decoder.blocked_streams` | 16 | The advertised count also fits the request limit, the QUIC visit limit, and one two-byte section prefix per slot. |
| `quic::Limits::turn` | 1 MiB, 4096 frames, 16,384 visits | Each drive call reads a bounded input slice. It handles one control-frame part or up to `frames` QPACK instructions. A feedback scan visits at most `visits` sections. |

A byte-limit refusal for blocked data resets that request with `H3_EXCESSIVE_LOAD`. Other requests can continue.
Exceeding the advertised blocked-stream count closes the connection with `QPACK_DECOMPRESSION_FAILED`.
Invalid encoder or decoder instructions close it with the corresponding QPACK stream error.
On `Step::Again`, resume with the same input slot. A cancellation can need several turns after its last byte arrives. [QPACK limits](qpack.md#limits)

Call `goaway` to end admission and finish accepted requests. A server sends the first excluded request ID.
A client that receives `Event::GoAway(id)` stops opening requests. Existing requests below the cutoff can still receive responses.
After the requests retire and QUIC acknowledges the critical-stream output, `drained()` returns true.
The host can then call `quic.close(h3::Code::NoError as u64, now)` and drive QUIC through its closing period. [RFC 9114, section 5.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.2)

Run the exchange from a repository checkout to check two Early Hints, the final body, its trailers, and graceful shutdown.

```sh
cargo xtask test -E 'test(early_hints_precede_the_final_response_and_goaway_drains_the_request)'
```

## Read a stream

The independent `rsnetwork::h3::frame` module also works with `default-features = false`.
Use it for wire framing when the caller owns the connection state.

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
