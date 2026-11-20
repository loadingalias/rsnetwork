# Bound the memory and the work of a connection

The core bounds the memory of each connection with charges to a budget that you own, and the work
of each drive call with turn limits. A slow or hostile peer cannot make an engine keep uncharged
state or do unbounded work in one call.

rsnetwork is in development and has no release. The budget is the `Budget` of
`rsnetwork::capacity`, the same type as in the rsasync runtime. Give clones of one budget to the
runtime, to networking, and to your own code, so that one total contains each charge.

## Admission

Each part of a connection reserves its memory from the budget before it allocates. A refusal at
construction is `Kind::Overload`, and it allocates nothing. Thus a connection is admitted whole,
before the engine parses its first byte.

| Part | Charge | When |
| --- | --- | --- |
| `Inbound` queue | `limit` entries of a received region | `Inbound::new(limit, &budget)` |
| `Outbound` queue | `limit` entries of an output region | `Outbound::new(limit, &budget)` |
| Chunk-size line pool of an engine | One 16-byte slot for each `Outbound` entry | `Server::new` and `Client::new` |
| Join of a head or a trailer section that continues in the next received region | `head_bytes` or `trailer_bytes` | When the section continues in a later region, until the last view of it drops |
| HPACK decoder | Its dynamic table: see [HPACK](hpack.md#limits) | `hpack::Decoder::new(limits, &budget)` |
| HPACK lines | The space for the decoded lines of one block, which you lend to each decode | `hpack::Lines::new(limits, &budget)` |
| HPACK encoder | Its dynamic table | `hpack::Encoder::new(table_bytes, &budget)` |
| QPACK decoder | Its dynamic table, the space for one inserted entry, and its list of blocked streams: see [QPACK](qpack.md#limits) | `qpack::Decoder::new(limits, &budget)` |
| QPACK lines | The space for the decoded lines of one field section, which you lend to each decode | `qpack::Lines::new(limits, &budget)` |
| QPACK encoder | Its dynamic table and its list of sections that wait for their acknowledgement | `qpack::Encoder::new(limits, &budget)` |
| HTTP/2 connection | Its HPACK decoder of at least 4096 bytes, its HPACK encoder, a stream table of `max_concurrent_streams` entries, three lists of as many 4-byte identifiers (reset streams and the two rings of the send scheduler), and a frame pool of one 64-byte slot for each `Outbound` entry and one more | `h2::Connection::new` |
| Join of an HTTP/2 header block that does not decode in place | Its bytes for a block in one frame, or `work` for a block that continues: see [HTTP/2](http2.md#header-blocks) | When the block arrives, until its decode |
| TLS plaintext list | One entry for each place of the `Inbound` queue of the engine inside `Tls` | `Tls::server` and `Tls::client` |
| TLS input region | `input_bytes` | When a receive needs a region, until the last view of its plaintext drops |
| TLS ciphertext output | Its capacity, as encryption and rustls write it | When the connection writes, until the transport releases the last view |
| TLS plaintext copy: plaintext that rustls gave in its own buffer, or that joined its own region | Its bytes | When the copy is made, until its last view drops |

A join that the budget cannot pay for does not fail the connection: the turn is
`Progress::Blocked(Blocked::Capacity(n))`, and the engine tries again in a later drive. The received
regions and the head regions that you give are yours, so you charge them, for example with a pool of
`rsnetwork::buffer` that charges its slots to the same budget.

## Turn limits

One drive call is one turn. `TurnLimits` bounds the work of each turn:

| Limit | Counts |
| --- | --- |
| `bytes` | The received bytes that the turn reads: framing, body bytes, and bytes that a drain discards |
| `frames` | The frames that the turn decodes, for example the chunks of an HTTP/1.1 body or the frames of an HTTP/2 connection |

The engine counts its work in each turn. At a limit, it stops between two steps, and the turn gives
`Progress::Pending`: work remains, so drive the engine again with no wait for input. Between the
two drives, your host can serve other connections. An event ends a turn at once. A head or a
trailer section that the engine starts to read in a turn ends in that turn, because its own limit
bounds it. Each turn makes at least one step, so a small limit slows an engine but cannot stop it.

## Slow peers

| Peer | What the engine keeps | Bound |
| --- | --- | --- |
| A head that arrives slowly or never completes | At most one join, charged to the budget, and the queued regions | `head_bytes`: at the limit, the head refuses with 431, and the connection ends |
| A slow request or response body | No state of its own: the body bytes are views of the received regions, and a consumer holds one waiting part | The `Inbound` limit: when the queue is full, `push` gives the region back, so stop receiving |
| An unread body after a response | The drain of the rest | `drain_bytes`: above it, the connection closes |
| A slow consumer of an HTTP/2 stream | No state of its own: the data bytes are views of the received regions | The receive window of the stream and of the connection: the peer gets more credit only for bytes that the consumer releases. The other streams go on when `connection_window` follows the rule of [isolate a slow consumer](multiplexing.md#isolate-a-slow-consumer) |
| An HTTP/2 peer whose consumer of a stream is slow | The chunk of that stream, a view of your region, in its send slot | The send window of the stream: the stream waits, and the other streams go on. See [multiplexing](multiplexing.md) |
| An HTTP/2 peer that floods resets, CONTINUATION, SETTINGS, PING, WINDOW_UPDATE, or empty frames | No state of its own, and at most one answer that waits | Handlers in flight, header blocks, and answers: see [HTTP/2 floods](http2.md#floods) |
| A QPACK encoder whose field sections arrive before their insertions | One charged entry for each blocked stream. You keep the bytes of each section that waits | `blocked_streams`: one stream more ends the connection. See [QPACK](qpack.md#decode-field-sections) |
| A QPACK encoder that floods the encoder stream | Its dynamic table, which `table_bytes` bounds | `work` bounds each read of the encoder stream: see [QPACK](qpack.md#limits) |

The head timeout of the server bounds the time of a slow head: see
[HTTP/1.1](http1.md#framing-and-connection-rules). Bound the time of a slow body with your own
deadline for it, and end the connection when it passes.

## Each limit

| Limits | Bounds | Reference |
| --- | --- | --- |
| `h1::Limits` | The bytes, field lines, names, and values of a head | [HTTP/1.1](http1.md#limits) |
| `h1::BodyLimits` | The body, the drain, the chunk extensions, and the trailers | [HTTP/1.1](http1.md#limits) |
| `hpack::Limits` | The dynamic table, the decoded lines, and the work of one HTTP/2 header block | [HPACK](hpack.md#limits) |
| `qpack::Limits`, `qpack::EncoderLimits` | The dynamic tables, the blocked streams, the decoded lines of one HTTP/3 field section, the sections that wait for an acknowledgement, and the work of one read of the encoder stream | [QPACK](qpack.md#limits) |
| `h2::Limits` | The settings that an HTTP/2 endpoint sends, the largest header block, the encoder table, and the connection receive window | [HTTP/2](http2.md#limits) |
| `tls::Limits` | The capacity of each TLS input region, which also bounds the largest handshake message, and the work of one drive | [TLS](tls.md#limits) |
| `drive::TurnLimits` | The work of one drive | This page |
| `Inbound::new`, `Outbound::new` | The regions that each queue holds | [Drive a protocol engine](drive.md) |
