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

A pool of `rsnetwork::buffer` charges each of its allocations: each slot at its size, rounded up
to its alignment, a 16-byte entry for each slot, and the shared state of the pool.

| Part | Charge | When |
| --- | --- | --- |
| `Inbound` queue | `limit` entries of a received region | `Inbound::new(limit, &budget)` |
| `Outbound` queue | `limit` entries of an output region | `Outbound::new(limit, &budget)` |
| Chunk-size line pool of an engine | A pool of one 16-byte slot for each `Outbound` entry | `Server::new` and `Client::new` |
| Join of a head or a trailer section that continues in the next received region | `head_bytes` or `trailer_bytes`, and the one allocation of the lease that owns the join | When the section continues in a later region, until the last view of it drops |
| HPACK decoder | Its dynamic table: see [HPACK](hpack.md#limits) | `hpack::Decoder::new(limits, &budget)` |
| HPACK lines | The space for the decoded lines of one block, which you lend to each decode | `hpack::Lines::new(limits, &budget)` |
| HPACK encoder | Its dynamic table | `hpack::Encoder::new(table_bytes, &budget)` |
| QPACK decoder | Its dynamic table, the space for one inserted entry, and its list of blocked streams: see [QPACK](qpack.md#limits) | `qpack::Decoder::new(limits, &budget)` |
| QPACK lines | The space for the decoded lines of one field section, which you lend to each decode | `qpack::Lines::new(limits, &budget)` |
| QPACK encoder | Its dynamic table and its list of sections that wait for their acknowledgement | `qpack::Encoder::new(limits, &budget)` |
| HTTP/2 connection | Its HPACK decoder of at least 4096 bytes, its HPACK encoder, a stream table of `max_concurrent_streams` entries, three lists of as many 4-byte identifiers (reset streams and the two rings of the send scheduler), and a frame pool of one 64-byte slot for each `Outbound` entry and one more | `h2::Connection::new` |
| Join of an HTTP/2 header block that does not decode in place | Its bytes for a block in one frame, or `work` for a block that continues: see [HTTP/2](http2.md#header-blocks) | When the block arrives, until its decode |
| TLS input region | A pool of one slot of `input_bytes` | When a receive needs a region, until the last view of its plaintext and the writable rest of the region drop |
| TLS sealed regions | One 32-byte mark for each entry of the plaintext output queue: the record layer seals no more regions before the transport accepts their records | `Tls::client` and `Tls::server` |
| HTTP/1.1 server regions | A pool of two slots of `head_bytes`, for response heads and trailer sections | `server::Http1::plain` and `server::Http1::tls` |
| Output region of the host | Nothing: your host charges the region, for example through its pool | `Connection::output_region` |
| Receive regions of `host::Tcp` and of the Tokio binding | Nothing: you charge its `Pool` to the budget that you give `Pool::new` | `Tcp::new`, and `new` of each type of `rsnetwork-tokio` |
| TLS ciphertext output | Its capacity, and the one allocation of the lease that owns it. Before a call of rustls, also twice the bytes that the call can write | When the connection writes, until the transport releases the last view |
| Join of a TLS handshake message after the handshake that arrives in two or more records | Its bytes, at most `input_bytes` | When the message continues in a later record, until the message is complete |
| TLS handshake | The state of rustls that the configuration fixes, and a bound of what rustls keeps of the messages of the peer: see [TLS handshakes](#tls-handshakes) | `Tls::client` and `Tls::server`, until the handshake completes |
| Call of rustls during a TLS handshake | Its working memory: see [TLS handshakes](#tls-handshakes) | Before the call, until it returns |
| TLS connection after the handshake | The key schedule of rustls, a copy of the end-entity certificate of the peer, and on a client one copy of the chain of the server | When the handshake completes, until the connection drops |
| TLS session store | One place for each session of `Resumption::Process(n)`, charged to the `budget` of the configuration | `ClientConfig::new` and `ServerConfig::new` |
| Stored TLS session | Its bytes, with the chain of the peer, to the `budget` of the configuration | When the store keeps it, until a handshake takes it or the store evicts it |
| TLS session that a handshake takes | The session and its copies in the handshake, to the budget of the connection | When the handshake takes it, until the handshake completes |

A join or a call of rustls that the budget cannot pay for does not fail the connection: the turn is
`Progress::Blocked(Blocked::Capacity(n))`, and the engine tries again in a later drive. The received
regions and the head regions that you give are yours, so you charge them, for example with a pool of
`rsnetwork::buffer` on the same budget. A region from a pool needs nothing more. Another region
costs one more allocation when the engine freezes it into a lease: `Backing::lease_layout()` gives
its size before you give the region. Charge it with the region, and keep that charge in the release
hook of the backing, which drops after the last view of the lease.

## TLS handshakes

rustls allocates its own memory, and it takes no budget. So a TLS connection charges a bound of
that memory before rustls can allocate it. The bounds come from the decoders of the rustls
release that rsnetwork pins, and a test checks them at each allocation:

| Charge | Bound |
| --- | --- |
| State of a handshake | About 20 KiB for a client, with more for each ALPN name, and 4 KiB for a server. A server that asks for a client certificate adds 8 KiB and twice the bytes of its roots |
| Working memory of one call | 16 KiB, a part for the own chain, and a factor times the bytes that rustls can read in the call: 56 for a client and 24 for a server |
| Messages of the peer that rustls keeps between calls | 17 times the most bytes that one call read, on a client and on a server that asks for a client certificate |
| Transcript for client authentication | Twice the bytes that this end sends, on a client with an identity and on a server that asks for one |

Only a connection in a call holds the working memory of the call, so it counts once for each
thread that runs a call, not once for each connection. rustls can read a whole handshake message in
one call, up to `input_bytes`. Thus one call of a client can charge 56 times `input_bytes` while it
runs, about 1.8 MiB for 32 KiB. Give the budget room for it, or a handshake waits for capacity.

A client factor of 56 comes from a list that rustls decodes in EncryptedExtensions also when the
client did not ask for it. The other lists of a client have a factor of 24 or less.

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
[HTTP/1.1](http1.md#framing-and-connection-rules). In `server::Http1` over TLS, it also bounds the
TLS handshake. After the last output, the [linger](server.md#linger) of `server::Http1` discards the
bytes of a peer that goes on sending, up to `linger.bytes` and `linger.time`. Bound the time of a slow body with your own
deadline for it, and end the connection when it passes.

## Each limit

| Limits | Bounds | Reference |
| --- | --- | --- |
| `h1::Limits` | The bytes, field lines, names, and values of a head | [HTTP/1.1](http1.md#limits) |
| `h1::BodyLimits` | The body, the drain, the chunk extensions, and the trailers | [HTTP/1.1](http1.md#limits) |
| `hpack::Limits` | The dynamic table, the decoded lines, and the work of one HTTP/2 header block | [HPACK](hpack.md#limits) |
| `qpack::Limits`, `qpack::EncoderLimits` | The dynamic tables, the blocked streams, the decoded lines of one HTTP/3 field section, the sections that wait for an acknowledgement, and the work of one read of the encoder stream | [QPACK](qpack.md#limits) |
| `h2::Limits` | The settings that an HTTP/2 endpoint sends, the largest header block, the encoder table, and the connection receive window | [HTTP/2](http2.md#limits) |
| `server::Limits`, `server::Linger` | The limits of an HTTP/1.1 server connection, its head timeout, and its linger after the last output | [Serve requests](server.md) |
| `tls::Limits` | The capacity of each TLS input region, which also bounds the largest handshake message, the records under one key, and the work of one drive | [TLS](tls.md#limits) |
| `drive::TurnLimits` | The work of one drive | This page |
| `Inbound::new`, `Outbound::new` | The regions that each queue holds | [Drive a protocol engine](drive.md) |
