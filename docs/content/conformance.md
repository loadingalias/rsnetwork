# The HTTP/1.1 conformance suite

The conformance suite checks that the HTTP/1.1 engines frame each message as RFC 9112 and RFC 9110
require. It also checks that the result stays the same when the bytes arrive in pieces, when the
transport accepts only part of the output, and when requests come pipelined. One suite qualifies
the core and each binding, so no binding needs a test platform of its own.

rsnetwork is in development and has no release.

## Run the suite

```sh
cargo xtask test -E 'binary(h1_conformance)'
```

The suite runs the server and client engines on the caller-driven host, in memory, with no
socket and no runtime. A failure names the vector, its RFC sections, and the schedule or the seed.
It shows the result of the run, and for a schedule also the result of the whole input.

## What a vector is

A vector is the bytes of a peer and the outcomes that the RFC permits for them. An outcome has
three parts:

- What the application saw: the head of each message, its body bytes, and the end of its body.
  A request head is `METHOD target`. A response head is the status code and each field line.
- The status of each response that the server sent.
- The end of the connection: no error, or the kind of its error.

The permitted outcomes come from the RFC sections that the vector names, never from the code
under test. When the RFC lets the recipient choose, for example to refuse a bare LF or to read it
as a line end, the vector lists each outcome that the RFC permits. When the RFC recommends one
outcome, the vector permits only that outcome.

Most server vectors end with a pipelined `GET /smuggled` request. A server that reads a framing
wrong shows it as a request that the application must not see.

| Vectors | RFC sections | Permitted outcomes |
| --- | --- | --- |
| CL.TE and TE.CL: `Content-Length` and `Transfer-Encoding` in one request, in each order | RFC 9112, sections 6.1, 6.3, and 11.2 | `400` and the close, or the chunked body and then the close |
| Two `Content-Length` values that differ, a sign, and a value past `u64` | RFC 9112, section 6.3; RFC 9110, section 8.6 | `400`, or `413` for the value past `u64`, and the close |
| Two equal `Content-Length` values | RFC 9110, section 8.6 | `400`, or one length |
| TE.TE: a coding that is not `chunked`, a quoted `chunked`, a second `Transfer-Encoding` line, and whitespace before the colon | RFC 9112, sections 5.1, 6.3, and 7 | `400` and the close |
| TE.TE: a tab before `chunked` and capital letters | RFC 9112, sections 5.1 and 7 | The chunked body |
| TE.TE: an empty list element before `chunked` | RFC 9110, section 5.6.1 | The chunked body |
| Obsolete line folding in a request, and whitespace before the first field line | RFC 9112, sections 2.2 and 5.2 | `400`, or the fold as a space or the line ignored |
| Bare LF and bare CR in a head | RFC 9112, section 2.2 | `400`, or the LF as a line end and the CR as a space |
| Bare LF in a chunk line, chunk sizes with `0x`, a sign, no digit, or a value past `u64`, and chunk data longer than its size | RFC 9112, section 7.1 | `End(Malformed)`, `400`, and the close |
| Chunk sizes with leading zeros and both letter cases, chunk extensions, and whitespace before an extension | RFC 9112, sections 7.1 and 7.1.1 | The chunked body |
| A `Content-Length` trailer field | RFC 9110, section 6.5.1 | The framing does not change |
| HTTP/1.0: `Transfer-Encoding`, no `Host`, and `keep-alive` | RFC 9112, sections 3.2, 6.1, 9.3, and appendix C.2 | As the RFC states for HTTP/1.0 |
| HTTP/1.1 with no `Host` or two `Host` lines | RFC 9112, section 3.2 | `400` |
| Pipelining: four requests and a `close` option | RFC 9112, sections 9.3.2 and 9.6 | Each response in the order of the requests, and no request after the close |
| A bare LF before a pipelined request line | RFC 9112, section 2.2 | `400`, or the LF as a line end |
| A refusal after two pipelined requests, with a full output queue | RFC 9112, sections 6.1 and 9.3.2 | The two responses, then `400` and the close, or a third response and then the close |
| Empty lines before a request line and before the end of input | RFC 9112, section 2.2 | The server ignores them |
| Client: two `Content-Length` values, both framing fields, a chunk size past `u64`, and a bare LF in a chunk line | RFC 9112, sections 6.3 and 7.1 | The client discards the response or ends its body as malformed, and closes. It never reads the `Content-Length` body when `Transfer-Encoding` is present |
| Client: a response to HEAD with a `Content-Length`, then the next response | RFC 9112, section 6.3 | No body for HEAD, and the next response whole |

## How each vector runs

The test application answers each complete request with `200` and no body. A client sends its
next request in answer to the end of the response, and the bytes of each response arrive only
after its request, as from a server. The output queue has two entries, so pipelined requests meet
output backpressure.

1. The whole input arrives in one region, and the transport accepts each output in one write. The
   outcome must be one that the vector permits.
2. The input arrives in two regions, cut at each byte, and then one byte at a time. Each run must
   give the outcome and the output bytes of the whole input.
3. The transport accepts the output with a short write at each byte, and then one byte at a time.
   The host drives the engine between two writes, so the engine meets output that the transport
   has not accepted. Each run must give the outcome and the output bytes of whole writes.
4. A seed gives the size of each region and each write, from 1 to 8 bytes, and a time step of 0
   to 50 ms before each round. Two runs with the same seed must give the same steps: each region,
   each drive with its time and its wait, and each written byte. Each seeded run must give the
   outcome of the whole input. The suite runs 64 seeds.

## Reuse the suite in a binding

The suite has two parts:

- `tests/conformance/mod.rs` holds the vectors, their permitted outcomes, the schedules, and the
  record of the steps. It does no I/O.
- `tests/h1_conformance.rs` is the runner of the caller-driven host. Each round, the transport
  receives one region or the end of input, the host drives until the connection waits, and the
  transport makes one write.

A binding adds a runner of its own, as a test file of this package that includes the module with
`mod conformance;`. A test of another package includes the same file with a `#[path]` attribute
on the module. The runner must keep the rules that the permitted outcomes assume:

1. Give the input in the regions of the schedule, and give the bytes of each response only after
   its request.
2. Accept each write in the sizes of the schedule, and drive between two writes.
3. Answer as the test application does.
4. Record the outcome, each accepted byte, and each step in a `Run`.

Then apply the same four checks to the server vectors and the client vectors.
