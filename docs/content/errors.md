# Errors

`rsnetwork::drive::Error` is the error of each protocol engine and binding. It has a `Kind`, which
names the recovery, and a reason, which is fixed text of the code that refused. An error never
holds peer text, a credential, or a body. Its `Display` output is `<kind>: <reason>`, and its
`Debug` output shows the same two facts.

rsnetwork is in development and has no release.

## Kinds

Match on `error.kind()` to select the recovery. `error.reason()` gives the fixed reason for a log.

| `Kind` | Meaning | Recovery |
| --- | --- | --- |
| `Misuse` | The caller broke a contract of the API, or gave a configuration that cannot work | Correct the code or the configuration. A retry gives the same error |
| `Malformed` | The peer sent bytes that the protocol forbids | Refuse the message. Close the connection when the protocol cannot find the next message |
| `Trust` | A trust check failed, for example a certificate chain or a name | Do not retry with a weaker check, and never downgrade |
| `Unsupported` | The peer or the operation needs a capability that this build or this peer does not have | Use a capability that both sides have, or refuse |
| `Overload` | A limit or a budget refused the work | Retry later, or with more capacity |
| `Deadline` | The deadline came before the operation completed | Give a new deadline if the operation is still useful |
| `Cancelled` | The caller cancelled the operation | None: the caller stopped it |
| `Partial` | Only a part of the data arrived or went before the end | Do not use the part as a complete value |
| `Uncertain` | The operation ended with no proof of whether the peer completed it | Retry only an operation that is safe to do two times |

A deadline or a cancellation ends interest. It does not release a region that the transport
still holds: see [drive a protocol engine](drive.md).

## Errors of each module

Each module keeps its own error type, with the detail that its caller needs. Each converts into
`Error` with `From`:

| Error | Kind |
| --- | --- |
| `h1::ParseError::HeadTooLarge`, `TooManyFields`, `FieldTooLarge`, `BodyTooLarge`, `ExtensionTooLarge` | `Overload` |
| `h1::ParseError::Version`, `TransferCoding` | `Unsupported` |
| `h1::ParseError::Malformed`, `Framing` | `Malformed` |
| `drive::AckError` | `Misuse` |
| `buffer::PoolRefused::Budget` and `Allocation` | `Overload` |
| `buffer::PoolRefused::Layout` | `Misuse` |

The reason of the converted error is the `Display` text of the module error.

## Make an error

`Error::new(kind, reason)` makes an error. Give a fixed text as the reason, such as a string
literal. Never give text from a peer, a credential, or a body.

```rust
use rsnetwork::drive::{Error, Kind};

let error = Error::new(Kind::Overload, "the connection has no free stream");
assert_eq!(error.kind(), Kind::Overload);
assert_eq!(error.to_string(), "overload: the connection has no free stream");
```
