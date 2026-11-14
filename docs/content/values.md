# Checked HTTP values

The `rsnetwork::value` module holds the checked values of HTTP: methods, request targets,
statuses, field lines, authorities, and schemes. Each constructor checks bytes against the grammar
of RFC 9110, RFC 9112, and RFC 3986. It refuses the bytes, or it gives a view of the same bytes.
A constructor allocates nothing, so a refusal comes before any allocation.

The parsers of the core make their values with the same rules. Thus a value from a parser needs
no second check. Use the constructors for values that your own code makes, and for values from a
source that the core did not parse.

rsnetwork is in development and has no release.

## Example

The code runs in a function that returns `Result<(), InvalidValue>`. The module documentation of
`rsnetwork::value` runs the same example as a test.

```rust
use core::net::Ipv4Addr;

use rsnetwork::value::{Authority, Host, Method, Scheme, Status, Target, TargetForm};

// An extension method stays as it is. The case of a method has a meaning.
let method = Method::new(b"PURGE")?;
assert_eq!(method.as_bytes(), b"PURGE");
assert_ne!(Method::new(b"get")?, Method::GET);

// A target keeps its exact bytes. Its form gives its parts as views of these bytes.
let target = Target::new(b"/where?q=now")?;
assert_eq!(target.as_bytes(), b"/where?q=now");
assert!(matches!(target.form(), TargetForm::Origin { path: b"/where", query: Some(b"q=now") }));

// An authority: the value of a Host field, or the authority of a target.
let authority = Authority::new(b"192.0.2.16:8080")?;
assert_eq!(authority.host(), Host::Ip(Ipv4Addr::new(192, 0, 2, 16).into()));
assert_eq!(authority.port(), Some(8080));

// The case of a scheme has no meaning. A status is in 100 to 599.
assert_eq!(Scheme::new(b"HTTPS")?, Scheme::HTTPS);
assert_eq!(Status::new(404)?.code(), 404);
assert!(Status::new(600).is_err());
```

## Values

| Value | Constructor | Accepts | Read with |
| --- | --- | --- | --- |
| `Method` | `Method::new(bytes)` | A token (RFC 9110, section 9.1) | `as_bytes()`. Compare with `Method::GET` and the other RFC 9110 methods |
| `Target` | `Target::new(bytes)` | One of the four forms below | `as_bytes()` for the exact bytes, `form()` for the parts |
| `Status` | `Status::new(code)` | A number from 100 to 599 | `code()` |
| `Field` | `Field::new(name, value)` | A token name, and a value with no control byte except HTAB and no edge whitespace | `name()`, `value()` |
| `Authority` | `Authority::new(bytes)` | A host and an optional port, as in a Host field value | `as_bytes()`, `host()`, `port()` |
| `Scheme` | `Scheme::new(bytes)` | A letter, then letters, digits, `+`, `-`, and `.` | `as_bytes()`. Compare with `Scheme::HTTP` and `Scheme::HTTPS` |

Each value is a view of the bytes that you give, with the same lifetime. To keep a value after its
bytes, keep the bytes. A parsed request head can keep its received region with no copy: see
[keep a head after the call](http1.md#keep-a-head-after-the-call).

## Methods

A method is case-sensitive, and an extension method stays as it is. Two methods are equal only
when their bytes are equal. Thus `get`, or a method that the core does not know, is never equal to
`Method::GET`.

## Request targets

`Target::form()` gives a `TargetForm`, with the parts of the target as views of its bytes.

| Form | Example | Parts | Request |
| --- | --- | --- | --- |
| `Origin` | `/where?q=now` | `path` (starts with `/`), `query` | A request to an origin server |
| `Absolute` | `http://www.example.org/pub?q=1` | `scheme`, `authority`, `path` (empty or starts with `/`), `query` | A request to a proxy |
| `Authority` | `www.example.com:443` | The authority, which always has a port | A CONNECT request |
| `Asterisk` | `*` | None | An OPTIONS request for the server as a whole |

The query is `None` when the target has no `?`, and `Some(b"")` when the `?` has nothing after
it. RFC 9110 makes an empty path of an absolute form equivalent to `/`. The value keeps the empty
path as it is.

A target refuses each other form. Examples: a relative target such as `a/b`, a fragment (`#`), a
space or other byte that RFC 3986 does not permit, a `%` that is not before two hexadecimal
digits, and an absolute form with no `//` and authority. An absolute form also refuses user
information and an empty host. An authority form refuses a missing or empty port.

## Authorities and hosts

`Authority::host()` gives a `Host`:

- `Host::Ip(address)` for an IPv4 address, such as `192.0.2.16`, or an IPv6 address in brackets,
  such as `[2001:db8::7]`. An IPv6 address that holds an IPv4 address, such as
  `[::ffff:127.0.0.1]`, gives the IPv4 address, because a connection to it reaches that address.
- `Host::Name(bytes)` for a registered name, such as a DNS name, in the case that it was given.
  A name has only ASCII letters, digits, `-`, `.`, and `_`. An internationalized name arrives in
  its `xn--` ASCII form, such as `xn--bcher-kva.example`. Compare names with
  `eq_ignore_ascii_case`, because the case has no meaning.

`Authority::port()` gives the port, or `None` for no port. An empty port, as in `example.com:`,
also gives `None`, because RFC 9110 makes it equivalent to no port.

An authority refuses these forms, so that no other reader can read a different host from the
same bytes:

- User information, such as `user@example.com`, which RFC 9110 forbids in HTTP.
- A percent-encoding or another byte that RFC 3986 permits in a name, such as `ex%61mple.com`,
  `exa$mple.com`, or `a!b.com`. A later reader can decode `ex%61mple.com` to `example.com`, so a
  check of the name would not see the host that a connection reaches.
- An empty host, such as `:80`.
- A port above 65535, or a port with a byte that is not a digit.
- An IPv6 address with no brackets, a zone such as `%25eth0`, or a future IP literal such as
  `[v1.fe]`.
- A name whose last label is a number but that is not an IPv4 address of four decimal parts, such
  as `127.1`, `0x7f.0.0.1`, `0177.0.0.1`, `2130706433`, or `1.2.3.4.`. WHATWG URL parsers and
  `inet_aton` read these names as IPv4 addresses, so a check of the name would not see the address
  that a connection reaches.

## Errors

Each constructor gives `Err(InvalidValue)` with the kind of the refused value: `Method`, `Target`,
`Status`, `Field`, `Authority`, or `Scheme`. A refusal changes nothing and allocates nothing.
For bytes from a peer, the recovery is a refusal of the message: the H1 parser refuses a request
head with an invalid value as `ParseError::Malformed`.

## Debug output

The `Debug` output of a method, a target, a target form, a field, an authority, a host, or a
scheme shows none of its bytes, because they can be credentials or other peer text. A `Status`
shows its number.
