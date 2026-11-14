//! The checked values of the core: methods, request targets, statuses, field lines, authorities,
//! and schemes.
//!
//! Each constructor checks its bytes against the grammar of RFC 9110, RFC 9112, and RFC 3986. It
//! refuses them, or it gives a view of the same bytes. A constructor allocates nothing, so a
//! refusal comes before any allocation. The parsers of the core make their values with these
//! rules, so a value that the core gives needs no second check.
//!
//! The `Debug` output of a value shows none of its bytes, because they can be credentials or other
//! peer text. Only a [`Status`] shows its number.
//!
//! ```
//! use core::net::Ipv4Addr;
//!
//! use rsnetwork::value::{Authority, Host, Method, Scheme, Status, Target, TargetForm};
//!
//! // An extension method stays as it is. The case of a method has a meaning.
//! let method = Method::new(b"PURGE")?;
//! assert_eq!(method.as_bytes(), b"PURGE");
//! assert_ne!(Method::new(b"get")?, Method::GET);
//!
//! // A target keeps its exact bytes. Its form gives its parts as views of these bytes.
//! let target = Target::new(b"/where?q=now")?;
//! assert_eq!(target.as_bytes(), b"/where?q=now");
//! assert!(matches!(target.form(), TargetForm::Origin { path: b"/where", query: Some(b"q=now") }));
//!
//! // An authority: the value of a Host field, or the authority of a target.
//! let authority = Authority::new(b"192.0.2.16:8080")?;
//! assert_eq!(authority.host(), Host::Ip(Ipv4Addr::new(192, 0, 2, 16).into()));
//! assert_eq!(authority.port(), Some(8080));
//!
//! // The case of a scheme has no meaning. A status is in 100 to 599.
//! assert_eq!(Scheme::new(b"HTTPS")?, Scheme::HTTPS);
//! assert_eq!(Status::new(404)?.code(), 404);
//! assert!(Status::new(600).is_err());
//! # Ok::<(), rsnetwork::value::InvalidValue>(())
//! ```

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A request method: a token (RFC 9110, section 9.1).
///
/// The case of a method has a meaning, and an extension method stays as it is. Two methods are
/// equal only when their bytes are equal. Thus `get`, or a method that the core does not know, is
/// never equal to [`Method::GET`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Method<'a>(pub(crate) &'a [u8]);

impl<'a> Method<'a> {
    /// `GET` (RFC 9110, section 9.3.1).
    pub const GET: Method<'static> = Method(b"GET");
    /// `HEAD` (RFC 9110, section 9.3.2).
    pub const HEAD: Method<'static> = Method(b"HEAD");
    /// `POST` (RFC 9110, section 9.3.3).
    pub const POST: Method<'static> = Method(b"POST");
    /// `PUT` (RFC 9110, section 9.3.4).
    pub const PUT: Method<'static> = Method(b"PUT");
    /// `DELETE` (RFC 9110, section 9.3.5).
    pub const DELETE: Method<'static> = Method(b"DELETE");
    /// `CONNECT` (RFC 9110, section 9.3.6).
    pub const CONNECT: Method<'static> = Method(b"CONNECT");
    /// `OPTIONS` (RFC 9110, section 9.3.7).
    pub const OPTIONS: Method<'static> = Method(b"OPTIONS");
    /// `TRACE` (RFC 9110, section 9.3.8).
    pub const TRACE: Method<'static> = Method(b"TRACE");

    /// Checks a method, or refuses it.
    pub fn new(bytes: &'a [u8]) -> Result<Self, InvalidValue> {
        if is_token(bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidValue::Method)
        }
    }

    /// The method, as bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for Method<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Method").finish_non_exhaustive()
    }
}

/// A request target in one of the four forms of RFC 9112, section 3.2.
///
/// The target keeps its exact bytes. [`form`](Self::form) gives its form and its parts as views
/// of these bytes. The constructor accepts only visible ASCII, a `%` only before two hexadecimal
/// digits, and no fragment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Target<'a>(pub(crate) &'a [u8]);

/// The form of a [`Target`], with its parts.
#[derive(Clone, Copy)]
pub enum TargetForm<'a> {
    /// The origin form, `/path?query`, of a request to an origin server.
    Origin {
        /// The path. It starts with `/`.
        path: &'a [u8],
        /// The query after `?`, if the target has a `?`. It can be empty.
        query: Option<&'a [u8]>,
    },
    /// The absolute form, `scheme://authority/path?query`, of a request to a proxy.
    Absolute {
        /// The scheme.
        scheme: Scheme<'a>,
        /// The authority. It has a host, and it has no user information.
        authority: Authority<'a>,
        /// The path. It is empty or it starts with `/`. RFC 9110, section 4.2.3, makes an empty
        /// path equivalent to `/`.
        path: &'a [u8],
        /// The query after `?`, if the target has a `?`. It can be empty.
        query: Option<&'a [u8]>,
    },
    /// The authority form, `host:port`, of a CONNECT request. It always has a port.
    Authority(Authority<'a>),
    /// The asterisk form, `*`, of an OPTIONS request for the server as a whole.
    Asterisk,
}

impl<'a> Target<'a> {
    /// Checks a request target, or refuses it.
    pub fn new(bytes: &'a [u8]) -> Result<Self, InvalidValue> {
        let target = Self(bytes);
        let valid = match target.form() {
            TargetForm::Origin { path, query } => is_path(path) && query.is_none_or(is_query),
            TargetForm::Absolute {
                scheme,
                authority,
                path,
                query,
            } => is_scheme(scheme.0) && is_authority(authority.0) && is_path(path) && query.is_none_or(is_query),
            TargetForm::Authority(authority) => is_authority(authority.0) && authority.port().is_some(),
            TargetForm::Asterisk => true,
        };
        if valid { Ok(target) } else { Err(InvalidValue::Target) }
    }

    /// The target, as bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The form of the target, with its parts.
    pub fn form(&self) -> TargetForm<'a> {
        let bytes = self.0;
        if bytes == b"*" {
            return TargetForm::Asterisk;
        }
        if bytes.first() == Some(&b'/') {
            let (path, query) = split_query(bytes);
            return TargetForm::Origin { path, query };
        }
        if let Some(colon) = bytes.iter().position(|&byte| byte == b':')
            && let Some(rest) = bytes[colon + 1..].strip_prefix(b"//")
        {
            let end = rest
                .iter()
                .position(|&byte| byte == b'/' || byte == b'?')
                .unwrap_or(rest.len());
            let (path, query) = split_query(&rest[end..]);
            return TargetForm::Absolute {
                scheme: Scheme(&bytes[..colon]),
                authority: Authority(&rest[..end]),
                path,
                query,
            };
        }
        TargetForm::Authority(Authority(bytes))
    }
}

impl fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target").finish_non_exhaustive()
    }
}

impl fmt::Debug for TargetForm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = match self {
            Self::Origin { .. } => "Origin",
            Self::Absolute { .. } => "Absolute",
            Self::Authority(_) => "Authority",
            Self::Asterisk => "Asterisk",
        };
        f.debug_struct(form).finish_non_exhaustive()
    }
}

/// Splits `bytes` at its first `?` into the path and the query.
fn split_query(bytes: &[u8]) -> (&[u8], Option<&[u8]>) {
    match bytes.iter().position(|&byte| byte == b'?') {
        Some(at) => (&bytes[..at], Some(&bytes[at + 1..])),
        None => (bytes, None),
    }
}

/// Whether `path` is empty, or `/` and segments (RFC 3986, section 3.3).
fn is_path(path: &[u8]) -> bool {
    matches!(path.first(), None | Some(b'/')) && is_uri_part(path, b":@/")
}

/// Whether `query` is a query (RFC 3986, section 3.4).
fn is_query(query: &[u8]) -> bool {
    is_uri_part(query, b":@/?")
}

/// Whether each byte of `bytes` is unreserved, a sub-delimiter, or in `extra`, and each `%` is
/// before two hexadecimal digits (RFC 3986, section 2).
fn is_uri_part(bytes: &[u8], extra: &[u8]) -> bool {
    let mut rest = bytes;
    while let [byte, tail @ ..] = rest {
        rest = match (byte, tail) {
            (b'%', [high, low, tail @ ..]) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => tail,
            (b'%', _) => return false,
            _ if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(byte) || extra.contains(byte) => tail,
            _ => return false,
        };
    }
    true
}

/// A status code: a number from 100 to 599 (RFC 9110, section 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(pub(crate) u16);

impl Status {
    /// Checks a status code, or refuses it.
    pub const fn new(code: u16) -> Result<Self, InvalidValue> {
        if matches!(code, 100..=599) {
            Ok(Self(code))
        } else {
            Err(InvalidValue::Status)
        }
    }

    /// The status code.
    pub const fn code(self) -> u16 {
        self.0
    }
}

/// One checked field line: a name and a value, as bytes.
///
/// The name is a token (RFC 9110, section 5.1), in the case that it was given or received. The
/// value has no CR, LF, NUL, or other control byte except HTAB, and no whitespace at its start or
/// end (RFC 9110, section 5.5). Bytes above 0x7F stay as they are.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
}

impl<'a> Field<'a> {
    /// Checks a field line, or refuses it.
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Result<Self, InvalidValue> {
        let edge = |byte: Option<&u8>| matches!(byte, Some(b' ' | b'\t'));
        let value_ok = !edge(value.first())
            && !edge(value.last())
            && value
                .iter()
                .all(|&byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f));
        if is_token(name) && value_ok {
            Ok(Self { name, value })
        } else {
            Err(InvalidValue::Field)
        }
    }

    /// The name, in the case that it was given or received. Compare names with
    /// [`eq_ignore_ascii_case`](slice::eq_ignore_ascii_case), because the case has no meaning.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The value, as bytes.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field").finish_non_exhaustive()
    }
}

/// An authority: a host and an optional port (RFC 3986, section 3.2), as in a Host field value
/// (RFC 9110, section 7.2).
///
/// The constructor refuses user information, which RFC 9110, section 4.2.4, forbids, and an
/// empty host, which section 4.2.1 forbids. It also refuses a port above 65535.
///
/// A registered name has only ASCII letters, digits, `-`, `.`, and `_`. An internationalized
/// name arrives in its `xn--` ASCII form. The constructor refuses a percent-encoding and each
/// other byte that RFC 3986 permits in a name, because a later reader can decode `ex%61mple.com`
/// to `example.com`. It also refuses a name whose last label is a number but that is not an IPv4
/// address, such as `127.1` or `0x7f.1`, because other parsers read it as an IPv4 address. Thus a
/// check of a name sees the host that a connection reaches.
#[derive(Clone, Copy)]
pub struct Authority<'a>(pub(crate) &'a [u8]);

/// The host of an [`Authority`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// An IP address. An IPv6 address that holds an IPv4 address, such as `[::ffff:127.0.0.1]`,
    /// gives that IPv4 address, because a connection to it reaches that address.
    Ip(IpAddr),
    /// A registered name, such as a DNS name, as bytes. Compare names with
    /// [`eq_ignore_ascii_case`](slice::eq_ignore_ascii_case), because the case has no meaning.
    Name(&'a [u8]),
}

impl<'a> Authority<'a> {
    /// Checks an authority, or refuses it.
    pub fn new(bytes: &'a [u8]) -> Result<Self, InvalidValue> {
        if is_authority(bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidValue::Authority)
        }
    }

    /// The authority, as bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The host.
    pub fn host(&self) -> Host<'a> {
        let (host, _) = split_host(self.0);
        let ip = match host {
            [b'[', literal @ .., b']'] => parse::<Ipv6Addr>(literal).map(|ip| IpAddr::V6(ip).to_canonical()),
            _ => parse::<Ipv4Addr>(host).map(IpAddr::V4),
        };
        ip.map_or(Host::Name(host), Host::Ip)
    }

    /// The port, if the authority has one. An empty port, as in `example.com:`, gives `None`,
    /// because RFC 9110, section 4.2.3, makes it equivalent to no port.
    pub fn port(&self) -> Option<u16> {
        match split_host(self.0) {
            (_, [b':', digits @ ..]) => decimal(digits).and_then(|port| u16::try_from(port).ok()),
            _ => None,
        }
    }
}

impl fmt::Debug for Authority<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority").finish_non_exhaustive()
    }
}

impl fmt::Debug for Host<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").finish_non_exhaustive()
    }
}

/// Whether `bytes` is a host and an optional port, with the refusals of [`Authority`].
fn is_authority(bytes: &[u8]) -> bool {
    let (host, rest) = split_host(bytes);
    let host_ok = match host {
        [b'[', literal @ .., b']'] => parse::<Ipv6Addr>(literal).is_some(),
        _ => {
            !host.is_empty()
                && host
                    .iter()
                    .all(|&byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
                && (parse::<Ipv4Addr>(host).is_some() || !ends_in_number(host))
        }
    };
    let port_ok = match rest {
        [] | [b':'] => true,
        [b':', digits @ ..] => decimal(digits).is_some_and(|port| u16::try_from(port).is_ok()),
        _ => false,
    };
    host_ok && port_ok
}

/// Splits an authority into its host and the rest, which is empty or starts with `:`.
fn split_host(bytes: &[u8]) -> (&[u8], &[u8]) {
    let end = if bytes.first() == Some(&b'[') {
        bytes
            .iter()
            .position(|&byte| byte == b']')
            .map_or(bytes.len(), |at| at + 1)
    } else {
        bytes.iter().position(|&byte| byte == b':').unwrap_or(bytes.len())
    };
    bytes.split_at(end)
}

/// Parses an IP address in the text form of RFC 3986, section 3.2.2.
fn parse<T: core::str::FromStr>(bytes: &[u8]) -> Option<T> {
    core::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Whether the last label of `name` is a number: decimal digits, or `0x` and hexadecimal digits.
/// A WHATWG URL parser and `inet_aton` read such a name as an IPv4 address.
fn ends_in_number(name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    let last = name.rsplit(|&byte| byte == b'.').next().unwrap_or(name);
    match last {
        [b'0', b'x' | b'X', hex @ ..] => hex.iter().all(u8::is_ascii_hexdigit),
        _ => !last.is_empty() && last.iter().all(u8::is_ascii_digit),
    }
}

/// A URI scheme (RFC 3986, section 3.1).
///
/// Two schemes are equal when their bytes are equal with no regard to case, because the case of a
/// scheme has no meaning.
#[derive(Clone, Copy)]
pub struct Scheme<'a>(pub(crate) &'a [u8]);

impl<'a> Scheme<'a> {
    /// `http` (RFC 9110, section 4.2.1).
    pub const HTTP: Scheme<'static> = Scheme(b"http");
    /// `https` (RFC 9110, section 4.2.2).
    pub const HTTPS: Scheme<'static> = Scheme(b"https");

    /// Checks a scheme, or refuses it.
    pub fn new(bytes: &'a [u8]) -> Result<Self, InvalidValue> {
        if is_scheme(bytes) {
            Ok(Self(bytes))
        } else {
            Err(InvalidValue::Scheme)
        }
    }

    /// The scheme, as bytes, in the case that it was given or received.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl PartialEq for Scheme<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for Scheme<'_> {}

impl fmt::Debug for Scheme<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheme").finish_non_exhaustive()
    }
}

/// Whether `bytes` is a letter and then letters, digits, `+`, `-`, and `.`.
fn is_scheme(bytes: &[u8]) -> bool {
    bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
}

/// Whether `bytes` is a token: one or more of the characters of RFC 9110, section 5.6.2.
fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&byte| is_tchar(byte))
}

/// Whether `byte` is a character of a token (RFC 9110, section 5.6.2).
pub(crate) fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// The value of one or more decimal digits, if it fits in a `u64`.
pub(crate) fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, &digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

/// A refusal of a constructor: the bytes are not a value of the kind that the variant names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidValue {
    /// The method is not a token.
    Method,
    /// The request target is not in one of the four forms of RFC 9112.
    Target,
    /// The status is not in 100 to 599.
    Status,
    /// The field name is not a token, or the field value has a forbidden byte.
    Field,
    /// The authority is not a host and an optional port, or it has a refused host or port.
    Authority,
    /// The scheme is not a letter and then letters, digits, `+`, `-`, and `.`.
    Scheme,
}

impl fmt::Display for InvalidValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Method => "the method is not a token",
            Self::Target => "the request target is not in one of the four forms",
            Self::Status => "the status is not in 100 to 599",
            Self::Field => "the field name is not a token, or the field value has a forbidden byte",
            Self::Authority => "the authority is not a host and an optional port",
            Self::Scheme => "the scheme has a forbidden character",
        })
    }
}

impl core::error::Error for InvalidValue {}
