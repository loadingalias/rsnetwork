//! The checked values accept each form that RFC 9110, RFC 9112, and RFC 3986 give, and refuse each
//! other form, with no allocation. Each vector and its expected parts come from an example or the
//! grammar of these RFCs, not from the code under test.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rsnetwork::value::{Authority, Field, Host, InvalidValue, Method, Scheme, Status, Target, TargetForm};

mod counting;

use counting::allocations;

/// The form of a target and its scheme, authority, path, and query.
type Parts<'a> = (
    &'static str,
    Option<&'a [u8]>,
    Option<&'a [u8]>,
    &'a [u8],
    Option<&'a [u8]>,
);

fn parts(form: TargetForm<'_>) -> Parts<'_> {
    match form {
        TargetForm::Origin { path, query } => ("origin", None, None, path, query),
        TargetForm::Absolute {
            scheme,
            authority,
            path,
            query,
        } => (
            "absolute",
            Some(scheme.as_bytes()),
            Some(authority.as_bytes()),
            path,
            query,
        ),
        TargetForm::Authority(authority) => ("authority", None, Some(authority.as_bytes()), b"", None),
        TargetForm::Asterisk => ("asterisk", None, None, b"", None),
    }
}

/// Each of the four forms of RFC 9112, section 3.2, is accepted with its exact bytes and parts.
/// Each other target refuses: a relative or empty target, a fragment, a byte that RFC 3986 does
/// not permit, a defective percent-encoding, user information, an empty host, an authority form
/// with no port, and an absolute form with no authority.
#[test]
fn a_target_has_one_of_the_four_forms_or_refuses() {
    let accepted: [(&[u8], Parts<'_>); 13] = [
        // RFC 9112, sections 3.2.1 to 3.2.4.
        (b"/where?q=now", ("origin", None, None, b"/where", Some(b"q=now"))),
        (
            b"http://www.example.org/pub/WWW/TheProject.html",
            (
                "absolute",
                Some(b"http"),
                Some(b"www.example.org"),
                b"/pub/WWW/TheProject.html",
                None,
            ),
        ),
        (
            b"www.example.com:80",
            ("authority", None, Some(b"www.example.com:80"), b"", None),
        ),
        (b"*", ("asterisk", None, None, b"", None)),
        (
            b"http://www.example.org:8001",
            ("absolute", Some(b"http"), Some(b"www.example.org:8001"), b"", None),
        ),
        // RFC 9110, section 4.2.3: an upper-case host, an empty port, and a percent-encoding.
        (
            b"http://EXAMPLE.com:/%7esmith/home.html",
            (
                "absolute",
                Some(b"http"),
                Some(b"EXAMPLE.com:"),
                b"/%7esmith/home.html",
                None,
            ),
        ),
        // RFC 3986: an empty segment, an empty query, `?` and `/` in a query, and each other
        // byte that a path permits.
        (b"/", ("origin", None, None, b"/", None)),
        (b"//a.example/b", ("origin", None, None, b"//a.example/b", None)),
        (b"/a?", ("origin", None, None, b"/a", Some(b""))),
        (b"/a?b?c/d", ("origin", None, None, b"/a", Some(b"b?c/d"))),
        (
            b"/p:@!$&'()*+,;=-._~%20",
            ("origin", None, None, b"/p:@!$&'()*+,;=-._~%20", None),
        ),
        (
            b"https://[2001:db8::7]:8443/x?y",
            (
                "absolute",
                Some(b"https"),
                Some(b"[2001:db8::7]:8443"),
                b"/x",
                Some(b"y"),
            ),
        ),
        (
            b"[2001:db8::7]:443",
            ("authority", None, Some(b"[2001:db8::7]:443"), b"", None),
        ),
    ];
    let refused: [&[u8]; 19] = [
        b"",
        b"a/b",
        b"/a#frag",
        b"/a b",
        b"/a<b",
        b"/caf\xc3\xa9",
        b"/%zz",
        b"/%4",
        b"**",
        b"http://user@www.example.org/",
        b"http:///path",
        b"http://www.example.org#frag",
        b"http:/path",
        b"1http://a.example/",
        b"http://127.1/",
        b"http://a.example:65536/",
        b"www.example.com",
        b"www.example.com:",
        b"www.example.com:80/x",
    ];
    let ((), count) = allocations(|| {
        for (bytes, expected) in accepted {
            let target = Target::new(bytes);
            assert_eq!(
                target.map(|target| target.as_bytes()),
                Ok(bytes),
                "{}",
                bytes.escape_ascii()
            );
            assert_eq!(
                target.map(|target| parts(target.form())),
                Ok(expected),
                "{}",
                bytes.escape_ascii()
            );
        }
        for bytes in refused {
            assert_eq!(
                Target::new(bytes),
                Err(InvalidValue::Target),
                "{}",
                bytes.escape_ascii()
            );
        }
    });
    assert_eq!(count, 0);
}

/// A method keeps its exact bytes, also an extension method. Its case has a meaning (RFC 9110,
/// section 9.1), so neither `get` nor an unknown method is equal to `GET`. A method that is not a
/// token refuses.
#[test]
fn an_unknown_method_stays_as_it_is_and_is_never_get() {
    let ((), count) = allocations(|| {
        assert_eq!(Method::new(b"GET"), Ok(Method::GET));
        for bytes in [&b"get"[..], b"Get", b"PURGE", b"M-SEARCH", b"!#$%&'*+-.^_`|~09aZ"] {
            let method = Method::new(bytes).unwrap();
            assert_eq!(method.as_bytes(), bytes, "{}", bytes.escape_ascii());
            assert_ne!(method, Method::GET, "{}", bytes.escape_ascii());
        }
        for bytes in [&b""[..], b"G T", b"GET:", b"(GET)", b"GET\0", b"G\xc3\x89T"] {
            assert_eq!(
                Method::new(bytes),
                Err(InvalidValue::Method),
                "{}",
                bytes.escape_ascii()
            );
        }
    });
    assert_eq!(count, 0);
}

/// An authority gives its host and port (RFC 3986, section 3.2). An IPv6 address that holds an
/// IPv4 address gives the IPv4 address, which a connection to it reaches. An authority refuses user
/// information and an empty host (RFC 9110, section 4.2), a port above 65535, and a defective IP
/// literal. A name has only letters, digits, `-`, `.`, and `_`: a later reader can decode
/// `ex%61mple.com` to `example.com`, past a check of the name. A name also refuses if its last
/// label is a number but it is not a dotted IPv4 address: WHATWG URL parsers and `inet_aton` read
/// `127.1` and `0x7f.0.0.1` as 127.0.0.1.
#[test]
fn an_authority_gives_its_host_and_port_or_refuses() {
    let v4 = |a, b, c, d| Host::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    let accepted: [(&[u8], Host<'_>, Option<u16>); 12] = [
        (b"example.com", Host::Name(b"example.com"), None),
        (b"EXAMPLE.com:8080", Host::Name(b"EXAMPLE.com"), Some(8080)),
        (b"example.com:", Host::Name(b"example.com"), None),
        (b"example.com.:80", Host::Name(b"example.com."), Some(80)),
        (
            b"xn--nxasmq6b.example:0080",
            Host::Name(b"xn--nxasmq6b.example"),
            Some(80),
        ),
        (b"192.0.2.16:65535", v4(192, 0, 2, 16), Some(65535)),
        (
            b"[2001:db8::7]",
            Host::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))),
            None,
        ),
        (b"[::ffff:127.0.0.1]:443", v4(127, 0, 0, 1), Some(443)),
        (b"[::1]:0", Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(0)),
        (b"a-1.example", Host::Name(b"a-1.example"), None),
        (b"_dmarc.example.com", Host::Name(b"_dmarc.example.com"), None),
        (b"xn--bcher-kva.example", Host::Name(b"xn--bcher-kva.example"), None),
    ];
    let refused: [&[u8]; 25] = [
        b"",
        b":80",
        b"user@example.com",
        b"user:pass@example.com:80",
        b"example.com:65536",
        b"example.com:8o",
        b"example.com:+80",
        b"example.com:80:80",
        b"exa mple.com",
        b"[::1",
        b"::1",
        b"[::1]x",
        b"[v1.fe]",
        b"[fe80::1%25eth0]",
        b"127.1",
        b"0x7f.0.0.1",
        b"0177.0.0.1",
        b"2130706433",
        b"1.2.3.4.",
        b"1.2.3.256",
        b"example.0x1f",
        b"example.123",
        b"ex%61mple.com",
        b"exa$mple.com",
        b"a!b.com",
    ];
    let ((), count) = allocations(|| {
        for (bytes, host, port) in accepted {
            let authority = Authority::new(bytes);
            assert_eq!(
                authority.map(|authority| (authority.as_bytes(), authority.host(), authority.port())),
                Ok((bytes, host, port)),
                "{}",
                bytes.escape_ascii()
            );
        }
        for bytes in refused {
            assert_eq!(
                Authority::new(bytes).map(|authority| authority.as_bytes()),
                Err(InvalidValue::Authority),
                "{}",
                bytes.escape_ascii()
            );
        }
    });
    assert_eq!(count, 0);
}

/// A status is a number from 100 to 599 (RFC 9110, section 15). The case of a scheme has no
/// meaning (RFC 3986, section 3.1), so `HTTP` is the scheme `http`. A scheme starts with a letter.
#[test]
fn a_status_and_a_scheme_have_their_ranges() {
    let ((), count) = allocations(|| {
        for code in [100, 599] {
            assert_eq!(Status::new(code).map(Status::code), Ok(code));
        }
        for code in [0, 99, 600, 999] {
            assert_eq!(Status::new(code), Err(InvalidValue::Status), "{code}");
        }
        for (bytes, expected) in [
            (&b"http"[..], Scheme::HTTP),
            (b"HTTP", Scheme::HTTP),
            (b"Https", Scheme::HTTPS),
        ] {
            assert_eq!(Scheme::new(bytes), Ok(expected), "{}", bytes.escape_ascii());
        }
        assert_ne!(Scheme::HTTP, Scheme::HTTPS);
        assert_eq!(
            Scheme::new(b"a+b-c.d").map(|scheme| scheme.as_bytes()),
            Ok(&b"a+b-c.d"[..])
        );
        for bytes in [&b""[..], b"1http", b"-http", b"ht tp", b"ht_tp"] {
            assert_eq!(
                Scheme::new(bytes),
                Err(InvalidValue::Scheme),
                "{}",
                bytes.escape_ascii()
            );
        }
    });
    assert_eq!(count, 0);
}

/// A CR or an LF in a field value ends the field line early, so the rest of the value becomes a
/// field or a second response (response splitting). Edge whitespace changes the value that the
/// peer reads. Each of these refuses. Other bytes stay as they are.
#[test]
fn a_field_refuses_bytes_that_change_its_line() {
    let ((), count) = allocations(|| {
        for (name, value) in [
            (&b"X-A"[..], &b"a\r\nX-B: b"[..]),
            (b"X-A", b"a\nb"),
            (b"X-A", b"a\rb"),
            (b"X-A", b"a\0b"),
            (b"X-A", b" a"),
            (b"X-A", b"a\t"),
            (b"X A", b"a"),
            (b"X-A:", b"a"),
            (b"", b"a"),
        ] {
            assert_eq!(
                Field::new(name, value),
                Err(InvalidValue::Field),
                "{}",
                value.escape_ascii()
            );
        }
        for value in [&b""[..], b"a \tb", b"caf\xc3\xa9"] {
            assert_eq!(Field::new(b"X-A", value).map(|field| field.value()), Ok(value));
        }
    });
    assert_eq!(count, 0);
}
