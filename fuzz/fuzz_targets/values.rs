//! The value constructors check fuzzed parts. The input is a status in two bytes, then the lengths
//! of a method, a target, and an authority in one byte each, then those parts. The rest is a
//! field line: the name, a colon, and the value.
//!
//! No constructor allocates. A host name has only the bytes that `Authority` permits, and its last
//! label is not a number. The values that the constructors accept pass through the writers and
//! the parsers with no change: a request with a Host field, where RFC 9112, section 3.2, permits
//! its method and target form, and a response with the field.

#![no_main]

use rsnetwork::buffer::WriteLoan;
use rsnetwork::h1::{Fields, Framing, Limits, RequestParser, ResponseParser, write_head, write_request};
use rsnetwork::value::{Authority, Field, Host, Method, Status, Target, TargetForm};
use rsnetwork_fuzz::allocated;

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [high, low, method, target, authority, rest @ ..] = input else {
        return;
    };
    let (method, rest) = rest.split_at(usize::from(*method).min(rest.len()));
    let (target, rest) = rest.split_at(usize::from(*target).min(rest.len()));
    let (authority, field) = rest.split_at(usize::from(*authority).min(rest.len()));
    let (name, value) = field
        .iter()
        .position(|&byte| byte == b':')
        .map_or((field, &[][..]), |colon| (&field[..colon], &field[colon + 1..]));
    let (values, bytes) = allocated(|| {
        let target = Target::new(target).map(|target| (target, target.form()));
        let authority = Authority::new(authority).map(|authority| (authority, authority.host(), authority.port()));
        let status = Status::new(u16::from_be_bytes([*high, *low]));
        (Method::new(method), target, authority, Field::new(name, value), status)
    });
    assert_eq!(bytes, 0, "a constructor allocated");
    let (method, target, authority, field, status) = values;
    if let Ok((_, TargetForm::Absolute { authority, .. } | TargetForm::Authority(authority))) = target {
        check_host(authority.host());
    }
    if let Ok((_, host, _)) = authority {
        check_host(host);
    }
    let field = field.ok().filter(|field| {
        let names: [&[u8]; 3] = [b"content-length", b"transfer-encoding", b"host"];
        !names.iter().any(|name| field.name().eq_ignore_ascii_case(name))
    });
    if let (Ok(method), Ok((target, form)), Ok((authority, ..)), Some(field)) = (method, target, authority, field) {
        request(method, target, form, authority, field);
    }
    if let (Ok(status), Some(field)) = (status, field) {
        response(status, field);
    }
});

/// Limits that no value of this target reaches, so that a refusal can only come from a value.
const WIDE: Limits = Limits {
    head_bytes: 1 << 16,
    fields: 8,
    name_bytes: 1 << 12,
    value_bytes: 1 << 12,
};

/// Checks the documented rules of a host name. Its bytes are ASCII letters, digits, `-`, `.`, and
/// `_`. Its last label is not a number in the sense of the "ends in a number" check of the WHATWG
/// URL Standard: decimal digits, or `0x` and hexadecimal digits. Such a name is an IPv4 address to
/// other parsers, so an allowlist of names would not see the host that a connection reaches.
fn check_host(host: Host<'_>) {
    let Host::Name(name) = host else { return };
    assert!(
        !name.is_empty()
            && name
                .iter()
                .all(|&byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
        "a host name has a byte that the rules do not permit"
    );
    let name = name.strip_suffix(b".").unwrap_or(name);
    let last = name.rsplit(|&byte| byte == b'.').next().unwrap_or(name);
    let number = match last {
        [b'0', b'x' | b'X', hex @ ..] => hex.iter().all(u8::is_ascii_hexdigit),
        _ => !last.is_empty() && last.iter().all(u8::is_ascii_digit),
    };
    assert!(!number, "a host name ends in a number");
}

/// The field lines of a head as names and values, with no framing field, which the writer adds.
fn lines<'a>(fields: Fields<'a>) -> Vec<(&'a [u8], &'a [u8])> {
    fields
        .filter(|field| !field.name().eq_ignore_ascii_case(b"content-length"))
        .map(|field| (field.name(), field.value()))
        .collect()
}

/// Writes a request with the values, and parses it back. The parser must read each value with
/// its bytes, and the authority of the target or of the Host field.
fn request(method: Method<'_>, target: Target<'_>, form: TargetForm<'_>, authority: Authority<'_>, field: Field<'_>) {
    let form_permitted = match form {
        TargetForm::Authority(_) => method == Method::CONNECT,
        TargetForm::Asterisk => method == Method::OPTIONS,
        TargetForm::Origin { .. } | TargetForm::Absolute { .. } => method != Method::CONNECT,
    };
    if !form_permitted {
        return;
    }
    let host = Field::new(b"Host", authority.as_bytes()).expect("an authority is a field value");
    let mut out = WriteLoan::new(Vec::with_capacity(4096));
    write_request(&mut out, method, target, &[host, field], Framing::Length(0))
        .expect("the writer takes checked values");
    let bytes = out.into_inner();
    let head = RequestParser::new(WIDE).parse(&bytes);
    let head = head
        .expect("the parser reads the head that the writer wrote")
        .expect("a complete head");
    assert_eq!(head.consumed(), bytes.len(), "the parser read another length");
    assert_eq!(
        head.method().as_bytes(),
        method.as_bytes(),
        "the parser read another method"
    );
    assert_eq!(
        head.target().as_bytes(),
        target.as_bytes(),
        "the parser read another target"
    );
    let expected = [(host.name(), host.value()), (field.name(), field.value())];
    assert_eq!(lines(head.fields()), expected, "the parser read other field lines");
    let authority = match form {
        TargetForm::Absolute { authority, .. } | TargetForm::Authority(authority) => authority,
        TargetForm::Origin { .. } | TargetForm::Asterisk => authority,
    };
    let read = head.authority().map(|authority| authority.as_bytes());
    assert_eq!(read, Some(authority.as_bytes()), "the parser read another authority");
}

/// Writes a response with the status and the field, and parses it back.
fn response(status: Status, field: Field<'_>) {
    let mut out = WriteLoan::new(Vec::with_capacity(4096));
    write_head(&mut out, status, &[field], Framing::Length(0)).expect("the writer takes checked values");
    let bytes = out.into_inner();
    let head = ResponseParser::new(WIDE).parse(&bytes, Method::GET);
    let head = head
        .expect("the parser reads the head that the writer wrote")
        .expect("a complete head");
    assert_eq!(head.consumed(), bytes.len(), "the parser read another length");
    assert_eq!(head.status(), status, "the parser read another status");
    let expected = [(field.name(), field.value())];
    assert_eq!(lines(head.fields()), expected, "the parser read other field lines");
}
