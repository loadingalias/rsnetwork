//! The checks of RFC 9113, section 8, on decoded header sections. The blocks are HPACK literals,
//! so a field name keeps the case that the test gives.

use core::num::NonZeroU64;

use rstypes::buffer::Buffer as _;
use rstypes::capacity::Budget;

use super::{Answer, Refusal, request, response, trailers};
use crate::hpack::{Decoder, Limits, Lines};

const LIMITS: Limits = Limits {
    table_bytes: 4096,
    list_bytes: 4096,
    work: 64 * 1024,
};

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 20).unwrap())
}

/// The field lines of a section, each a name and a value.
type Section = Vec<(&'static [u8], &'static [u8])>;

/// A header block of `lines`, each a literal with no indexing and a new name (RFC 7541, section
/// 6.2.2).
fn block(lines: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in lines {
        block.push(0);
        block.push(u8::try_from(name.len()).unwrap());
        block.extend_from_slice(name);
        block.push(u8::try_from(value.len()).unwrap());
        block.extend_from_slice(value);
    }
    block
}

/// Decodes `lines`, and runs `check` on the block.
fn checked<T>(lines: &[(&[u8], &[u8])], check: impl FnOnce(crate::hpack::Block<'_>, &Budget) -> T) -> T {
    let budget = budget();
    let mut decoder = Decoder::new(LIMITS, &budget).unwrap();
    let mut decoded = Lines::new(LIMITS, &budget).unwrap();
    let bytes = block(lines);
    check(decoder.decode(&bytes, &mut decoded).unwrap(), &budget)
}

/// The request pseudo-header fields of RFC 9113, section 8.3.1, and then `fields`.
fn get(fields: &[(&'static [u8], &'static [u8])]) -> Vec<(&'static [u8], &'static [u8])> {
    let mut lines: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"server.test"),
        (b":path", b"/a?b"),
    ];
    lines.extend_from_slice(fields);
    lines
}

#[test]
fn a_request_section_is_malformed_exactly_when_rfc_9113_section_8_says() {
    let malformed: [(&str, Section); 24] = [
        ("an uppercase name", get(&[(b"Accept", b"x")])),
        ("a name that is not a token", get(&[(b"a b", b"x")])),
        ("a value with whitespace at its start", get(&[(b"accept", b" x")])),
        ("a value with a CR", get(&[(b"accept", b"x\ry")])),
        ("a value with a NUL", get(&[(b"accept", b"x\0y")])),
        ("connection", get(&[(b"connection", b"close")])),
        ("keep-alive", get(&[(b"keep-alive", b"5")])),
        ("proxy-connection", get(&[(b"proxy-connection", b"close")])),
        ("transfer-encoding", get(&[(b"transfer-encoding", b"chunked")])),
        ("upgrade", get(&[(b"upgrade", b"h2c")])),
        ("te other than trailers", get(&[(b"te", b"gzip")])),
        (
            "a pseudo-header after a field",
            vec![
                (b":method", b"GET"),
                (b"accept", b"x"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"a"),
            ],
        ),
        ("an unknown pseudo-header", get(&[(b":protocol", b"websocket")])),
        ("a :status", get(&[(b":status", b"200")])),
        ("two :path", get(&[(b":path", b"/")])),
        (
            "no :method",
            vec![(b":scheme", b"https"), (b":authority", b"a"), (b":path", b"/")],
        ),
        (
            "no :path",
            vec![(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"a")],
        ),
        (
            "an absolute :path",
            vec![
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"https://a/"),
            ],
        ),
        (
            "a * :path of GET",
            vec![
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"a"),
                (b":path", b"*"),
            ],
        ),
        (
            "no authority for https",
            vec![(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")],
        ),
        ("a host that names another authority", get(&[(b"host", b"other.test")])),
        (
            "CONNECT with a :path",
            vec![(b":method", b"CONNECT"), (b":authority", b"a:443"), (b":path", b"/")],
        ),
        (
            "CONNECT with no port",
            vec![(b":method", b"CONNECT"), (b":authority", b"a")],
        ),
        (
            "two content-length values",
            get(&[(b"content-length", b"1"), (b"content-length", b"2")]),
        ),
    ];
    for (case, lines) in malformed {
        let checked = checked(&lines, request);
        assert!(matches!(checked, Err(Refusal::Malformed)), "{case}");
    }

    let head = checked(
        &get(&[
            (b"accept", b"text/plain"),
            (b"te", b"trailers"),
            (b"content-length", b"5"),
        ]),
        request,
    )
    .unwrap();
    assert_eq!(head.method().as_bytes(), b"GET");
    assert_eq!(head.target().as_bytes(), b"/a?b");
    assert_eq!(head.authority().unwrap().as_bytes(), b"server.test");
    assert_eq!(head.scheme().unwrap().as_bytes(), b"https");
    assert_eq!(head.length(), Some(5));
    let fields: Vec<_> = head.fields().map(|field| (field.name(), field.value())).collect();
    assert_eq!(
        fields,
        [
            (&b"accept"[..], &b"text/plain"[..]),
            (b"te", b"trailers"),
            (b"content-length", b"5")
        ]
    );
    // The Host field gives the authority of a request with no `:authority`.
    let lines: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":path", b"/"),
        (b"host", b"h.test"),
    ];
    assert_eq!(
        checked(&lines, request).unwrap().authority().unwrap().as_bytes(),
        b"h.test"
    );
    // A CONNECT request has only its method and its authority, which is its target.
    let lines: Vec<(&[u8], &[u8])> = vec![(b":method", b"CONNECT"), (b":authority", b"a.test:443")];
    let connect = checked(&lines, request).unwrap();
    assert_eq!(connect.target().as_bytes(), b"a.test:443");
    assert!(connect.scheme().is_none());
    // An asterisk is the target of OPTIONS for the server as a whole.
    let lines: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"OPTIONS"),
        (b":scheme", b"https"),
        (b":authority", b"a"),
        (b":path", b"*"),
    ];
    checked(&lines, request).unwrap();
}

#[test]
fn a_response_section_has_one_three_digit_status_and_http2_has_no_101() {
    let malformed: [(&str, Section); 6] = [
        ("no :status", vec![(b"server", b"x")]),
        ("a status of two digits", vec![(b":status", b"20")]),
        ("a status that is not a number", vec![(b":status", b"2x0")]),
        ("101", vec![(b":status", b"101")]),
        ("a request pseudo-header", vec![(b":status", b"200"), (b":path", b"/")]),
        ("an uppercase name", vec![(b":status", b"200"), (b"Server", b"x")]),
    ];
    for (case, lines) in malformed {
        let checked = checked(&lines, response);
        assert!(matches!(checked, Err(Refusal::Malformed)), "{case}");
    }
    let lines: Vec<(&[u8], &[u8])> = vec![(b":status", b"103"), (b"link", b"</a>")];
    assert!(matches!(checked(&lines, response), Ok(Answer::Interim)));
    let lines: Vec<(&[u8], &[u8])> = vec![(b":status", b"200"), (b"content-length", b"7")];
    let Ok(Answer::Final(head)) = checked(&lines, response) else {
        panic!("a final response")
    };
    assert_eq!((head.status().code(), head.length()), (200, Some(7)));
    assert_eq!(head.bodiless().length(), Some(0));
    // A 204 response has no body, whatever its fields say.
    let lines: Vec<(&[u8], &[u8])> = vec![(b":status", b"204")];
    let Ok(Answer::Final(head)) = checked(&lines, response) else {
        panic!("a final response")
    };
    assert_eq!(head.length(), Some(0));
}

#[test]
fn a_trailer_section_has_no_pseudo_header_and_keeps_its_fields_in_order() {
    let lines: Vec<(&[u8], &[u8])> = vec![(b":status", b"200")];
    assert!(matches!(checked(&lines, trailers), Err(Refusal::Malformed)));
    let lines: Vec<(&[u8], &[u8])> = vec![(b"grpc-status", b"0"), (b"grpc-message", b"ok")];
    let lease = checked(&lines, trailers).unwrap();
    assert_eq!(lease.bytes(), b"grpc-status: 0\r\ngrpc-message: ok\r\n");
}
