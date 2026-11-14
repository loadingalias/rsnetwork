//! The contracts of the request parser and the response writer. Each expected result comes from
//! the grammar of RFC 9112 and RFC 9110, not from the code under test.

use core::num::NonZeroUsize;

use rstypes::buffer::WriteLoan;

use super::{
    Framing, Limits, ParseError, RequestHead, RequestParser, WriteError, begin_chunk, end_chunk, last_chunk, write_head,
};
use crate::value::{Field, Status};

/// The method, target, fields, consumed count, and framing of a head.
type Summary<'a> = (&'a [u8], &'a [u8], Vec<(&'a [u8], &'a [u8])>, usize, Framing);

fn summary(head: RequestHead<'_>) -> Summary<'_> {
    (
        head.method().as_bytes(),
        head.target().as_bytes(),
        head.fields().map(|field| (field.name(), field.value())).collect(),
        head.consumed(),
        head.framing(),
    )
}

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

fn parser() -> RequestParser {
    RequestParser::new(LIMITS)
}

fn parse<'a>(parser: &mut RequestParser, input: &'a [u8]) -> Option<Summary<'a>> {
    parser.parse(input).unwrap().map(summary)
}

/// A head with an extension method, a repeated field, edge whitespace, and bytes above 0x7F,
/// then its body of 5 bytes.
const LENGTH_HEAD: &[u8] =
    b"PURGE /cache/item?x=1 HTTP/1.1\r\nHost: example.com\r\nX-Tag: a\r\nx-tag:\t b \r\nX-Name: caf\xc3\xa9\r\nContent-Length: 5\r\n\r\n";

/// A head with a chunked body, then its body and the start of the next request.
const CHUNKED_HEAD: &[u8] = b"POST /upload HTTP/1.1\r\nhost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";

/// The bytes of a head can arrive in any pieces: whole, in two parts that split at each position,
/// or one byte at a time. Each way gives the same head and consumed count, and none gives a head
/// before its last byte arrives. The bytes after the head stay unread.
#[test]
fn split_and_byte_at_a_time_input_give_the_same_head() {
    let cases: [(&[u8], &[u8], Summary<'_>); 2] = [
        (
            LENGTH_HEAD,
            b"hello",
            (
                b"PURGE",
                b"/cache/item?x=1",
                vec![
                    (b"Host", b"example.com"),
                    (b"X-Tag", b"a"),
                    (b"x-tag", b"b"),
                    (b"X-Name", b"caf\xc3\xa9"),
                    (b"Content-Length", b"5"),
                ],
                LENGTH_HEAD.len(),
                Framing::Length(5),
            ),
        ),
        (
            CHUNKED_HEAD,
            b"5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\n",
            (
                b"POST",
                b"/upload",
                vec![(b"host", b"example.com"), (b"Transfer-Encoding", b"chunked")],
                CHUNKED_HEAD.len(),
                Framing::Chunked,
            ),
        ),
    ];
    for (head, after, expected) in cases {
        let input = [head, after].concat();
        assert_eq!(parse(&mut parser(), &input), Some(expected.clone()));
        for split in 1..input.len() {
            let mut parser = parser();
            let first = parse(&mut parser, &input[..split]);
            assert_eq!(
                first,
                (split >= head.len()).then(|| expected.clone()),
                "split at {split}"
            );
            if first.is_none() {
                assert_eq!(parse(&mut parser, &input), Some(expected.clone()), "split at {split}");
            }
        }
        let mut parser = parser();
        let first = (1..=input.len()).find_map(|len| parse(&mut parser, &input[..len]).map(|head| (len, head)));
        assert_eq!(first, Some((head.len(), expected)));
    }
}

/// A head refuses as soon as its limit is reached with no end of the head, also when its bytes
/// arrive one at a time. A head of exactly the limit passes. The field limit works the same way.
#[test]
fn a_head_over_its_limit_refuses_before_it_ends() {
    let limits = |head_bytes, fields| {
        RequestParser::new(Limits {
            head_bytes,
            fields,
            ..LIMITS
        })
    };
    let len = LENGTH_HEAD.len();
    assert!(limits(len, 5).parse(LENGTH_HEAD).unwrap().is_some());

    let mut parser = limits(len - 1, 5);
    for end in 0..len - 1 {
        assert_eq!(parser.parse(&LENGTH_HEAD[..end]), Ok(None), "{end} bytes");
    }
    assert_eq!(parser.parse(&LENGTH_HEAD[..len - 1]), Err(ParseError::HeadTooLarge));
    assert_eq!(limits(len - 1, 5).parse(LENGTH_HEAD), Err(ParseError::HeadTooLarge));

    assert_eq!(limits(len, 4).parse(LENGTH_HEAD), Err(ParseError::TooManyFields));
}

/// Framing that two parsers could read in two ways refuses. A request with such framing can
/// smuggle a second request past a proxy (RFC 9112, section 11.2).
#[test]
fn unclear_framing_refuses() {
    for (fields, expected) in [
        ("", Ok(Framing::Length(0))),
        ("Content-Length: 0042\r\n", Ok(Framing::Length(42))),
        (
            "Content-Length: 18446744073709551615\r\n",
            Ok(Framing::Length(u64::MAX)),
        ),
        ("transfer-encoding: Chunked\r\n", Ok(Framing::Chunked)),
        ("Content-Length: 18446744073709551616\r\n", Err(ParseError::Framing)),
        ("Content-Length: 5\r\nContent-Length: 5\r\n", Err(ParseError::Framing)),
        ("Content-Length: 5, 5\r\n", Err(ParseError::Framing)),
        ("Content-Length: +5\r\n", Err(ParseError::Framing)),
        ("Content-Length: 0x5\r\n", Err(ParseError::Framing)),
        ("Content-Length:\r\n", Err(ParseError::Framing)),
        (
            "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            Err(ParseError::Framing),
        ),
        (
            "Transfer-Encoding: chunked\r\ncontent-length: 5\r\n",
            Err(ParseError::Framing),
        ),
        ("Transfer-Encoding: chunked, gzip\r\n", Err(ParseError::Framing)),
        ("Transfer-Encoding: gzip\r\n", Err(ParseError::Framing)),
        ("Transfer-Encoding: gzip, chunked\r\n", Err(ParseError::TransferCoding)),
        (
            "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
            Err(ParseError::TransferCoding),
        ),
    ] {
        let input = format!("POST / HTTP/1.1\r\nHost: a\r\n{fields}\r\n");
        let framing = parser()
            .parse(input.as_bytes())
            .map(|head| head.map(|head| head.framing()));
        assert_eq!(framing, expected.map(Some), "{fields:?}");
    }
}

/// Each input differs from a valid head by one defect, and each refuses. A parser that accepts
/// one of them reads a different request than a strict peer does. A defect in a line end refuses
/// before the head ends.
#[test]
fn each_syntax_defect_refuses() {
    assert!(parser().parse(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n").unwrap().is_some());
    for (input, expected) in [
        (&b"GET /a HTTP/1.1\n"[..], ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost: a\rb", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost: a\r\n b\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\n Host: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost : a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\n: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost: a\0b\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1\r\nHost: a\x7fb\r\n\r\n", ParseError::Malformed),
        (b"GET  /a HTTP/1.1\r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a  HTTP/1.1\r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.1 \r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"G(T /a HTTP/1.1\r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"GET /\x01a HTTP/1.1\r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a http/1.1\r\nHost: a\r\n\r\n", ParseError::Malformed),
        (b"GET /a HTTP/1.0\r\nHost: a\r\n\r\n", ParseError::Version),
        (b"GET /a HTTP/2.0\r\nHost: a\r\n\r\n", ParseError::Version),
    ] {
        assert_eq!(
            parser().parse(input),
            Err(expected),
            "{:?}",
            input.escape_ascii().to_string()
        );
    }
}

/// The `Debug` output of a head, its fields, and its values shows no peer text, so a log line of a
/// request does not show a credential.
#[test]
fn debug_output_shows_no_peer_text() {
    let input = b"SECRET /?token=secret HTTP/1.1\r\nAuthorization: Bearer secret\r\nHost: secret.example\r\n\r\n";
    let head = parser().parse(input).unwrap().unwrap();
    let field = head.fields().next().unwrap();
    for text in [
        format!("{head:?}"),
        format!("{:?}", head.fields()),
        format!("{field:?}"),
        format!("{:?}", head.method()),
        format!("{:?}", head.target()),
        format!("{:?}", head.target().form()),
        format!("{:?}", head.authority()),
        format!("{:?}", head.authority().host()),
    ] {
        assert!(
            !text.to_ascii_lowercase().contains("secret") && !text.contains("Authorization"),
            "{text}"
        );
    }
}

/// An HTTP/1.1 request has exactly one Host field with a valid authority, or it refuses (RFC 9112,
/// section 3.2). A target in the absolute or the authority form gives the authority, and the Host
/// value then has no effect (RFC 9112, sections 3.2.2 and 3.3). With two Host values, two readers
/// can send the request to two different virtual hosts.
#[test]
fn the_authority_comes_from_the_target_or_from_one_valid_host_field() {
    for (input, expected) in [
        (
            &b"GET /where?q=now HTTP/1.1\r\nHost: www.example.org\r\n\r\n"[..],
            Ok(&b"www.example.org"[..]),
        ),
        (
            b"GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1\r\nHost: other.example\r\n\r\n",
            Ok(b"www.example.org"),
        ),
        (
            b"CONNECT server.example.com:80 HTTP/1.1\r\nHost: server.example.com\r\n\r\n",
            Ok(b"server.example.com:80"),
        ),
        (
            b"OPTIONS * HTTP/1.1\r\nHost: www.example.org:8001\r\n\r\n",
            Ok(b"www.example.org:8001"),
        ),
        (b"GET /a HTTP/1.1\r\nX-Host: a\r\n\r\n", Err(ParseError::Malformed)),
        (
            b"GET /a HTTP/1.1\r\nHost: a\r\nhost: a\r\n\r\n",
            Err(ParseError::Malformed),
        ),
        (b"GET /a HTTP/1.1\r\nHost:\r\n\r\n", Err(ParseError::Malformed)),
        (b"GET /a HTTP/1.1\r\nHost: user@a\r\n\r\n", Err(ParseError::Malformed)),
        (b"GET /a HTTP/1.1\r\nHost: a, b\r\n\r\n", Err(ParseError::Malformed)),
        (b"GET http://a.example/ HTTP/1.1\r\n\r\n", Err(ParseError::Malformed)),
        (
            b"GET http://a.example/ HTTP/1.1\r\nHost: a.example:99999\r\n\r\n",
            Err(ParseError::Malformed),
        ),
    ] {
        let authority = parser().parse(input).map(|head| head.unwrap().authority().as_bytes());
        assert_eq!(authority, expected, "{:?}", input.escape_ascii().to_string());
    }
}

/// Only CONNECT has the authority form, and a CONNECT has no other form. Only OPTIONS has the
/// asterisk form (RFC 9112, section 3.2, and RFC 9110, section 9.3.6). Each other pair refuses.
/// The case of a method has a meaning, so `connect` is an extension method.
#[test]
fn a_method_refuses_a_target_form_that_it_does_not_permit() {
    for (request_line, permitted) in [
        ("CONNECT a.example:443", true),
        ("OPTIONS *", true),
        ("OPTIONS /a", true),
        ("GET a.example:443", false),
        ("connect a.example:443", false),
        ("CONNECT /a", false),
        ("CONNECT http://a.example/", false),
        ("GET *", false),
    ] {
        let input = format!("{request_line} HTTP/1.1\r\nHost: a.example\r\n\r\n");
        let result = parser().parse(input.as_bytes()).map(|head| head.is_some());
        let expected = if permitted {
            Ok(true)
        } else {
            Err(ParseError::Malformed)
        };
        assert_eq!(result, expected, "{request_line}");
    }
}

/// A field name or value longer than its limit refuses, and one of exactly its limit passes. The
/// length of a value does not include the whitespace at its start and end.
#[test]
fn a_field_over_its_name_or_value_limit_refuses() {
    let name = "N".repeat(LIMITS.name_bytes);
    let value = "v".repeat(LIMITS.value_bytes);
    let parse = |name: &str, value: &str| {
        let input = format!("GET / HTTP/1.1\r\nHost: a\r\n{name}: {value}\r\n\r\n");
        parser().parse(input.as_bytes()).map(|head| head.is_some())
    };
    assert_eq!(parse(&name, &format!(" \t{value}\t ")), Ok(true));
    assert_eq!(parse(&format!("{name}N"), "v"), Err(ParseError::FieldTooLarge));
    assert_eq!(parse("N", &format!("{value}v")), Err(ParseError::FieldTooLarge));
}

/// The fields of a request keep their order and the case of their names when a server writes them
/// again, also for a repeated name. A map of fields would merge them, change their order, or change
/// their case.
#[test]
fn fields_keep_their_order_and_name_case_from_parse_to_write() {
    let input = b"GET / HTTP/1.1\r\nHost: a\r\nX-Tag: a\r\nx-tag: b\r\nX-TAG: c\r\n\r\n";
    let head = parser().parse(input).unwrap().unwrap();
    let fields: Vec<Field<'_>> = head.fields().collect();
    let mut out = WriteLoan::new(Vec::with_capacity(256));
    write_head(&mut out, Status::new(200).unwrap(), &fields, Framing::Length(0)).unwrap();
    assert_eq!(
        out.into_inner(),
        b"HTTP/1.1 200 \r\nHost: a\r\nX-Tag: a\r\nx-tag: b\r\nX-TAG: c\r\ncontent-length: 0\r\n\r\n"
    );
}

/// A region with exactly `capacity` free bytes.
fn region(capacity: usize) -> Vec<u8> {
    let mut region = vec![0; capacity].into_boxed_slice().into_vec();
    region.clear();
    region
}

/// Each head has the exact bytes that RFC 9112 gives: the status line, the fields in their order,
/// one framing field, and the empty line. A 204 or a 304 has no framing field. The chunk framing
/// gives the size in hexadecimal.
#[test]
fn heads_and_chunks_have_the_exact_framing() {
    let fields = [
        Field::new(b"Server", b"rsnetwork").unwrap(),
        Field::new(b"X-Tag", b"a b").unwrap(),
    ];
    let head = |status, fields: &[Field<'_>], framing| {
        let mut out = WriteLoan::new(Vec::with_capacity(256));
        write_head(&mut out, Status::new(status).unwrap(), fields, framing).unwrap();
        out.into_inner()
    };
    assert_eq!(
        head(200, &fields, Framing::Length(u64::MAX)),
        b"HTTP/1.1 200 \r\nServer: rsnetwork\r\nX-Tag: a b\r\ncontent-length: 18446744073709551615\r\n\r\n"
    );
    assert_eq!(
        head(599, &[], Framing::Length(0)),
        b"HTTP/1.1 599 \r\ncontent-length: 0\r\n\r\n"
    );
    assert_eq!(
        head(204, &fields[..1], Framing::Length(0)),
        b"HTTP/1.1 204 \r\nServer: rsnetwork\r\n\r\n"
    );
    assert_eq!(head(304, &[], Framing::Length(0)), b"HTTP/1.1 304 \r\n\r\n");

    let mut out = WriteLoan::new(Vec::with_capacity(256));
    write_head(&mut out, Status::new(200).unwrap(), &[], Framing::Chunked).unwrap();
    begin_chunk(&mut out, NonZeroUsize::new(26).unwrap()).unwrap();
    assert_eq!(out.fill_from(b"abcdefghijklmnopqrstuvwxyz"), 26);
    end_chunk(&mut out).unwrap();
    last_chunk(&mut out).unwrap();
    assert_eq!(
        out.into_inner(),
        b"HTTP/1.1 200 \r\ntransfer-encoding: chunked\r\n\r\n1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n"
    );
}

/// A refused write writes nothing. The caller can then write into a larger region, or write an
/// error response, with no partial head before it.
#[test]
fn a_refused_write_writes_nothing() {
    let expected = b"HTTP/1.1 200 \r\ncontent-length: 0\r\n\r\n";
    let mut out = WriteLoan::new(region(expected.len()));
    write_head(&mut out, Status::new(200).unwrap(), &[], Framing::Length(0)).unwrap();
    assert_eq!(out.filled(), expected);
    let mut out = WriteLoan::new(region(expected.len() - 1));
    assert_eq!(
        write_head(&mut out, Status::new(200).unwrap(), &[], Framing::Length(0)),
        Err(WriteError::Full {
            needed: expected.len(),
            available: expected.len() - 1
        })
    );
    assert!(out.filled().is_empty());

    let length = [Field::new(b"Content-Length", b"5").unwrap()];
    let coding = [Field::new(b"TRANSFER-ENCODING", b"chunked").unwrap()];
    for (status, fields, framing, expected) in [
        (100, &[][..], Framing::Length(0), WriteError::Status),
        (199, &[], Framing::Length(0), WriteError::Status),
        (204, &[], Framing::Length(1), WriteError::Status),
        (304, &[], Framing::Chunked, WriteError::Status),
        (200, &length, Framing::Length(5), WriteError::FramingField),
        (200, &coding, Framing::Chunked, WriteError::FramingField),
    ] {
        let mut out = WriteLoan::new(Vec::with_capacity(256));
        assert_eq!(
            write_head(&mut out, Status::new(status).unwrap(), fields, framing),
            Err(expected),
            "{status}"
        );
        assert!(out.filled().is_empty());
    }
}
