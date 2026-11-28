//! NET-K-1 and NET-K-2 request heads.

use core::hint::black_box;
use criterion::{Criterion, Throughput};

use super::records;
use crate::h1::{Framing, Limits, RequestHead, RequestParser};

const LIMITS: Limits = Limits {
    head_bytes: 32 << 10,
    fields: 64,
    name_bytes: 256,
    value_bytes: 24 << 10,
};

// BROWSER_GET from http-net-bench, revision 7415649ac6c8, src/inputs.rs.
const BROWSER: &[u8] = b"GET /assets/app.3f9a1c.js?v=2 HTTP/1.1\r\n\
Host: 127.0.0.1:53817\r\n\
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n\
Accept: */*\r\n\
Accept-Encoding: gzip, deflate, br, zstd\r\n\
Accept-Language: en-US,en;q=0.9\r\n\
Cache-Control: no-cache\r\n\
Connection: keep-alive\r\n\
Pragma: no-cache\r\n\
Referer: http://127.0.0.1:53817/\r\n\
Sec-Fetch-Dest: script\r\n\
Sec-Fetch-Mode: no-cors\r\n\
Sec-Fetch-Site: same-origin\r\n\r\n";

#[inline(never)]
fn raw(parser: &mut RequestParser, bytes: &[u8]) {
    black_box(parser.parse(bytes).unwrap().unwrap());
}

/// Routing and Bearer extraction belong to the NET-K-1 consumer.
fn route(head: &RequestHead<'_>) -> (u8, Option<u64>) {
    let path = head.target().as_bytes();
    let (route, digits) = match (head.method().as_bytes(), path) {
        (b"GET", b"/feed") => return (1, None),
        (b"GET", b"/health") => return (2, None),
        (b"POST", b"/posts") => return (3, None),
        (b"GET", rest) => (4, rest.strip_prefix(b"/posts/")),
        (b"POST", rest) => (5, rest.strip_prefix(b"/posts/").and_then(|p| p.strip_suffix(b"/like"))),
        _ => return (0, None),
    };
    let Some(digits) = digits.filter(|p| !p.contains(&b'/')) else {
        return (0, None);
    };
    let id = crate::value::decimal(digits).filter(|&id| digits.len() <= 16 && id != 0);
    (route, id)
}

#[inline(never)]
fn with_logic(parser: &mut RequestParser, bytes: &[u8]) {
    let head = parser.parse(bytes).unwrap().unwrap();
    let (route, id) = route(&head);
    let token = head
        .fields()
        .find(|f| f.name().eq_ignore_ascii_case(b"authorization"))
        .and_then(|f| f.value().strip_prefix(b"Bearer "));
    let end = match head.framing() {
        Framing::Length(length) => (head.consumed() as u64)
            .checked_add(length)
            .filter(|&end| end <= bytes.len() as u64),
        _ => None,
    };
    black_box((route, id, token.filter(|_| matches!(route, 3 | 5)), end));
}

pub(super) fn heads(c: &mut Criterion) {
    let mut group = c.benchmark_group("http1");
    for (name, count) in [
        ("api", 4096),
        ("curl", 512),
        ("chrome", 512),
        ("firefox", 512),
        ("long", 512),
    ] {
        let requests = records(&format!("h1_{name}"));
        assert_eq!(requests.len(), count);
        let mut parser = RequestParser::new(LIMITS);
        for request in &requests {
            let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = parser.parse(request).unwrap().unwrap();
            assert_eq!(head.consumed(), end);
            assert_eq!(head.framing(), Framing::Length((request.len() - end) as u64));
        }
        group.throughput(Throughput::Elements(count as u64));
        for (mode, parse) in [("raw", raw as fn(&mut RequestParser, &[u8])), ("logic", with_logic)] {
            group.bench_function(format!("{name}_{mode}"), |b| {
                b.iter(|| {
                    for request in black_box(&requests) {
                        parse(&mut parser, request);
                    }
                })
            });
        }
    }
    let mut parser = RequestParser::new(Limits { fields: 16, ..LIMITS });
    let head = parser.parse(BROWSER).unwrap().unwrap();
    assert_eq!((head.fields().count(), head.consumed()), (12, BROWSER.len()));
    group.throughput(Throughput::Elements(1));
    group.bench_function("browser_16", |b| {
        b.iter(|| {
            let head = parser.parse(black_box(BROWSER)).unwrap().unwrap();
            black_box((
                head.method(),
                head.target(),
                head.fields().count(),
                head.consumed(),
                head.framing(),
                head.persistent(),
                head.authority().is_some(),
            ));
        })
    });
}
