//! Differential parsing: two independent parsers read each request of the corpora of N009 and
//! N010, and no request that rsnetwork accepts has a second meaning.
//!
//! `httparse` reads each head and each chunked body in this process. llhttp, the parser of
//! Node.js, reads each request stream in `tests/differential/llhttp.mjs`, outside the Cargo build,
//! and `tests/differential/llhttp.txt` keeps its readings. Each disagreement is a refusal by
//! rsnetwork or a recorded defect of the independent parser in [`RECORDED`].

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use rsnetwork::body::Outcome;
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received, TurnLimits};
use rsnetwork::h1::{Framing, Server, ServerEvent};
use rsnetwork::message::Version;
use rsnetwork::value::Status;

mod differential;

use differential::{BODY, End, LIMITS, Reading, Verdict, fields, judge, text};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
    visits: 1 << 12,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The head of the request that carries each chunked body of `fuzz/seeds/chunked`.
const CHUNKED: &[u8] = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";

/// The most drives of one input. An input that needs more makes no progress.
const DRIVES: usize = 10_000;

/// Each disagreement that is not a refusal by rsnetwork: the corpus input, the parser, the class,
/// and the resolution. Each is a refusal by the independent parser, so no input has two meanings.
const RECORDED: &[(&str, &str, Verdict, &str)] = &[
    (
        "chunked/n010-space-before-extension",
        "llhttp",
        Verdict::OtherRefuses,
        BWS,
    ),
    ("request/n010-29", "llhttp", Verdict::OtherRefuses, BWS),
    ("request/rfc3253-7.1-update", "llhttp", Verdict::OtherRefuses, METHOD),
];

/// A defect of llhttp: it refuses whitespace before a chunk extension (`HPE_INVALID_CHUNK_SIZE`).
/// RFC 9112, section 7.1.1, permits BWS (bad whitespace) there, and RFC 9110, section 5.6.3, makes
/// a recipient accept it.
const BWS: &str = "llhttp refuses the BWS that a recipient must accept";

/// A defect of llhttp: it knows only a fixed table of methods, and it refuses each other method
/// (`HPE_INVALID_METHOD`). A method is a token (RFC 9110, section 9.1), and a server answers a
/// method that it does not implement with 501. rsnetwork keeps an unknown method as it is.
const METHOD: &str = "llhttp refuses a method that is not in its table";

/// The root of the package, which the test runner gives in `CARGO_MANIFEST_DIR` when the test
/// runs. The corpora and the record of llhttp are under it.
fn root() -> PathBuf {
    PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("the runner gives the package root"))
}

/// The inputs of the corpora, by name, in the order of their names: each file of
/// `fuzz/seeds/request` after its two control bytes, each file of `fuzz/seeds/chunked` after its
/// control byte as the body of a chunked request.
///
fn corpus() -> BTreeMap<String, Vec<u8>> {
    let root = root();
    let mut inputs = BTreeMap::new();
    for (corpus, prefix, skip) in [("request", &b""[..], 2), ("chunked", CHUNKED, 1)] {
        let dir = root.join("fuzz/seeds").join(corpus);
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display())) {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            let name = format!("{corpus}/{}", path.file_name().unwrap().to_string_lossy());
            let input = [prefix, bytes.get(skip..).unwrap_or_default()].concat();
            inputs.insert(name, input);
        }
    }
    inputs
}

/// The request that the application reads, and whether it asks to change the protocol.
struct Current {
    head: String,
    upgrade: bool,
    body: Vec<u8>,
}

/// The reading of the server engine of `input`, which arrives whole and then ends.
///
/// A message part is `method target version persistence fields body trailers`, for each request
/// whose body is complete. The application accepts each body that waits for `100 Continue`. It
/// answers an upgrade with 101, a CONNECT with 200, which opens a tunnel, and each other request
/// with 200 and no body. After a protocol change, the last part is `switch` and the bytes after
/// the request.
fn serve(input: &[u8]) -> Reading {
    let budget = Budget::new(NonZeroU64::new(1 << 22).unwrap());
    let mut inbound = Inbound::new(NonZeroUsize::new(4).unwrap(), &budget).unwrap();
    let mut outbound = Outbound::new(NonZeroUsize::new(64).unwrap(), &budget).unwrap();
    let mut server = Server::new(LIMITS, BODY, TURN, &outbound, &budget)
        .unwrap()
        .head_timeout(None);
    if !input.is_empty() {
        let region = Lease::from(input.to_vec());
        let received = Received {
            region,
            endpoint: ENDPOINT,
            capacity: 1 << 16,
        };
        inbound.push(received).unwrap();
    }
    inbound.end();
    let (mut parts, mut current) = (Vec::new(), None::<Current>);
    for _ in 0..DRIVES {
        let (event, turn) = server.drive(&mut inbound, &mut outbound, None);
        match event {
            Some(ServerEvent::Request(request)) => {
                let head = request.head();
                if head.expects_continue() {
                    server.accept_body(&mut outbound).unwrap();
                }
                let version = match head.version() {
                    Version::Http10 => "HTTP/1.0",
                    Version::Http11 => "HTTP/1.1",
                    Version::Http2 => panic!("an HTTP/1.1 head has no HTTP/2 version"),
                };
                let persistence = if head.persistent() { "keep" } else { "close" };
                let lines = fields(head.fields().map(|field| (field.name(), field.value())));
                let (method, target) = (text(head.method().as_bytes()), text(head.target().as_bytes()));
                current = Some(Current {
                    head: format!("{method} {target} {version} {persistence} {lines}"),
                    upgrade: head.upgrade(),
                    body: Vec::new(),
                });
            }
            Some(ServerEvent::Data(data)) => current.as_mut().unwrap().body.extend_from_slice(data.bytes()),
            Some(ServerEvent::End(Outcome::Complete(trailers))) => {
                let current = current.take().unwrap();
                let trailers = trailers
                    .map(|trailers| fields(trailers.fields().map(|field| (field.name(), field.value()))))
                    .unwrap_or_default();
                parts.push(format!("{} {} {trailers}", current.head, text(&current.body)));
                let status = Status::new(if current.upgrade { 101 } else { 200 }).unwrap();
                let head = Backing::from(Vec::with_capacity(256));
                server
                    .respond(&mut outbound, status, &[], Framing::Length(0), head)
                    .unwrap();
                server.finish(&mut outbound).unwrap();
            }
            // A body that is not complete makes the next turn terminal.
            Some(ServerEvent::End(_)) | None => {}
            Some(ServerEvent::Handoff) => {
                let mut rest = Vec::new();
                while let Some(received) = inbound.take_front() {
                    rest.extend_from_slice(received.region.bytes());
                }
                parts.push(format!("switch {}", text(&rest)));
                return Reading { parts, end: End::Done };
            }
        }
        while let Some(output) = outbound.submit() {
            outbound.ack(output.id, output.region.initialized()).unwrap();
        }
        if let Progress::Terminal(end) = turn.progress {
            let end = match end {
                Ok(()) => End::Done,
                Err(error) if error.kind() == Kind::Partial => End::Cut,
                Err(_) => End::Refused,
            };
            return Reading { parts, end };
        }
    }
    panic!(
        "the engine made no progress in {DRIVES} drives on {}",
        input.escape_ascii()
    );
}

/// The readings of llhttp in `tests/differential/llhttp.txt`, by input name: the input in
/// hexadecimal, and the reading.
fn llhttp() -> BTreeMap<String, (Vec<u8>, Reading)> {
    let record = std::fs::read_to_string(root().join("tests/differential/llhttp.txt")).unwrap();
    record
        .lines()
        .map(|line| {
            let mut columns = line.split('\t');
            let (name, hex) = (columns.next().unwrap(), columns.next().unwrap());
            let mut parts: Vec<String> = columns.map(String::from).collect();
            let end = match parts.pop().as_deref() {
                Some("done") => End::Done,
                Some("cut") => End::Cut,
                Some("refused") => End::Refused,
                other => panic!("{name}: the record ends with {other:?}"),
            };
            let input = hex
                .as_bytes()
                .chunks(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            (name.to_owned(), (input, Reading { parts, end }))
        })
        .collect()
}

/// Judges the reading of rsnetwork and of `parser` for each input, and fails with each
/// disagreement that is not a refusal by rsnetwork and not in [`RECORDED`], and with each
/// recorded disagreement that did not occur.
fn check(parser: &str, readings: impl Iterator<Item = (String, Reading, Reading)>) {
    let (mut failures, mut counts) = (Vec::new(), BTreeMap::<String, usize>::new());
    let mut recorded: Vec<_> = RECORDED.iter().filter(|entry| entry.1 == parser).collect();
    for (name, rsnetwork, other) in readings {
        let verdict = judge(&rsnetwork, &other);
        *counts.entry(format!("{verdict:?}")).or_default() += 1;
        let known = recorded.iter().position(|entry| entry.0 == name && entry.2 == verdict);
        match (verdict, known) {
            (Verdict::Same | Verdict::RsnetworkRefuses, None) => {}
            (_, Some(at)) => {
                recorded.swap_remove(at);
            }
            (_, None) => failures.push(format!(
                "{name}: {verdict:?}\n  rsnetwork {rsnetwork:?}\n  {parser} {other:?}"
            )),
        }
    }
    failures.extend(
        recorded
            .iter()
            .map(|entry| format!("{}: the recorded {:?} ({}) did not occur", entry.0, entry.2, entry.3)),
    );
    println!("{parser}: {counts:?}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `httparse` reads each head that rsnetwork accepts, and each chunked body after it, with the
/// same method, target, version, field lines, data, trailer section, and length.
#[test]
fn httparse_gives_each_accepted_head_and_chunked_body_the_same_meaning() {
    let readings = corpus().into_iter().map(|(name, input)| {
        let (rsnetwork, other) = differential::heads_and_chunks(&input);
        (name, rsnetwork, other)
    });
    check("httparse", readings);
}

/// llhttp reads each request stream that rsnetwork accepts with the same messages, bodies,
/// trailers, persistence, and end. The record has exactly the inputs of the corpora.
#[test]
fn llhttp_gives_each_accepted_request_stream_the_same_meaning() {
    let (inputs, mut record) = (corpus(), llhttp());
    let stale: Vec<_> = record
        .keys()
        .filter(|name| !inputs.contains_key(*name))
        .cloned()
        .collect();
    assert!(
        stale.is_empty(),
        "the record has inputs that the corpora do not have: {stale:?}"
    );
    let readings = inputs.into_iter().map(|(name, input)| {
        let (recorded, other) = record
            .remove(&name)
            .unwrap_or_else(|| panic!("{name}: the record has no reading; run tests/differential/llhttp.mjs"));
        assert_eq!(
            recorded, input,
            "{name}: the record has other bytes; run tests/differential/llhttp.mjs"
        );
        (name, serve(&input), other)
    });
    check("llhttp", readings);
}
