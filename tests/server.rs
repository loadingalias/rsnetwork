//! The server on HTTP/1.1, over TCP and over TLS. The test is the binding: it moves the bytes of
//! the transport, and it makes the calls of the exchange as the handler. `tests/http2.rs` runs
//! these rules on HTTP/2. The rules: a finished
//! response is not a delivered one, a shutdown drains the exchange in flight and refuses new work,
//! the report keeps the first failure, and the linger after the last output is bounded.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::body::{Outcome, Read};
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client;
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{self, BodyLimits, Framing};
use rsnetwork::h2;
use rsnetwork::host::{Connection, Io as _, Wait};
use rsnetwork::message::{RequestHead, Stream};
use rsnetwork::server::{Cleartext, Closed, Delivery, Http, Limits, Linger, Response};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Closure, Entropy, Identity, Limits as TlsLimits, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions, TimeProvider, Tls, UnixTime,
};
use rsnetwork::value::{Authority, Method, Status, Target};

const CA: &[u8] = include_bytes!("tls/ca.der");
const SERVER: (&[u8], &[u8]) = (include_bytes!("tls/server.der"), include_bytes!("tls/server.key.der"));

/// 2027-01-01, inside the validity of each test certificate.
const VALID: u64 = 1_798_761_600;

const HEAD: h1::Limits = h1::Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

/// The rest of an unread body that the connection drains: at most 64 bytes.
const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 64,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

/// The linger: at most 1 second and 1000 bytes.
const LINGER: Linger = Linger {
    time: Duration::from_secs(1),
    bytes: 1000,
};

/// The HTTP/2 connection, which a TLS client can select.
const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 8,
        max_header_list_size: 4096,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 1 << 20,
};

const LIMITS: Limits = Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: NonZeroUsize::new(16).unwrap(),
    head_timeout: Some(Duration::from_secs(5)),
    linger: LINGER,
    cleartext: Cleartext::Http1,
};

const TLS: TlsLimits = TlsLimits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

/// The content of a full TLS record: 2^14 bytes (RFC 8446, section 5.1).
const RECORD: usize = 1 << 14;

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 443),
    ecn: Ecn::NotEct,
    segment: None,
};

/// A wall clock that stays at one time.
#[derive(Debug)]
struct At(u64);

impl TimeProvider for At {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn clock() -> ClockDomain {
    ClockDomain::new(1, Suspend::Pauses)
}

/// The time `ms` milliseconds after the start of a test.
fn at(ms: u64) -> Instant {
    Instant::new(clock(), ms * 1_000_000)
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 24).unwrap())
}

fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

fn server_config(protocols: &[&[u8]]) -> ServerConfig {
    ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![certificate(SERVER.0)],
            key: PrivateKeyDer::try_from(SERVER.1.to_vec()).unwrap(),
        },
        client_roots: None,
        protocols,
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

fn client_config(protocols: &[&[u8]]) -> ClientConfig {
    ClientConfig::new(ClientOptions {
        roots: &[certificate(CA)],
        identity: None,
        protocols,
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(At(VALID)),
        entropy: Entropy::System,
    })
    .unwrap()
}

fn plain() -> Http {
    Http::plain(LIMITS, clock(), &budget()).unwrap()
}

fn tls(protocols: &[&[u8]]) -> Http {
    Http::tls(&server_config(protocols), (LIMITS, TLS), clock(), &budget()).unwrap()
}

/// The TLS client of the core, which offers `protocols`.
fn tls_client(protocols: &[&[u8]]) -> client::Http1 {
    let limits = client::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: NonZeroUsize::new(16).unwrap(),
    };
    client::Http1::tls(
        &client_config(protocols),
        "server.test",
        (limits, TLS),
        clock(),
        &budget(),
    )
    .unwrap()
}

fn get() -> client::Request<'static> {
    client::Request {
        method: Method::GET,
        target: Target::new(b"/").unwrap(),
        authority: Authority::new(b"server.test").unwrap(),
        fields: &[],
        length: Some(0),
    }
}

fn ok(length: Option<u64>) -> Response<'static> {
    Response {
        status: Status::new(200).unwrap(),
        fields: &[],
        length,
    }
}

/// Gives `bytes` to the server as one read-only received region.
fn give(server: &mut Http, bytes: &[u8]) {
    let received = Received {
        region: Lease::from(bytes.to_vec()),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    assert!(server.receive(received).is_ok(), "the server takes the bytes");
}

/// The transport accepts each output of the server: gives its bytes.
fn take(server: &mut Http) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(output) = server.output() {
        bytes.extend_from_slice(output.region.bytes());
        server.ack(output.id, output.region.initialized()).unwrap();
    }
    bytes
}

/// Gives `bytes` to the client as one read-only received region. The next call of the client
/// reads them.
fn give_client(client: &mut client::Http1, bytes: &[u8]) {
    let received = Received {
        region: Lease::from(bytes.to_vec()),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    assert!(client.receive(received).is_ok(), "the client takes the bytes");
}

/// Moves the bytes between a TLS client and the server until the server gives a request head.
fn handshake(client: &mut client::Http1, server: &mut Http) -> (Stream, RequestHead) {
    assert!(client.send(&get(), Deadline::at(at(60_000)), at(0)).unwrap());
    for _ in 0..16 {
        while let Some(output) = client.output() {
            give(server, output.region.bytes());
            client.ack(output.id, output.region.initialized()).unwrap();
        }
        if let Some(head) = server.request(at(0)).unwrap() {
            return head;
        }
        let bytes = take(server);
        give_client(client, &bytes);
        assert!(client.response(at(0)).unwrap().is_none(), "the response comes later");
    }
    panic!("the request did not reach the server");
}

/// Each TLS record in `bytes`, which holds whole records: its bytes.
fn records(mut bytes: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    while let [_, _, _, high, low, ..] = *bytes {
        let (record, rest) = bytes.split_at(5 + usize::from(u16::from_be_bytes([high, low])));
        records.push(record);
        bytes = rest;
    }
    records
}

/// A full data record of the body: a header, 2^14 bytes of content, its content type, and a
/// 16-byte tag.
fn full_record(record: &[u8]) -> bool {
    record.len() == 5 + RECORD + 1 + 16
}

#[test]
fn a_reset_after_the_handler_finished_gives_a_partial_delivery_apart_from_the_finish() {
    // Over TCP the count is exact: the transport accepts the head and 20,000 bytes of the body.
    let mut server = plain();
    give(&mut server, b"GET / HTTP/1.1\r\nhost: a\r\n\r\n");
    let (stream, _) = server.request(at(0)).unwrap().expect("a request");
    assert!(server.respond(stream, &ok(Some(4 * RECORD as u64)), at(0)).unwrap());
    for _ in 0..4 {
        server.write(stream, &Lease::from(vec![b'x'; RECORD]), at(0)).unwrap();
    }
    server.finish(stream, at(0)).unwrap();
    assert_eq!(
        server.delivery(stream),
        Some(Delivery::Sending {
            finished: true,
            accepted: 0
        })
    );
    let head = server.output().unwrap();
    assert!(head.region.bytes().starts_with(b"HTTP/1.1 200 "));
    server.ack(head.id, head.region.initialized()).unwrap();
    let first = server.output().unwrap();
    server.ack(first.id, RECORD).unwrap();
    let second = server.output().unwrap();
    server.ack(second.id, 20_000 - RECORD).unwrap();
    assert_eq!(
        server.delivery(stream),
        Some(Delivery::Sending {
            finished: true,
            accepted: 20_000
        })
    );
    server.reset();
    assert_matches!(
        server.delivery(stream),
        Some(Delivery::Partial { finished: true, accepted: 20_000, error }) if error.kind() == Kind::Partial
    );
    assert_matches!(server.release(), Some(Closed { result: Err(error), .. }) if error.kind() == Kind::Partial);

    // Over TLS a record counts when each of its bytes went: two full records and 100 bytes of the
    // third give two records of the body.
    let mut client = tls_client(&[b"http/1.1"]);
    let mut server = tls(&[b"http/1.1"]);
    let (stream, _) = handshake(&mut client, &mut server);
    assert!(server.respond(stream, &ok(Some(4 * RECORD as u64)), at(0)).unwrap());
    for _ in 0..4 {
        server.write(stream, &Lease::from(vec![b'x'; RECORD]), at(0)).unwrap();
    }
    server.finish(stream, at(0)).unwrap();
    let mut whole = 0;
    'send: while let Some(output) = server.output() {
        let mut accepted = 0;
        for record in records(output.region.bytes()) {
            if full_record(record) && whole == 2 {
                server.ack(output.id, accepted + 100).unwrap();
                break 'send;
            }
            whole += usize::from(full_record(record));
            accepted += record.len();
        }
        server.ack(output.id, accepted).unwrap();
    }
    assert_eq!(whole, 2, "the transport accepted two full records of the body");
    let accepted = 2 * RECORD as u64;
    assert_eq!(
        server.delivery(stream),
        Some(Delivery::Sending {
            finished: true,
            accepted
        })
    );
    server.reset();
    assert_matches!(
        server.delivery(stream),
        Some(Delivery::Partial { finished: true, accepted: two, error })
            if two == accepted && error.kind() == Kind::Partial
    );
}

#[test]
fn a_complete_delivery_needs_each_byte_of_the_response() {
    let mut server = plain();
    give(&mut server, b"GET / HTTP/1.1\r\nhost: a\r\n\r\n");
    let (stream, _) = server.request(at(0)).unwrap().expect("a request");
    assert!(server.respond(stream, &ok(None), at(0)).unwrap());
    server.write(stream, &Lease::from(&b"hello"[..]), at(0)).unwrap();
    server.finish(stream, at(0)).unwrap();
    let bytes = take(&mut server);
    assert!(bytes.ends_with(b"5\r\nhello\r\n0\r\n\r\n"));
    // The chunk framing does not count as body bytes.
    assert_eq!(server.delivery(stream), Some(Delivery::Complete { accepted: 5 }));
}

#[test]
fn a_shutdown_drains_the_request_in_flight_and_refuses_the_one_that_the_application_did_not_see() {
    let mut server = plain();
    give(
        &mut server,
        b"GET /a HTTP/1.1\r\nhost: a\r\n\r\nGET /b HTTP/1.1\r\nhost: a\r\n\r\n",
    );
    let (stream, a) = server.request(at(0)).unwrap().expect("the first request");
    assert_eq!(a.target().as_bytes(), b"/a");
    assert!(server.respond(stream, &ok(Some(2)), at(0)).unwrap());
    server.write(stream, &Lease::from(&b"ok"[..]), at(0)).unwrap();
    server.finish(stream, at(0)).unwrap();
    // The second request waits for the delivery of the first response.
    assert!(server.request(at(0)).unwrap().is_none());
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    let bytes = take(&mut server);
    let (first, refusal) = bytes.split_at(bytes.windows(2).position(|pair| pair == b"ok").unwrap() + 2);
    assert!(first.starts_with(b"HTTP/1.1 200 "));
    assert!(refusal.starts_with(b"HTTP/1.1 503 "));
    assert!(refusal.windows(17).any(|line| line == b"connection: close"));
    assert_eq!(server.delivery(stream), Some(Delivery::Complete { accepted: 2 }));
    // The application never sees the second request. After the last output, the server lingers.
    assert!(server.request(at(0)).unwrap().is_none());
    assert_eq!(
        server.wait(),
        Wait::Linger {
            deadline: Deadline::at(at(1_000))
        }
    );
    server.end_input();
    assert_eq!(
        server.release(),
        Some(Closed {
            result: Ok(()),
            cleanup: None
        })
    );
}

/// After a shutdown, the client learns which requests the server did not process: from
/// `connection: close` on the response in flight, or from `503` for its next request, also when
/// the bytes of that request arrived and the engine did not read them yet.
#[test]
fn a_shutdown_tells_the_client_which_requests_the_server_did_not_process() {
    const PIPELINED: &[u8] = b"GET /a HTTP/1.1\r\nhost: a\r\n\r\nGET /b HTTP/1.1\r\nhost: a\r\n\r\n";
    let has_close = |bytes: &[u8]| bytes.windows(17).any(|line| line == b"connection: close");
    let ends = |server: &mut Http| {
        while server.release().is_none() {
            assert!(server.request(at(0)).unwrap().is_none());
            server.end_input();
        }
        server.release().map(|closed| closed.result)
    };

    // The head of the response in flight is out with no `close`: the next request gets 503.
    let mut server = plain();
    give(&mut server, PIPELINED);
    let (stream, _) = server.request(at(0)).unwrap().expect("the first request");
    assert!(server.respond(stream, &ok(Some(2)), at(0)).unwrap());
    server.write(stream, &Lease::from(&b"o"[..]), at(0)).unwrap();
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    server.write(stream, &Lease::from(&b"k"[..]), at(0)).unwrap();
    server.finish(stream, at(0)).unwrap();
    assert!(server.request(at(0)).unwrap().is_none());
    let bytes = take(&mut server);
    let (first, refusal) = bytes.split_at(bytes.windows(2).position(|pair| pair == b"ok").unwrap() + 2);
    assert!(
        first.starts_with(b"HTTP/1.1 200 ") && !has_close(first),
        "{}",
        first.escape_ascii()
    );
    assert!(
        refusal.starts_with(b"HTTP/1.1 503 ") && has_close(refusal),
        "{}",
        refusal.escape_ascii()
    );
    assert_eq!(ends(&mut server), Some(Ok(())));

    // The head of the response in flight is not out: it gets `close`, and nothing follows it.
    let mut server = plain();
    give(&mut server, PIPELINED);
    let (stream, _) = server.request(at(0)).unwrap().expect("the first request");
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    assert!(server.respond(stream, &ok(Some(2)), at(0)).unwrap());
    server.write(stream, &Lease::from(&b"ok"[..]), at(0)).unwrap();
    server.finish(stream, at(0)).unwrap();
    assert!(server.request(at(0)).unwrap().is_none());
    let bytes = take(&mut server);
    assert!(bytes.starts_with(b"HTTP/1.1 200 ") && has_close(&bytes) && bytes.ends_with(b"ok"));
    assert_eq!(ends(&mut server), Some(Ok(())));

    // No exchange in flight, and a head that arrived whole: it gets 503, and the application
    // never sees it.
    let mut server = plain();
    give(&mut server, b"GET /c HTTP/1.1\r\nhost: a\r\n\r\n");
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    assert!(server.request(at(0)).unwrap().is_none());
    let bytes = take(&mut server);
    assert!(
        bytes.starts_with(b"HTTP/1.1 503 ") && has_close(&bytes),
        "{}",
        bytes.escape_ascii()
    );
    assert_eq!(ends(&mut server), Some(Ok(())));

    // A part of a head gets no response.
    let mut server = plain();
    give(&mut server, b"GET /c HTT");
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    assert!(server.request(at(0)).unwrap().is_none());
    assert_eq!(take(&mut server), b"");
    assert_eq!(ends(&mut server), Some(Ok(())));
}

#[test]
fn over_tls_a_shutdown_sends_close_notify_before_the_linger() {
    // The peer is the client engine of the core over TLS, which the test drives explicitly.
    let budget = budget();
    let limit = NonZeroUsize::new(16).unwrap();
    let queues = || {
        (
            Inbound::new(limit, &budget).unwrap(),
            Outbound::new(limit, &budget).unwrap(),
        )
    };
    let (inbound, outbound) = queues();
    let engine = h1::Client::new(HEAD, BODY, TURN, &outbound, &budget).unwrap();
    let config = client_config(&[b"http/1.1"]);
    let layer = Tls::client(&config, "server.test", engine, (inbound, outbound), TLS, &budget).unwrap();
    let (inbound, outbound) = queues();
    let mut peer = Connection::new(layer, inbound, outbound, Some(clock())).unwrap();
    let (engine, plaintext) = peer.parts().0.parts();
    let (target, authority) = (Target::new(b"/").unwrap(), Authority::new(b"server.test").unwrap());
    let head = Backing::from(Vec::with_capacity(256));
    engine
        .request(plaintext, Method::GET, target, authority, &[], Framing::Length(0), head)
        .unwrap();
    engine.finish(plaintext).unwrap();
    let mut server = tls(&[b"http/1.1"]);
    let exchange = |peer: &mut Connection<Tls<h1::Client>>, server: &mut Http| {
        while peer.drive(Some(at(0))).unwrap().is_some() {}
        while let Some(output) = peer.output() {
            give(server, output.region.bytes());
            peer.ack(output.id, output.region.initialized()).unwrap();
        }
        let head = server.request(at(0)).unwrap();
        let received = Received {
            region: Lease::from(take(server)),
            endpoint: ENDPOINT,
            capacity: 1 << 20,
        };
        peer.receive(received).unwrap();
        head
    };
    let request = (0..8).find_map(|_| exchange(&mut peer, &mut server));
    let (stream, _) = request.expect("the request reached the server");
    server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
    assert!(server.respond(stream, &ok(Some(2)), at(0)).unwrap());
    server.write(stream, &Lease::from(&b"ok"[..]), at(0)).unwrap();
    server.finish(stream, at(0)).unwrap();
    assert!(exchange(&mut peer, &mut server).is_none());
    while peer.drive(Some(at(0))).unwrap().is_some() {}
    // The transport did not end: the close_notify of the server ended the input of the client.
    assert_eq!(peer.parts().0.closure(), Some(Closure::Notified));
    assert!(server.request(at(0)).unwrap().is_none());
    assert_matches!(server.wait(), Wait::Linger { .. });
}

#[test]
fn a_failed_drain_keeps_the_original_failure() {
    let mut server = plain();
    // A field line with no colon: the server refuses the request with 400 and ends.
    give(&mut server, b"GET / HTTP/1.1\r\nhost: a\r\nbad\r\n\r\n");
    assert!(server.request(at(0)).unwrap().is_none());
    server.shutdown(Deadline::at(at(100)), at(0)).unwrap();
    // The client reads nothing, so the 400 response does not go before the deadline.
    assert!(server.request(at(50)).unwrap().is_none());
    assert!(server.release().is_none());
    assert!(server.request(at(100)).unwrap().is_none());
    let closed = server.release().expect("the shutdown deadline ends the connection");
    assert_matches!(closed.result, Err(error) if error.kind() == Kind::Malformed);
    assert_matches!(closed.cleanup, Some(error) if error.kind() == Kind::Deadline);
    assert!(!server.outstanding().is_empty(), "the 400 response did not go");
}

#[test]
fn the_linger_discards_late_bytes_and_ends_at_the_end_of_input_its_bytes_or_its_time() {
    // The server answers 413 and does not read the body, which is longer than the drain, so the
    // connection closes after the response.
    let closing = || {
        let mut server = plain();
        give(
            &mut server,
            b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 100000\r\n\r\nfirst bytes",
        );
        let (stream, _) = server.request(at(0)).unwrap().expect("a request");
        let too_large = Response {
            status: Status::new(413).unwrap(),
            fields: &[],
            length: Some(0),
        };
        assert!(server.respond(stream, &too_large, at(0)).unwrap());
        assert!(server.request(at(0)).unwrap().is_none());
        // The linger starts after the last output.
        assert_matches!(
            server.wait(),
            Wait::Until {
                blocked: Blocked::Output,
                ..
            }
        );
        let response = take(&mut server);
        assert!(response.windows(17).any(|line| line == b"connection: close"));
        assert!(server.request(at(10)).unwrap().is_none());
        assert_eq!(
            server.wait(),
            Wait::Linger {
                deadline: Deadline::at(at(1_010))
            }
        );
        give(&mut server, &[b'x'; 600]);
        assert!(server.release().is_none(), "the linger discards bytes within its limit");
        server
    };
    let mut ended = closing();
    ended.end_input();
    assert_eq!(ended.release().map(|closed| closed.result), Some(Ok(())));

    let mut flooded = closing();
    give(&mut flooded, &[b'x'; 401]);
    assert_eq!(flooded.release().map(|closed| closed.result), Some(Ok(())));

    let mut slow = closing();
    assert!(slow.request(at(1_009)).unwrap().is_none());
    assert!(slow.release().is_none());
    assert!(slow.request(at(1_010)).unwrap().is_none());
    assert_eq!(slow.release().map(|closed| closed.result), Some(Ok(())));
}

#[test]
fn a_request_that_waits_for_100_continue_gets_it_at_the_first_read_of_its_body() {
    let mut server = plain();
    give(
        &mut server,
        b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 2\r\nexpect: 100-continue\r\n\r\n",
    );
    let (stream, _) = server.request(at(0)).unwrap().expect("a request");
    assert!(
        take(&mut server).is_empty(),
        "no 100 before the application reads the body"
    );
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(16)));
    assert_matches!(server.read_into(stream, at(0), &mut region).unwrap(), Read::Wait);
    assert_eq!(take(&mut server), b"HTTP/1.1 100 Continue\r\n\r\n");
    give(&mut server, b"ok");
    assert_matches!(server.read_into(stream, at(0), &mut region).unwrap(), Read::Bytes(2));
    assert_matches!(
        server.read_into(stream, at(0), &mut region).unwrap(),
        Read::Done(Outcome::Complete(_))
    );
}

#[test]
fn a_reset_inside_the_request_body_ends_it_reset_not_truncated() {
    let mut server = plain();
    give(
        &mut server,
        b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 10\r\n\r\nfour",
    );
    let (stream, _) = server.request(at(0)).unwrap().expect("a request");
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(16)));
    assert_matches!(server.read_into(stream, at(0), &mut region).unwrap(), Read::Bytes(4));
    server.reset();
    assert_matches!(
        server.read_into(stream, at(0), &mut region).unwrap(),
        Read::Done(Outcome::Reset(None))
    );
    assert_matches!(server.release(), Some(Closed { result: Err(error), .. }) if error.kind() == Kind::Partial);
}

#[test]
fn over_tls_the_head_timeout_bounds_the_handshake() {
    let mut server = tls(&[b"http/1.1"]);
    assert!(server.request(at(0)).unwrap().is_none());
    // A part of a record header, and then nothing.
    give(&mut server, &[22, 3, 1]);
    assert!(server.request(at(4_999)).unwrap().is_none());
    assert!(server.release().is_none());
    assert!(server.request(at(5_000)).unwrap().is_none());
    assert_matches!(server.release(), Some(Closed { result: Err(error), .. }) if error.kind() == Kind::Deadline);
}

#[test]
fn over_tls_a_client_that_selects_another_protocol_ends_the_server() {
    let mut client = tls_client(&[b"spdy/3.1"]);
    let mut server = tls(&[b"spdy/3.1", b"http/1.1"]);
    assert!(client.send(&get(), Deadline::at(at(60_000)), at(0)).unwrap());
    for _ in 0..8 {
        while let Some(output) = client.output() {
            give(&mut server, output.region.bytes());
            client.ack(output.id, output.region.initialized()).unwrap();
        }
        assert!(server.request(at(0)).unwrap().is_none(), "the server takes no request");
        if server.release().is_some() {
            break;
        }
        let bytes = take(&mut server);
        give_client(&mut client, &bytes);
        // The client refuses the protocol too.
        if let Err(error) = client.response(at(0)) {
            assert_eq!(error.kind(), Kind::Unsupported);
        }
    }
    assert_matches!(server.release(), Some(Closed { result: Err(error), .. }) if error.kind() == Kind::Unsupported);
}
