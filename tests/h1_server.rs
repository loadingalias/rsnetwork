//! The contracts of the H1 server engine: reuse, pipelining, the drain of an unread body, HTTP/1.0
//! clients, refusals, `100 Continue`, cancellation, and a chunked body with no allocation. Each
//! expected byte comes from RFC 9112 and RFC 9110, not from the code under test.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received};
use rsnetwork::h1::{BodyLimits, Framing, Limits, Server, ServerEvent};
use rsnetwork::value::{Field, Status};
use rstypes::capacity::Budget;

mod counting;

use counting::allocations;

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 16,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 8080),
    ecn: Ecn::NotEct,
    segment: None,
};

/// What the application saw: a request with its method and target, body bytes, or the end with
/// its trailer lines.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Request(Vec<u8>, Vec<u8>),
    Data(Vec<u8>),
    End(Vec<u8>),
}

/// The host of one connection: the queues, and the engine.
struct Host {
    inbound: Inbound,
    outbound: Outbound,
    server: Server,
}

impl Host {
    fn new(body: BodyLimits) -> Self {
        let outbound = Outbound::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
        Self {
            inbound: Inbound::new(NonZeroUsize::new(8).unwrap()).unwrap(),
            server: Server::new(LIMITS, body, &outbound, &budget).unwrap(),
            outbound,
        }
    }

    /// Queues bytes that the transport received.
    fn receive(&mut self, bytes: &[u8]) {
        let received = Received {
            region: Lease::from(bytes.to_vec()),
            endpoint: ENDPOINT,
            capacity: 1 << 16,
        };
        self.inbound.push(received).unwrap();
    }

    /// Drives the engine until it gives no event, and gives the events and the last progress.
    fn drive(&mut self) -> (Vec<Seen>, Progress) {
        let mut seen = Vec::new();
        loop {
            let (event, turn) = self.server.drive(&mut self.inbound, &mut self.outbound);
            match event {
                Some(ServerEvent::Request(head)) => {
                    let head = head.head();
                    seen.push(Seen::Request(
                        head.method().as_bytes().to_vec(),
                        head.target().as_bytes().to_vec(),
                    ));
                }
                Some(ServerEvent::Data(data)) => seen.push(Seen::Data(data.bytes().to_vec())),
                Some(ServerEvent::End(trailers)) => {
                    let lines = trailers.map(|trailers| {
                        trailers
                            .fields()
                            .flat_map(|field| [field.name(), b": ", field.value(), b"\r\n"].concat())
                            .collect()
                    });
                    seen.push(Seen::End(lines.unwrap_or_default()));
                }
                None => return (seen, turn.progress),
            }
        }
    }

    /// Answers with `status`, `fields`, and `body` in one piece, with the framing `framing`.
    fn respond(&mut self, status: u16, fields: &[Field<'_>], framing: Framing, body: &[u8]) {
        let head = Backing::from(Vec::with_capacity(256));
        let status = Status::new(status).unwrap();
        self.server
            .respond(&mut self.outbound, status, fields, framing, head)
            .unwrap();
        if !body.is_empty() {
            self.server
                .send(&mut self.outbound, &Lease::from(body.to_vec()))
                .unwrap();
        }
        self.server.finish(&mut self.outbound).unwrap();
    }

    /// Sends each output, with an acknowledgement of all of its bytes, and gives the bytes.
    fn sent(&mut self) -> Vec<u8> {
        let mut sent = Vec::new();
        while let Some(output) = self.outbound.submit() {
            sent.extend_from_slice(output.region.bytes());
            self.outbound.ack(output.id, output.region.initialized()).unwrap();
        }
        sent
    }
}

fn request(method: &[u8], target: &[u8]) -> Seen {
    Seen::Request(method.to_vec(), target.to_vec())
}

const WAIT: Progress = Progress::Blocked(Blocked::Input);

/// Two pipelined requests in one region get their responses in their order on one connection.
/// The second request waits until the response to the first is complete (RFC 9112, section
/// 9.3.2), and the connection then waits for the next request.
#[test]
fn pipelined_requests_get_their_responses_in_order_on_one_connection() {
    let mut host = Host::new(BODY);
    host.receive(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nPOST /b HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi");
    assert_eq!(
        host.drive(),
        (vec![request(b"GET", b"/a"), Seen::End(Vec::new())], WAIT)
    );
    host.respond(200, &[], Framing::Length(1), b"a");
    assert_eq!(
        host.drive(),
        (
            vec![
                request(b"POST", b"/b"),
                Seen::Data(b"hi".to_vec()),
                Seen::End(Vec::new())
            ],
            WAIT
        )
    );
    host.respond(201, &[], Framing::Chunked, b"b");
    assert_eq!(
        host.sent(),
        b"HTTP/1.1 200 \r\ncontent-length: 1\r\n\r\na\
          HTTP/1.1 201 \r\ntransfer-encoding: chunked\r\n\r\n1\r\nb\r\n0\r\n\r\n"
    );
    assert_eq!(host.drive(), (Vec::new(), WAIT));
}

/// A response before the end of the request body leaves unread bytes. The engine reads and
/// discards them, up to the drain limit, before the next request on the connection. Above the
/// limit, it closes the connection: a Content-Length body that the response can see as too long
/// gets `connection: close`, and a chunked body closes when the drain passes the limit. A
/// connection that reads the next request from inside an unread body reads the body as a request.
#[test]
fn reuse_after_an_unread_body_drains_it_or_closes() {
    // A chunked body within the drain limit, and the next request after it.
    let mut host = Host::new(BODY);
    host.receive(b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n");
    assert_eq!(
        host.drive(),
        (vec![request(b"POST", b"/up"), Seen::Data(b"abc".to_vec())], WAIT)
    );
    host.respond(413, &[], Framing::Length(0), b"");
    host.receive(b"5\r\nhello\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(
        host.drive(),
        (vec![request(b"GET", b"/next"), Seen::End(Vec::new())], WAIT)
    );
    assert_eq!(host.sent(), b"HTTP/1.1 413 \r\ncontent-length: 0\r\n\r\n");

    // A chunked body that passes the drain limit closes the connection.
    let mut host = Host::new(BODY);
    host.receive(b"POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    host.drive();
    host.respond(413, &[], Framing::Length(0), b"");
    host.receive(b"20\r\n0123456789abcdef0123456789abcdef\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));

    // A Content-Length body above the drain limit gets `connection: close`.
    let mut host = Host::new(BODY);
    host.receive(b"PUT /up HTTP/1.1\r\nHost: a\r\nContent-Length: 17\r\n\r\n");
    host.drive();
    host.respond(413, &[], Framing::Length(0), b"");
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
    assert_eq!(
        host.sent(),
        b"HTTP/1.1 413 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
}

/// An HTTP/1.0 request with no Host is served with an HTTP/1.1 status line. Its response has
/// Content-Length or close framing and never chunks, and the connection closes unless the
/// request has `Connection: keep-alive`, which the response then names. A Transfer-Encoding in
/// an HTTP/1.0 request makes its framing faulty, and the connection closes after the error
/// response (RFC 9112, section 6.1, and appendix C.2).
#[test]
fn an_http_1_0_client_gets_no_chunks_and_a_close_unless_keep_alive() {
    let mut host = Host::new(BODY);
    host.receive(b"GET /old HTTP/1.0\r\n\r\n");
    assert_eq!(
        host.drive(),
        (vec![request(b"GET", b"/old"), Seen::End(Vec::new())], WAIT)
    );
    host.respond(200, &[], Framing::Chunked, b"hello");
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
    assert_eq!(host.sent(), b"HTTP/1.1 200 \r\nconnection: close\r\n\r\nhello");

    let mut host = Host::new(BODY);
    host.receive(b"GET /a HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /b HTTP/1.0\r\n\r\n");
    host.drive();
    host.respond(200, &[], Framing::Length(1), b"a");
    assert_eq!(
        host.drive(),
        (vec![request(b"GET", b"/b"), Seen::End(Vec::new())], WAIT)
    );
    host.respond(200, &[], Framing::Length(1), b"b");
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
    assert_eq!(
        host.sent(),
        b"HTTP/1.1 200 \r\nconnection: keep-alive\r\ncontent-length: 1\r\n\r\na\
          HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 1\r\n\r\nb"
    );

    let mut host = Host::new(BODY);
    host.receive(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    let (seen, progress) = host.drive();
    assert_eq!(seen, Vec::new());
    assert!(matches!(progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Malformed));
    assert_eq!(
        host.sent(),
        b"HTTP/1.1 400 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
}

/// A refused request gets the error response that its refusal names, with `connection: close`,
/// and the connection ends with the error of the refusal.
#[test]
fn a_refused_request_gets_its_error_response_and_the_connection_ends() {
    for (input, response, kind) in [
        (&b"GET /a HTTP/1.1\r\n\r\n"[..], &b"400"[..], Kind::Malformed),
        (b"GET /a HTTP/2.0\r\nHost: a\r\n\r\n", b"505", Kind::Unsupported),
        (
            b"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"501",
            Kind::Unsupported,
        ),
        (
            b"POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1048577\r\n\r\n",
            b"413",
            Kind::Overload,
        ),
    ] {
        let mut host = Host::new(BODY);
        host.receive(input);
        let (seen, progress) = host.drive();
        assert_eq!(seen, Vec::new());
        assert!(
            matches!(progress, Progress::Terminal(Err(error)) if error.kind() == kind),
            "{progress:?}"
        );
        let expected = [
            b"HTTP/1.1 ",
            response,
            b" \r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
        ]
        .concat();
        assert_eq!(host.sent(), expected);
    }
}

/// A request with `Expect: 100-continue` waits for `100 Continue` before it sends its body. The
/// engine reads no body byte until the application accepts the body, which sends the 100. A
/// final response before the 100 closes the connection, because the client may send its body
/// or not (RFC 9110, section 10.1.1).
#[test]
fn a_body_that_expects_100_waits_for_the_application() {
    let expecting = b"PUT /up HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n";
    let mut host = Host::new(BODY);
    host.receive(&[&expecting[..], b"ok"].concat());
    assert_eq!(host.drive(), (vec![request(b"PUT", b"/up")], WAIT));
    host.server.accept_body(&mut host.outbound).unwrap();
    assert_eq!(
        host.drive(),
        (vec![Seen::Data(b"ok".to_vec()), Seen::End(Vec::new())], WAIT)
    );
    assert_eq!(host.sent(), b"HTTP/1.1 100 Continue\r\n\r\n");

    let mut host = Host::new(BODY);
    host.receive(expecting);
    host.drive();
    host.respond(417, &[], Framing::Length(0), b"");
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
    assert_eq!(
        host.sent(),
        b"HTTP/1.1 417 \r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
    );
}

/// A cancelled response stops with no end of its body: no last chunk, and fewer bytes than its
/// Content-Length. The client then sees an incomplete response, never a complete one, and the
/// connection ends (RFC 9112, section 9).
#[test]
fn a_cancelled_response_ends_with_no_end_of_its_body() {
    for (framing, expected) in [
        (
            Framing::Chunked,
            &b"HTTP/1.1 200 \r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n"[..],
        ),
        (Framing::Length(10), b"HTTP/1.1 200 \r\ncontent-length: 10\r\n\r\nabc"),
    ] {
        let mut host = Host::new(BODY);
        host.receive(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        host.drive();
        let head = Backing::from(Vec::with_capacity(256));
        host.server
            .respond(&mut host.outbound, Status::new(200).unwrap(), &[], framing, head)
            .unwrap();
        host.server
            .send(&mut host.outbound, &Lease::from(b"abc".to_vec()))
            .unwrap();
        host.server.cancel();
        let (seen, progress) = host.drive();
        assert_eq!(seen, Vec::new());
        assert!(matches!(progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Cancelled));
        assert_eq!(host.sent(), expected);
    }
}

/// After construction, the engine sends a long chunked body with no allocation: each size line
/// comes from its pool, and the CR LF after each chunk and the last chunk are static. A slot
/// returns to the pool when the queue drops its line after the acknowledgement. The head region
/// is the caller's, so its freeze is outside the count.
#[test]
fn a_long_chunked_body_sends_with_no_allocation_after_construction() {
    let mut host = Host::new(BODY);
    host.receive(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    host.drive();
    let head = Backing::from(Vec::with_capacity(256));
    host.server
        .respond(
            &mut host.outbound,
            Status::new(200).unwrap(),
            &[],
            Framing::Chunked,
            head,
        )
        .unwrap();
    let chunk = Lease::from(b"0123456789".to_vec());
    let mut sent = Vec::with_capacity(64 * 1024);
    let ((), count) = allocations(|| {
        for _ in 0..1000 {
            while host.server.send(&mut host.outbound, &chunk).is_err() {
                let output = host.outbound.submit().unwrap();
                sent.extend_from_slice(output.region.bytes());
                host.outbound.ack(output.id, output.region.initialized()).unwrap();
            }
        }
        while host.server.finish(&mut host.outbound).is_err() {
            let output = host.outbound.submit().unwrap();
            sent.extend_from_slice(output.region.bytes());
            host.outbound.ack(output.id, output.region.initialized()).unwrap();
        }
        while let Some(output) = host.outbound.submit() {
            sent.extend_from_slice(output.region.bytes());
            host.outbound.ack(output.id, output.region.initialized()).unwrap();
        }
    });
    assert_eq!(count, 0);
    let mut expected = b"HTTP/1.1 200 \r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..1000 {
        expected.extend_from_slice(b"a\r\n0123456789\r\n");
    }
    expected.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(sent, expected);
}

/// A client that closes between requests ends the connection with no error. A close inside a
/// request body ends it as a partial delivery, and the engine gives no end of the body.
#[test]
fn the_close_of_the_client_ends_the_connection() {
    let mut host = Host::new(BODY);
    host.receive(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    host.drive();
    host.respond(204, &[], Framing::Length(0), b"");
    host.inbound.end();
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));

    let mut host = Host::new(BODY);
    host.receive(b"PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nab");
    host.inbound.end();
    let (seen, progress) = host.drive();
    assert_eq!(seen, vec![request(b"PUT", b"/"), Seen::Data(b"ab".to_vec())]);
    assert!(matches!(progress, Progress::Terminal(Err(error)) if error.kind() == Kind::Partial));
}
