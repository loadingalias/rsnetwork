//! The contracts of the H1 client engine: the body length of each response, informational
//! responses, reuse, HTTP/1.0 servers, the end of the connection, and cancellation. Each expected
//! byte and event comes from RFC 9112 and RFC 9110, not from the code under test.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::drive::{Blocked, Ecn, Endpoint, Inbound, Kind, Outbound, Progress, Received};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits};
use rsnetwork::value::{Authority, Method, Target};
use rstypes::capacity::Budget;

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
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    ecn: Ecn::NotEct,
    segment: None,
};

/// What the application saw: an informational or a final status, body bytes, or the end with
/// its trailer lines.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Informational(u16),
    Response(u16),
    Data(Vec<u8>),
    End(Vec<u8>),
    Handoff,
}

const WAIT: Progress = Progress::Blocked(Blocked::Input);

/// The host of one connection: the queues, and the engine.
struct Host {
    inbound: Inbound,
    outbound: Outbound,
    client: Client,
}

impl Host {
    fn new() -> Self {
        let outbound = Outbound::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
        Self {
            inbound: Inbound::new(NonZeroUsize::new(8).unwrap()).unwrap(),
            client: Client::new(LIMITS, BODY, &outbound, &budget).unwrap(),
            outbound,
        }
    }

    /// Sends a request to `a.example` with `body` in one piece and the framing `framing`.
    fn request(&mut self, method: &[u8], target: &[u8], framing: Framing, body: &[u8]) {
        let head = Backing::from(Vec::with_capacity(256));
        self.client
            .request(
                &mut self.outbound,
                Method::new(method).unwrap(),
                Target::new(target).unwrap(),
                Authority::new(b"a.example").unwrap(),
                &[],
                framing,
                head,
            )
            .unwrap();
        if !body.is_empty() {
            self.client
                .send(&mut self.outbound, &Lease::from(body.to_vec()))
                .unwrap();
        }
        self.client.finish(&mut self.outbound).unwrap();
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
            let (event, turn) = self.client.drive(&mut self.inbound);
            seen.push(match event {
                Some(ClientEvent::Informational(head)) => Seen::Informational(head.head().status().code()),
                Some(ClientEvent::Response(head)) => Seen::Response(head.head().status().code()),
                Some(ClientEvent::Data(data)) => Seen::Data(data.bytes().to_vec()),
                Some(ClientEvent::End(trailers)) => Seen::End(
                    trailers
                        .map(|trailers| {
                            trailers
                                .fields()
                                .flat_map(|field| [field.name(), b": ", field.value(), b"\r\n"].concat())
                                .collect()
                        })
                        .unwrap_or_default(),
                ),
                Some(ClientEvent::Handoff) => Seen::Handoff,
                None => return (seen, turn.progress),
            });
        }
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

fn terminal(progress: &Progress, kind: Kind) -> bool {
    matches!(progress, Progress::Terminal(Err(error)) if error.kind() == kind)
}

/// A client reads a Content-Length body and a chunked body with trailers on one connection. Each
/// request has the Host field first, and the connection carries the next request after each
/// complete response.
#[test]
fn a_client_reads_each_body_and_reuses_the_connection() {
    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    assert_eq!(
        host.drive(),
        (
            vec![
                Seen::Response(200),
                Seen::Data(b"hello".to_vec()),
                Seen::End(Vec::new())
            ],
            WAIT
        )
    );
    host.request(b"POST", b"/b", Framing::Chunked, b"up");
    host.receive(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Sum: 1\r\n\r\n");
    assert_eq!(
        host.drive(),
        (
            vec![
                Seen::Response(201),
                Seen::Data(b"ok".to_vec()),
                Seen::End(b"X-Sum: 1\r\n".to_vec())
            ],
            WAIT
        )
    );
    assert_eq!(
        host.sent(),
        b"GET /a HTTP/1.1\r\nhost: a.example\r\n\r\n\
          POST /b HTTP/1.1\r\nhost: a.example\r\ntransfer-encoding: chunked\r\n\r\n2\r\nup\r\n0\r\n\r\n"
    );
}

/// Informational responses come as their own events before the final response, which then has
/// its body (RFC 9110, section 15.2). A response to HEAD, and a 204 response, have no body.
#[test]
fn informational_responses_come_before_the_final_response_and_some_have_no_body() {
    let mut host = Host::new();
    host.request(b"PUT", b"/a", Framing::Length(2), b"ok");
    host.receive(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n\
          HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    assert_eq!(
        host.drive(),
        (
            vec![
                Seen::Informational(100),
                Seen::Informational(103),
                Seen::Response(200),
                Seen::Data(b"ok".to_vec()),
                Seen::End(Vec::new())
            ],
            WAIT
        )
    );

    host.request(b"HEAD", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    assert_eq!(host.drive(), (vec![Seen::Response(200), Seen::End(Vec::new())], WAIT));
    host.request(b"DELETE", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n");
    assert_eq!(host.drive(), (vec![Seen::Response(204), Seen::End(Vec::new())], WAIT));
}

/// A response with no framing field ends with the close, as an HTTP/1.0 server sends it, and the
/// connection then ends. A close before the end of a Content-Length body is a partial delivery.
/// A close before any response leaves it unknown whether the server processed the request.
#[test]
fn the_close_ends_a_close_delimited_body_and_cuts_any_other() {
    let mut host = Host::new();
    host.request(b"GET", b"/old", Framing::Length(0), b"");
    host.receive(b"HTTP/1.0 200 OK\r\n\r\nhello");
    assert_eq!(
        host.drive(),
        (vec![Seen::Response(200), Seen::Data(b"hello".to_vec())], WAIT)
    );
    host.receive(b" world");
    host.inbound.end();
    assert_eq!(
        host.drive(),
        (
            vec![Seen::Data(b" world".to_vec()), Seen::End(Vec::new())],
            Progress::Terminal(Ok(()))
        )
    );

    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello");
    host.inbound.end();
    let (seen, progress) = host.drive();
    assert_eq!(seen, vec![Seen::Response(200), Seen::Data(b"hello".to_vec())]);
    assert!(terminal(&progress, Kind::Partial), "{progress:?}");

    let mut host = Host::new();
    host.request(b"POST", b"/a", Framing::Length(0), b"");
    host.inbound.end();
    let (seen, progress) = host.drive();
    assert_eq!(seen, Vec::new());
    assert!(terminal(&progress, Kind::Uncertain), "{progress:?}");
}

/// A cancelled response reads and discards the rest of its body, up to the drain limit, and the
/// connection then carries the next request. A body longer than the limit closes the connection
/// at once. A connection that reuses the connection inside an unread body reads the body as a
/// response.
#[test]
fn reuse_after_a_cancelled_response_drains_it_or_closes() {
    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n");
    assert_eq!(
        host.drive(),
        (vec![Seen::Response(200), Seen::Data(b"abc".to_vec())], WAIT)
    );
    host.client.cancel_response();
    host.receive(b"5\r\nhello\r\n0\r\n\r\n");
    assert_eq!(host.drive(), (Vec::new(), WAIT));
    host.request(b"GET", b"/b", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb");
    assert_eq!(
        host.drive(),
        (
            vec![Seen::Response(200), Seen::Data(b"b".to_vec()), Seen::End(Vec::new())],
            WAIT
        )
    );

    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nab");
    host.drive();
    host.client.cancel_response();
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
}

/// A cancelled upload sends no more body bytes and no last chunk, so the server never sees a
/// complete request. The response that came first still arrives, and then the connection closes
/// (RFC 9112, section 9).
#[test]
fn a_cancelled_upload_has_no_end_and_the_connection_closes_after_the_response() {
    let mut host = Host::new();
    let head = Backing::from(Vec::with_capacity(256));
    host.client
        .request(
            &mut host.outbound,
            Method::POST,
            Target::new(b"/up").unwrap(),
            Authority::new(b"a.example").unwrap(),
            &[],
            Framing::Chunked,
            head,
        )
        .unwrap();
    host.client
        .send(&mut host.outbound, &Lease::from(b"abc".to_vec()))
        .unwrap();
    host.receive(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(host.drive(), (vec![Seen::Response(413), Seen::End(Vec::new())], WAIT));
    host.client.cancel_upload();
    assert_eq!(host.drive(), (Vec::new(), Progress::Terminal(Ok(()))));
    assert_eq!(
        host.sent(),
        b"POST /up HTTP/1.1\r\nhost: a.example\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n"
    );
}

/// Bytes that arrive with no request in flight make each later response unclear, for example a
/// 408 that the server sent before it closed, so the connection ends. Conflicting framing in a
/// response refuses.
#[test]
fn unclear_responses_end_the_connection() {
    let mut host = Host::new();
    host.receive(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n");
    let (seen, progress) = host.drive();
    assert_eq!(seen, Vec::new());
    assert!(terminal(&progress, Kind::Malformed), "{progress:?}");

    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n");
    let (seen, progress) = host.drive();
    assert_eq!(seen, Vec::new());
    assert!(terminal(&progress, Kind::Malformed), "{progress:?}");
}

/// A 2xx response to CONNECT, and a 101 response to a request that asked to upgrade, change the
/// protocol. After the request ends, the engine gives the handoff, and the front of the queue is
/// exactly the bytes after the response head, at their address. A 101 to a request that did not
/// ask for it ends the connection.
#[test]
fn a_tunnel_or_an_upgrade_hands_off_exactly_the_bytes_after_the_response_head() {
    let upgrade = [
        rsnetwork::value::Field::new(b"Connection", b"Upgrade").unwrap(),
        rsnetwork::value::Field::new(b"Upgrade", b"websocket").unwrap(),
    ];
    for (method, target, fields, head) in [
        (
            Method::CONNECT,
            &b"b.example:443"[..],
            &[][..],
            &b"HTTP/1.1 200 Connection Established\r\n\r\n"[..],
        ),
        (
            Method::GET,
            b"/chat",
            &upgrade[..],
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        ),
    ] {
        let mut host = Host::new();
        let region = Backing::from(Vec::with_capacity(256));
        host.client
            .request(
                &mut host.outbound,
                method,
                Target::new(target).unwrap(),
                Authority::new(b"b.example:443").unwrap(),
                fields,
                Framing::Length(0),
                region,
            )
            .unwrap();
        host.client.finish(&mut host.outbound).unwrap();
        let received = Lease::from([head, b"\x16\x03\x01new protocol"].concat());
        let after = received.as_ptr().wrapping_add(head.len());
        host.inbound
            .push(Received {
                region: received,
                endpoint: ENDPOINT,
                capacity: 1 << 16,
            })
            .unwrap();
        let (seen, progress) = host.drive();
        assert_eq!(seen[1..], [Seen::Handoff]);
        assert_eq!(progress, Progress::Terminal(Ok(())));
        let front = &host.inbound.front().unwrap().region;
        assert_eq!(
            (front.as_ptr(), front.bytes()),
            (after, &b"\x16\x03\x01new protocol"[..])
        );
    }

    let mut host = Host::new();
    host.request(b"GET", b"/a", Framing::Length(0), b"");
    host.receive(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
    let (_, progress) = host.drive();
    assert!(terminal(&progress, Kind::Malformed), "{progress:?}");
}

/// A response head that continues across received regions, cut at each position, gives the same
/// response and body.
#[test]
fn a_response_head_across_regions_gives_the_same_response() {
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    for cut in 1..RESPONSE.len() - 2 {
        let mut host = Host::new();
        host.request(b"GET", b"/a", Framing::Length(0), b"");
        host.receive(&RESPONSE[..cut]);
        host.receive(&RESPONSE[cut..]);
        assert_eq!(
            host.drive(),
            (
                vec![Seen::Response(200), Seen::Data(b"ok".to_vec()), Seen::End(Vec::new())],
                WAIT
            ),
            "cut at {cut}"
        );
    }
}
