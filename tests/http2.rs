//! The client and the server on HTTP/2, in the caller-driven host: the test moves the bytes of
//! the transport, and it makes the calls of the exchange. The rules of N103 and N104 hold on
//! each stream: one deadline for each exchange, a delivery apart from the finish, a body complete
//! only with its outcome, and a reset that ends a body as reset. HTTP/2 adds its own: a GOAWAY
//! drains the accepted streams and refuses new ones, the cancel of one stream ends only that
//! stream, and a message that breaks RFC 9113, section 8, resets only its stream.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::body::{Collect, Outcome, Part, Read};
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::{Ecn, Endpoint, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2::frame::ErrorCode;
use rsnetwork::h2::{self, Connection, Event, Role};
use rsnetwork::host::{Io, Wait};
use rsnetwork::hpack::{FieldLine, Lines};
use rsnetwork::message::{Stream, Version};
use rsnetwork::server::{Cleartext, Closed, Delivery, Http, Limits, Linger, Response};
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, Entropy, Identity, Limits as TlsLimits, PrivateKeyDer, Resumption,
    ServerConfig, ServerOptions, TimeProvider, UnixTime,
};
use rsnetwork::value::{Authority, Field, Method, Status, Target};

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

/// A request body of at most 1 MiB.
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
    visits: 1 << 12,
};

/// Eight streams at a time, and a header list of at most 4 KiB.
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

const QUEUE: NonZeroUsize = NonZeroUsize::new(16).unwrap();

const SERVER_LIMITS: Limits = Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: QUEUE,
    head_timeout: Some(Duration::from_secs(5)),
    linger: Linger {
        time: Duration::from_secs(1),
        bytes: 1000,
    },
    cleartext: Cleartext::Http2,
};

const CLIENT_LIMITS: client::Limits = client::Limits {
    head: HEAD,
    h2: H2,
    body: BODY,
    turn: TURN,
    queue: QUEUE,
};

const TLS: TlsLimits = TlsLimits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 443),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The size of a DATA frame of the send scheduler: 16,384 bytes.
const FRAME: usize = 1 << 14;

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

fn later() -> Deadline {
    Deadline::at(at(60_000))
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

fn get(target: &'static [u8]) -> Request<'static> {
    Request {
        method: Method::GET,
        target: Target::new(target).unwrap(),
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

/// Gives `bytes` to `connection` as one read-only received region.
fn give(connection: &mut impl Io, bytes: Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    let received = Received {
        region: Lease::from(bytes),
        endpoint: ENDPOINT,
        capacity: 1 << 20,
    };
    assert!(connection.receive(received).is_ok(), "the connection takes the bytes");
}

/// The transport accepts each output of `connection`: gives its bytes.
fn take(connection: &mut impl Io) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(output) = connection.output() {
        bytes.extend_from_slice(output.region.bytes());
        connection.ack(output.id, output.region.initialized()).unwrap();
    }
    bytes
}

/// An HTTP/2 client and server of the core, and the transport between them.
struct Pair {
    client: client::Http2,
    server: Http,
}

impl Pair {
    fn plain() -> Self {
        Self {
            client: client::Http2::plain(CLIENT_LIMITS, clock(), &budget()).unwrap(),
            server: Http::plain(SERVER_LIMITS, clock(), &budget()).unwrap(),
        }
    }

    /// Over TLS: the server offers `h2` and `http/1.1`, and the client `h2`.
    fn tls() -> Self {
        let config = client_config(&[b"h2"]);
        let client = client::Http2::tls(&config, "server.test", (CLIENT_LIMITS, TLS), clock(), &budget()).unwrap();
        let config = server_config(&[b"h2", b"http/1.1"]);
        Self {
            client,
            server: Http::tls(&config, (SERVER_LIMITS, TLS), clock(), &budget()).unwrap(),
        }
    }

    /// The client drives at `now`, as its binding does while it waits, and then the output of
    /// each end moves to the other one time.
    fn transport(&mut self, now: Instant) {
        self.client.drive(now).unwrap();
        let bytes = take(&mut self.client);
        give(&mut self.server, bytes);
        let bytes = take(&mut self.server);
        give(&mut self.client, bytes);
    }

    /// Sends `request` at `now`, with the transport between the tries.
    fn send(&mut self, request: &Request<'_>, deadline: Deadline, now: Instant) -> Stream {
        for _ in 0..16 {
            if let Some(stream) = self.client.send(request, deadline, now).unwrap() {
                return stream;
            }
            self.transport(now);
        }
        panic!("the client did not take the request after 16 tries");
    }

    /// The next request at the server, with the transport between the tries.
    fn request(&mut self, now: Instant) -> (Stream, rsnetwork::message::RequestHead) {
        for _ in 0..16 {
            if let Some(request) = self.server.request(now).unwrap() {
                return request;
            }
            self.transport(now);
        }
        panic!("no request at the server after 16 calls");
    }

    /// The response head of `stream`, with the transport between the tries.
    fn response(
        &mut self,
        stream: Stream,
        now: Instant,
    ) -> Result<rsnetwork::message::ResponseHead, rsnetwork::drive::Error> {
        for _ in 0..16 {
            if let Some(head) = self.client.response(stream, now)? {
                return Ok(head);
            }
            // The server drives at each call, as its binding does.
            assert!(self.server.request(now).unwrap().is_none());
            self.transport(now);
        }
        panic!("no response head after 16 calls");
    }

    /// The response body of `stream`, collected, with the transport between the tries.
    fn collect(&mut self, stream: Stream, now: Instant) -> (Vec<u8>, Collect) {
        let mut region = WriteLoan::new(Vec::with_capacity(1 << 20));
        for _ in 0..64 {
            match self.client.collect(stream, now, &mut region).unwrap() {
                Collect::More => {
                    assert!(self.server.request(now).unwrap().is_none());
                    self.transport(now);
                }
                collect => return (region.filled().to_vec(), collect),
            }
        }
        panic!("the body did not end after 64 calls");
    }

    /// Sends a whole response of `body` to `stream`.
    fn answer(&mut self, stream: Stream, body: &[u8], now: Instant) {
        assert!(self.server.respond(stream, &ok(Some(body.len() as u64)), now).unwrap());
        if !body.is_empty() {
            self.server.write(stream, &Lease::from(body.to_vec()), now).unwrap();
            self.server.finish(stream, now).unwrap();
        }
    }
}

#[cfg(feature = "tower")]
#[test]
fn tower_serves_a_caller_driven_http2_upload_without_a_runtime() {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use rsnetwork::http::{Adapter, Body as _};
    use rsnetwork::tower::{Bytes, dispatch};
    use std::sync::Mutex;

    let now = at(0);
    let mut pair = Pair::plain();
    let upload = pair.send(
        &Request {
            method: Method::POST,
            length: Some(5),
            ..get(b"/echo")
        },
        later(),
        now,
    );
    pair.client
        .write(upload, &Lease::from(b"bytes".as_slice()), now)
        .unwrap();
    pair.client.finish(upload, now).unwrap();
    let (stream, head) = pair.request(now);
    let pair = Arc::new(Mutex::new(pair));
    let source = Arc::clone(&pair);
    let adapter = Adapter::new(HEAD, &budget());
    let request = adapter
        .tower_request(&head, move |_: &mut Context<'_>| {
            let mut pair = source.lock().unwrap();
            match pair.server.next(stream, now)? {
                Some(part) => Poll::Ready(Ok(part)),
                None => Poll::Pending,
            }
        })
        .unwrap();
    let mut app = axum::Router::new().route("/echo", axum::routing::post(|data: Bytes| async move { data }));
    let cx = &mut Context::from_waker(Waker::noop());
    let mut call = pin!(dispatch(&mut app, request));
    let response = (0..16)
        .find_map(|_| match call.as_mut().poll(cx) {
            Poll::Ready(value) => Some(value.unwrap()),
            Poll::Pending => {
                pair.lock().unwrap().transport(now);
                None
            }
        })
        .expect("the uploaded bytes reach the router");
    let mut pair = pair.lock().unwrap();
    let head = adapter.native_response(&response, Some(5)).unwrap();
    assert!(pair.server.respond(stream, &head.head(), now).unwrap());
    drop(head);
    let mut source = pin!(response.into_body());
    let mut body = adapter.tower_body(source.as_mut());
    let Poll::Ready(Ok(Part::Data(bytes))) = pin!(body.next()).poll(cx) else {
        panic!("expected the echo body")
    };
    pair.server.write(stream, &bytes, now).unwrap();
    assert_matches!(
        pin!(body.next()).poll(cx),
        Poll::Ready(Ok(Part::End(Outcome::Complete(None))))
    );
    pair.server.finish(stream, now).unwrap();
    assert_eq!(pair.response(upload, now).unwrap().status().code(), 200);
    assert_matches!(pair.collect(upload, now), (bytes, Collect::Complete(None)) if bytes == b"bytes");
    pair.server.close(stream);
}

#[cfg(feature = "http")]
#[test]
fn http_conversion_mounts_a_caller_driven_http2_handler_over_cleartext_and_tls() {
    use rsnetwork::http::{Adapter, Response};

    let adapter = Adapter::new(HEAD, &budget());
    for (mut pair, scheme) in [(Pair::plain(), "http"), (Pair::tls(), "https")] {
        let now = at(0);
        let client = pair.send(&get(b"/a%2Fb?x=1"), later(), now);
        let (stream, response) = (0..16)
            .find_map(|_| {
                pair.transport(now);
                pair.server
                    .handle_http(&adapter, now, |request| {
                        assert_eq!(request.uri().scheme_str(), Some(scheme));
                        assert_eq!(request.uri().authority().unwrap().as_str(), "server.test");
                        assert_eq!(request.uri().path_and_query().unwrap().as_str(), "/a%2Fb?x=1");
                        Response::builder().status(202).body(()).unwrap()
                    })
                    .unwrap()
            })
            .expect("the handler receives the HTTP/2 request");
        let view = adapter.native_response(&response, Some(0)).unwrap();
        assert!(pair.server.respond(stream, &view.head(), now).unwrap());
        assert_eq!(pair.response(client, now).unwrap().status().code(), 202);
        assert_matches!(pair.collect(client, now), (bytes, Collect::Complete(None)) if bytes.is_empty());
        pair.server.close(stream);
    }
}

#[test]
fn a_complete_delivery_needs_each_byte_and_a_reset_after_the_finish_makes_it_partial() {
    // Over TCP, the count is exact: each DATA payload byte that the transport accepted.
    let mut pair = Pair::plain();
    let a = pair.send(&get(b"/a"), later(), at(0));
    let (stream, head) = pair.request(at(0));
    assert_eq!(head.version(), Version::Http2);
    assert_eq!(head.target().as_bytes(), b"/a");
    pair.answer(stream, b"hello", at(0));
    pair.transport(at(0));
    assert_eq!(pair.server.delivery(stream), Some(Delivery::Complete { accepted: 5 }));
    assert_eq!(pair.response(a, at(0)).unwrap().status(), Status::new(200).unwrap());
    assert_matches!(pair.collect(a, at(0)), (body, Collect::Complete(None)) if body == b"hello");
    pair.server.close(stream);

    // Three frames of 16,384 bytes. The transport accepts the head and 20,000 bytes of the body.
    pair.send(&get(b"/b"), later(), at(0));
    let (stream, _) = pair.request(at(0));
    let length = 3 * FRAME as u64;
    assert!(pair.server.respond(stream, &ok(Some(length)), at(0)).unwrap());
    for _ in 0..3 {
        let part = Lease::from(vec![b'x'; FRAME]);
        while pair.server.write(stream, &part, at(0)).is_err() {
            assert!(pair.server.request(at(0)).unwrap().is_none());
        }
    }
    pair.server.finish(stream, at(0)).unwrap();
    assert_eq!(
        pair.server.delivery(stream),
        Some(Delivery::Sending {
            finished: true,
            accepted: 0
        })
    );
    let mut payload = 20_000;
    while let Some(output) = pair.server.output() {
        let len = output.region.initialized();
        // A frame header has 9 bytes, and each DATA payload of the body has 16,384.
        let accepted = if len == FRAME { len.min(payload) } else { len };
        if len == FRAME {
            payload -= accepted;
        }
        pair.server.ack(output.id, accepted).unwrap();
        if accepted < len {
            break;
        }
    }
    assert_eq!(
        pair.server.delivery(stream),
        Some(Delivery::Sending {
            finished: true,
            accepted: 20_000
        })
    );
    pair.server.reset();
    assert_matches!(
        pair.server.delivery(stream),
        Some(Delivery::Partial { finished: true, accepted: 20_000, error }) if error.kind() == Kind::Partial
    );
}

/// The wrong implementation that this test catches: a server that resets its accepted streams at
/// the GOAWAY, so the response in flight never completes.
#[test]
fn a_goaway_drains_the_accepted_streams_and_refuses_new_ones() {
    for mut pair in [Pair::plain(), Pair::tls()] {
        let a = pair.send(&get(b"/a"), later(), at(0));
        let b = pair.send(&get(b"/b"), later(), at(0));
        // The server takes the first request. The second one arrives, and the application does
        // not see it.
        let (stream, head) = pair.request(at(0));
        assert_eq!(head.target().as_bytes(), b"/a");
        pair.server.shutdown(Deadline::at(at(1_000)), at(0)).unwrap();
        for _ in 0..4 {
            assert!(
                pair.server.request(at(0)).unwrap().is_none(),
                "no request after the shutdown"
            );
            pair.transport(at(0));
            let _ = pair.client.response(a, at(0)).unwrap();
        }
        // The client learns at once that the server did not process the second request.
        assert_matches!(pair.client.response(b, at(0)), Err(error) if error.kind() == Kind::Overload);
        assert_matches!(pair.client.send(&get(b"/c"), later(), at(0)), Err(error) if error.kind() == Kind::Misuse);
        // The first request drains: its response completes after the GOAWAY.
        pair.answer(stream, b"drained", at(0));
        assert_eq!(pair.response(a, at(0)).unwrap().status(), Status::new(200).unwrap());
        assert_matches!(pair.collect(a, at(0)), (body, Collect::Complete(None)) if body == b"drained");
        assert_eq!(pair.server.delivery(stream), Some(Delivery::Complete { accepted: 7 }));
        pair.server.close(stream);
        // With no stream left, the server ends, and then it lingers until the end of input.
        for _ in 0..4 {
            assert!(pair.server.request(at(0)).unwrap().is_none());
            pair.transport(at(0));
        }
        assert_matches!(pair.server.wait(), Wait::Linger { .. });
        pair.server.end_input();
        assert_eq!(
            pair.server.release(),
            Some(Closed {
                result: Ok(()),
                cleanup: None
            })
        );
    }
}

#[test]
fn the_cancel_of_one_stream_resets_it_and_the_connection_carries_the_others() {
    let mut pair = Pair::plain();
    let post = Request {
        method: Method::POST,
        length: None,
        ..get(b"/upload")
    };
    let a = pair.send(&post, later(), at(0));
    let b = pair.send(&get(b"/b"), later(), at(0));
    let (upload, _) = pair.request(at(0));
    let (stream, _) = pair.request(at(0));
    // The client cancels its upload: the server reads the reset of the stream.
    pair.client.cancel(a);
    pair.transport(at(0));
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
    assert_matches!(
        pair.server.read_into(upload, at(0), &mut region).unwrap(),
        Read::Done(Outcome::Reset(Some(code))) if *code == u64::from(ErrorCode::CANCEL.0)
    );
    assert_matches!(pair.server.respond(upload, &ok(Some(0)), at(0)), Err(error) if error.kind() == Kind::Partial);
    pair.server.close(upload);
    // The server cancels its response after a part of its body: the client reads a reset body.
    assert!(pair.server.respond(stream, &ok(None), at(0)).unwrap());
    pair.server.write(stream, &Lease::from(&b"part"[..]), at(0)).unwrap();
    pair.transport(at(0));
    pair.server.cancel(stream);
    pair.server.close(stream);
    pair.response(b, at(0)).unwrap();
    let mut parts = Vec::new();
    let outcome = loop {
        match pair.client.next(b, at(0)).unwrap() {
            Some(Part::Data(data)) => parts.extend_from_slice(data.bytes()),
            Some(Part::End(outcome)) => break outcome,
            None => {
                assert!(pair.server.request(at(0)).unwrap().is_none());
                pair.transport(at(0));
            }
        }
    };
    assert_eq!(parts, b"part");
    assert_matches!(outcome, Outcome::Reset(Some(code)) if code == u64::from(ErrorCode::CANCEL.0));
    // The connection carries the next exchange.
    let c = pair.send(&get(b"/c"), later(), at(0));
    let (stream, _) = pair.request(at(0));
    pair.answer(stream, b"three", at(0));
    pair.response(c, at(0)).unwrap();
    assert_matches!(pair.collect(c, at(0)), (body, Collect::Complete(None)) if body == b"three");
}

#[test]
fn a_read_goes_on_when_its_drive_removes_a_stream_that_the_application_left() {
    let mut pair = Pair::plain();
    let a = pair.send(&get(b"/a"), later(), at(0));
    let b = pair.send(&get(b"/b"), later(), at(0));
    pair.request(at(0));
    let (second, _) = pair.request(at(0));
    // The second stream has its response head, and waits for its body.
    assert!(pair.server.respond(second, &ok(Some(5)), at(0)).unwrap());
    pair.response(b, at(0)).unwrap();
    // The application leaves the first stream: the next drive of the client removes it. The
    // body of the second stream arrives for that same drive.
    pair.client.cancel(a);
    pair.server.write(second, &Lease::from(&b"three"[..]), at(0)).unwrap();
    pair.server.finish(second, at(0)).unwrap();
    let bytes = take(&mut pair.server);
    give(&mut pair.client, bytes);
    assert_matches!(pair.collect(b, at(0)), (body, Collect::Complete(None)) if body == b"three");
}

#[test]
fn a_left_stream_whose_credit_finds_a_full_output_waits_and_its_credit_goes_back_later() {
    // The least connection window, so the credit of an unread body of 40,000 bytes is due at its
    // removal. An output of three places, the least, which requests fill.
    let limits = client::Limits {
        h2: h2::Limits {
            connection_window: 65_535,
            ..H2
        },
        queue: NonZeroUsize::new(3).unwrap(),
        ..CLIENT_LIMITS
    };
    let mut pair = Pair {
        client: client::Http2::plain(limits, clock(), &budget()).unwrap(),
        server: Http::plain(SERVER_LIMITS, clock(), &budget()).unwrap(),
    };
    let a = pair.send(&get(b"/a"), later(), at(0));
    let (stream, _) = pair.request(at(0));
    pair.answer(stream, &[7; 40_000], at(0));
    pair.response(a, at(0)).unwrap();
    pair.server.close(stream);
    let b = pair.send(&get(b"/b"), later(), at(0));
    let mut sent = 0;
    while pair.client.send(&get(b"/c"), later(), at(0)).unwrap().is_some() {
        sent += 1;
        assert!(sent < 3, "the output has three places");
    }
    // The answer to a PING of the server takes the last place.
    let ping = [0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    give(&mut pair.client, [ping, ping].concat());
    pair.client.drive(at(0)).unwrap();
    // The application leaves the first stream with its body unread. The drive cannot send the
    // credit of that body, so it keeps the stream and returns.
    pair.client.cancel(a);
    pair.client.drive(at(0)).unwrap();
    // The output drains, and the next drive sends the credit. The server sends a body as large as
    // the connection window, and the client takes each byte of it before it reads one.
    pair.transport(at(0));
    let (stream, _) = pair.request(at(0));
    for _ in 0..sent {
        pair.request(at(0));
    }
    pair.answer(stream, &[9; 65_535], at(0));
    pair.response(b, at(0)).unwrap();
    // Only the output of the server moves, so no read of the client gives credit.
    for _ in 0..4 {
        assert!(pair.server.request(at(0)).unwrap().is_none());
        let bytes = take(&mut pair.server);
        give(&mut pair.client, bytes);
    }
    let mut region = WriteLoan::new(Vec::with_capacity(1 << 16));
    assert_matches!(
        pair.client.collect(b, at(0), &mut region).unwrap(),
        Collect::Complete(None)
    );
    assert_eq!(region.filled().len(), 65_535);
}

#[test]
fn a_write_goes_on_when_its_wait_for_the_chunk_before_removes_a_stream_that_the_server_closed() {
    let mut pair = Pair::plain();
    let a = pair.send(&get(b"/a"), later(), at(0));
    let b = pair.send(&get(b"/b"), later(), at(0));
    let (first, _) = pair.request(at(0));
    let (second, _) = pair.request(at(0));
    // The first chunk of the second stream is one byte larger than the window of the stream.
    let chunk = vec![7; 4 * FRAME];
    assert!(
        pair.server
            .respond(second, &ok(Some(chunk.len() as u64 + 1)), at(0))
            .unwrap()
    );
    pair.server.write(second, &Lease::from(chunk.clone()), at(0)).unwrap();
    // The client reads the whole answer of the first stream, and then the server leaves it.
    pair.answer(first, b"one", at(0));
    pair.response(a, at(0)).unwrap();
    assert_matches!(pair.collect(a, at(0)), (body, Collect::Complete(None)) if body == b"one");
    pair.server.close(first);
    // The wait for the chunk before drives, and that drive removes the first stream.
    let last = Lease::from(&b"!"[..]);
    assert_matches!(pair.server.write(second, &last, at(0)), Err(error) if error.kind() == Kind::Overload);
    pair.response(b, at(0)).unwrap();
    let mut region = WriteLoan::new(Vec::with_capacity(chunk.len() + 1));
    for _ in 0..16 {
        match pair.client.collect(b, at(0), &mut region).unwrap() {
            Collect::More => {}
            other => panic!("the body ends after its last byte: {other:?}"),
        }
        if pair.server.write(second, &last, at(0)).is_ok() {
            break;
        }
        pair.transport(at(0));
    }
    pair.server.finish(second, at(0)).unwrap();
    pair.transport(at(0));
    assert_matches!(
        pair.client.collect(b, at(0), &mut region).unwrap(),
        Collect::Complete(None)
    );
    assert_eq!(region.filled(), [chunk.as_slice(), b"!"].concat());
}

#[test]
fn an_early_http2_response_leaves_only_the_lifetime_on_the_unfinished_upload() {
    let mut pair = Pair::plain();
    let op = client::Operation::new(Deadline::at(at(100)), NonZeroUsize::MIN)
        .with_body_idle(Duration::from_millis(20))
        .unwrap();
    let request = Request {
        method: Method::POST,
        length: Some(2),
        ..get(b"/upload")
    };
    let stream = pair.client.send(&request, &op, at(0)).unwrap().unwrap();
    let (server, _) = pair.request(at(10));
    pair.answer(server, b"", at(10));
    pair.response(stream, at(10)).unwrap();
    assert_matches!(pair.collect(stream, at(10)).1, Collect::Complete(None));
    let byte = Lease::from(&b"x"[..]);
    pair.client.write(stream, &byte, at(40)).unwrap();
    let error = pair.client.write(stream, &byte, at(100)).unwrap_err();
    assert_eq!(
        (error.kind(), error.reason()),
        (Kind::Deadline, "the deadline came before the end of the request")
    );
}

#[test]
fn a_slow_body_meets_its_deadline_on_its_stream_and_the_connection_goes_on() {
    let mut pair = Pair::plain();
    let slow = pair.send(&get(b"/slow"), Deadline::at(at(1_000)), at(0));
    let quick = pair.send(&get(b"/quick"), later(), at(0));
    let (first, _) = pair.request(at(0));
    let (second, _) = pair.request(at(0));
    assert!(pair.server.respond(first, &ok(Some(10)), at(0)).unwrap());
    pair.server.write(first, &Lease::from(&b"four"[..]), at(0)).unwrap();
    pair.transport(at(0));
    pair.response(slow, at(0)).unwrap();
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
    assert_matches!(
        pair.client.read_into(slow, at(999), &mut region).unwrap(),
        Read::Bytes(4)
    );
    // The deadline covers each byte of the body: the stream ends, with its partial progress.
    assert_matches!(pair.client.read_into(slow, at(1_000), &mut region), Err(error) if error.kind() == Kind::Deadline);
    assert_eq!(pair.client.delivered(slow), 4);
    pair.client.cancel(slow);
    // The server learns the end of the stream, and the other stream completes.
    pair.answer(second, b"ok", at(1_000));
    pair.transport(at(1_000));
    assert!(pair.server.request(at(1_000)).unwrap().is_none());
    assert_matches!(
        pair.server.write(first, &Lease::from(&b"rest"[..]), at(1_000)),
        Err(error) if error.kind() == Kind::Partial
    );
    pair.response(quick, at(1_000)).unwrap();
    assert_matches!(pair.collect(quick, at(1_000)), (body, Collect::Complete(None)) if body == b"ok");
}

#[test]
fn a_deadline_resets_its_stream_at_the_next_drive_also_with_no_call_of_its_own() {
    let mut pair = Pair::plain();
    let slow = pair.send(&get(b"/slow"), Deadline::at(at(1_000)), at(0));
    let quick = pair.send(&get(b"/quick"), Deadline::at(at(5_000)), at(0));
    let (first, _) = pair.request(at(0));
    pair.request(at(0));
    pair.client.changed(drop);
    // The host drives the idle client at the deadline, and calls no exchange.
    pair.client.drive(at(1_000)).unwrap();
    let mut changed = Vec::new();
    pair.client.changed(|stream| changed.push(stream));
    assert_eq!(changed, [slow]);
    // The next wait is the deadline of the other stream, so a host that waits as it says does
    // not wake again at once.
    assert_matches!(
        pair.client.wait(),
        Wait::Until { deadline: Some(deadline), .. } if deadline == Deadline::at(at(5_000))
    );
    assert_matches!(pair.client.response(slow, at(1_000)), Err(error) if error.kind() == Kind::Deadline);
    // The reset reached the server, and the other stream goes on.
    pair.transport(at(1_000));
    assert!(pair.server.request(at(1_000)).unwrap().is_none());
    assert_matches!(
        pair.server.respond(first, &ok(Some(2)), at(1_000)),
        Err(error) if error.kind() == Kind::Partial
    );
    assert!(pair.client.response(quick, at(1_000)).unwrap().is_none());
}

#[test]
fn over_tls_the_deadline_covers_the_handshake() {
    let config = client_config(&[b"h2"]);
    let mut client = client::Http2::tls(&config, "server.test", (CLIENT_LIMITS, TLS), clock(), &budget()).unwrap();
    let stream = client.send(&get(b"/"), Deadline::at(at(100)), at(0)).unwrap().unwrap();
    assert!(client.response(stream, at(99)).unwrap().is_none());
    assert_matches!(client.response(stream, at(100)), Err(error) if error.kind() == Kind::Deadline);
}

#[test]
fn over_tls_a_server_that_selects_http_1_1_ends_an_http2_client() {
    let config = client_config(&[b"h2", b"http/1.1"]);
    let mut client = client::Http2::tls(&config, "server.test", (CLIENT_LIMITS, TLS), clock(), &budget()).unwrap();
    let config = server_config(&[b"http/1.1"]);
    let mut server = Http::tls(&config, (SERVER_LIMITS, TLS), clock(), &budget()).unwrap();
    let stream = client.send(&get(b"/"), later(), at(0)).unwrap().unwrap();
    let mut end = None;
    for _ in 0..8 {
        let bytes = take(&mut client);
        give(&mut server, bytes);
        // The server ends at the first byte of the client after the handshake.
        if server.request(at(0)).is_err() {
            break;
        }
        let bytes = take(&mut server);
        give(&mut client, bytes);
        if let Err(error) = client.response(stream, at(0)) {
            end = Some(error);
            break;
        }
    }
    assert_matches!(end, Some(error) if error.kind() == Kind::Unsupported);
    take(&mut client);
    assert_matches!(client.release(), Some(Err(error)) if error.kind() == Kind::Unsupported);
}

#[test]
fn a_close_after_the_exchange_sends_goaway_and_releases_both_ends() {
    let mut pair = Pair::tls();
    let a = pair.send(&get(b"/"), later(), at(0));
    let (stream, _) = pair.request(at(0));
    pair.answer(stream, b"done", at(0));
    pair.response(a, at(0)).unwrap();
    assert_matches!(pair.collect(a, at(0)), (body, Collect::Complete(None)) if body == b"done");
    pair.server.close(stream);
    pair.client.close(at(0)).unwrap();
    for _ in 0..4 {
        assert!(pair.server.request(at(0)).unwrap().is_none());
        pair.transport(at(0));
    }
    assert_eq!(pair.client.release(), Some(Ok(())));
    // The GOAWAY of the client ends the server with no error, and the server lingers.
    assert_matches!(pair.server.wait(), Wait::Linger { .. });
    pair.server.end_input();
    assert_eq!(pair.server.release().map(|closed| closed.result), Some(Ok(())));
}

#[test]
fn a_reset_of_the_transport_ends_each_body_in_flight_as_reset_not_complete() {
    let mut pair = Pair::plain();
    let post = Request {
        method: Method::POST,
        length: Some(10),
        ..get(b"/upload")
    };
    let a = pair.send(&post, later(), at(0));
    pair.client.write(a, &Lease::from(&b"four"[..]), at(0)).unwrap();
    let (stream, _) = pair.request(at(0));
    assert!(pair.server.respond(stream, &ok(Some(10)), at(0)).unwrap());
    pair.server.write(stream, &Lease::from(&b"half"[..]), at(0)).unwrap();
    pair.transport(at(0));
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
    assert_matches!(
        pair.server.read_into(stream, at(0), &mut region).unwrap(),
        Read::Bytes(4)
    );
    pair.response(a, at(0)).unwrap();
    assert_matches!(pair.client.next(a, at(0)).unwrap(), Some(Part::Data(data)) if data.bytes() == b"half");
    // Each end sees its transport fail.
    pair.server.reset();
    pair.client.reset();
    assert_matches!(
        pair.server.read_into(stream, at(0), &mut region).unwrap(),
        Read::Done(Outcome::Reset(None))
    );
    assert_matches!(
        pair.client.next(a, at(0)).unwrap(),
        Some(Part::End(Outcome::Reset(None)))
    );
    assert_matches!(pair.server.release(), Some(Closed { result: Err(error), .. }) if error.kind() == Kind::Partial);
}

#[test]
fn a_response_before_the_end_of_the_request_body_leaves_the_client_working() {
    let mut pair = Pair::tls();
    let post = Request {
        method: Method::POST,
        length: Some(9),
        ..get(b"/upload")
    };
    let a = pair.send(&post, later(), at(0));
    let (stream, _) = pair.request(at(0));
    // The server answers at the request head, before the body.
    pair.answer(stream, b"onetwosix", at(0));
    for part in [b"abc", b"def", b"ghi"] {
        pair.transport(at(0));
        while pair.client.write(a, &Lease::from(&part[..]), at(0)).is_err() {
            pair.transport(at(0));
        }
    }
    pair.client.finish(a, at(0)).unwrap();
    pair.response(a, at(0)).unwrap();
    assert_matches!(pair.collect(a, at(0)), (body, Collect::Complete(None)) if body == b"onetwosix");
    // The request body reached the server too.
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
    loop {
        match pair.server.collect(stream, at(0), &mut region).unwrap() {
            Collect::More => pair.transport(at(0)),
            collect => {
                assert_matches!(collect, Collect::Complete(None));
                break;
            }
        }
    }
    assert_eq!(region.filled(), b"abcdefghi");
}

#[test]
fn a_connection_with_no_stream_for_the_head_timeout_closes_with_goaway() {
    let mut pair = Pair::plain();
    let a = pair.send(&get(b"/"), later(), at(0));
    let (stream, _) = pair.request(at(0));
    pair.answer(stream, b"ok", at(0));
    pair.server.close(stream);
    pair.transport(at(0));
    pair.response(a, at(0)).unwrap();
    pair.collect(a, at(0));
    // The idle time starts when the last stream ends.
    assert!(pair.server.request(at(1_000)).unwrap().is_none());
    assert!(pair.server.request(at(5_999)).unwrap().is_none());
    pair.transport(at(5_999));
    assert!(
        pair.client.send(&get(b"/"), later(), at(5_999)).unwrap().is_some(),
        "the connection is open"
    );
    let mut pair = Pair::plain();
    assert!(pair.server.request(at(0)).unwrap().is_none());
    assert!(pair.server.request(at(5_000)).unwrap().is_none());
    pair.transport(at(5_000));
    // The client learns of the GOAWAY, and takes no more requests.
    assert_matches!(pair.client.send(&get(b"/"), later(), at(5_000)), Err(error) if error.kind() == Kind::Misuse);
}

/// A raw HTTP/2 client: the engine of the core, which sends any field lines.
struct Raw {
    connection: Connection,
    inbound: Inbound,
    outbound: Outbound,
    lines: Lines,
}

/// What a raw client saw on a stream.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Status(u32, Vec<u8>),
    Reset(u32, ErrorCode),
}

impl Raw {
    fn new(role: Role) -> Self {
        let budget = budget();
        let inbound = Inbound::new(QUEUE, &budget).unwrap();
        let mut outbound = Outbound::new(QUEUE, &budget).unwrap();
        let connection = Connection::new(role, H2, TURN, &mut outbound, &budget).unwrap();
        let lines = Lines::new(connection.header_limits(), &budget).unwrap();
        Self {
            connection,
            inbound,
            outbound,
            lines,
        }
    }

    /// Opens a stream with `lines`, and gives it.
    fn open(&mut self, lines: &[(&[u8], &[u8])], end_stream: bool) -> u32 {
        let lines = lines.iter().map(|&(name, value)| FieldLine {
            name,
            value,
            never_indexed: false,
        });
        let region = Backing::from(Vec::with_capacity(16 * 1024));
        self.connection
            .open(&mut self.outbound, lines, end_stream, region)
            .unwrap()
    }

    fn output(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(output) = self.outbound.submit() {
            bytes.extend_from_slice(output.region.bytes());
            self.outbound.ack(output.id, output.region.initialized()).unwrap();
        }
        bytes
    }

    /// Takes `bytes`, and drives until no event comes. Gives the status of each response and each
    /// reset.
    fn input(&mut self, bytes: Vec<u8>) -> Vec<Seen> {
        if !bytes.is_empty() {
            let received = Received {
                region: Lease::from(bytes),
                endpoint: ENDPOINT,
                capacity: 1 << 20,
            };
            self.inbound.push(received).unwrap();
        }
        let mut seen = Vec::new();
        for _ in 0..64 {
            let (event, _) = self
                .connection
                .drive(&mut self.inbound, &mut self.outbound, &mut self.lines, Some(at(0)));
            match event {
                Some(Event::Headers {
                    stream,
                    lines: Some(block),
                    ..
                }) => {
                    let status = block.lines().find(|line| line.name == b":status");
                    seen.push(Seen::Status(
                        stream,
                        status.map(|line| line.value.to_vec()).unwrap_or_default(),
                    ));
                }
                Some(Event::Reset { stream, code }) => {
                    seen.push(Seen::Reset(stream, code));
                    self.connection.close(stream).unwrap();
                }
                Some(_) => {}
                None => break,
            }
        }
        seen
    }
}

/// The field lines of a section, each a name and a value.
type Section = Vec<(&'static [u8], &'static [u8])>;

/// A request section of each field line of RFC 9113, section 8.3.1, and then `fields`.
fn request(fields: &[(&'static [u8], &'static [u8])]) -> Vec<(&'static [u8], &'static [u8])> {
    let mut lines: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"server.test"),
        (b":path", b"/"),
    ];
    lines.extend_from_slice(fields);
    lines
}

/// The check of each rule of RFC 9113, section 8, is in the unit tests of `h2::message`. This
/// test shows what the connection does with a request that breaks one: it resets or answers only
/// its stream, and the application never sees it.
#[test]
fn a_request_that_breaks_rfc_9113_section_8_resets_only_its_stream() {
    let protocol = ErrorCode::PROTOCOL_ERROR;
    let long = vec![b'v'; 4096].leak();
    let cases: Vec<(&str, Section, Seen)> = vec![
        (
            "a connection field",
            request(&[(b"connection", b"keep-alive")]),
            Seen::Reset(0, protocol),
        ),
        (
            "a pseudo-header after a field",
            vec![
                (b":method", b"GET"),
                (b"accept", b"x"),
                (b":scheme", b"https"),
                (b":path", b"/"),
                (b":authority", b"a"),
            ],
            Seen::Reset(0, protocol),
        ),
        (
            "a header list past its limit",
            request(&[(b"x-long", long)]),
            Seen::Status(0, b"431".to_vec()),
        ),
        (
            "a content-length past the body limit",
            request(&[(b"content-length", b"2000000")]),
            Seen::Status(0, b"413".to_vec()),
        ),
    ];
    let mut raw = Raw::new(Role::Client);
    let mut server = Http::plain(SERVER_LIMITS, clock(), &budget()).unwrap();
    give(&mut server, raw.output());
    assert!(server.request(at(0)).unwrap().is_none());
    raw.input(take(&mut server));
    for (case, lines, expected) in cases {
        let stream = raw.open(&lines, true);
        give(&mut server, raw.output());
        assert!(
            server.request(at(0)).unwrap().is_none(),
            "{case}: the application never sees it"
        );
        let mut seen = raw.input(take(&mut server));
        assert!(server.request(at(0)).unwrap().is_none(), "{case}");
        seen.extend(raw.input(take(&mut server)));
        let expected = match expected {
            Seen::Reset(_, code) => Seen::Reset(stream, code),
            Seen::Status(_, status) => Seen::Status(stream, status),
        };
        assert!(seen.contains(&expected), "{case}: {seen:?}");
    }
    // A valid head goes up, and a body past its `content-length` is malformed: only its stream
    // resets.
    let stream = raw.open(&request(&[(b"content-length", b"2")]), false);
    raw.connection
        .data(&mut raw.outbound, stream, Lease::from(&b"three"[..]), true)
        .unwrap();
    raw.input(Vec::new());
    give(&mut server, raw.output());
    let (upload, _) = server.request(at(0)).unwrap().expect("a valid head");
    let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
    assert_matches!(
        server.read_into(upload, at(0), &mut region).unwrap(),
        Read::Done(Outcome::Malformed)
    );
    assert!(server.request(at(0)).unwrap().is_none());
    assert!(raw.input(take(&mut server)).contains(&Seen::Reset(stream, protocol)));
    server.close(upload);
    // The connection goes on: a request that RFC 9113 permits goes up.
    raw.open(&request(&[(b"accept", b"text/plain"), (b"te", b"trailers")]), true);
    give(&mut server, raw.output());
    let (_, head) = server.request(at(0)).unwrap().expect("the connection goes on");
    let fields: Vec<_> = head
        .fields()
        .map(|field| (field.name().to_vec(), field.value().to_vec()))
        .collect();
    assert_eq!(
        fields,
        [
            (b"accept".to_vec(), b"text/plain".to_vec()),
            (b"te".to_vec(), b"trailers".to_vec())
        ]
    );
}

#[test]
fn the_client_learns_which_requests_the_server_did_not_process_and_refuses_a_malformed_response() {
    let mut raw = Raw::new(Role::Server);
    let mut client = client::Http2::plain(CLIENT_LIMITS, clock(), &budget()).unwrap();
    let mut streams = Vec::new();
    for target in [&b"/0"[..], b"/1", b"/2", b"/3"] {
        streams.push(client.send(&get(target), later(), at(0)).unwrap().unwrap());
        // The request heads go: their regions come back.
        raw.input(take(&mut client));
    }
    let id = |stream: Stream| u32::try_from(stream.id()).unwrap();
    let respond = |raw: &mut Raw, stream: u32, lines: &[(&[u8], &[u8])], end_stream: bool| {
        let lines = lines.iter().map(|&(name, value)| FieldLine {
            name,
            value,
            never_indexed: false,
        });
        let region = Backing::from(Vec::with_capacity(1024));
        raw.connection
            .headers(&mut raw.outbound, stream, lines, end_stream, region)
            .unwrap();
    };
    // A connection-specific field, and a body past its `content-length`.
    respond(
        &mut raw,
        id(streams[0]),
        &[(b":status", b"200"), (b"connection", b"close")],
        true,
    );
    respond(
        &mut raw,
        id(streams[1]),
        &[(b":status", b"200"), (b"content-length", b"2")],
        false,
    );
    raw.connection
        .data(&mut raw.outbound, id(streams[1]), Lease::from(&b"three"[..]), true)
        .unwrap();
    raw.input(Vec::new());
    // A stream that the server refuses, and a GOAWAY whose last stream is below the last one.
    // The engine of a server refuses no stream that went up to it, so the frame is written here.
    let mut bytes = raw.output();
    bytes.extend_from_slice(&[0, 0, 4, 0x3, 0]);
    bytes.extend_from_slice(&id(streams[2]).to_be_bytes());
    bytes.extend_from_slice(&ErrorCode::REFUSED_STREAM.0.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 8, 0x7, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&id(streams[2]).to_be_bytes());
    bytes.extend_from_slice(&ErrorCode::NO_ERROR.0.to_be_bytes());
    give(&mut client, bytes);
    assert_matches!(client.response(streams[0], at(0)), Err(error) if error.kind() == Kind::Malformed);
    client
        .response(streams[1], at(0))
        .unwrap()
        .expect("the head of the second response");
    let mut region = WriteLoan::new(Vec::with_capacity(64));
    assert_matches!(
        client.collect(streams[1], at(0), &mut region).unwrap(),
        Collect::Interrupted(Outcome::Malformed)
    );
    assert_matches!(client.response(streams[2], at(0)), Err(error) if error.kind() == Kind::Overload);
    assert_matches!(client.response(streams[3], at(0)), Err(error) if error.kind() == Kind::Overload);
    assert_matches!(client.send(&get(b"/4"), later(), at(0)), Err(error) if error.kind() == Kind::Misuse);
    let field = Field::new(b"connection", b"close").unwrap();
    let fields = [field];
    let request = Request {
        fields: &fields,
        ..get(b"/5")
    };
    assert_matches!(client.send(&request, later(), at(0)), Err(error) if error.kind() == Kind::Misuse);
}
