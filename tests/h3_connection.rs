//! The HTTP/3 connection exchanges encrypted QUIC datagrams with an HTTP engine or a wire peer.
#![cfg(feature = "tls")]

mod counting;
#[expect(dead_code, reason = "the QUIC suites share the path and its impairment profiles")]
mod quic_path;

use core::mem;
use std::assert_matches;

use quic_path::{Pair, Received, Setup, budget, driven_at, give_at, ms, sent_at};
use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Kind, TurnLimits};
use rsnetwork::h3::{self, Code, Event, Step};
use rsnetwork::message::Version;
use rsnetwork::qpack::FieldLine;
use rsnetwork::quic::{self, PeerClose, StreamId, frame::Direction};
use rsnetwork::time::Instant;

struct Peer {
    quic: quic::Connection,
    http: Option<h3::Connection>,
    events: Vec<Event>,
    budget: Budget,
    wire: Received,
}

impl Peer {
    fn new(quic: quic::Connection, limits: Option<h3::Limits>) -> Self {
        let budget = budget();
        Self {
            http: limits.map(|limits| h3::Connection::new(&quic, limits, &budget).unwrap()),
            budget,
            quic,
            events: Vec::new(),
            wire: Received::default(),
        }
    }
    fn drive(&mut self, events: Vec<quic::Event>, at: Instant) -> Result<(), h3::Error> {
        let Some(h) = &mut self.http else {
            self.wire.take(&mut self.quic, events, |_| true);
            return Ok(());
        };
        for mut event in events.into_iter().map(Some).chain([None]) {
            for turn in 0..8192 {
                match h.drive(&mut self.quic, &mut event, at)? {
                    Step::Again => {}
                    Step::Event(e) => self.events.push(e),
                    Step::Wait => {
                        assert!(event.is_none());
                        break;
                    }
                }
                assert!(turn < 8191, "HTTP/3 must reach a wait");
            }
        }
        Ok(())
    }
    fn request(&mut self) -> StreamId {
        let h = self.http.as_mut().unwrap();
        let id = h.open(&mut self.quic).unwrap().unwrap();
        h.headers(
            id,
            &[
                field(b":method", b"GET"),
                field(b":scheme", b"https"),
                field(b":authority", b"server.test"),
                field(b":path", b"/"),
            ],
            true,
        )
        .unwrap();
        id
    }
    fn headers(&mut self, id: StreamId, lines: &[FieldLine<'_>], end: bool) {
        self.http.as_mut().unwrap().headers(id, lines, end).unwrap();
    }
    fn raw(&mut self, id: StreamId, data: &'static [u8], end: bool) {
        self.quic.send(id, Lease::from(data), end).unwrap();
    }
    fn stream(&mut self, dir: Direction, data: &'static [u8], end: bool) -> StreamId {
        let id = self.quic.open(dir).unwrap().unwrap();
        self.raw(id, data, end);
        id
    }
}

fn field<'a>(name: &'a [u8], value: &'a [u8]) -> FieldLine<'a> {
    FieldLine {
        name,
        value,
        never_indexed: false,
    }
}

struct Network {
    client: Peer,
    server: Peer,
    ticks: u64,
}
impl Network {
    fn new(client: bool, server: bool) -> Self {
        Self::with(Setup::default(), client, server)
    }
    fn with(setup: Setup, client: bool, server: bool) -> Self {
        Self::configured(
            setup,
            client.then(h3::Limits::default),
            server.then(h3::Limits::default),
        )
    }
    fn configured(setup: Setup, client: Option<h3::Limits>, server: Option<h3::Limits>) -> Self {
        let pair = Pair::build(setup, usize::MAX, b"h3");
        let mut n = Self {
            client: Peer::new(pair.client, client),
            server: Peer::new(pair.server, server),
            ticks: 0,
        };
        n.pump().unwrap();
        n
    }
    fn pump(&mut self) -> Result<(), h3::Error> {
        self.ticks += 30;
        let at = ms(self.ticks);
        for _ in 0..512 {
            for p in [&mut self.client, &mut self.server] {
                let events = driven_at(&mut p.quic, at);
                p.drive(events, at)?;
            }
            let up = sent_at(&mut self.client.quic, at);
            let down = sent_at(&mut self.server.quic, at);
            if up.is_empty() && down.is_empty() {
                return Ok(());
            }
            for (peer, packets) in [(&mut self.server, up), (&mut self.client, down)] {
                for packet in packets {
                    let events = give_at(&mut peer.quic, &packet, at);
                    peer.drive(events, at)?;
                }
            }
        }
        panic!("the HTTP/3 exchange must reach a wait")
    }

    fn closed(&mut self, client: bool, code: Code) {
        assert_eq!(self.pump(), Err(h3::Error::Connection(code)));
        let (local, remote) = if client {
            (&mut self.client, &mut self.server)
        } else {
            (&mut self.server, &mut self.client)
        };
        for packet in sent_at(&mut local.quic, ms(self.ticks)) {
            drop(give_at(&mut remote.quic, &packet, ms(self.ticks)));
        }
        assert_eq!(remote.quic.peer_close(), Some(PeerClose::Application(code as u64)));
    }
}

#[cfg(feature = "tower")]
#[test]
fn tower_runs_an_axum_route_on_caller_driven_http3_and_returns_consumed_quic_credit() {
    use core::pin::pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll, Waker};
    use rsnetwork::http::{Adapter, Body as _, StatusCode};
    use rsnetwork::tower::{Bytes, dispatch};
    use std::sync::Arc;

    let mut n = Network::new(true, true);
    n.client.events.clear();
    let adapter = Adapter::new(
        rsnetwork::h1::Limits {
            head_bytes: 4096,
            fields: 32,
            name_bytes: 64,
            value_bytes: 512,
        },
        &n.server.budget,
    );
    let http = n.client.http.as_mut().unwrap();
    let id = http.open(&mut n.client.quic).unwrap().unwrap();
    http.headers(
        id,
        &[
            field(b":method", b"POST"),
            field(b":scheme", b"https"),
            field(b":authority", b"server.test"),
            field(b":path", b"/echo"),
        ],
        false,
    )
    .unwrap();
    n.pump().unwrap();
    n.client
        .http
        .as_mut()
        .unwrap()
        .data(id, &Lease::from(b"over QUIC".as_slice()), true)
        .unwrap();
    n.pump().unwrap();
    let mut events = mem::take(&mut n.server.events).into_iter();
    let head = events
        .find_map(|e| match e {
            Event::Request(s, head) if s == id => Some(head),
            _ => None,
        })
        .unwrap();
    let credit = Arc::new(AtomicUsize::new(0));
    let consumed = Arc::clone(&credit);
    let request = adapter
        .tower_request(&head, move |_: &mut Context<'_>| {
            let Event::Body(s, part) = events.next().expect("the complete upload is available") else {
                panic!("expected a request body event")
            };
            assert_eq!(s, id);
            if let Part::Data(bytes) = &part {
                consumed.fetch_add(bytes.initialized(), Ordering::Relaxed);
            }
            Poll::Ready(Ok(part))
        })
        .unwrap();
    let mut app = axum::Router::new().route(
        "/echo",
        axum::routing::post(|body: Bytes| async move { (StatusCode::CREATED, body) }),
    );
    let cx = &mut Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(response)) = pin!(dispatch(&mut app, request)).poll(cx) else {
        panic!("the router has all its input")
    };
    let consumed = credit.load(Ordering::Relaxed);
    assert_eq!(consumed, 9);
    let http = n.server.http.as_mut().unwrap();
    http.release(&mut n.server.quic, id, consumed as u64).unwrap();
    http.respond_http(id, &response, false).unwrap();
    n.pump().unwrap();
    let mut producer = pin!(response.into_body());
    let mut body = adapter.tower_body(producer.as_mut());
    let Poll::Ready(Ok(Part::Data(data))) = pin!(body.next()).poll(cx) else {
        panic!("expected the router's bytes")
    };
    assert_matches!(
        pin!(body.next()).poll(cx),
        Poll::Ready(Ok(Part::End(Outcome::Complete(None))))
    );
    n.server.http.as_mut().unwrap().data(id, &data, true).unwrap();
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(), [Event::Response(s, h), Event::Body(_, Part::Data(d)), Event::Body(_, Part::End(Outcome::Complete(None)))] if *s == id && h.status().code() == 201 && d.bytes()==b"over QUIC");
}

#[cfg(feature = "http")]
#[test]
fn http_conversion_mounts_a_handler_on_the_http3_request_stream() {
    use rsnetwork::http::{Adapter, Response, Version as HttpVersion, header};
    let mut n = Network::new(true, true);
    let adapter = Adapter::new(
        rsnetwork::h1::Limits {
            head_bytes: 4096,
            fields: 32,
            name_bytes: 64,
            value_bytes: 512,
        },
        &n.server.budget,
    );
    let id = n
        .client
        .http
        .as_mut()
        .unwrap()
        .open(&mut n.client.quic)
        .unwrap()
        .unwrap();
    n.client.headers(
        id,
        &[
            field(b":method", b"RePoRt"),
            field(b":scheme", b"https"),
            field(b":authority", b"server.test"),
            field(b":path", b"/a%2fb?"),
            field(b"accept", b"one"),
            field(b"accept", b"two"),
        ],
        true,
    );
    n.pump().unwrap();
    let (stream, head) = n
        .server
        .events
        .iter()
        .find_map(|e| {
            if let Event::Request(s, h) = e {
                Some((*s, h))
            } else {
                None
            }
        })
        .unwrap();
    let response = adapter
        .handle(head, stream, |request| {
            assert_eq!(*request.body(), id);
            assert_eq!(request.version(), HttpVersion::HTTP_3);
            assert_eq!(request.method().as_str(), "RePoRt");
            assert_eq!(request.uri().to_string(), "https://server.test/a%2fb?");
            assert_eq!(
                request
                    .headers()
                    .get_all(header::ACCEPT)
                    .iter()
                    .map(header::HeaderValue::as_bytes)
                    .collect::<Vec<_>>(),
                [b"one", b"two"]
            );
            let native = adapter.native_request(&request, Some(0)).unwrap();
            assert_eq!(native.head().target.as_bytes(), b"/a%2fb?");
            assert_eq!(native.head().authority.as_bytes(), b"server.test");
            Response::builder()
                .status(207)
                .header("set-cookie", "a=1")
                .header("set-cookie", "b=2")
                .body(())
                .unwrap()
        })
        .unwrap();
    n.server
        .http
        .as_mut()
        .unwrap()
        .respond_http(id, &response, true)
        .unwrap();
    n.pump().unwrap();
    let head = n
        .client
        .events
        .iter()
        .find_map(|e| {
            if let Event::Response(s, h) = e
                && *s == id
            {
                Some(h)
            } else {
                None
            }
        })
        .unwrap();
    let pointer = head.fields().next().unwrap().value().as_ptr();
    let (response, allocations) = counting::allocations(|| adapter.response(head, ()).unwrap());
    assert_eq!(allocations, 4);
    assert_eq!(response.version(), HttpVersion::HTTP_3);
    assert_eq!(response.status(), 207);
    assert_eq!(response.headers()[header::SET_COOKIE].as_bytes().as_ptr(), pointer);
    let native = adapter.native_response(&response, Some(0)).unwrap();
    assert_eq!(
        native.head().fields.iter().map(|f| f.value()).collect::<Vec<_>>(),
        [b"a=1", b"b=2"]
    );
}

#[test]
fn early_hints_precede_the_final_response_and_goaway_drains_the_request() {
    let mut n = Network::new(true, true);
    assert_matches!(n.client.events.as_slice(),[Event::Settings(s)] if s.qpack.table_bytes==4096);
    n.client.events.clear();
    n.server.events.clear();
    let id = n.client.request();
    n.pump().unwrap();
    assert_matches!(n.server.events.as_slice(),[Event::Request(stream,head),Event::Body(_,Part::End(Outcome::Complete(None)))] if *stream==id && head.version()==Version::Http3 && head.target().as_bytes()==b"/");
    assert_eq!(n.server.http.as_mut().unwrap().goaway().unwrap(), 4);
    assert!(!n.server.http.as_ref().unwrap().drained());
    n.pump().unwrap();
    assert!(
        n.client
            .http
            .as_mut()
            .unwrap()
            .open(&mut n.client.quic)
            .unwrap()
            .is_none()
    );
    for link in [b"</one>".as_slice(), b"</two>"] {
        n.server
            .headers(id, &[field(b":status", b"103"), field(b"link", link)], false);
        n.pump().unwrap();
    }
    n.server
        .headers(id, &[field(b":status", b"200"), field(b"content-length", b"3")], false);
    n.pump().unwrap();
    n.server
        .http
        .as_mut()
        .unwrap()
        .data(id, &Lease::from(&b"abc"[..]), false)
        .unwrap();
    n.pump().unwrap();
    n.server.headers(id, &[field(b"x-finished", b"yes")], true);
    n.pump().unwrap();
    let events = mem::take(&mut n.client.events);
    assert_matches!(events.as_slice(), [
        Event::GoAway(4),Event::Informational(_,first),Event::Informational(_,second),Event::Response(_,last),
        Event::Body(_,Part::Data(data)),Event::Body(_,Part::End(Outcome::Complete(Some(trailers))))
    ] if first.version()==Version::Http3 && first.status().code()==103 && second.status().code()==103 &&
        first.fields().next().unwrap().value()==b"</one>" && second.fields().next().unwrap().value()==b"</two>" &&
        last.status().code()==200 && last.length()==Some(3) && data.bytes()==b"abc" &&
        trailers.fields().next().unwrap().value()==b"yes");
    let h = n.client.http.as_mut().unwrap();
    assert_matches!(h.release(&mut n.client.quic,id,4),Err(h3::Error::Host(e)) if e.kind()==Kind::Misuse);
    h.release(&mut n.client.quic, id, 3).unwrap();
    n.pump().unwrap();
    for p in [&mut n.client, &mut n.server] {
        assert!(p.http.as_mut().unwrap().retire(&mut p.quic, id).unwrap());
    }
    assert!(n.server.http.as_ref().unwrap().drained());
}

#[test]
fn reset_isolates_a_request_and_preserves_dynamic_qpack() {
    let mut n = Network::new(true, false);
    let s = &mut n.server;
    s.stream(Direction::Unidirectional, b"\x00\x04\x00", false);
    let encoder = s.stream(Direction::Unidirectional, b"\x02", false);
    s.stream(Direction::Unidirectional, b"\x03", false);
    let first = n.client.request();
    let other = n.client.request();
    n.pump().unwrap();
    n.client.events.clear();
    // Required Insert Count 1, Base 1, static :status 200, dynamic relative index 0.
    n.server.raw(first, b"\x01\x04\x02\x00\xd9\x80", false);
    n.server.raw(other, b"\x01\x04\x02\x00\xd9\x80\x00\x03abc", true);
    n.pump().unwrap();
    assert!(n.client.events.is_empty(), "both field sections wait for the insertion");
    n.server.quic.reset(first, Code::RequestCancelled as u64).unwrap();
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(),[Event::Body(id,Part::End(Outcome::Reset(Some(0x10c))))] if *id==first);
    n.client.events.clear();
    // Set capacity to 128, then insert x-source: one.
    n.server.raw(encoder, b"\x3f\x61\x48x-source\x03one", false);
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(),[Event::Response(id,h),Event::Body(_,Part::Data(d)),Event::Body(_,Part::End(Outcome::Complete(None)))] if
        *id==other && h.fields().any(|f| f.name()==b"x-source" && f.value()==b"one") && d.bytes()==b"abc");
    let feedback = &n.server.wire.streams[&10].0;
    assert_eq!(feedback[0], 3);
    assert!(
        feedback.contains(&0x40) && feedback.contains(&0x84),
        "cancel stream zero and acknowledge stream four"
    );
    let later = n.client.request();
    n.pump().unwrap();
    n.client.events.clear();
    n.server.raw(later, b"\x01\x04\x02\x00\xd9\x80", true);
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(),[Event::Response(id,h),Event::Body(_,Part::End(Outcome::Complete(None)))] if
        *id==later && h.fields().next().unwrap().value()==b"one");
}

#[test]
fn client_grants_no_push_ids_and_closes_for_an_unpermitted_push() {
    for (bytes, request) in [(&b"\x01\x00"[..], false), (&b"\x05\x03\x00\x00\x00"[..], true)] {
        let mut n = Network::new(true, false);
        let control = &n.server.wire.streams[&2].0;
        assert_eq!(control[0], 0);
        let mut decoder = h3::frame::Decoder::new(h3::frame::Stream::ClientControl);
        let mut input = &control[1..];
        let mut frames = Vec::new();
        while !input.is_empty() {
            if let Some(h3::frame::Part::Header(h)) = decoder.next(&mut input).unwrap() {
                frames.push(h.kind);
            }
        }
        assert_eq!(frames, [h3::frame::Kind::SETTINGS]);
        if request {
            let id = n.client.request();
            n.pump().unwrap();
            n.server.raw(id, bytes, false);
        } else {
            n.server.stream(Direction::Unidirectional, bytes, true);
        }
        n.closed(true, Code::Id);
    }
}

#[test]
fn server_serves_requests_with_push_credit_and_ignores_extension_streams_and_frames() {
    let mut n = Network::new(false, true);
    let ctrl = n.client.stream(
        Direction::Unidirectional,
        b"\x00\x04\x00\x0d\x01\x00\x0d\x01\x02\x0d\x01\x02",
        false,
    );
    n.client.stream(Direction::Unidirectional, b"\x40\x42extension", true);
    let id = n.client.stream(
        Direction::Bidirectional,
        b"\x21\x02zz\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo\x21\x02xx",
        true,
    );
    n.pump().unwrap();
    assert_matches!(n.server.events.as_slice(),[Event::Settings(_),Event::Request(stream,head),Event::Body(_,Part::End(Outcome::Complete(None)))] if *stream==id && head.method().as_bytes()==b"GET");
    n.server.headers(id, &[field(b":status", b"204")], true);
    n.pump().unwrap();
    assert_eq!(n.client.wire.streams[&id.get()], (vec![1, 4, 0, 0, 0xff, 1], true));
    n.client.raw(ctrl, b"\x0d\x01\x01", false);
    n.closed(false, Code::Id);
}

#[test]
fn critical_stream_and_frame_violations_send_their_connection_codes() {
    use Direction::{Bidirectional, Unidirectional};
    for (client, dir, bytes, fin, code) in [
        (
            false,
            Unidirectional,
            &b"\x00\x07\x01\x00"[..],
            false,
            Code::MissingSettings,
        ),
        (
            true,
            Unidirectional,
            b"\x00\x04\x00\x00\x00",
            false,
            Code::FrameUnexpected,
        ),
        (
            true,
            Unidirectional,
            b"\x00\x04\x00\x04\x00",
            false,
            Code::FrameUnexpected,
        ),
        (
            true,
            Unidirectional,
            b"\x00\x04\x04\x01\x00\x01\x01",
            false,
            Code::Settings,
        ),
        (false, Unidirectional, b"\x00\x04\x02\x02\x00", false, Code::Settings),
        (true, Unidirectional, b"\x00\x04\x00\x07\x01\x01", false, Code::Id),
        (
            true,
            Unidirectional,
            b"\x00\x04\x00\x07\x01\x04\x07\x01\x08",
            false,
            Code::Id,
        ),
        (
            true,
            Unidirectional,
            b"\x00\x04\x00\x0d\x01\x00",
            false,
            Code::FrameUnexpected,
        ),
        (false, Unidirectional, b"\x00\x04\x00\x03\x01\x00", false, Code::Id),
        (true, Unidirectional, b"\x00\x04\x00", true, Code::ClosedCriticalStream),
        (true, Unidirectional, b"\x00\x04\x02\x01", true, Code::Frame),
        (false, Unidirectional, b"\x02", true, Code::ClosedCriticalStream),
        (true, Unidirectional, b"\x03", true, Code::ClosedCriticalStream),
        (true, Unidirectional, b"\x02\x00", false, Code::EncoderStream),
        (false, Unidirectional, b"\x03\x00", false, Code::DecoderStream),
        (false, Unidirectional, b"\x01\x00", false, Code::StreamCreation),
        (true, Bidirectional, b"\x00", false, Code::StreamCreation),
        (false, Bidirectional, b"\x07\x01\x00", false, Code::FrameUnexpected),
        (false, Bidirectional, b"\x00\x01x", false, Code::FrameUnexpected),
        (false, Bidirectional, b"\x01\x02\x00", true, Code::Frame),
        (false, Bidirectional, b"\x01\x00", false, Code::Decompression),
    ] {
        let mut n = Network::new(client, !client);
        let sender = if client { &mut n.server } else { &mut n.client };
        sender.stream(dir, bytes, fin);
        n.closed(client, code);
    }
    for kind in [&b"\x00\x04\x00"[..], b"\x02", b"\x03"] {
        for duplicate in [false, true] {
            let mut n = Network::new(true, false);
            let first = n.server.stream(Unidirectional, kind, false);
            n.pump().unwrap();
            if duplicate {
                n.server.stream(Unidirectional, kind, false);
            } else {
                n.server.quic.reset(first, 123).unwrap();
            }
            n.closed(
                true,
                if duplicate {
                    Code::StreamCreation
                } else {
                    Code::ClosedCriticalStream
                },
            );
        }
    }
}

#[test]
fn h3_checks_stream_credit_before_either_handshake_consumes_a_budget() {
    use core::num::NonZeroU64;
    use quic_path::{SERVER_ADDRESS, client_address, configs_for, from_server, now, sent};
    let (client, server) = configs_for(Some(1), b"h3");
    let path = quic::Path {
        local: client_address(4301),
        peer: SERVER_ADDRESS,
    };
    let mut usable =
        quic::Connection::client(&client, "server.test", path, quic::Limits::DEFAULT, &budget(), now()).unwrap();
    let datagram = sent(&mut usable);
    let initial = quic::packet::Header::parse(&datagram[0], 0).unwrap();
    let small = Budget::new(NonZeroU64::MIN);
    for limits in [
        quic::Limits {
            streams_uni_max: 2,
            ..quic::Limits::DEFAULT
        },
        quic::Limits {
            stream_bytes_max: 0,
            ..quic::Limits::DEFAULT
        },
        quic::Limits {
            data_bytes_max: 0,
            ..quic::Limits::DEFAULT
        },
        quic::Limits {
            send_bytes_max: 0,
            ..quic::Limits::DEFAULT
        },
    ] {
        assert_matches!(quic::Connection::client(&client,"server.test",path,limits,&small,now()),Err(e) if e.kind()==Kind::Misuse);
        assert_matches!(quic::Connection::server(&server,&initial,from_server(path.local),limits,&small,now()),Err(e) if e.kind()==Kind::Misuse);
    }
    let (raw, _) = configs_for(Some(1), b"test");
    let two = quic::Limits {
        streams_uni_max: 2,
        ..quic::Limits::DEFAULT
    };
    let connection = quic::Connection::client(&raw, "server.test", path, two, &budget(), now()).unwrap();
    assert_matches!(h3::Connection::new(&connection,h3::Limits::default(),&small),Err(h3::Error::Host(e)) if e.kind()==Kind::Misuse);
}

#[test]
fn a_slow_body_reader_releases_exact_credit_and_the_admitted_suffix_finishes() {
    let mut n = Network::with(
        Setup {
            client: quic::Limits {
                stream_bytes_max: 48,
                ..quic::Limits::DEFAULT
            },
            server: quic::Limits {
                send_bytes_max: 256,
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        true,
        true,
    );
    let id = n.client.request();
    n.pump().unwrap();
    n.server.headers(
        id,
        &[field(b":status", b"200"), field(b"content-length", b"240")],
        false,
    );
    n.pump().unwrap();
    let payload = quic_path::region(0, 240);
    n.server.http.as_mut().unwrap().data(id, &payload, true).unwrap();
    let mut received = Vec::new();
    let mut complete = false;
    for _ in 0..32 {
        n.pump().unwrap();
        let before = received.len();
        for e in mem::take(&mut n.client.events) {
            match e {
                Event::Body(_, Part::Data(d)) => received.extend_from_slice(d.bytes()),
                Event::Body(_, Part::End(Outcome::Complete(None))) => complete = true,
                Event::Settings(_) | Event::Response(..) => {}
                other => panic!("unexpected body event {other:?}"),
            }
        }
        let held = received.len() - before;
        assert!(held <= 48);
        if held > 0 {
            n.pump().unwrap();
            assert!(
                n.client.events.is_empty(),
                "withheld DATA credit bounds the next delivery"
            );
            n.client
                .http
                .as_mut()
                .unwrap()
                .release(&mut n.client.quic, id, held as u64)
                .unwrap();
        }
        if complete {
            break;
        }
    }
    assert!(complete);
    assert_eq!(received, payload.bytes());
}

#[test]
fn a_request_crossing_goaway_is_rejected_while_a_malformed_message_is_stream_local() {
    let mut n = Network::new(false, true);
    // The first field section contains a response status in a request.
    let bad = n
        .client
        .stream(Direction::Bidirectional, b"\x01\x03\x00\x00\xd9", false);
    let accepted = n.client.stream(
        Direction::Bidirectional,
        b"\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo",
        true,
    );
    n.pump().unwrap();
    assert!(
        n.server
            .events
            .iter()
            .any(|e| matches!(e,Event::Body(id,Part::End(Outcome::Malformed)) if *id==bad))
    );
    assert!(
        n.server
            .events
            .iter()
            .any(|e| matches!(e,Event::Request(id,_) if *id==accepted))
    );
    let excluded = n.server.http.as_mut().unwrap().goaway().unwrap();
    let late = n.client.stream(
        Direction::Bidirectional,
        b"\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo",
        true,
    );
    assert_eq!(late.get(), excluded);
    n.server.headers(accepted, &[field(b":status", b"200")], true);
    n.pump().unwrap();
    assert!(
        n.client
            .wire
            .other
            .iter()
            .any(|e| matches!(e,quic::Event::Reset{stream,code:0x10e} if *stream==bad))
    );
    assert!(
        n.client
            .wire
            .other
            .iter()
            .any(|e| matches!(e,quic::Event::Reset{stream,code:0x10b} if *stream==late))
    );
    assert_eq!(n.client.wire.streams[&accepted.get()], (vec![1, 3, 0, 0, 0xd9], true));
}

#[test]
fn a_peer_can_stop_the_response_before_its_request_headers_arrive() {
    let mut n = Network::new(false, true);
    let id = n.client.quic.open(Direction::Bidirectional).unwrap().unwrap();
    n.client.quic.stop(id, Code::RequestCancelled as u64).unwrap();
    n.pump().unwrap();
    assert_matches!(n.server.events.as_slice(),[Event::Stopped(stream,0x10c)] if *stream==id);
    n.client.raw(id, b"\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo", true);
    n.pump().unwrap();
    assert!(
        n.server
            .events
            .iter()
            .any(|e| matches!(e,Event::Request(stream,_) if *stream==id))
    );
    assert!(n.server.http.as_mut().unwrap().retire(&mut n.server.quic, id).unwrap());
}

#[test]
fn goaway_reaches_a_reader_that_holds_connection_credit_and_the_server_budget() {
    let mut n = Network::with(
        Setup {
            client: quic::Limits {
                data_bytes_max: 128,
                stream_bytes_max: 1024,
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        true,
        true,
    );
    let id = n.client.request();
    n.pump().unwrap();
    n.server.headers(id, &[field(b":status", b"200")], false);
    n.pump().unwrap();
    n.client.events.clear();
    let body = quic_path::region(0, 512);
    n.server.http.as_mut().unwrap().data(id, &body, true).unwrap();
    // Allow pacing and delayed credit for the consumed frame headers to settle.
    for _ in 0..8 {
        n.pump().unwrap();
    }
    let mut held = Vec::new();
    for event in mem::take(&mut n.client.events) {
        let Event::Body(_, Part::Data(d)) = event else {
            panic!("expected body data")
        };
        held.extend_from_slice(d.bytes());
    }
    assert!(!held.is_empty() && held.len() < 128);
    assert_eq!(held, &body.bytes()[..held.len()]);
    n.pump().unwrap();
    assert!(
        n.client.events.is_empty(),
        "the application still holds all body credit"
    );
    let _held_budget = n.server.budget.reserve(n.server.budget.available()).unwrap();
    assert_eq!(n.server.budget.available(), 0);
    assert_eq!(n.server.http.as_mut().unwrap().goaway().unwrap(), 4);
    n.pump().unwrap();
    let mut events = mem::take(&mut n.client.events).into_iter();
    assert_matches!(events.next(), Some(Event::GoAway(4)));
    // Consuming GOAWAY can trigger a grant for previously consumed framing bytes.
    for event in events {
        let Event::Body(_, Part::Data(d)) = event else {
            panic!("expected body data")
        };
        held.extend_from_slice(d.bytes());
    }
    assert!(held.len() <= 128 - 32);
    assert_eq!(held, &body.bytes()[..held.len()]);
}

#[test]
fn a_field_section_uses_literals_when_an_insertion_exceeds_encoder_stream_credit() {
    let mut n = Network::with(
        Setup {
            client: quic::Limits {
                stream_bytes_max: 16,
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        false,
        true,
    );
    // The peer permits a 256-byte dynamic table and four blocked streams.
    n.client
        .stream(Direction::Unidirectional, b"\x00\x04\x05\x01\x41\x00\x07\x04", false);
    let id = n.client.stream(
        Direction::Bidirectional,
        b"\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo",
        true,
    );
    n.pump().unwrap();
    let value = [b'z'; 80];
    n.server
        .headers(id, &[field(b":status", b"200"), field(b"x-result", &value)], true);
    n.pump().unwrap();
    // Only the stream type and Set Dynamic Table Capacity reach the peer.
    assert_eq!(n.client.wire.streams[&7].0, [2, 0x3f, 0xe1, 1]);
    let (response, fin) = &n.client.wire.streams[&id.get()];
    assert!(fin);
    let mut rest = response.as_slice();
    let mut decoder = h3::frame::Decoder::new(h3::frame::Stream::Response);
    assert_matches!(decoder.next(&mut rest).unwrap(), Some(h3::frame::Part::Header(_)));
    let Some(h3::frame::Part::Bytes { bytes, end: true, .. }) = decoder.next(&mut rest).unwrap() else {
        panic!("missing complete HEADERS")
    };
    assert_eq!(bytes[..2], [0, 0], "the section requires no insertion");
    let limits = h3::Limits::default().decoder;
    let mut qpack = rsnetwork::qpack::Decoder::new(limits, &budget()).unwrap();
    let mut lines = rsnetwork::qpack::Lines::new(limits, &budget()).unwrap();
    let mut feedback = rsnetwork::buffer::WriteLoan::new(Vec::new());
    let block = qpack.decode(id.get(), bytes, &mut lines, &mut feedback).unwrap();
    assert!(
        block
            .lines()
            .any(|line| line.name == b"x-result" && line.value == value)
    );
}

#[test]
fn blocked_field_sections_share_one_byte_limit_and_release_it_on_cancel() {
    let mut n = Network::configured(
        Setup::default(),
        Some(h3::Limits {
            blocked_bytes: 24,
            ..h3::Limits::default()
        }),
        None,
    );
    let encoder = n.server.stream(Direction::Unidirectional, b"\x02", false);
    let first = n.client.request();
    let second = n.client.request();
    let third = n.client.request();
    n.pump().unwrap();
    n.client.events.clear();
    let room = n.client.budget.available();
    // Four bytes for the blocked section and sixteen for its following DATA frame.
    n.server
        .raw(first, b"\x01\x04\x02\x00\xd9\x80\x00\x0eabcdefghijklmn", false);
    n.pump().unwrap();
    assert!(n.client.events.is_empty());
    assert!(n.client.budget.available() < room);
    n.server.raw(second, b"\x01\x04\x02\x00\xd9\x80\x00\x01x", true);
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(), [Event::Body(id, Part::End(Outcome::Reset(Some(0x107))))] if *id==second);
    n.client.events.clear();
    n.client
        .http
        .as_mut()
        .unwrap()
        .cancel(&mut n.client.quic, first)
        .unwrap();
    n.pump().unwrap();
    assert_eq!(n.client.budget.available(), room);
    n.server.raw(third, b"\x01\x04\x02\x00\xd9\x80\x00\x06abcdef", true);
    n.pump().unwrap();
    assert!(n.client.events.is_empty());
    n.server.raw(encoder, b"\x3f\x61\x48x-source\x03one", false);
    n.pump().unwrap();
    assert_matches!(n.client.events.as_slice(), [Event::Response(id,_), Event::Body(_, Part::Data(d)), Event::Body(_, Part::End(Outcome::Complete(None)))] if *id==third && d.bytes()==b"abcdef");
}

#[test]
fn exceeding_the_advertised_blocked_stream_limit_sends_decompression_failed() {
    let mut n = Network::with(
        Setup {
            client: quic::Limits {
                turn: TurnLimits {
                    visits: 2,
                    ..quic::Limits::DEFAULT.turn
                },
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        true,
        true,
    );
    assert_matches!(n.server.events.as_slice(), [Event::Settings(s)] if s.qpack.blocked_streams==2);
    let ids = [n.client.request(), n.client.request(), n.client.request()];
    n.pump().unwrap();
    for id in &ids[..2] {
        n.server.raw(*id, b"\x01\x04\x02\x00\xd9\x80", false);
        n.pump().unwrap();
    }
    assert!(n.client.events.iter().all(|e| !matches!(e, Event::Response(..))));
    n.server.raw(ids[2], b"\x01\x04\x02\x00\xd9\x80", false);
    n.closed(true, Code::Decompression);
}

/// Gives one encrypted stream region to HTTP. The counts below start after QUIC delivers the region.
fn batch(n: &mut Network, stream: StreamId, bytes: Vec<u8>) {
    let size = bytes.len();
    n.client.quic.send(stream, Lease::from(bytes), false).unwrap();
    n.ticks += 30;
    let at = ms(n.ticks);
    let mut input = None;
    for packet in sent_at(&mut n.client.quic, at) {
        for e in give_at(&mut n.server.quic, &packet, at) {
            if matches!(&e, quic::Event::Stream {stream: id, data, ..} if *id==stream && data.initialized()==size) {
                assert!(input.replace(e).is_none());
            } else {
                n.server.drive(vec![e], at).unwrap();
            }
        }
    }
    assert!(input.is_some(), "QUIC delivers the complete batch in one region");
    assert_matches!(
        n.server
            .http
            .as_mut()
            .unwrap()
            .drive(&mut n.server.quic, &mut input, at),
        Ok(Step::Again)
    );
    assert!(input.is_none());
}

/// Each successful turn uses the connection's funded state. The last instruction has a known wire error.
fn limited_turns(n: &mut Network, turns: core::ops::RangeInclusive<usize>, code: Code) {
    let available = n.server.budget.available();
    let at = ms(n.ticks);
    for count in 0..=*turns.end() {
        let (result, allocs) =
            counting::allocations(|| n.server.http.as_mut().unwrap().drive(&mut n.server.quic, &mut None, at));
        match result {
            Ok(Step::Again) => {
                assert_eq!(allocs, 0, "a critical-stream turn retained or allocated extra storage");
                assert_eq!(available, n.server.budget.available());
            }
            Err(h3::Error::Connection(actual)) => {
                assert_eq!(actual, code);
                assert!(turns.contains(&count), "error after {count} turns, expected {turns:?}");
                n.closed(false, code);
                return;
            }
            other => panic!("unexpected critical-stream result {other:?}"),
        }
    }
    panic!("the engine did not reach the last instruction");
}

fn limited_network() -> Network {
    Network::with(
        Setup {
            server: quic::Limits {
                turn: TurnLimits {
                    frames: 2,
                    visits: 2,
                    ..quic::Limits::DEFAULT.turn
                },
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        false,
        true,
    )
}

#[test]
fn encoder_instructions_fit_funded_storage_and_yield_at_the_turn_limit() {
    let mut n = limited_network();
    let encoder = n.client.stream(Direction::Unidirectional, b"\x02", false);
    n.pump().unwrap();
    // Twelve Set Dynamic Table Capacity instructions, then an invalid duplicate of a missing entry.
    let mut bytes = vec![0x20; 12];
    bytes.push(0);
    batch(&mut n, encoder, bytes);
    limited_turns(&mut n, 6..=6, Code::EncoderStream);
}

#[test]
fn control_frames_and_stream_cancellations_yield_and_send_the_specified_error() {
    let mut n = limited_network();
    let control = n.client.stream(Direction::Unidirectional, b"\x00\x04\x00", false);
    n.pump().unwrap();
    let mut frames = [0x0d, 1, 1].repeat(12);
    frames.extend_from_slice(&[0x0d, 1, 0]); // A lower MAX_PUSH_ID is an ID error.
    batch(&mut n, control, frames);
    limited_turns(&mut n, 25..=25, Code::Id);

    let mut n = limited_network();
    let decoder = n.client.stream(Direction::Unidirectional, b"\x03", false);
    n.pump().unwrap();
    let mut feedback = vec![0x40; 12];
    feedback.push(0); // An Insert Count Increment must be positive.
    batch(&mut n, decoder, feedback);
    limited_turns(&mut n, 6..=6, Code::DecoderStream);
}

#[test]
fn cancelling_outstanding_sections_yields_after_two_visits_and_preserves_other_requests() {
    let mut n = limited_network();
    n.client
        .stream(Direction::Unidirectional, b"\x00\x04\x05\x01\x41\x00\x07\x04", false);
    let decoder = n.client.stream(Direction::Unidirectional, b"\x03", false);
    let ids = core::array::from_fn::<_, 2, _>(|_| {
        n.client.stream(
            Direction::Bidirectional,
            b"\x01\x0a\x00\x00\xd1\xd7\xc1\x50\x03foo",
            true,
        )
    });
    n.pump().unwrap();
    for i in 0..12 {
        n.server.headers(
            ids[i % 2],
            &[field(b":status", b"103"), field(b"x-source", b"one")],
            false,
        );
        n.pump().unwrap();
    }
    assert!(n.client.wire.streams[&7].0.len() > 4, "the encoder sent an insertion");
    batch(&mut n, decoder, vec![0x40]);
    for _ in 0..5 {
        assert_matches!(
            n.server
                .http
                .as_mut()
                .unwrap()
                .drive(&mut n.server.quic, &mut None, ms(n.ticks)),
            Ok(Step::Again)
        );
    }
    // This response arrives while cancellation still has sections to visit.
    n.server
        .headers(ids[1], &[field(b":status", b"200"), field(b"x-source", b"one")], true);
    n.pump().unwrap();
    let response = &n.client.wire.streams[&ids[1].get()];
    assert!(response.1);
    let mut rest = response.0.as_slice();
    let mut frames = h3::frame::Decoder::new(h3::frame::Stream::Response);
    let mut required = Vec::new();
    while !rest.is_empty() {
        if let Some(h3::frame::Part::Bytes { bytes, .. }) = frames.next(&mut rest).unwrap() {
            required.push(bytes[0]);
        }
    }
    assert_eq!(required.len(), 7);
    assert!(required[..6].iter().all(|count| *count != 0));
    assert_eq!(required[6], 0);
    // The six sections of stream four can still be acknowledged. A seventh has no matching section.
    batch(&mut n, decoder, vec![0x84; 7]);
    limited_turns(&mut n, 3..=3, Code::DecoderStream);
}

#[test]
fn a_fragmented_blocked_body_replays_exactly_after_a_qpack_duplicate() {
    let mut n = Network::with(
        Setup {
            client: quic::Limits {
                turn: TurnLimits {
                    bytes: 16,
                    ..quic::Limits::DEFAULT.turn
                },
                ..quic::Limits::DEFAULT
            },
            ..Setup::default()
        },
        true,
        false,
    );
    let encoder = n.server.stream(Direction::Unidirectional, b"\x02", false);
    let id = n.client.request();
    n.pump().unwrap();
    n.client.events.clear();
    // The section refers to the second insertion. The DATA frame holds 160 bytes.
    n.server.raw(id, b"\x01\x04\x03\x00\xd9\x80\x00\x40\xa0", false);
    n.pump().unwrap();
    n.server.raw(encoder, b"\x3f\x61\x48x-source\x03one", false);
    n.pump().unwrap();
    let payload: Vec<u8> = (0..160).collect();
    for (i, part) in payload.chunks(40).enumerate() {
        n.server.quic.send(id, Lease::from(part.to_vec()), i == 3).unwrap();
        n.pump().unwrap();
        assert!(n.client.events.is_empty());
    }
    n.server.raw(encoder, b"\x00", false);
    n.pump().unwrap();
    let mut events = mem::take(&mut n.client.events).into_iter();
    assert_matches!(events.next(), Some(Event::Response(stream,h)) if stream==id && h.fields().any(|f|f.name()==b"x-source" && f.value()==b"one"));
    assert_matches!(events.next_back(), Some(Event::Body(stream,Part::End(Outcome::Complete(None)))) if stream==id);
    let mut received = Vec::new();
    for e in events {
        let Event::Body(_, Part::Data(d)) = e else {
            panic!("expected a body region")
        };
        assert!(d.initialized() <= 16);
        received.extend_from_slice(d.bytes());
    }
    assert_eq!(received, payload);
    n.client
        .http
        .as_mut()
        .unwrap()
        .release(&mut n.client.quic, id, 160)
        .unwrap();
    assert!(n.client.http.as_mut().unwrap().retire(&mut n.client.quic, id).unwrap());
}
