//! The HTTP/3 connection exchanges encrypted QUIC datagrams with an HTTP engine or a wire peer.
#![cfg(feature = "tls")]

#[expect(dead_code, reason = "the QUIC suites share the path and its impairment profiles")]
mod quic_path;

use core::mem;
use std::assert_matches;

use quic_path::{Pair, Received, Setup, budget, driven_at, give_at, ms, sent_at};
use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::drive::Kind;
use rsnetwork::h3::{self, Code, Event, Step};
use rsnetwork::message::Version;
use rsnetwork::qpack::FieldLine;
use rsnetwork::quic::{self, PeerClose, StreamId, frame::Direction};
use rsnetwork::time::Instant;

struct Peer {
    quic: quic::Connection,
    http: Option<h3::Connection>,
    events: Vec<Event>,
    wire: Received,
}

impl Peer {
    fn new(quic: quic::Connection, http: bool) -> Self {
        Self {
            http: http.then(|| h3::Connection::new(&quic, h3::Limits::default(), &budget()).unwrap()),
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
    use rsnetwork::capacity::Budget;
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
