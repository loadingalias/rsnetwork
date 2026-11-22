//! The QUIC packet layer and frame codec (N301, N302). The packet and header protection and the
//! Retry tag give the bytes of RFC 9001, appendix A, through the provider. Received packets open in
//! the region that they arrived in, with no copy before decryption, across coalesced packets and
//! the datagrams of a segmented receive. Version negotiation follows RFC 9000, section 6, and each
//! built packet is the same bytes for the same random source.

use core::num::NonZeroUsize;
use std::assert_matches;

use rscrypto_rustls::quic::CHACHA20_POLY1305;
use rsnetwork::buffer::{Backing, Buffer as _};
use rsnetwork::quic::frame::{Direction, EcnCounts, Frame};
use rsnetwork::quic::packet::{
    self, Builder, Datagrams, DirectionalKeys, Header, Kind, Malformed, Negotiation, OpenError, Outgoing, Side,
};
use rsnetwork::quic::{ConnectionId, ErrorCode, Version};
use rustls::crypto::tls13::OkmBlock;
use rustls::crypto::{GetRandomFailed, SecureRandom};
use rustls::quic::KeyBuilder;

fn hex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.trim().as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "two digits for each byte");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// The `frame`, `header`, and `packet` lines of a vector file of RFC 9001, appendix A.
fn vector(text: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let field = |name: &str| {
        let line = text.lines().find(|line| line.starts_with(name)).unwrap();
        hex(line.split_once(" = ").unwrap().1)
    };
    (field("frame"), field("header"), field("packet"))
}

/// The destination connection ID of the first Initial packet of the client (RFC 9001, A.1).
fn client_dcid() -> ConnectionId {
    ConnectionId::new(&hex("8394c8f03e515708")).unwrap()
}

/// A source that gives each byte from a counter, so each run draws the same bytes.
#[derive(Debug)]
struct Counter(std::sync::Mutex<u8>);

impl SecureRandom for Counter {
    fn fill(&self, out: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut next = self.0.lock().unwrap();
        for byte in out {
            *byte = *next;
            *next = next.wrapping_add(1);
        }
        Ok(())
    }
}

/// A source that gives the byte `0xff` each time.
#[derive(Debug)]
struct Ones;

impl SecureRandom for Ones {
    fn fill(&self, out: &mut [u8]) -> Result<(), GetRandomFailed> {
        out.fill(0xff);
        Ok(())
    }
}

/// The frames of `payload`.
fn frames(payload: &[u8]) -> Vec<Frame<'_>> {
    let (mut frames, mut at) = (Vec::new(), 0);
    while at < payload.len() {
        let (frame, len) = Frame::parse(&payload[at..]).unwrap();
        frames.push(frame);
        at += len;
    }
    frames
}

/// Seals one packet with `header`, `number` in `number_len` bytes, `frames`, padded to `pad`.
fn seal(
    header: Outgoing<'_>,
    (number, number_len): (u64, usize),
    frames: &[Frame<'_>],
    pad: usize,
    keys: &DirectionalKeys,
) -> Vec<u8> {
    let mut out = vec![0; 1500];
    let mut builder = Builder::new(&mut out, header, number, number_len).unwrap();
    for frame in frames {
        builder.frame(frame).unwrap();
    }
    builder.pad_to(pad).unwrap();
    let len = builder.seal(keys).unwrap();
    out.truncate(len);
    out
}

#[test]
fn the_initial_packets_of_rfc_9001_seal_and_open_to_their_bytes() {
    let dcid = client_dcid();
    let client = packet::initial_keys(&dcid, Side::Client);
    let server = packet::initial_keys(&dcid, Side::Server);

    // A.2: the first Initial packet of the client, with packet number 2 in 4 bytes, padded to
    // 1,200 bytes.
    let (frame, header, expected) = vector(include_str!("quic/rfc9001-client.txt"));
    let crypto = frames(&frame);
    let initial = Outgoing::Initial {
        dcid: &dcid,
        scid: &ConnectionId::EMPTY,
        token: &[],
    };
    let sealed = seal(initial, (2, 4), &crypto, 1200, &client.local);
    assert_eq!(sealed, expected);

    // The server opens it in the region that it arrived in.
    let mut region = Backing::from(Vec::with_capacity(1500));
    let start = region.as_ptr().addr();
    let mut loan = rsnetwork::buffer::WriteLoan::new(region);
    loan.fill_from(&expected);
    region = loan.into_inner();
    let mut datagrams = Datagrams::new(region, None, 8);
    let protected = datagrams.next_packet().unwrap().unwrap();
    assert_matches!(protected.header(), Header::Protected { kind: Kind::Initial, dcid: id, .. } if *id == dcid);
    let unmasked = protected.unmask(&*server.remote.header, 0).unwrap();
    assert_eq!(unmasked.number(), 2);
    let packet = unmasked.open(&*server.remote.packet).unwrap();
    let payload = packet.payload();
    // The plaintext is in place: after the 22 bytes of the header, in the received region.
    assert_eq!(payload.as_ptr().addr(), start + header.len());
    assert_eq!(&payload.bytes()[..frame.len()], frame);
    assert!(
        payload.bytes()[frame.len()..].iter().all(|&byte| byte == 0),
        "the rest is PADDING"
    );
    assert!(datagrams.next_packet().is_none());

    // A.3: the first Initial packet of the server, with an ACK and a CRYPTO frame.
    let (frame, _, expected) = vector(include_str!("quic/rfc9001-server.txt"));
    let scid = ConnectionId::new(&hex("f067a5502a4262b5")).unwrap();
    let initial = Outgoing::Initial {
        dcid: &ConnectionId::EMPTY,
        scid: &scid,
        token: &[],
    };
    let sealed = seal(initial, (1, 2), &frames(&frame), 0, &server.local);
    assert_eq!(sealed, expected);
    let mut datagrams = Datagrams::new(Backing::from(expected), None, 0);
    let packet = datagrams
        .next_packet()
        .unwrap()
        .unwrap()
        .unmask(&*client.remote.header, 0)
        .unwrap()
        .open(&*client.remote.packet)
        .unwrap();
    assert_eq!(packet.number(), 1);
    assert_eq!(packet.payload().bytes(), frame);
}

#[test]
fn a_retry_of_rfc_9001_has_its_tag_and_a_changed_byte_fails_it() {
    // A.4: a Retry packet with the token `token`, to the Initial packet of A.2.
    let expected = hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
    let scid = ConnectionId::new(&hex("f067a5502a4262b5")).unwrap();
    let original = client_dcid();
    let mut out = [0; 64];
    let len = packet::retry(&mut out, (&ConnectionId::EMPTY, &scid, &original), b"token", &Ones).unwrap();
    assert_eq!(out[..len], expected);
    assert!(packet::retry_is_valid(&expected, &original));
    assert_matches!(
        Header::parse(&expected, 8),
        Ok(Header::Retry { scid: id, ref token, .. }) if id == scid && expected[token.clone()] == *b"token"
    );
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] ^= 1;
        assert!(!packet::retry_is_valid(&changed, &original), "byte {index}");
    }
    assert!(!packet::retry_is_valid(&expected, &ConnectionId::EMPTY));
}

#[test]
fn a_short_header_with_chacha20_seals_and_opens_to_the_bytes_of_rfc_9001() {
    // A.5: a 1-RTT packet with one PING frame and packet number 654,360,564 in 3 bytes.
    let secret = OkmBlock::new(&hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"));
    let builder = KeyBuilder::new(
        &secret,
        rustls::quic::Version::V1,
        CHACHA20_POLY1305,
        rscrypto_rustls::hash::HKDF_SHA256,
    );
    let keys = DirectionalKeys {
        header: builder.header_protection_key(),
        packet: builder.packet_key(),
    };
    let short = Outgoing::OneRtt {
        dcid: &ConnectionId::EMPTY,
        spin: false,
        key_phase: false,
    };
    let sealed = seal(short, (654_360_564, 3), &[Frame::Ping], 0, &keys);
    assert_eq!(sealed, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
    let mut datagrams = Datagrams::new(Backing::from(sealed), None, 0);
    let unmasked = datagrams
        .next_packet()
        .unwrap()
        .unwrap()
        .unmask(&*keys.header, 654_360_564)
        .unwrap();
    assert_eq!(unmasked.number(), 654_360_564);
    assert!(!unmasked.key_phase());
    assert_eq!(unmasked.open(&*keys.packet).unwrap().payload().bytes(), [0x01]);
}

/// A Handshake packet that a peer seals with `keys` itself: the first byte `first`, which gives
/// the reserved bits and the length of the packet number, the packet number `number`, and the
/// plaintext `payload`.
fn raw(first: u8, dcid: &ConnectionId, number: u32, payload: &[u8], keys: &DirectionalKeys) -> Vec<u8> {
    let number_len = usize::from(first & 0x3) + 1;
    let length = number_len + payload.len() + packet::TAG;
    let mut bytes = vec![first, 0, 0, 0, 1, u8::try_from(dcid.as_bytes().len()).unwrap()];
    bytes.extend_from_slice(dcid.as_bytes());
    bytes.extend_from_slice(&[
        0,
        0x40 | u8::try_from(length >> 8).unwrap(),
        u8::try_from(length & 0xff).unwrap(),
    ]);
    let at = bytes.len();
    bytes.extend_from_slice(&number.to_be_bytes()[4 - number_len..]);
    let header_end = bytes.len();
    bytes.extend_from_slice(payload);
    let (head, rest) = bytes.split_at_mut(header_end);
    let tag = keys
        .packet
        .encrypt_in_place(u64::from(number), head, rest, None)
        .unwrap();
    bytes.extend_from_slice(tag.as_ref());
    let sample: [u8; 16] = bytes[at + 4..at + 20].try_into().unwrap();
    let (first, rest) = bytes.split_first_mut().unwrap();
    keys.header
        .encrypt_in_place(&sample, first, &mut rest[at - 1..at - 1 + number_len])
        .unwrap();
    bytes
}

/// The bytes of a region that holds `datagrams`, each in a segment of `segment` bytes.
fn region(datagrams: &[Vec<u8>], segment: usize) -> Backing {
    let mut bytes = Vec::with_capacity(segment * datagrams.len());
    for (index, datagram) in datagrams.iter().enumerate() {
        bytes.extend_from_slice(datagram);
        assert!(datagram.len() <= segment);
        if index + 1 < datagrams.len() {
            assert_eq!(datagram.len(), segment, "only the last datagram is shorter");
        }
    }
    Backing::from(bytes)
}

#[test]
fn coalesced_packets_and_segmented_datagrams_open_in_place_one_after_another() {
    let dcid = client_dcid();
    let later_id = ConnectionId::new(b"handshake").unwrap();
    // Keys that the Initial packet gives in a connection: here, the keys of another ID.
    let (initial, later) = (
        packet::initial_keys(&dcid, Side::Client),
        packet::initial_keys(&later_id, Side::Client),
    );
    let scid = ConnectionId::new(&[7; 8]).unwrap();
    let ping = |header, keys: &DirectionalKeys| seal(header, (0, 1), &[Frame::Ping], 0, keys);
    let first = ping(
        Outgoing::Initial {
            dcid: &dcid,
            scid: &scid,
            token: &[],
        },
        &initial.local,
    );
    let second = ping(
        Outgoing::Handshake {
            dcid: &dcid,
            scid: &scid,
        },
        &later.local,
    );
    let third = ping(
        Outgoing::OneRtt {
            dcid: &dcid,
            spin: false,
            key_phase: true,
        },
        &later.local,
    );
    // Datagram 1: an Initial and a Handshake packet, coalesced, then bytes of zero. Datagram 2,
    // the last segment of the receive: a 1-RTT packet.
    let segment = 200;
    let mut one = [first.clone(), second.clone()].concat();
    one.resize(segment, 0);
    let region = region(&[one, third.clone()], segment);
    let start = region.as_ptr().addr();
    let (server, later_server) = (
        packet::initial_keys(&dcid, Side::Server),
        packet::initial_keys(&later_id, Side::Server),
    );
    let mut datagrams = Datagrams::new(region, NonZeroUsize::new(segment), dcid.as_bytes().len());
    let opened = |datagrams: &mut Datagrams, keys: &DirectionalKeys| {
        datagrams
            .next_packet()
            .unwrap()
            .unwrap()
            .unmask(&*keys.header, 0)
            .unwrap()
            .open(&*keys.packet)
            .unwrap()
    };
    let initial_packet = opened(&mut datagrams, &server.remote);
    // The Initial packet stays frozen while the next packet of its datagram opens in place.
    let handshake_packet = opened(&mut datagrams, &later_server.remote);
    assert_matches!(
        handshake_packet.header(),
        Header::Protected {
            kind: Kind::Handshake,
            ..
        }
    );
    // The bytes of zero after the two packets are not a packet: the rest of the datagram goes.
    assert_matches!(datagrams.next_packet(), Some(Err(Malformed)));
    let one_rtt = opened(&mut datagrams, &later_server.remote);
    assert!(one_rtt.key_phase());
    assert!(datagrams.next_packet().is_none());
    // Each plaintext payload is in the received region, before the tag of its packet: no packet
    // was copied before its decryption.
    for (packet, end) in [
        (&initial_packet, first.len()),
        (&handshake_packet, first.len() + second.len()),
        (&one_rtt, segment + third.len()),
    ] {
        let payload = packet.payload();
        assert_eq!(
            payload.as_ptr().addr(),
            start + end - packet::TAG - payload.bytes().len()
        );
        assert_eq!(payload.bytes()[0], 0x01, "a PING frame");
    }
}

#[test]
fn a_packet_that_breaks_a_rule_refuses_with_its_reason() {
    let dcid = client_dcid();
    let (client, server) = (
        packet::initial_keys(&dcid, Side::Client),
        packet::initial_keys(&dcid, Side::Server),
    );
    let header = Outgoing::Handshake {
        dcid: &dcid,
        scid: &ConnectionId::EMPTY,
    };
    let sealed = seal(header, (5, 1), &[Frame::Ping], 0, &client.local);
    let open = |bytes: Vec<u8>, keys: &DirectionalKeys| {
        let mut datagrams = Datagrams::new(Backing::from(bytes), None, 8);
        let protected = datagrams.next_packet().unwrap().unwrap();
        protected
            .unmask(&*keys.header, 0)?
            .open(&*keys.packet)
            .map(|packet| packet.number())
    };
    assert_eq!(open(sealed.clone(), &server.remote), Ok(5));
    // Another key, or a changed byte of the payload, does not open.
    assert_eq!(open(sealed.clone(), &client.remote), Err(OpenError::Authentication));
    let mut changed = sealed;
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(open(changed, &server.remote), Err(OpenError::Authentication));

    // A peer that sets the reserved bits under the protection, or sends no frame, breaks a rule
    // of version 1, though the packet opens.
    // Each has a packet number of 4 bytes, so the sample of the header protection is there.
    for (first, payload) in [(0xef, &[0x01][..]), (0xe3, &[][..])] {
        let bytes = raw(first, &dcid, 5, payload, &client.local);
        assert_eq!(open(bytes, &server.remote), Err(OpenError::Violation), "{first:#x}");
    }

    // A header that is not valid.
    for bytes in [
        // A short header with no fixed bit.
        vec![0x00; 30],
        // A long header of version 1 with a connection ID of 21 bytes.
        [&[0xc0, 0, 0, 0, 1, 21][..], &[0; 40]].concat(),
        // A Length past the datagram.
        [&[0xe0, 0, 0, 0, 1, 0, 0][..], &[0x44, 0x00]].concat(),
    ] {
        assert_eq!(Header::parse(&bytes, 8), Err(Malformed), "{bytes:02x?}");
    }
    // A packet too short for the sample of its header protection.
    let short = [&[0xe0, 0, 0, 0, 1, 0, 0, 5][..], &[0; 5]].concat();
    let mut datagrams = Datagrams::new(Backing::from(short), None, 8);
    let protected = datagrams.next_packet().unwrap().unwrap();
    assert_matches!(protected.unmask(&*server.remote.header, 0), Err(OpenError::Short));
}

#[test]
fn a_packet_number_decodes_against_the_next_number_of_its_space() {
    // RFC 9000, appendix A.3: the next number 0xa82f30eb, and 0x9b32 in 2 bytes.
    assert_eq!(packet::decode_number(0x9b32, 2, 0xa82f_30eb), 0xa82f_9b32);
    // Appendix A.2: 0xac5c02 after the acknowledged 0xabe8b3 needs 2 bytes.
    assert_eq!(packet::number_len(0xac_5c02, Some(0xab_e8b3)), Some(2));
    assert_eq!(packet::number_len(0, None), Some(1));
    assert_eq!(packet::number_len(1 << 40, Some(0)), None);
}

#[test]
fn version_negotiation_follows_rfc_9000_section_6() {
    // A client probes with a reserved version (section 6.3), and the server answers it.
    let (dcid, scid) = (client_dcid(), ConnectionId::new(&[9; 4]).unwrap());
    let probe = Version(0x1a2a_3a4a);
    assert!(probe.is_reserved() && !Version::V1.is_reserved());
    let mut first = vec![0xc0];
    first.extend_from_slice(&probe.0.to_be_bytes());
    for id in [&dcid, &scid] {
        first.push(u8::try_from(id.as_bytes().len()).unwrap());
        first.extend_from_slice(id.as_bytes());
    }
    first.resize(1200, 0);
    let header = Header::parse(&first, 8).unwrap();
    assert_matches!(header, Header::Unsupported { version, .. } if version == probe);
    let mut out = [0; 64];
    let random = Counter(std::sync::Mutex::new(0x3f));
    let len = packet::negotiation(&mut out, (&first, &header), &random)
        .unwrap()
        .unwrap();
    let answer = out[..len].to_vec();
    // The same source gives the same packet.
    let len_again = packet::negotiation(&mut out, (&first, &header), &Counter(std::sync::Mutex::new(0x3f)))
        .unwrap()
        .unwrap();
    assert_eq!(out[..len_again], answer);

    let header = Header::parse(&answer, 8).unwrap();
    let Header::Negotiation {
        dcid: to,
        scid: from,
        versions,
        ..
    } = &header
    else {
        panic!("{header:?}");
    };
    // The IDs of the client in the place of each other, version 1, and a reserved version.
    assert_eq!(
        (&answer[to.clone()], &answer[from.clone()]),
        (scid.as_bytes(), dcid.as_bytes())
    );
    let listed: Vec<Version> = answer[versions.clone()]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|version| Version(u32::from_be_bytes(*version)))
        .collect();
    assert_eq!(listed[0], Version::V1);
    assert!(listed[1].is_reserved() && listed[1] != probe);
    assert_eq!(answer[0] & 0xc0, 0xc0, "the long form and the fixed bit");

    let of = |selected, processed, ids: (&ConnectionId, &ConnectionId)| {
        Negotiation::of((&answer, &header), (ids.0, ids.1, selected), processed)
    };
    // No version in common: a client of version 1 only abandons the attempt.
    assert_eq!(of(probe, false, (&dcid, &scid)), Negotiation::Abandon);
    // It discards a packet that lists its own version, a packet after another one, and a packet
    // for other connection IDs.
    assert_eq!(of(Version::V1, false, (&dcid, &scid)), Negotiation::Discard);
    assert_eq!(of(probe, true, (&dcid, &scid)), Negotiation::Discard);
    assert_eq!(of(probe, false, (&scid, &dcid)), Negotiation::Discard);
    // Only a packet of another version gets an answer.
    let v1 = Header::parse(&answer, 8).unwrap();
    assert_eq!(packet::negotiation(&mut out, (&answer, &v1), &random), Ok(None));
}

#[test]
fn each_frame_writes_and_parses_back_to_itself() {
    let mut ranges = Vec::new();
    // An ACK of 100..=110 and 90..=95: largest 110, first 10, one range with gap 3 and length 5.
    let ack_bytes = [0x03, 0x40, 110, 0x0a, 1, 10, 3, 5, 1, 2, 3];
    let (ack, _) = Frame::parse(&ack_bytes).unwrap();
    let Frame::Ack(parsed) = ack else { panic!("{ack:?}") };
    ranges.extend(parsed.ranges());
    assert_eq!(ranges, [100..=110, 90..=95]);
    assert_eq!(
        parsed.ecn,
        Some(EcnCounts {
            ect0: 1,
            ect1: 2,
            ce: 3
        })
    );
    let id = ConnectionId::new(&[4; 8]).unwrap();
    let all = [
        Frame::Padding { len: 3 },
        Frame::Ping,
        ack,
        Frame::ResetStream {
            stream: 4,
            code: 7,
            final_size: 1 << 40,
        },
        Frame::StopSending { stream: 8, code: 1 },
        Frame::Crypto {
            offset: 100,
            data: b"hello",
        },
        Frame::NewToken { token: b"token" },
        Frame::Stream {
            stream: 1,
            offset: 0,
            data: b"data",
            fin: true,
        },
        Frame::Stream {
            stream: 2,
            offset: 77,
            data: b"",
            fin: false,
        },
        Frame::MaxData { max: 1 << 20 },
        Frame::MaxStreamData { stream: 3, max: 65_535 },
        Frame::MaxStreams {
            direction: Direction::Unidirectional,
            max: 1 << 60,
        },
        Frame::DataBlocked { limit: 9 },
        Frame::StreamDataBlocked { stream: 5, limit: 6 },
        Frame::StreamsBlocked {
            direction: Direction::Bidirectional,
            limit: 100,
        },
        Frame::NewConnectionId {
            sequence: 2,
            retire_prior_to: 1,
            id,
            reset_token: [0xaa; 16],
        },
        Frame::RetireConnectionId { sequence: 1 },
        Frame::PathChallenge { data: [1; 8] },
        Frame::PathResponse { data: [2; 8] },
        Frame::ConnectionClose {
            code: ErrorCode::PROTOCOL_VIOLATION.0,
            frame_type: Some(0x08),
            reason: b"why",
        },
        Frame::ConnectionClose {
            code: 0x100,
            frame_type: None,
            reason: b"",
        },
        Frame::HandshakeDone,
        Frame::Datagram { data: b"unreliable" },
    ];
    let mut out = [0; 128];
    for frame in all {
        let len = frame.write(&mut out).unwrap();
        assert_eq!(Frame::parse(&out[..len]), Ok((frame, len)), "{frame:?}");
    }
    // A frame that has no room writes nothing.
    Frame::Datagram { data: b"unreliable" }
        .write(&mut out[..5])
        .unwrap_err();
}

#[test]
fn a_frame_that_breaks_a_rule_refuses_with_its_code() {
    let encoding = |frame_type| {
        Err(rsnetwork::quic::frame::FrameError {
            code: ErrorCode::FRAME_ENCODING_ERROR,
            frame_type,
        })
    };
    let cases: [(&[u8], u64); 9] = [
        // A type that version 1 does not define.
        (&[0x1f], 0x1f),
        // An ACK whose first range passes packet number 0, and one whose second range does.
        (&[0x02, 5, 0, 0, 6], 0x02),
        (&[0x02, 5, 0, 1, 2, 1, 1], 0x02),
        // A NEW_TOKEN frame with no token.
        (&[0x07, 0], 0x07),
        // MAX_STREAMS above 2^60.
        (&[0x12, 0xd0, 0, 0, 0, 0, 0, 0, 1], 0x12),
        // NEW_CONNECTION_ID with retire_prior_to above the sequence, and with an empty ID.
        (
            &[0x18, 1, 2, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            0x18,
        ),
        (&[0x18, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0x18),
        // A STREAM frame whose data ends past 2^62 - 1.
        (&[0x0e, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 0], 0x0e),
        // A CRYPTO frame cut inside its data.
        (&[0x06, 0, 5, b'a'], 0x06),
    ];
    for (bytes, frame_type) in cases {
        assert_eq!(Frame::parse(bytes), encoding(frame_type), "{bytes:02x?}");
    }
    // A type in a longer encoding than its shortest is a protocol violation.
    assert_eq!(
        Frame::parse(&[0x40, 0x01]),
        Err(rsnetwork::quic::frame::FrameError {
            code: ErrorCode::PROTOCOL_VIOLATION,
            frame_type: 0x01,
        })
    );
    // The packets that can carry each frame (RFC 9000, table 3).
    assert!(Frame::Crypto { offset: 0, data: b"" }.permitted(Kind::Initial));
    assert!(!Frame::Crypto { offset: 0, data: b"" }.permitted(Kind::ZeroRtt));
    assert!(!Frame::HandshakeDone.permitted(Kind::Handshake));
    assert!(Frame::HandshakeDone.permitted(Kind::OneRtt));
    let application = Frame::ConnectionClose {
        code: 0,
        frame_type: None,
        reason: b"",
    };
    assert!(!application.permitted(Kind::Initial) && application.permitted(Kind::ZeroRtt));
    assert!(!Frame::Datagram { data: b"" }.permitted(Kind::Handshake));
}
