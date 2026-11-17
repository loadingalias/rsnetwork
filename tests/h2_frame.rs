//! The contracts of the HTTP/2 frame codec: each frame type reads and writes the bytes of an
//! independent implementation or of the layout of RFC 9113, and a receiver ignores the unused
//! flags and the reserved bit.
//!
//! The vectors with a source of Go are the `wantEnc` strings and the frame values of
//! `src/net/http/internal/http2/frame_test.go` of Go 1.27.4 (BSD-3-Clause, Copyright 2014 The Go
//! Authors). The other vectors follow the figures of RFC 9113, section 6, field by field, as each
//! comment states.

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::h2::frame::{Entries, ErrorCode, Frame, Head, Kind, Priority};

/// The `SETTINGS_MAX_FRAME_SIZE` of the receiver in each test: the initial value of RFC 9113.
const MAX: u32 = 1 << 14;

fn settings(bytes: &'static [u8]) -> Entries<'static> {
    Entries::new(bytes).expect("6 bytes for each setting")
}

/// Each vector: its source, its bytes, and its frame.
fn vectors() -> Vec<(&'static str, &'static [u8], Frame<'static>)> {
    let priority = |exclusive, dependency, weight| Priority {
        exclusive,
        dependency,
        weight,
    };
    vec![
        (
            "Go TestWriteData",
            b"\x00\x00\x03\x00\x01\x01\x02\x03\x04ABC",
            Frame::Data {
                stream: 0x0102_0304,
                data: b"ABC",
                end_stream: true,
                padding: None,
            },
        ),
        (
            // Go TestWriteDataPadded case 1: PADDED with a pad length of 0, so the length is 4.
            "Go TestWriteDataPadded 1, with the layout of RFC 9113, figure 3",
            b"\x00\x00\x04\x00\x09\x00\x00\x00\x01\x00foo",
            Frame::Data {
                stream: 1,
                data: b"foo",
                end_stream: true,
                padding: Some(0),
            },
        ),
        (
            // Go TestWriteDataPadded case 2: the length 7 is the pad length, the data, and 3 bytes
            // of padding.
            "Go TestWriteDataPadded 2, with the layout of RFC 9113, figure 3",
            b"\x00\x00\x07\x00\x08\x00\x00\x00\x01\x03foo\x00\x00\x00",
            Frame::Data {
                stream: 1,
                data: b"foo",
                end_stream: false,
                padding: Some(3),
            },
        ),
        (
            "Go TestWriteHeaders basic",
            b"\x00\x00\x03\x01\x00\x00\x00\x00*abc",
            Frame::Headers {
                stream: 42,
                fragment: b"abc",
                end_stream: false,
                end_headers: false,
                priority: None,
                padding: None,
            },
        ),
        (
            "Go TestWriteHeaders basic + end flags",
            b"\x00\x00\x03\x01\x05\x00\x00\x00*abc",
            Frame::Headers {
                stream: 42,
                fragment: b"abc",
                end_stream: true,
                end_headers: true,
                priority: None,
                padding: None,
            },
        ),
        (
            "Go TestWriteHeaders with padding",
            b"\x00\x00\x09\x01\x0d\x00\x00\x00*\x05abc\x00\x00\x00\x00\x00",
            Frame::Headers {
                stream: 42,
                fragment: b"abc",
                end_stream: true,
                end_headers: true,
                priority: None,
                padding: Some(5),
            },
        ),
        (
            "Go TestWriteHeaders with priority",
            b"\x00\x00\x0b\x01\x2d\x00\x00\x00*\x02\x80\x00\x00\x0f\x7fabc\x00\x00",
            Frame::Headers {
                stream: 42,
                fragment: b"abc",
                end_stream: true,
                end_headers: true,
                priority: Some(priority(true, 15, 127)),
                padding: Some(2),
            },
        ),
        (
            "Go TestWriteHeaders with priority stream dep zero",
            b"\x00\x00\x0b\x01\x2d\x00\x00\x00*\x02\x80\x00\x00\x00\x7fabc\x00\x00",
            Frame::Headers {
                stream: 42,
                fragment: b"abc",
                end_stream: true,
                end_headers: true,
                priority: Some(priority(true, 0, 127)),
                padding: Some(2),
            },
        ),
        (
            "Go TestWriteHeaders zero length",
            b"\x00\x00\x00\x01\x00\x00\x00\x00*",
            Frame::Headers {
                stream: 42,
                fragment: b"",
                end_stream: false,
                end_headers: false,
                priority: None,
                padding: None,
            },
        ),
        (
            // Go TestWritePriority "not exclusive": stream 42, length 5, dependency 2, weight
            // 127, in the fields of RFC 9113, figure 5.
            "Go TestWritePriority, with the layout of RFC 9113, figure 5",
            b"\x00\x00\x05\x02\x00\x00\x00\x00*\x00\x00\x00\x02\x7f",
            Frame::Priority {
                stream: 42,
                priority: priority(false, 2, 127),
            },
        ),
        (
            // Go TestWritePriority "exclusive": the high bit of the dependency is the flag.
            "Go TestWritePriority exclusive, with the layout of RFC 9113, figure 5",
            b"\x00\x00\x05\x02\x00\x00\x00\x00*\x80\x00\x00\x03\x4d",
            Frame::Priority {
                stream: 42,
                priority: priority(true, 3, 77),
            },
        ),
        (
            "Go TestWriteRST",
            b"\x00\x00\x04\x03\x00\x01\x02\x03\x04\x07\x06\x05\x04",
            Frame::RstStream {
                stream: 0x0102_0304,
                code: ErrorCode(0x0706_0504),
            },
        ),
        (
            "Go TestWriteSettings",
            b"\x00\x00\x0c\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x03\x00\x00\x00\x04",
            Frame::Settings {
                ack: false,
                settings: settings(b"\x00\x01\x00\x00\x00\x02\x00\x03\x00\x00\x00\x04"),
            },
        ),
        (
            "Go TestWriteSettingsAck",
            b"\x00\x00\x00\x04\x01\x00\x00\x00\x00",
            Frame::Settings {
                ack: true,
                settings: settings(b""),
            },
        ),
        (
            "Go TestWritePushPromise",
            b"\x00\x00\x07\x05\x00\x00\x00\x00*\x00\x00\x00*abc",
            Frame::PushPromise {
                stream: 42,
                promised: 42,
                fragment: b"abc",
                end_headers: false,
                padding: None,
            },
        ),
        (
            "Go TestWritePing",
            b"\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08",
            Frame::Ping {
                ack: false,
                opaque: [1, 2, 3, 4, 5, 6, 7, 8],
            },
        ),
        (
            "Go TestWritePingAck",
            b"\x00\x00\x08\x06\x01\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08",
            Frame::Ping {
                ack: true,
                opaque: [1, 2, 3, 4, 5, 6, 7, 8],
            },
        ),
        (
            "Go TestWriteGoAway",
            b"\x00\x00\x0b\x07\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08foo",
            Frame::GoAway {
                last_stream: 0x0102_0304,
                code: ErrorCode(0x0506_0708),
                debug: b"foo",
            },
        ),
        (
            "Go TestWriteWindowUpdate",
            b"\x00\x00\x04\x08\x00\x01\x02\x03\x04\x07\x06\x05\x04",
            Frame::WindowUpdate {
                stream: 0x0102_0304,
                increment: 0x0706_0504,
            },
        ),
        (
            // Go TestWriteContinuation "not end": stream 42, length 3, no flag.
            "Go TestWriteContinuation, with the layout of RFC 9113, figure 12",
            b"\x00\x00\x03\x09\x00\x00\x00\x00*abc",
            Frame::Continuation {
                stream: 42,
                fragment: b"abc",
                end_headers: false,
            },
        ),
        (
            // Go TestWriteContinuation "end": the flag END_HEADERS is 0x4.
            "Go TestWriteContinuation end, with the layout of RFC 9113, figure 12",
            b"\x00\x00\x03\x09\x04\x00\x00\x00*def",
            Frame::Continuation {
                stream: 42,
                fragment: b"def",
                end_headers: true,
            },
        ),
        (
            // RFC 9113, figure 1: a type that section 6 does not define keeps its flags and its
            // payload.
            "RFC 9113, figure 1",
            b"\x00\x00\x02\xfa\x0b\x00\x00\x00\x03xy",
            Frame::Unknown {
                kind: 0xfa,
                flags: 0x0b,
                stream: 3,
                payload: b"xy",
            },
        ),
    ]
}

/// A peer reads each frame as the independent implementation wrote it, and it reads each frame
/// that this codec writes as the same frame.
#[test]
fn each_frame_type_reads_and_writes_its_independent_vector() {
    let mut kinds = Vec::new();
    for (source, wire, frame) in vectors() {
        let parsed = Frame::parse(wire, MAX).unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(parsed, Some((frame, wire.len())), "{source}");
        let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
        frame
            .write(&mut out)
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(out.filled(), wire, "{source}");
        kinds.push(Head::parse(*wire.first_chunk().expect("a header")).kind);
    }
    for kind in (0..=9).map(Kind::from_code) {
        assert!(kinds.contains(&kind), "no vector for {kind:?}");
    }
}

/// Go TestReadFrameHeader: the reserved bit of the stream is ignored (RFC 9113, section 4.1), so
/// a peer that sets it does not move a frame to another stream.
#[test]
fn a_frame_header_ignores_the_reserved_bit() {
    let vectors: [([u8; 9], Head); 3] = [
        (
            *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            Head {
                length: 66_051,
                kind: Kind::Settings,
                flags: 5,
                stream: 101_124_105,
            },
        ),
        (
            [0xff; 9],
            Head {
                length: 16_777_215,
                kind: Kind::Unknown(255),
                flags: 255,
                stream: 2_147_483_647,
            },
        ),
        (
            *b"\xff\xff\xff\xff\xff\x7f\xff\xff\xff",
            Head {
                length: 16_777_215,
                kind: Kind::Unknown(255),
                flags: 255,
                stream: 2_147_483_647,
            },
        ),
    ];
    for (bytes, head) in vectors {
        assert_eq!(Head::parse(bytes), head, "{bytes:02x?}");
    }
}

/// Unused flags are ignored on receipt and unset when sent (RFC 9113, section 4.1). Each frame
/// has every flag bit set that its type does not define, and the reserved bit of its stream.
#[test]
fn unused_flags_are_ignored_and_never_sent() {
    let cases: [(&[u8], &[u8]); 4] = [
        // PING with each flag except ACK: a PING that needs an answer.
        (
            b"\x00\x00\x08\x06\xfe\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08",
            b"\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08",
        ),
        // DATA with each flag except PADDED and END_STREAM: no padding, and the stream goes on.
        (
            b"\x00\x00\x03\x00\xf6\x80\x00\x00\x01abc",
            b"\x00\x00\x03\x00\x00\x00\x00\x00\x01abc",
        ),
        // RST_STREAM, which defines no flag.
        (
            b"\x00\x00\x04\x03\xff\x80\x00\x00\x05\x00\x00\x00\x08",
            b"\x00\x00\x04\x03\x00\x00\x00\x00\x05\x00\x00\x00\x08",
        ),
        // CONTINUATION with each flag except END_HEADERS.
        (
            b"\x00\x00\x01\x09\xfb\x00\x00\x00\x07x",
            b"\x00\x00\x01\x09\x00\x00\x00\x00\x07x",
        ),
    ];
    for (received, clean) in cases {
        let (frame, _) = Frame::parse(received, MAX)
            .expect("unused flags do not refuse")
            .expect("a complete frame");
        assert_eq!(
            Frame::parse(clean, MAX),
            Ok(Some((frame, clean.len()))),
            "{received:02x?}"
        );
        let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(64)));
        frame.write(&mut out).expect("the region holds the frame");
        assert_eq!(out.filled(), clean, "{received:02x?}");
    }
}
