//! HTTP/3 frame boundaries and stream placement from RFC 9114, sections 6 and 7.

use rsnetwork::h3::frame::{Decoder, Error, Header, Kind, Part, Stream, StreamType, WriteError};

#[test]
fn early_hints_and_the_final_response_have_separate_qpack_sections() {
    use core::num::NonZeroU64;
    use rsnetwork::buffer::WriteLoan;
    use rsnetwork::capacity::Budget;
    use rsnetwork::qpack;

    // RFC 9204 Appendix A. Static entries 24 and 25 are :status 103 and 200.
    // Literal with a static name reference to entry 11 (link), then a plain string.
    let link = b"</s.css>; rel=preload; as=style";
    let mut wire = vec![
        1,
        u8::try_from(5 + link.len()).unwrap(),
        0,
        0,
        0xd8,
        0x5b,
        u8::try_from(link.len()).unwrap(),
    ];
    wire.extend_from_slice(link);
    wire.extend_from_slice(&[1, 3, 0, 0, 0xd9, 0, 2, b'o', b'k']);
    let limits = qpack::Limits {
        table_bytes: 0,
        blocked_streams: 0,
        list_bytes: 1024,
        work: 1024,
    };
    let budget = Budget::new(NonZeroU64::new(64 << 10).unwrap());
    let mut qpack = qpack::Decoder::new(limits, &budget).unwrap();
    let mut lines = qpack::Lines::new(limits, &budget).unwrap();
    let mut feedback = WriteLoan::new(Vec::<u8>::new());
    let mut frames = Decoder::new(Stream::Response);
    let mut sections = Vec::new();
    let mut body = Vec::new();
    for part in drive(&mut frames, [wire.as_slice()]).unwrap() {
        match part {
            Part::Bytes {
                kind: Kind::HEADERS,
                bytes,
                end: true,
            } => {
                let block = qpack.decode(0, bytes, &mut lines, &mut feedback).unwrap();
                sections.push(
                    block
                        .lines()
                        .map(|line| (line.name.to_vec(), line.value.to_vec()))
                        .collect::<Vec<_>>(),
                );
            }
            Part::Bytes {
                kind: Kind::DATA,
                bytes,
                ..
            } => body.extend_from_slice(bytes),
            _ => {}
        }
    }
    assert_eq!(
        sections,
        [
            vec![
                (b":status".to_vec(), b"103".to_vec()),
                (b"link".to_vec(), link.to_vec())
            ],
            vec![(b":status".to_vec(), b"200".to_vec())],
        ]
    );
    assert_eq!(body, b"ok");
    assert_eq!(frames.finish(), Ok(()));
}

fn drive<'a>(decoder: &mut Decoder, chunks: impl IntoIterator<Item = &'a [u8]>) -> Result<Vec<Part<'a>>, Error> {
    let mut parts = Vec::new();
    for mut chunk in chunks {
        while !chunk.is_empty() {
            let before = chunk.len();
            if let Some(part) = decoder.next(&mut chunk)? {
                parts.push(part);
            }
            assert!(chunk.len() < before, "each step consumes input");
        }
    }
    Ok(parts)
}

#[test]
fn settings_an_extension_and_goaway_survive_every_wire_boundary() {
    // SETTINGS (two parameters), a grease frame with three opaque bytes, then GOAWAY for request 12.
    // HTTP/3 permits the nonminimal two-byte encodings of types, lengths, IDs, and values.
    let wire = [
        0x40, 4, 0x40, 7, 1, 0x41, 0, 0x40, 7, 0x40, 16, 0x21, 3, 0xff, 0x09, 4, 7, 2, 0x40, 12,
    ];
    for width in 1..=wire.len() {
        let mut decoder = Decoder::new(Stream::ServerControl);
        let mut events = drive(&mut decoder, wire.chunks(width)).unwrap();
        assert_eq!(
            events
                .iter()
                .filter_map(|p| match p {
                    Part::Skipped(n) => Some(n),
                    _ => None,
                })
                .sum::<usize>(),
            3
        );
        events.retain(|p| !matches!(p, Part::Skipped(_)));
        assert_eq!(
            events,
            [
                Part::Header(Header {
                    kind: Kind::SETTINGS,
                    len: 7
                }),
                Part::Setting { id: 1, value: 256 },
                Part::Setting { id: 7, value: 16 },
                Part::Header(Header {
                    kind: Kind::new(0x21).unwrap(),
                    len: 3
                }),
                Part::Header(Header {
                    kind: Kind::GOAWAY,
                    len: 2
                }),
                Part::Id {
                    kind: Kind::GOAWAY,
                    id: 12
                },
            ]
        );
        assert_eq!(decoder.finish(), Err(Error::ClosedCriticalStream));
    }
}

#[test]
fn request_and_push_payloads_borrow_only_the_bytes_in_their_own_frame() {
    let wire = [1, 2, 0x00, 0x00, 0, 3, b'a', b'b', b'c', 1, 0];
    for stream in [Stream::Request, Stream::Response, Stream::Push] {
        let mut decoder = Decoder::new(stream);
        let parts = drive(&mut decoder, [&wire[..7], &wire[7..]]).unwrap();
        assert_eq!(
            parts,
            [
                Part::Header(Header {
                    kind: Kind::HEADERS,
                    len: 2
                }),
                Part::Bytes {
                    kind: Kind::HEADERS,
                    bytes: &wire[2..4],
                    end: true
                },
                Part::Header(Header {
                    kind: Kind::DATA,
                    len: 3
                }),
                Part::Bytes {
                    kind: Kind::DATA,
                    bytes: &wire[6..7],
                    end: false
                },
                Part::Bytes {
                    kind: Kind::DATA,
                    bytes: &wire[7..9],
                    end: true
                },
                Part::Header(Header {
                    kind: Kind::HEADERS,
                    len: 0
                }),
            ]
        );
        let Part::Bytes { bytes, .. } = parts[3] else {
            panic!("expected a DATA region")
        };
        assert_eq!(bytes.as_ptr(), wire[6..].as_ptr());
        assert_eq!(decoder.finish(), Ok(()));
    }
    let mut response = Decoder::new(Stream::Response);
    let wire = [5, 4, 0x40, 23, 0, 0];
    assert_eq!(
        drive(&mut response, [&wire[..3], &wire[3..]]).unwrap(),
        [
            Part::Header(Header {
                kind: Kind::PUSH_PROMISE,
                len: 4
            }),
            Part::Id {
                kind: Kind::PUSH_PROMISE,
                id: 23
            },
            Part::Bytes {
                kind: Kind::PUSH_PROMISE,
                bytes: &[0, 0],
                end: true
            }
        ]
    );
}

#[test]
fn frame_placement_and_the_first_settings_follow_the_sending_stream() {
    use Stream::{ClientControl as C, Push as P, Request as Q, Response as R, ServerControl as S};
    let cases: &[(&[u8], &[Stream])] = &[
        (&[0, 0], &[Q, R, P]),
        (&[1, 0], &[Q, R, P]),
        (&[3, 1, 0], &[C, S]),
        (&[5, 3, 0, 0, 0], &[R]),
        (&[7, 1, 0], &[C, S]),
        (&[13, 1, 0], &[C]),
        (&[0x21, 0], &[C, S, Q, R, P]),
        (&[2, 0], &[]),
        (&[6, 0], &[]),
        (&[8, 0], &[]),
        (&[9, 0], &[]),
    ];
    for stream in [C, S, Q, R, P] {
        for &(wire, allowed) in cases {
            let mut decoder = Decoder::new(stream);
            if matches!(stream, C | S) {
                drive(&mut decoder, [&[4, 0][..]]).unwrap();
            }
            assert_eq!(
                drive(&mut decoder, [wire]).map(|_| ()),
                if allowed.contains(&stream) {
                    Ok(())
                } else {
                    Err(Error::FrameUnexpected)
                },
                "{stream:?} {wire:?}"
            );
        }
        let mut decoder = Decoder::new(stream);
        let first = drive(&mut decoder, [&[4, 0][..]]);
        if matches!(stream, C | S) {
            first.unwrap();
            assert_eq!(drive(&mut decoder, [&[4, 0][..]]), Err(Error::FrameUnexpected));
            assert_eq!(
                drive(&mut Decoder::new(stream), [&[0x21, 0][..]]),
                Err(Error::MissingSettings)
            );
        } else {
            assert_eq!(first, Err(Error::FrameUnexpected));
        }
    }
}

#[test]
fn an_id_or_setting_cannot_take_bytes_from_the_next_frame() {
    for (frame, error) in [
        (&[7, 1, 0x40][..], Error::Frame),
        (&[7, 2, 0, 0], Error::Frame),
        (&[7, 1, 2], Error::Id),
        (&[4, 1, 1], Error::Frame),
        (&[4, 2, 1, 0x40], Error::Frame),
        (&[4, 2, 2, 0], Error::Settings),
        (&[4, 2, 3, 0], Error::Settings),
        (&[4, 2, 4, 0], Error::Settings),
        (&[4, 2, 5, 0], Error::Settings),
    ] {
        let mut decoder = Decoder::new(Stream::ServerControl);
        if frame[0] != 4 {
            drive(&mut decoder, [&[4, 0][..]]).unwrap();
        }
        let wire = [frame, &[0x21, 0]].concat();
        let mut rest = wire.as_slice();
        let result = loop {
            match decoder.next(&mut rest) {
                Ok(Some(_)) => continue,
                other => break other,
            }
        };
        assert_eq!(result, Err(error));
        assert!(rest.ends_with(&[0x21, 0]), "the following frame stays intact");
        assert_eq!(decoder.finish(), Err(error));
        assert_eq!(decoder.next(&mut rest), Err(error));
    }
}

#[test]
fn clean_fin_distinguishes_a_complete_boundary_from_a_partial_frame() {
    let mut decoder = Decoder::new(Stream::Request);
    let wire = [0x40, 0x21, 0xc0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3];
    assert_eq!(decoder.finish(), Ok(()));
    for (i, one) in wire.chunks(1).enumerate() {
        drive(&mut decoder, [one]).unwrap();
        assert_eq!(
            decoder.finish(),
            if i + 1 == wire.len() { Ok(()) } else { Err(Error::Frame) }
        );
    }
    let mut decoder = Decoder::new(Stream::Response);
    let large = [0x21, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2];
    assert_eq!(
        drive(&mut decoder, [&large[..]]).unwrap(),
        [
            Part::Header(Header {
                kind: Kind::new(0x21).unwrap(),
                len: (1 << 62) - 1
            }),
            Part::Skipped(2),
        ]
    );
    assert_eq!(decoder.finish(), Err(Error::Frame));
}

#[test]
fn stream_prefixes_preserve_the_first_byte_of_stream_content() {
    for (id, ty) in [
        (0, StreamType::Control),
        (1, StreamType::Push),
        (2, StreamType::QpackEncoder),
        (3, StreamType::QpackDecoder),
        (0x21, StreamType::Extension(0x21)),
    ] {
        let wire = [0x80, 0, 0, id, 0xff];
        for cut in 0..4 {
            assert_eq!(StreamType::read(&wire[..cut]), None);
        }
        assert_eq!(StreamType::read(&wire), Some((ty, 4)));
    }
}

#[test]
fn writing_a_header_uses_the_shortest_encoding_or_leaves_the_output_intact() {
    let header = Header {
        kind: Kind::new(0x1234).unwrap(),
        len: 65_536,
    };
    let mut out = [0xa5; 7];
    for cap in 0..6 {
        assert_eq!(header.write(&mut out[..cap]), Err(WriteError::Space));
        assert_eq!(out, [0xa5; 7]);
    }
    assert_eq!(
        Header { len: 1 << 62, ..header }.write(&mut out),
        Err(WriteError::Value)
    );
    assert_eq!(out, [0xa5; 7]);
    assert_eq!(header.write(&mut out), Ok(6));
    assert_eq!(out, [0x52, 0x34, 0x80, 1, 0, 0, 0xa5]);
}
