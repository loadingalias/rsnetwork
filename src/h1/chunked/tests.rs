//! The contracts of the chunked decoder. Each body, its data, and its trailers come from the
//! grammar of RFC 9112, section 7.1, not from the code under test.

use std::collections::VecDeque;

use super::{ChunkDecoder, ChunkStep};
use crate::h1::{BodyLimits, Limits, ParseError};

const FIELDS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 0,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

/// The data, the trailer field lines, and the length of a decoded body.
type Decoded = (Vec<u8>, Vec<u8>, usize);

/// Decodes the body at the start of `input`, cut at `cuts` into pieces, as an engine gives
/// received regions: the decoder reads the bytes of the front piece that it did not consume, and
/// a trailer section that continues joins the next piece. Gives `None` if the input ends first.
fn decode(limits: BodyLimits, input: &[u8], cuts: &[usize]) -> Result<Option<Decoded>, ParseError> {
    let mut pieces = VecDeque::new();
    let mut start = 0;
    for &cut in cuts.iter().chain([&input.len()]) {
        pieces.push_back(input[start..cut].to_vec());
        start = cut;
    }
    let mut decoder = ChunkDecoder::new(limits, FIELDS);
    let (mut data, mut consumed) = (Vec::new(), 0);
    while let Some(front) = pieces.front_mut() {
        match decoder.decode(front)? {
            ChunkStep::Data { framing, data: len } => {
                data.extend_from_slice(&front[framing..framing + len]);
                front.drain(..framing + len);
                consumed += framing + len;
                if front.is_empty() {
                    pieces.pop_front();
                }
            }
            ChunkStep::End { len, trailers } => return Ok(Some((data, front[trailers].to_vec(), consumed + len))),
            ChunkStep::More => match pieces.remove(1) {
                Some(next) => pieces[0].extend_from_slice(&next),
                None => return Ok(None),
            },
        }
    }
    Ok(None)
}

/// A body with an extension of each form, a hexadecimal size in upper case, a last chunk with
/// leading zeros, and two trailers. The bytes of the next request follow it.
const BODY_BYTES: &[u8] = b"5;name=value;flag\r\nhello\r\n\
    1A ; q=\"a \\\"b\\\" c\"\t;n = v\r\nabcdefghijklmnopqrstuvwxyz\r\n\
    0000\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Sum: 31\r\n\r\n";

/// The body decodes to the same data, trailers, and length whole, cut in two at each position,
/// and one byte at a time. The bytes after the body stay unread.
#[test]
fn a_chunked_body_decodes_the_same_in_any_pieces() {
    let input = [BODY_BYTES, b"GET / HTTP/1.1\r\n"].concat();
    let expected = (
        b"helloabcdefghijklmnopqrstuvwxyz".to_vec(),
        b"Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Sum: 31\r\n".to_vec(),
        BODY_BYTES.len(),
    );
    assert_eq!(decode(BODY, &input, &[]), Ok(Some(expected.clone())));
    for cut in 1..input.len() {
        assert_eq!(decode(BODY, &input, &[cut]), Ok(Some(expected.clone())), "cut at {cut}");
    }
    let each: Vec<usize> = (1..input.len()).collect();
    assert_eq!(decode(BODY, &input, &each), Ok(Some(expected)));

    // No trailer, and a body that ends in its last byte.
    assert_eq!(
        decode(BODY, b"1\r\na\r\n0\r\n\r\n", &[]),
        Ok(Some((b"a".to_vec(), Vec::new(), 11)))
    );
    assert_eq!(decode(BODY, b"1\r\na\r\n0\r\n\r", &[]), Ok(None));
}

/// Each body differs from a valid one by one defect, and each refuses. A decoder that accepts one
/// of them reads a different body than a strict peer does, which can smuggle a request.
#[test]
fn each_chunk_framing_defect_refuses() {
    for (input, expected) in [
        (&b"g\r\n"[..], ParseError::Framing),
        (b"\r\n", ParseError::Framing),
        (b"+5\r\n", ParseError::Framing),
        (b"0x5\r\n", ParseError::Framing),
        (b"11111111111111111\r\n", ParseError::Framing),
        (b"5\nhello\r\n", ParseError::Framing),
        (b"5\r\nhelloX\r\n", ParseError::Framing),
        (b"5\r\nhello\r\r\n", ParseError::Framing),
        (b"5 \r\nhello\r\n", ParseError::Framing),
        (b"5;\r\nhello\r\n", ParseError::Framing),
        (b"5;a=\r\nhello\r\n", ParseError::Framing),
        (b"5;a b\r\nhello\r\n", ParseError::Framing),
        (b"5;a=b c\r\nhello\r\n", ParseError::Framing),
        (b"5;a=\"b\r\nhello\r\n", ParseError::Framing),
        (b"5;a=\"\x01\"\r\nhello\r\n", ParseError::Framing),
        (b"5;a\n\r\nhello\r\n", ParseError::Framing),
        (b"0\r\n\r\x00", ParseError::Framing),
        (b"0\r\n\n", ParseError::Malformed),
        (b"0\r\nX a\r\n\r\n", ParseError::Malformed),
        (b"0\r\n X: a\r\n\r\n", ParseError::Malformed),
    ] {
        assert_eq!(decode(BODY, input, &[]), Err(expected), "{}", input.escape_ascii());
    }
}

/// A body over a limit refuses as soon as the size line or the trailer field that passes the
/// limit arrives, before its data. A body of exactly a limit passes.
#[test]
fn a_chunked_body_over_a_limit_refuses_before_its_data() {
    let limits = BodyLimits {
        body_bytes: 16,
        extension_bytes: 8,
        trailer_bytes: 32,
        trailer_fields: 2,
        ..BODY
    };
    let refused = |input: &[u8]| decode(limits, input, &[]).err();
    assert_eq!(refused(b"11\r\n"), Some(ParseError::BodyTooLarge));
    assert_eq!(refused(b"8\r\n12345678\r\n9\r\n"), Some(ParseError::BodyTooLarge));
    assert_eq!(refused(b"10\r\n0123456789abcdef\r\n0\r\n\r\n"), None);
    assert_eq!(refused(b"1;abcdefgh\r\n"), Some(ParseError::ExtensionTooLarge));
    assert_eq!(refused(b"1;abcdefg\r\na\r\n0\r\n\r\n"), None);
    assert_eq!(
        refused(b"0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"),
        Some(ParseError::TooManyFields)
    );
    assert_eq!(
        refused(b"0\r\nA: 01234567890123456789012345\r\n\r\n"),
        Some(ParseError::HeadTooLarge)
    );
    assert_eq!(refused(b"0\r\nA: 0123456789012345678901\r\n\r\n"), None);
}
