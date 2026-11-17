//! The chunk decoder reads a chunked body. The first byte of the input sets the size of each piece
//! that arrives, with zero for whole. The rest is the body bytes.
//!
//! The pieces must give what the whole input gives: the same data, the same trailers, the same
//! end, and the same refusal. Each step consumes bytes, and no step allocates. The data stays in
//! the body limit, and the trailers stay in their limits.

#![no_main]

use rsnetwork::h1::{ChunkDecoder, ChunkStep, ParseError};
use rsnetwork_fuzz::{BODY, Cut, LIMITS, allocated};

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [pieces, body @ ..] = input else {
        return;
    };
    let whole = decode(body, Cut::Whole);
    let pieces = Cut::from_byte(*pieces);
    if pieces != Cut::Whole {
        assert_eq!(decode(body, pieces), whole, "pieces changed the decoded body");
    }
});

/// The end of a decoded body.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// The body ended after this many bytes, with these trailer field lines.
    Complete { len: usize, trailers: Vec<u8> },
    /// The decoder refused the body.
    Refused(ParseError),
    /// The input ended inside the body.
    Truncated,
}

/// Decodes `body` as it arrives in `pieces`, and gives its data and its end.
fn decode(body: &[u8], pieces: Cut) -> (Vec<u8>, End) {
    let mut decoder = ChunkDecoder::new(BODY, LIMITS);
    let (mut data, mut at, mut arrived) = (Vec::new(), 0, pieces.take(body.len()));
    loop {
        let input = &body[at..arrived];
        let step = if input.is_empty() {
            None
        } else {
            let (step, bytes) = allocated(|| decoder.decode(input));
            assert_eq!(bytes, 0, "a decode step allocated");
            Some(step)
        };
        match step {
            Some(Ok(ChunkStep::Data { framing, data: len })) => {
                assert_ne!(framing + len, 0, "a step consumed nothing");
                data.extend_from_slice(&input[framing..framing + len]);
                assert!(data.len() as u64 <= BODY.body_bytes, "the data passed the body limit");
                at += framing + len;
            }
            Some(Ok(ChunkStep::End { len, trailers })) => {
                let trailers = input[trailers].to_vec();
                assert!(trailers.len() <= BODY.trailer_bytes, "the trailers passed their limit");
                let lines = trailers.array_windows().filter(|&pair| pair == b"\r\n").count();
                assert!(lines <= BODY.trailer_fields, "the trailers passed their line limit");
                return (
                    data,
                    End::Complete {
                        len: at + len,
                        trailers,
                    },
                );
            }
            Some(Err(refusal)) => return (data, End::Refused(refusal)),
            // The decoder needs the next piece: after the input, or with the same trailer bytes.
            Some(Ok(ChunkStep::More)) | None if arrived < body.len() => {
                arrived += pieces.take(body.len() - arrived);
            }
            Some(Ok(ChunkStep::More)) | None => return (data, End::Truncated),
        }
    }
}
