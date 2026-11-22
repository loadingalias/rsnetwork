//! The QUIC frame codec reads a fuzzed payload of frames. The input is the payload.
//!
//! Each frame that parses takes at least one byte and at most the rest of the payload. It writes
//! and parses back to the same frame. The ranges of an ACK frame go down, and none passes packet
//! number 0. The parse stops at the first frame that refuses, as a connection does.

#![no_main]

use rsnetwork::quic::frame::Frame;
use rsnetwork::quic::packet::Kind;

libfuzzer_sys::fuzz_target!(|payload: &[u8]| {
    let mut rest = payload;
    let mut out = vec![0; payload.len() + 64];
    while !rest.is_empty() {
        let Ok((frame, len)) = Frame::parse(rest) else {
            return;
        };
        assert!(
            (1..=rest.len()).contains(&len),
            "a frame took {len} of {} bytes",
            rest.len()
        );
        for kind in [Kind::Initial, Kind::ZeroRtt, Kind::Handshake, Kind::OneRtt] {
            let _permitted = frame.permitted(kind);
        }
        if let Frame::Ack(ack) = frame {
            let mut below = None;
            for range in ack.ranges() {
                assert!(range.start() <= range.end(), "an ACK range goes up");
                assert!(
                    below.is_none_or(|low: u64| *range.end() < low),
                    "the ACK ranges overlap"
                );
                below = Some(*range.start());
            }
        }
        // Each parsed frame writes back to a frame of its own value.
        let written = frame.write(&mut out).expect("a parsed frame writes back");
        assert_eq!(Frame::parse(&out[..written]), Ok((frame, written)), "{frame:?}");
        rest = &rest[len..];
    }
});
