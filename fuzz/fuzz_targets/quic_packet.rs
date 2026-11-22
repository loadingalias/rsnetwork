//! The QUIC packet layer reads a fuzzed region, and seals and opens fuzzed frames. The first byte
//! of the input selects the length of the connection IDs of short headers (its low 5 bits, at most
//! 20) and the kind of the sealed packet (its top 2 bits). The second byte selects the segment
//! size of the region: 0 for one datagram. The rest is the region, and also the frames to seal.
//!
//! The walk of the region gives each packet in its datagram: a packet ends inside the bytes that
//! remain, and each step takes at least one byte, so the walk ends. A packet opens with the
//! Initial keys of the connection ID of RFC 9001, appendix A, or refuses; an opened payload is in
//! the region. The
//! frames that the rest parses to seal in a packet of the selected kind, which opens in place to
//! the same frames.

#![no_main]

use core::num::NonZeroUsize;

use rsnetwork::buffer::{Backing, Buffer as _};
use rsnetwork::quic::ConnectionId;
use rsnetwork::quic::frame::Frame;
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Outgoing, Side};

/// The frames at the start of `bytes` that parse.
fn frames(bytes: &[u8]) -> Vec<Frame<'_>> {
    let (mut frames, mut rest) = (Vec::new(), bytes);
    while let Ok((frame, len)) = Frame::parse(rest) {
        frames.push(frame);
        rest = &rest[len..];
        if rest.is_empty() {
            break;
        }
    }
    frames
}

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, segment, region @ ..] = input else {
        return;
    };
    let short = usize::from(control & 0x1f).min(ConnectionId::MAX);
    // The connection ID of RFC 9001, appendix A, so the packet of a seed opens.
    let dcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).expect("8 bytes");
    let keys = packet::initial_keys(&dcid, Side::Server);

    // The walk of a fuzzed region.
    let backing = Backing::from(region.to_vec());
    let (start, end) = (backing.as_ptr().addr(), backing.as_ptr().addr() + region.len());
    let mut datagrams = Datagrams::new(backing, NonZeroUsize::new(usize::from(*segment)), short);
    let mut steps = 0;
    while let Some(next) = datagrams.next_packet() {
        steps += 1;
        assert!(steps <= region.len(), "the walk takes no byte");
        let Ok(protected) = next else { continue };
        if matches!(protected.header(), Header::Protected { .. }) {
            if let Ok(unmasked) = protected.unmask(&*keys.remote.header, 0)
                && let Ok(packet) = unmasked.open(&*keys.remote.packet)
            {
                let payload = packet.payload();
                let at = payload.as_ptr().addr();
                assert!(
                    at >= start && at + payload.bytes().len() <= end,
                    "a payload left the region"
                );
                frames(payload.bytes());
            }
        } else {
            let taken = protected.take();
            assert!(!taken.bytes().is_empty(), "a packet has no byte");
        }
    }

    // A packet of fuzzed frames seals and opens in place to the same frames.
    let frames = frames(region);
    let client = packet::initial_keys(&dcid, Side::Client);
    let scid = ConnectionId::new(&[0x11; 4]).expect("4 bytes");
    let header = match control >> 6 {
        0 => Outgoing::Initial {
            dcid: &dcid,
            scid: &scid,
            token: b"token",
        },
        1 => Outgoing::ZeroRtt {
            dcid: &dcid,
            scid: &scid,
        },
        2 => Outgoing::Handshake {
            dcid: &dcid,
            scid: &scid,
        },
        _ => Outgoing::OneRtt {
            dcid: &dcid,
            spin: control & 0x20 != 0,
            key_phase: true,
        },
    };
    let number_len = usize::from(*segment & 3) + 1;
    let mut out = vec![0; region.len() * 2 + 128];
    let mut builder = Builder::new(&mut out, header, 7, number_len).expect("the output has room for the header");
    let mut sealed_frames = Vec::new();
    for frame in &frames {
        if builder.frame(frame).is_ok() {
            sealed_frames.push(*frame);
        }
    }
    if sealed_frames.is_empty() {
        builder.frame(&Frame::Ping).expect("a PING fits");
        sealed_frames.push(Frame::Ping);
    }
    let len = builder.seal(&client.local).expect("the Initial keys seal");
    out.truncate(len);
    let short = if matches!(header, Outgoing::OneRtt { .. }) {
        dcid.as_bytes().len()
    } else {
        0
    };
    let mut datagrams = Datagrams::new(Backing::from(out), None, short);
    let packet = datagrams
        .next_packet()
        .expect("a packet")
        .expect("a valid header")
        .unmask(&*keys.remote.header, 7)
        .expect("the header protection opens")
        .open(&*keys.remote.packet)
        .expect("the payload opens");
    assert_eq!(packet.number(), 7);
    let payload = packet.payload();
    let opened = self::frames(payload.bytes());
    // The seal can add PADDING after the frames for the sample of the header protection.
    let opened: Vec<Frame<'_>> = opened
        .into_iter()
        .filter(|frame| !matches!(frame, Frame::Padding { .. }))
        .collect();
    let sealed: Vec<Frame<'_>> = sealed_frames
        .into_iter()
        .filter(|frame| !matches!(frame, Frame::Padding { .. }))
        .collect();
    assert_eq!(opened, sealed);
});
