//! The first byte selects the sending stream and chunk size. The remaining bytes carry HTTP/3 frames.
//! Fragmentation preserves each header, field, payload byte, skipped length, and terminal result.
#![no_main]

use rsnetwork::h3::frame::{Decoder, Error, Header, Part, Stream};

#[derive(Debug, PartialEq, Eq)]
struct Seen {
    headers: Vec<Header>,
    fields: Vec<(u64, u64)>,
    bytes: Vec<u8>,
    skipped: usize,
    end: Result<(), Error>,
}

fn observe(wire: &[u8], width: usize, stream: Stream) -> Seen {
    let mut decoder = Decoder::new(stream);
    let mut seen = Seen {
        headers: Vec::new(),
        fields: Vec::new(),
        bytes: Vec::new(),
        skipped: 0,
        end: Ok(()),
    };
    for mut chunk in wire.chunks(width) {
        while !chunk.is_empty() {
            let before = chunk.len();
            match decoder.next(&mut chunk) {
                Ok(Some(Part::Header(header))) => seen.headers.push(header),
                Ok(Some(Part::Bytes { bytes, .. })) => seen.bytes.extend_from_slice(bytes),
                Ok(Some(Part::Id { kind, id })) => seen.fields.push((kind.id(), id)),
                Ok(Some(Part::Setting { id, value })) => seen.fields.push((id, value)),
                Ok(Some(Part::Skipped(n))) => seen.skipped += n,
                Ok(None) => assert!(chunk.is_empty()),
                Err(e) => {
                    seen.end = Err(e);
                    return seen;
                }
            }
            assert!(chunk.len() < before);
        }
    }
    seen.end = decoder.finish();
    seen
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&mode, wire)) = data.split_first() else {
        return;
    };
    let streams = [
        Stream::Request,
        Stream::Response,
        Stream::Push,
        Stream::ClientControl,
        Stream::ServerControl,
    ];
    let stream = streams[usize::from(mode) % streams.len()];
    let whole = observe(wire, wire.len().max(1), stream);
    let split = observe(wire, usize::from(mode / 5) + 1, stream);
    assert_eq!(whole, split);
});
