//! The QPACK encoder encodes fuzzed field lines and reads a fuzzed decoder stream on one
//! connection. The first byte of the input selects the table of the encoder, the settings of the
//! peer, and the most sections that wait. The second byte selects the room of the region for a
//! section. The rest is a sequence of records, each a kind byte, a length in two bytes,
//! big-endian, and the bytes. An even kind is a section of stream `kind >> 1`: its bytes are
//! lines, each a byte with the never-indexed mark in bit 7 and the length of the name in the
//! other bits, a byte with the length of the value, the name, and the value. An odd kind is the
//! next bytes of the decoder stream.
//!
//! No call allocates. A section that refuses for lack of room writes no instruction, and then
//! encodes in a larger region. A decoder with the settings of the peer reads each section after
//! its instructions, with no wait, and gives the same lines, with each never-indexed mark. Its
//! decoder stream goes back to the encoder with the fuzzed one. A refused decoder instruction
//! ends the run, after a check that a later call refuses too.

#![no_main]

use core::num::NonZeroU64;

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::qpack::{
    DecodeError, Decoder, EncodeError, Encoder, EncoderLimits, FieldLine, Limits, Lines, Settings, StreamError,
};
use rsnetwork_fuzz::allocated;

/// Table capacities, blocked streams, section limits, and rooms that the control bytes select.
const TABLES: [usize; 4] = [0, 64, 256, 4096];
const BLOCKED: [u64; 4] = [0, 1, 4, 100];
const SECTIONS: [usize; 4] = [0, 1, 4, 64];
const ROOMS: [usize; 4] = [4, 64, 1024, 1 << 20];

fn region(capacity: usize) -> WriteLoan<Backing> {
    WriteLoan::new(Backing::from(Vec::with_capacity(capacity)))
}

/// The lines of `bytes`, in the format of the module documentation. A cut line is dropped.
fn lines(mut bytes: &[u8]) -> Vec<FieldLine<'_>> {
    let mut lines = Vec::new();
    while let &[head, value, ref rest @ ..] = bytes {
        let name = usize::from(head & 0x7f);
        let value = usize::from(value);
        let Some((line, after)) = rest.split_at_checked(name + value) else {
            break;
        };
        let (name, value) = line.split_at(name);
        lines.push(FieldLine {
            name,
            value,
            never_indexed: head & 0x80 != 0,
        });
        bytes = after;
    }
    lines
}

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, room, records @ ..] = input else {
        return;
    };
    let pick = |shift: u8| usize::from((control >> shift) & 3);
    let peer = Settings {
        table_bytes: TABLES[pick(2)] as u64,
        blocked_streams: BLOCKED[pick(4)],
    };
    let room = ROOMS[usize::from(room & 3)];
    let budget = Budget::new(NonZeroU64::new(1 << 26).expect("not zero"));
    let limits = EncoderLimits {
        table_bytes: TABLES[pick(0)],
        sections: SECTIONS[pick(6)],
    };
    let mut encoder = Encoder::new(limits, &budget).expect("the budget pays for the encoder");
    encoder.set_peer(peer).expect("the first settings");
    let decoder_limits = Limits {
        table_bytes: TABLES[pick(2)],
        blocked_streams: 100,
        list_bytes: 1 << 20,
        work: 1 << 24,
    };
    let mut decoder = Decoder::new(decoder_limits, &budget).expect("the budget pays for the decoder");
    let mut decoded_lines = Lines::new(decoder_limits, &budget).expect("the budget pays for the lines");
    let mut rest = records;
    while let &[kind, high, low, ref after @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([high, low])).min(after.len());
        let (bytes, next) = after.split_at(len);
        rest = next;
        if kind & 1 == 1 {
            let (result, allocations) = allocated(|| encoder.receive(bytes));
            assert_eq!(allocations, 0, "a read of the decoder stream allocated");
            if result.is_err() {
                assert_eq!(encoder.receive(b""), Err(StreamError::Decoder), "a later read");
                return;
            }
            continue;
        }
        let stream = u64::from(kind >> 1);
        let lines = lines(bytes);
        let (mut section, mut instructions) = (region(room), region(1 << 16));
        let (mut result, allocations) =
            allocated(|| encoder.encode(stream, lines.iter().copied(), &mut section, &mut instructions));
        assert_eq!(allocations, 0, "an encode allocated");
        if let Err(EncodeError::Full(_)) = result {
            assert!(
                instructions.filled().is_empty(),
                "a refused encode wrote an instruction"
            );
            section = region(1 << 20);
            result = encoder.encode(stream, lines.iter().copied(), &mut section, &mut instructions);
        }
        let prefix = result.expect("the region holds the section");
        let mut back = region(1 << 16);
        let read = decoder
            .receive(instructions.filled(), &mut back)
            .expect("the decoder reads the encoder stream");
        assert_eq!(read, instructions.filled().len(), "the decoder stopped early");
        let bytes = [prefix.bytes(), section.filled()].concat();
        let block = match decoder.decode(stream, &bytes, &mut decoded_lines, &mut back) {
            Ok(block) => block,
            Err(DecodeError::Blocked) => panic!("a section waits after its instructions"),
            Err(error) => panic!("the decoder refused the section: {error}"),
        };
        assert_eq!(block.len(), lines.len(), "the decoder read another number of lines");
        for (line, again) in lines.iter().zip(block.lines()) {
            assert_eq!((line.name, line.value), (again.name, again.value), "a line changed");
            assert!(
                !line.never_indexed || again.never_indexed,
                "a never-indexed line lost its mark"
            );
        }
        if encoder.receive(back.filled()).is_err() {
            // The fuzzed decoder stream can make the true one invalid, for example with a second
            // acknowledgement of a section.
            return;
        }
    }
});
