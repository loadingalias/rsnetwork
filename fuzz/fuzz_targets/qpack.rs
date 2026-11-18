//! The QPACK decoder reads a fuzzed encoder stream and fuzzed field sections on one connection.
//! The first byte of the input selects the limits of the decoder, and the second byte the room of
//! each region for the decoder stream. The rest is a sequence of records, each a kind byte, a
//! length in two bytes, big-endian, and the bytes. The low two bits of the kind select the
//! record: 0 is the next bytes of the encoder stream, 1 a field section of stream `kind >> 2`,
//! and 2 a cancellation of that stream.
//!
//! No call allocates or changes the charge. Each read of the encoder stream reads at least one
//! byte. After a refused instruction, each later call refuses, and a connection error ends the
//! run. A model of the blocked streams holds: a stream blocks only while fewer than
//! `blocked_streams` other streams wait, and `unblocked` gives only streams that wait. A section
//! that refuses for lack of room on the decoder stream decodes in a new region of 64 bytes. The
//! lines of a section stay in the list limit. An encoder sends the lines of each decoded section
//! to a second decoder, which must read the same lines and marks, and the encoder must accept the
//! decoder stream of the second decoder.

#![no_main]

use core::num::NonZeroU64;

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::qpack::{DecodeError, Decoder, Encoder, EncoderLimits, FieldLine, Limits, Lines, Settings, StreamError};
use rsnetwork_fuzz::allocated;

/// Table capacities, blocked streams, list sizes, work limits, and rooms that the control bytes
/// select.
const TABLES: [usize; 4] = [0, 64, 256, 4096];
const BLOCKED: [usize; 4] = [0, 1, 4, 100];
const LISTS: [usize; 4] = [0, 128, 1024, 16 * 1024];
const WORK: [usize; 4] = [16, 256, 4096, 1 << 20];
const ROOMS: [usize; 4] = [0, 2, 8, 64];

fn region(capacity: usize) -> WriteLoan<Backing> {
    WriteLoan::new(Backing::from(Vec::with_capacity(capacity)))
}

/// The second decoder, its lines, and the encoder that writes to it.
struct Echo {
    encoder: Encoder,
    decoder: Decoder,
    lines: Lines,
}

impl Echo {
    fn new(budget: &Budget) -> Self {
        let limits = Limits {
            table_bytes: 4096,
            blocked_streams: 100,
            list_bytes: 1 << 20,
            work: 1 << 24,
        };
        let mut encoder = Encoder::new(
            EncoderLimits {
                table_bytes: 4096,
                sections: 64,
            },
            budget,
        )
        .expect("the budget pays for the encoder");
        encoder
            .set_peer(Settings {
                table_bytes: 4096,
                blocked_streams: 100,
            })
            .expect("the first settings");
        Self {
            encoder,
            decoder: Decoder::new(limits, budget).expect("the budget pays for the second decoder"),
            lines: Lines::new(limits, budget).expect("the budget pays for the second lines"),
        }
    }

    /// Encodes `received` on `stream`, and checks that the second decoder reads the same lines.
    fn check(&mut self, stream: u64, received: &[FieldLine<'_>]) {
        let (mut section, mut instructions, mut back) = (region(1 << 20), region(1 << 20), region(1 << 20));
        let prefix = self
            .encoder
            .encode(stream, received.iter().copied(), &mut section, &mut instructions)
            .expect("the region holds the section");
        let read = self
            .decoder
            .receive(instructions.filled(), &mut back)
            .expect("the second decoder reads the encoder stream");
        assert_eq!(read, instructions.filled().len(), "the second decoder stopped early");
        let bytes = [prefix.bytes(), section.filled()].concat();
        let decoded = self
            .decoder
            .decode(stream, &bytes, &mut self.lines, &mut back)
            .expect("the second decoder reads the encoder");
        assert_eq!(
            decoded.len(),
            received.len(),
            "the second decoder read another number of lines"
        );
        for (line, again) in received.iter().zip(decoded.lines()) {
            assert_eq!((line.name, line.value), (again.name, again.value), "a line changed");
            assert!(
                !line.never_indexed || again.never_indexed,
                "a never-indexed line lost its mark"
            );
        }
        self.encoder
            .receive(back.filled())
            .expect("the encoder reads the decoder stream");
    }
}

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, room, records @ ..] = input else {
        return;
    };
    let pick = |byte: u8, shift: u8| usize::from((byte >> shift) & 3);
    let limits = Limits {
        table_bytes: TABLES[pick(*control, 0)],
        blocked_streams: BLOCKED[pick(*control, 2)],
        list_bytes: LISTS[pick(*control, 4)],
        work: WORK[pick(*control, 6)],
    };
    let room = ROOMS[pick(*room, 0)];
    let budget = Budget::new(NonZeroU64::new(1 << 26).expect("not zero"));
    let mut decoder = Decoder::new(limits, &budget).expect("the budget pays for the decoder");
    let mut lines = Lines::new(limits, &budget).expect("the budget pays for the lines");
    let mut echo = Echo::new(&budget);
    // The streams that wait, with their sections.
    let mut waiting: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut rest = records;
    while let &[kind, high, low, ref after @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([high, low])).min(after.len());
        let (bytes, next) = after.split_at(len);
        rest = next;
        let stream = u64::from(kind >> 2);
        let available = budget.available();
        let mut out = region(room.max(64));
        let mut ready = Vec::new();
        match kind & 3 {
            0 => {
                let mut left = bytes;
                loop {
                    let (result, allocations) = allocated(|| decoder.receive(left, &mut out));
                    assert_eq!(allocations, 0, "a read allocated");
                    match result {
                        Ok(read) => {
                            assert!(read > 0 || left.is_empty(), "a read made no progress");
                            left = &left[read..];
                        }
                        Err(error) => {
                            assert_eq!(error, StreamError::Encoder, "the decoder refused with another error");
                            assert_eq!(
                                decoder.receive(b"", &mut out),
                                Err(StreamError::Encoder),
                                "a later read"
                            );
                            let later = decoder.decode(stream, &[0, 0], &mut lines, &mut out).map(|_| ());
                            assert_eq!(later, Err(DecodeError::Malformed), "a later section");
                            // A connection error ends the connection.
                            return;
                        }
                    }
                    if left.is_empty() {
                        break;
                    }
                }
                while let Some(stream) = decoder.unblocked() {
                    let at = waiting
                        .iter()
                        .position(|&(waits, _)| waits == stream)
                        .expect("unblocked gave a stream that does not wait");
                    ready.push(waiting.swap_remove(at));
                }
            }
            1 => ready.push((stream, bytes.to_vec())),
            2 => {
                let mut small = region(room);
                let (result, allocations) = allocated(|| decoder.cancel(stream, &mut small));
                assert_eq!(allocations, 0, "a cancellation allocated");
                if result.is_ok() {
                    waiting.retain(|&(waits, _)| waits != stream);
                } else {
                    assert!(room < 64, "a cancellation refused a region of 64 bytes");
                }
            }
            _ => {}
        }
        for (stream, section) in ready {
            let mut small = region(room);
            let (result, allocations) = allocated(|| decoder.decode(stream, &section, &mut lines, &mut small));
            assert_eq!(allocations, 0, "a decode allocated");
            let owned = |block: rsnetwork::qpack::Block<'_>| -> Vec<(Vec<u8>, Vec<u8>, bool)> {
                block
                    .lines()
                    .map(|line| (line.name.to_vec(), line.value.to_vec(), line.never_indexed))
                    .collect()
            };
            let mut result = result.map(owned);
            if let Err(DecodeError::Full(_)) = result {
                // A new region: earlier reads of the record can fill `out` with increments.
                result = decoder.decode(stream, &section, &mut lines, &mut region(64)).map(owned);
                assert!(
                    !matches!(
                        result,
                        Err(DecodeError::Full(_) | DecodeError::Blocked | DecodeError::TooManyBlocked)
                    ),
                    "a section that refused for room gave {result:?} in a new region"
                );
            }
            let waits = waiting.iter().any(|&(waits, _)| waits == stream);
            match result {
                Ok(decoded) => {
                    waiting.retain(|&(waits, _)| waits != stream);
                    let size: usize = decoded
                        .iter()
                        .map(|(name, value, _)| name.len() + value.len() + 32)
                        .sum();
                    assert!(size <= limits.list_bytes, "the lines are larger than the list limit");
                    let received: Vec<FieldLine<'_>> = decoded
                        .iter()
                        .map(|(name, value, never_indexed)| FieldLine {
                            name,
                            value,
                            never_indexed: *never_indexed,
                        })
                        .collect();
                    echo.check(stream, &received);
                }
                Err(DecodeError::TooLarge) => waiting.retain(|&(waits, _)| waits != stream),
                Err(DecodeError::Blocked) => {
                    if !waits {
                        assert!(
                            waiting.len() < limits.blocked_streams,
                            "a stream blocked past the limit"
                        );
                        waiting.push((stream, section));
                    }
                }
                Err(DecodeError::TooManyBlocked) => {
                    assert!(
                        !waits && waiting.len() == limits.blocked_streams,
                        "a refusal within the limit"
                    );
                    // A connection error ends the connection.
                    return;
                }
                Err(DecodeError::Malformed) => return,
                Err(error @ (DecodeError::Misuse | DecodeError::Full(_))) => panic!("a decode refused with {error}"),
            }
        }
        assert_eq!(budget.available(), available, "a call changed the charge");
    }
});
