//! The HPACK decoder reads fuzzed header blocks on one connection. The first byte of the input
//! selects the limits of the decoder, and the second byte the table of an encoder and the limit of
//! its peer. The rest is a sequence of blocks, each after its length in two bytes, big-endian.
//!
//! No decode allocates or changes the charge of the decoder. The lines of a block stay in the
//! list limit. After `Malformed` or `Overload`, each later block gives the same error. The encoder
//! sends the lines of each decoded block to a second decoder, which must read the same lines,
//! with each never-indexed mark, so the tables of the encoder and the second decoder stay in step.

#![no_main]

use core::num::NonZeroU64;

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::hpack::{DecodeError, Decoder, Encoder, FieldLine, Limits, Lines};
use rsnetwork_fuzz::allocated;

/// Table sizes, list sizes, work limits, and peer limits that the control bytes select.
const TABLES: [usize; 4] = [0, 64, 256, 4096];
const LISTS: [usize; 4] = [0, 128, 1024, 16 * 1024];
const WORK: [usize; 4] = [64, 1024, 16 * 1024, 1 << 20];
const PEERS: [usize; 4] = [64, 256, 1024, 4096];

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [control, peer, blocks @ ..] = input else {
        return;
    };
    let mut rest = blocks;
    let pick = |byte: u8, shift: u8| usize::from((byte >> shift) & 3);
    let limits = Limits {
        table_bytes: TABLES[pick(*control, 0)],
        list_bytes: LISTS[pick(*control, 2)],
        work: WORK[pick(*control, 4)],
    };
    let budget = Budget::new(NonZeroU64::new(1 << 24).expect("not zero"));
    let mut decoder = Decoder::new(limits, &budget).expect("the budget pays for the decoder");
    let mut lines = Lines::new(limits, &budget).expect("the budget pays for the lines");
    let mut encoder = Encoder::new(TABLES[pick(*peer, 0)], &budget).expect("the budget pays for the encoder");
    encoder.set_peer_limit(PEERS[pick(*peer, 2)]);
    let wide = Limits {
        table_bytes: 4096,
        list_bytes: 1 << 20,
        work: 1 << 24,
    };
    let mut second = Decoder::new(wide, &budget).expect("the budget pays for the second decoder");
    let mut second_lines = Lines::new(wide, &budget).expect("the budget pays for the second lines");
    let mut failed = None;
    while let &[high, low, ref after @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([high, low])).min(after.len());
        let (block, next) = after.split_at(len);
        rest = next;
        let available = budget.available();
        let (result, bytes) = allocated(|| decoder.decode(block, &mut lines));
        assert_eq!(bytes, 0, "a decode allocated");
        assert_eq!(budget.available(), available, "a decode changed the charge");
        let block = match (result, failed) {
            (Ok(block), None) => block,
            (Err(error), Some(earlier)) => {
                assert_eq!(error, earlier, "a later block gave another error");
                continue;
            }
            (Err(DecodeError::TooLarge), None) => continue,
            (Err(error), None) => {
                failed = Some(error);
                continue;
            }
            (Ok(_), Some(earlier)) => panic!("a block decoded after {earlier}"),
        };
        let received: Vec<FieldLine<'_>> = block.lines().collect();
        let size: usize = received
            .iter()
            .map(|line| line.name.len() + line.value.len() + 32)
            .sum();
        assert!(size <= limits.list_bytes, "the lines are larger than the list limit");
        let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(1 << 20)));
        encoder
            .encode(received.iter().copied(), &mut out)
            .expect("the region holds the block");
        let decoded = second
            .decode(out.filled(), &mut second_lines)
            .expect("the second decoder reads the encoder");
        let again: Vec<FieldLine<'_>> = decoded.lines().collect();
        assert_eq!(
            again.len(),
            received.len(),
            "the second decoder read another number of lines"
        );
        for (line, again) in received.iter().zip(&again) {
            assert_eq!((line.name, line.value), (again.name, again.value), "a line changed");
            assert!(
                !line.never_indexed || again.never_indexed,
                "a never-indexed line lost its mark"
            );
        }
    }
});
