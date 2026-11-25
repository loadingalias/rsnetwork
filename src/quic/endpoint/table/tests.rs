use core::hash::BuildHasher as _;
use core::hint::black_box;
use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use std::time::Instant;

use rstypes::capacity::Budget;

use super::Table;
use crate::quic::endpoint::Key;
use crate::quic::{ConnectionId, Path};

/// A production route lookup for each CID. The result is the elapsed nanoseconds for one pass.
fn elapsed(table: &Table<Key, usize>, ids: &[Key]) -> u128 {
    let start = Instant::now();
    for (i, key) in ids.iter().enumerate() {
        assert_eq!(black_box(table).get(black_box(key)), Some(i));
    }
    start.elapsed().as_nanos()
}

#[test]
fn chosen_initial_ids_keep_lookup_work_bounded_and_change_placement_with_the_endpoint_key() {
    const COUNT: usize = 1024;
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
    let path = Path { local: peer, peer };
    let mut chosen = Vec::with_capacity(COUNT);
    let mut random = Vec::with_capacity(COUNT);
    for i in 0..COUNT {
        let mut id = [0x42; 16];
        id[8..].copy_from_slice(&(i as u64).to_be_bytes());
        chosen.push(Key::Initial(path, ConnectionId::new(&id).unwrap()));
        let digest = rscrypto::Sha256::digest(&(i as u64).to_be_bytes());
        random.push(Key::Initial(path, ConnectionId::new(&digest[..16]).unwrap()));
    }
    let budget = Budget::new(NonZeroU64::new(1 << 21).unwrap());
    let build = |ids: &[Key], seed: u8| {
        let mut table = Table::new(
            COUNT,
            |b| {
                b.fill(seed);
                Ok(())
            },
            &budget,
        )
        .unwrap();
        for (i, key) in ids.iter().enumerate() {
            assert!(table.insert(*key, i));
        }
        table
    };
    let mut structured = build(&chosen, 1);
    let baseline = build(&random, 1);
    let independent = build(&chosen, 2);
    let position = |table: &Table<Key, usize>, key: &Key| {
        let hash = table.key.hash_one(key);
        let slot = table.position(hash, |found| found == key).unwrap();
        (
            slot,
            1 + (slot.wrapping_sub(table.home(hash)) & (table.slots.len() - 1)),
        )
    };
    let equal = chosen
        .iter()
        .filter(|k| position(&structured, k).0 == position(&independent, k).0)
        .count();
    assert!(
        equal < COUNT / 4,
        "{equal} of {COUNT} chosen IDs retained their slot across independent endpoint keys"
    );
    let visits = |table: &Table<Key, usize>, ids: &[Key]| ids.iter().map(|k| position(table, k).1).sum::<usize>();
    let (a, b) = (visits(&structured, &chosen), visits(&baseline, &random));
    assert!(
        a <= 2 * b,
        "{a} chosen-ID slot visits exceed twice {b} random-ID visits"
    );
    if std::env::var_os("RSNETWORK_MEASURE_CID_LOOKUPS").is_some() {
        let mut chosen_ns = [0; 7];
        let mut random_ns = [0; 7];
        for (i, (left, right)) in chosen_ns.iter_mut().zip(&mut random_ns).enumerate() {
            if i % 2 == 0 {
                *left = elapsed(&structured, &chosen);
                *right = elapsed(&baseline, &random);
            } else {
                *right = elapsed(&baseline, &random);
                *left = elapsed(&structured, &chosen);
            }
        }
        chosen_ns.sort_unstable();
        random_ns.sort_unstable();
        eprintln!(
            "{COUNT} lookups: chosen {a} slots, {} ns; random {b} slots, {} ns",
            chosen_ns[3], random_ns[3]
        );
        assert!(
            chosen_ns[3] <= 2 * random_ns[3],
            "the median exceeds the declared factor of two"
        );
    }
    for k in chosen.iter().step_by(2) {
        structured.remove(k);
    }
    for (i, k) in chosen.iter().enumerate() {
        assert_eq!(structured.get(k), (i % 2 == 1).then_some(i));
    }
}
