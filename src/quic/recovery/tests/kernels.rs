//! Criterion measures the private kernels in the same crate as their callers.
//! Run `python3 benches/kernels/run.py` to select the corpus and the measurement mode.

use core::num::NonZeroU64;
use core::time::Duration;
use std::env;
use std::fs;
use std::path::PathBuf;

use criterion::Criterion;
use rstypes::capacity::Budget;

mod compression;
mod http1;
mod transport;

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(32 << 20).unwrap())
}

/// The reference harness writes a little-endian u32 before each record.
fn records(name: &str) -> Vec<Vec<u8>> {
    let root = PathBuf::from(env::var_os("RSNETWORK_KERNEL_CORPUS").expect("the kernel runner supplies the corpus"));
    let file = fs::read(root.join(format!("{name}.bin"))).unwrap();
    let mut bytes = file.as_slice();
    let mut records = Vec::new();
    while !bytes.is_empty() {
        let (size, tail) = bytes.split_first_chunk::<4>().unwrap();
        let (record, tail) = tail.split_at(u32::from_le_bytes(*size) as usize);
        records.push(record.to_vec());
        bytes = tail;
    }
    records
}

#[test]
#[ignore = "the kernel runner supplies the reference corpus and selects the timed cells"]
fn protocol_kernels() {
    let mode = env::var("RSNETWORK_KERNEL_MODE").unwrap();
    let filter = env::var("RSNETWORK_KERNEL_FILTER").unwrap_or_default();
    let mut criterion = Criterion::default()
        .without_plots()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100)
        .with_filter(if mode == "check" { "^$" } else { &filter });
    if mode == "profile" {
        criterion = criterion.profile_time(Some(Duration::from_secs(4)));
    }
    http1::heads(&mut criterion);
    compression::blocks(&mut criterion);
    compression::huffman(&mut criterion);
    transport::packets(&mut criterion);
    transport::streams(&mut criterion);
    transport::frames(&mut criterion);
}
