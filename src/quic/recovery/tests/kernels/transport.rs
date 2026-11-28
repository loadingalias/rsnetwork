//! NET-K-6 and NET-K-7 exercise the store and the stream receiver without UDP or packet protection.

use core::hint::black_box;
use core::time::Duration;
use criterion::{BatchSize, Criterion, Throughput};
use rstypes::buffer::{Buffer as _, Lease};

use super::super::{UNBOUNDED, at, connection, packet};
use super::budget;
use crate::drive::{Ecn, Work};
use crate::quic::Event;
use crate::quic::frame::Frame;
use crate::quic::packet::Side;
use crate::quic::recovery::{History, Paths, Settlement};
use crate::quic::stream::{Config, Streams};

fn window(live: u64) -> (History, Paths) {
    let mut paths = connection(&budget(), Duration::from_millis(20));
    let mut history = History::new();
    for number in 0..live {
        history.insert(&mut paths, packet(number, at(0), Ecn::NotEct)).unwrap();
    }
    (history, paths)
}

fn number(paths: &Paths, index: usize) -> u64 {
    paths.store.slots.get(index).unwrap().packet.as_ref().unwrap().number
}

#[derive(Clone, Copy)]
enum Removal {
    Forward,
    Reverse,
}

/// Locate the largest packet and collect the oldest ACK range. Retire it and replenish the window.
#[inline(never)]
fn cycle(history: &mut History, paths: &mut Paths, next: &mut u64, slots: &mut [usize], removal: Removal) {
    let mut cursor = history.first;
    for slot in &mut *slots {
        *slot = cursor;
        cursor = paths.store.slots.get(cursor).unwrap().next;
    }
    black_box(number(paths, *slots.last().unwrap()));
    if matches!(removal, Removal::Reverse) {
        slots.reverse();
    }
    for &slot in &*slots {
        black_box(history.remove(paths, slot, Settlement::Delivered));
    }
    for _ in &*slots {
        history.insert(paths, packet(*next, at(0), Ecn::NotEct)).unwrap();
        *next += 1;
    }
    black_box(history.elicitors);
}

pub(super) fn packets(c: &mut Criterion) {
    let mut group = c.benchmark_group("sent");
    for (live, batch, removal) in [
        (64, 32, Removal::Forward),
        (1024, 1, Removal::Forward),
        (1024, 32, Removal::Forward),
        (16384, 32, Removal::Forward),
        (1024, 32, Removal::Reverse),
    ] {
        let order = match removal {
            Removal::Forward => "dense",
            Removal::Reverse => "reorder",
        };
        let (mut history, mut paths) = window(live);
        let mut next = live;
        let mut slots = vec![0; batch];
        cycle(&mut history, &mut paths, &mut next, &mut slots, removal);
        assert_eq!(history.bytes, live * 1200);
        assert_eq!(number(&paths, history.first), batch as u64);
        assert_eq!(number(&paths, history.last), next - 1);
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_function(format!("{order}_{live}_{batch}"), |b| {
            b.iter(|| {
                cycle(&mut history, &mut paths, &mut next, &mut slots, removal);
            })
        });
    }
    for gap in [4096, 65536] {
        let (mut history, mut paths) = window(1);
        history.insert(&mut paths, packet(gap, at(0), Ecn::NotEct)).unwrap();
        let successor = |first| number(&paths, paths.store.slots.get(first).unwrap().next);
        assert_eq!(successor(history.first), gap);
        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("successor_{gap}"), |b| {
            b.iter(|| black_box(successor(black_box(history.first))))
        });
    }
}

const FRAME_BYTES: usize = 1200;
const DATA: [u8; FRAME_BYTES] = [42; FRAME_BYTES];

fn receiver() -> Streams {
    let config = Config {
        data_bytes: 8 << 20,
        stream_bytes: 8 << 20,
        reassembly_bytes: 8 << 20,
        streams: [1, 0],
        send_bytes: 0,
        unreliable_bytes: None,
    };
    Streams::new(Side::Server, config, &budget())
}

/// Return the bytes that went straight to the consumer on receipt of each STREAM frame.
#[inline(never)]
fn insert_frames(receiver: &mut Streams, offsets: &[u64], payload: &Lease) -> usize {
    let mut received = 0;
    for &offset in offsets {
        if let Some(Event::Stream { data, .. }) =
            receiver.stream_in(0, (offset, false), 0..FRAME_BYTES, payload).unwrap()
        {
            received += black_box(data).initialized();
        }
    }
    received
}

fn drain(receiver: &mut Streams) -> usize {
    let mut received = 0;
    while let Some(event) = receiver.event(&mut Work::default(), &UNBOUNDED) {
        if let Event::Stream { data, .. } = event {
            received += data.initialized();
        }
    }
    received
}

/// Keep setup on a separate stack so a profile can select only the timed insertions.
#[inline(never)]
fn buffered(offsets: &[u64], payload: &Lease) -> Streams {
    let mut streams = receiver();
    assert_eq!(insert_frames(&mut streams, offsets, payload), 0);
    streams
}

pub(super) fn streams(c: &mut Criterion) {
    let payload = Lease::from(DATA.as_slice());
    let mut group = c.benchmark_group("reassembly");
    let mut offsets: Vec<_> = (0..256).map(|i| i * FRAME_BYTES as u64).collect();
    for order in ["ordered", "descending"] {
        if order == "descending" {
            offsets.reverse();
        }
        let mut verify = receiver();
        let mut received = insert_frames(&mut verify, &offsets, &payload);
        received += drain(&mut verify);
        assert_eq!(received, offsets.len() * FRAME_BYTES);
        group.throughput(Throughput::Elements(offsets.len() as u64));
        group.bench_function(order, |b| {
            b.iter_batched_ref(
                receiver,
                |streams| black_box(insert_frames(streams, black_box(&offsets), &payload)),
                BatchSize::PerIteration,
            )
        });
    }
    for spans in [1000, 1900] {
        let before: Vec<_> = (0..spans).map(|i| (2 * i + 1) * FRAME_BYTES as u64).collect();
        let middle: Vec<_> = (spans / 2 - 32..spans / 2 + 32)
            .map(|i| 2 * i * FRAME_BYTES as u64)
            .collect();
        let prepare = || buffered(&before, &payload);
        let mut verify = prepare();
        assert_eq!(insert_frames(&mut verify, &middle, &payload), 0);
        let gaps: Vec<_> = (0..spans)
            .map(|i| 2 * i * FRAME_BYTES as u64)
            .filter(|offset| !middle.contains(offset))
            .collect();
        let received = insert_frames(&mut verify, &gaps, &payload) + drain(&mut verify);
        assert_eq!(received as u64, 2 * spans * FRAME_BYTES as u64);
        group.throughput(Throughput::Elements(middle.len() as u64));
        group.bench_function(format!("middle_{spans}"), |b| {
            b.iter_batched_ref(
                &prepare,
                |streams| black_box(insert_frames(streams, black_box(&middle), &payload)),
                BatchSize::PerIteration,
            )
        });
    }
}

pub(super) fn frames(c: &mut Criterion) {
    // RFC 9000 STREAM with offset and length, and ACK with two ranges.
    let stream = [&[0x0e, 4, 0x44, 0xb0, 0x44, 0xb0][..], &DATA].concat();
    let ack = [2, 0x40, 0x80, 0, 1, 3, 2, 1];
    let mut group = c.benchmark_group("frame");
    group.throughput(Throughput::Elements(1));
    for (name, wire) in [("stream", stream.as_slice()), ("ack", &ack)] {
        let (frame, len) = Frame::parse(wire).unwrap();
        assert_eq!(len, wire.len());
        match frame {
            Frame::Ack(ack) => assert!(ack.ranges().eq([125..=128, 120..=121])),
            Frame::Stream {
                stream,
                offset,
                data,
                fin,
            } => assert_eq!((stream, offset, data, fin), (4, 1200, DATA.as_slice(), false)),
            _ => panic!("the fixture holds a STREAM or ACK frame"),
        }
        let mut out = [0; 1280];
        let len = frame.write(&mut out).unwrap();
        assert_eq!(&out[..len], wire);
        group.bench_function(format!("decode_{name}"), |b| {
            b.iter(|| black_box(Frame::parse(black_box(wire)).unwrap()))
        });
        group.bench_function(format!("encode_{name}"), |b| {
            b.iter(|| {
                let len = black_box(&frame).write(&mut out).unwrap();
                black_box(&out[..len]);
            })
        });
    }
}
