//! NET-K-3 to NET-K-5. Each pass starts a connection and uses its table for 256 requests.

use core::hint::black_box;
use criterion::{Criterion, Throughput};
use rstypes::buffer::WriteLoan;

use super::{budget, records};
use crate::hpack::{self, Block, FieldLine, huffman};
use crate::qpack;

const REQUESTS: usize = 256;
const TABLE: usize = 4096;
const LIST: usize = 8192;
const HPACK: hpack::Limits = hpack::Limits {
    table_bytes: TABLE,
    list_bytes: LIST,
    work: 4 * LIST,
};

fn fields(records: &[Vec<u8>]) -> Vec<Vec<FieldLine<'_>>> {
    let mut records = records.iter();
    let mut requests = Vec::new();
    while let Some(count) = records.next() {
        let count = usize::try_from(crate::value::decimal(count).unwrap()).unwrap();
        requests.push(
            (0..count)
                .map(|_| FieldLine {
                    name: records.next().unwrap(),
                    value: records.next().unwrap(),
                    never_indexed: false,
                })
                .collect(),
        );
    }
    assert_eq!(requests.len(), REQUESTS);
    requests
}

fn check(block: Block<'_>, fields: &[FieldLine<'_>]) {
    assert!(
        block
            .lines()
            .map(|f| (f.name, f.value))
            .eq(fields.iter().map(|f| (f.name, f.value)))
    );
}

fn output() -> WriteLoan<Vec<u8>> {
    WriteLoan::new(Vec::with_capacity(LIST))
}

fn reuse(loan: WriteLoan<Vec<u8>>) -> WriteLoan<Vec<u8>> {
    let mut bytes = loan.into_inner();
    bytes.clear();
    WriteLoan::new(bytes)
}

fn hpack(c: &mut Criterion, name: &str, requests: &[Vec<FieldLine<'_>>]) {
    let encoded = records(&format!("hpack_{name}"));
    assert_eq!(encoded.len(), REQUESTS);
    let budget = budget();
    let decoder = || hpack::Decoder::new(HPACK, &budget).unwrap();
    let encoder = || hpack::Encoder::new(TABLE, &budget).unwrap();
    let mut lines = hpack::Lines::new(HPACK, &budget).unwrap();
    let (mut peer, mut local, mut send) = (decoder(), decoder(), encoder());
    let mut out = output();
    for (input, fields) in encoded.iter().zip(requests) {
        check(peer.decode(input, &mut lines).unwrap(), fields);
        send.encode(fields.iter().copied(), &mut out).unwrap();
        check(local.decode(out.filled(), &mut lines).unwrap(), fields);
        out = reuse(out);
    }
    let mut group = c.benchmark_group("hpack");
    group.throughput(Throughput::Elements(REQUESTS as u64));
    group.bench_function(format!("decode_{name}"), |b| {
        b.iter(|| {
            let mut decoder = decoder();
            for block in black_box(&encoded) {
                black_box(decoder.decode(block, &mut lines).unwrap());
            }
        })
    });
    group.bench_function(format!("encode_{name}"), |b| {
        b.iter(|| {
            let mut encoder = encoder();
            let mut out = output();
            for fields in black_box(requests) {
                encoder.encode(fields.iter().copied(), &mut out).unwrap();
                black_box(out.filled());
                out = reuse(out);
            }
        })
    });
}

fn qpack(c: &mut Criterion, name: &str, requests: &[Vec<FieldLine<'_>>], table: usize) {
    let mode = if table == 0 { "static" } else { "dynamic" };
    let wire = records(&format!("qpack_{mode}_{name}"));
    let (pairs, tail) = wire.as_chunks::<2>();
    assert!(tail.is_empty());
    assert_eq!(pairs.len(), REQUESTS);
    let limits = qpack::Limits {
        table_bytes: table,
        blocked_streams: 0,
        list_bytes: LIST,
        work: 4 * LIST,
    };
    let budget = budget();
    let decoder = || qpack::Decoder::new(limits, &budget).unwrap();
    let encoder = || {
        let mut encoder = qpack::Encoder::new(
            qpack::EncoderLimits {
                table_bytes: table,
                sections: REQUESTS,
            },
            &budget,
        )
        .unwrap();
        encoder
            .set_peer(qpack::Settings {
                table_bytes: table as u64,
                blocked_streams: 0,
            })
            .unwrap();
        encoder
    };
    let mut lines = qpack::Lines::new(limits, &budget).unwrap();
    let (mut peer, mut local, mut send) = (decoder(), decoder(), encoder());
    let mut feedback = Vec::new();
    let (mut response, mut control, mut section) = (output(), output(), output());
    let mut prefixed = Vec::with_capacity(LIST);
    for (i, ([instructions, encoded], fields)) in pairs.iter().zip(requests).enumerate() {
        let stream = i as u64 * 4;
        assert_eq!(peer.receive(instructions, &mut response).unwrap(), instructions.len());
        check(peer.decode(stream, encoded, &mut lines, &mut response).unwrap(), fields);
        response = reuse(response);
        let prefix = send
            .encode(stream, fields.iter().copied(), &mut section, &mut control)
            .unwrap();
        prefixed.clear();
        prefixed.extend_from_slice(prefix.bytes());
        prefixed.extend_from_slice(section.filled());
        assert_eq!(
            local.receive(control.filled(), &mut response).unwrap(),
            control.filled().len()
        );
        check(
            local.decode(stream, &prefixed, &mut lines, &mut response).unwrap(),
            fields,
        );
        send.receive(response.filled()).unwrap();
        feedback.push(response.filled().to_vec());
        (response, section, control) = (reuse(response), reuse(section), reuse(control));
    }
    let mut group = c.benchmark_group("qpack");
    group.throughput(Throughput::Elements(REQUESTS as u64));
    group.bench_function(format!("decode_{mode}_{name}"), |b| {
        b.iter(|| {
            let mut decoder = decoder();
            let mut response = output();
            for (i, [instructions, section]) in black_box(pairs).iter().enumerate() {
                if !instructions.is_empty() {
                    black_box(decoder.receive(instructions, &mut response).unwrap());
                }
                black_box(
                    decoder
                        .decode(i as u64 * 4, section, &mut lines, &mut response)
                        .unwrap(),
                );
                response = reuse(response);
            }
        })
    });
    group.bench_function(format!("encode_{mode}_{name}"), |b| {
        b.iter(|| {
            let mut encoder = encoder();
            let (mut section, mut instructions) = (output(), output());
            for (i, (fields, ack)) in black_box(requests).iter().zip(&feedback).enumerate() {
                let prefix = encoder
                    .encode(i as u64 * 4, fields.iter().copied(), &mut section, &mut instructions)
                    .unwrap();
                black_box((prefix.bytes(), section.filled(), instructions.filled()));
                if !ack.is_empty() {
                    encoder.receive(ack).unwrap();
                }
                (section, instructions) = (reuse(section), reuse(instructions));
            }
        })
    });
    if table != 0 && name == "browser" {
        let i = pairs.iter().position(|[_, block]| block[0] != 0).unwrap();
        let stream = i as u64 * 4;
        let instructions: Vec<_> = pairs[..=i]
            .iter()
            .flat_map(|[input, _]| input.iter().copied())
            .collect();
        let section = &pairs[i][1];
        let mut delayed = || {
            let mut decoder = qpack::Decoder::new(
                qpack::Limits {
                    blocked_streams: 1,
                    ..limits
                },
                &budget,
            )
            .unwrap();
            let mut out = output();
            assert!(matches!(
                decoder.decode(stream, section, &mut lines, &mut out),
                Err(qpack::DecodeError::Blocked)
            ));
            assert_eq!(decoder.receive(&instructions, &mut out).unwrap(), instructions.len());
            assert_eq!(decoder.unblocked(), Some(stream));
            black_box(decoder.decode(stream, section, &mut lines, &mut out).unwrap());
        };
        delayed();
        group.throughput(Throughput::Elements(1));
        group.bench_function("blocked_browser", |b| b.iter(&mut delayed));
    }
}

pub(super) fn blocks(c: &mut Criterion) {
    for name in ["browser", "gRPC", "h2load"] {
        let raw = records(&format!("fields_{name}"));
        let requests = fields(&raw);
        hpack(c, name, &requests);
        qpack(c, name, &requests, 0);
        qpack(c, name, &requests, TABLE);
    }
}

pub(super) fn huffman(c: &mut Criterion) {
    let octets: Vec<_> = (0..=255).collect();
    let mut group = c.benchmark_group("huffman");
    group.throughput(Throughput::Elements(1));
    for (name, input) in [
        ("short", b"www.example.com".as_slice()),
        ("header", b"text/html,application/xhtml+xml,application/xml;q=0.9;q=0.8"),
        (
            "long",
            b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:16.0) Gecko/20100101 Firefox/16.0",
        ),
        ("octets", octets.as_slice()),
    ] {
        let mut code = Vec::new();
        huffman::encode(input.iter().copied(), |part| code.extend_from_slice(part));
        if name == "short" {
            assert_eq!(
                code,
                [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
            );
        }
        let mut out = Vec::with_capacity(input.len().max(code.len()));
        huffman::decode(&code, &mut out, input.len()).unwrap();
        assert_eq!(out, input);
        group.bench_function(format!("decode_{name}"), |b| {
            b.iter(|| {
                out.clear();
                huffman::decode(black_box(&code), &mut out, input.len()).unwrap();
                black_box(&out);
            })
        });
        group.bench_function(format!("encode_{name}"), |b| {
            b.iter(|| {
                out.clear();
                huffman::encode(black_box(input).iter().copied(), |part| out.extend_from_slice(part));
                black_box(&out);
            })
        });
    }
}
