//! HPACK: the vectors of RFC 7541, Appendix C, the hpack-test-case corpus, refusals before
//! allocation, the bounds of a block, and the sensitive-field rule.

mod counting;
mod json;

use core::num::NonZeroU64;
use std::fs;
use std::path::{Path, PathBuf};

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::hpack::{Block, DecodeError, Decoder, EncodeError, Encoder, FieldLine, Limits, Lines};

use counting::allocations;
use json::Json;

/// One block of an example of Appendix C: its bytes in hexadecimal, its decoded lines, and the
/// dynamic table after it, newest entry first.
struct Step {
    wire: &'static str,
    lines: &'static [(&'static str, &'static str)],
    table: &'static [(&'static str, &'static str)],
}

// The vectors are the hex dumps, the decoded header lists, and the dynamic tables of RFC 7541,
// Appendix C, which a script took from the text of the RFC. It checked the size of each entry and
// of each table against the RFC.

/// RFC 7541, Appendix C.2: one block each, on a new decoder.
const C2: [Step; 4] = [
    Step {
        wire: "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
        lines: &[("custom-key", "custom-header")],
        table: &[("custom-key", "custom-header")],
    },
    Step {
        wire: "040c2f73616d706c652f70617468",
        lines: &[(":path", "/sample/path")],
        table: &[],
    },
    Step {
        wire: "100870617373776f726406736563726574",
        lines: &[("password", "secret")],
        table: &[],
    },
    Step {
        wire: "82",
        lines: &[(":method", "GET")],
        table: &[],
    },
];

/// RFC 7541, Appendix C.3: requests with no Huffman coding, on one decoder.
const C3: [Step; 3] = [
    Step {
        wire: "828684410f7777772e6578616d706c652e636f6d",
        lines: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
    },
    Step {
        wire: "828684be58086e6f2d6361636865",
        lines: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        table: &[("cache-control", "no-cache"), (":authority", "www.example.com")],
    },
    Step {
        wire: "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
        lines: &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        table: &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
    },
];

/// RFC 7541, Appendix C.4: the requests of C.3 with Huffman coding.
const C4: [Step; 3] = [
    Step {
        wire: "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        lines: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
    },
    Step {
        wire: "828684be5886a8eb10649cbf",
        lines: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        table: &[("cache-control", "no-cache"), (":authority", "www.example.com")],
    },
    Step {
        wire: "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
        lines: &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        table: &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
    },
];

/// RFC 7541, Appendix C.5: responses with no Huffman coding, on one decoder of 256 bytes.
const C5: [Step; 3] = [
    Step {
        wire: "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
        lines: &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
            (":status", "302"),
        ],
    },
    Step {
        wire: "4803333037c1c0bf",
        lines: &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            (":status", "307"),
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
        ],
    },
    Step {
        wire: "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
        lines: &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ],
        table: &[
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            ("content-encoding", "gzip"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ],
    },
];

/// RFC 7541, Appendix C.6: the responses of C.5 with Huffman coding.
const C6: [Step; 3] = [
    Step {
        wire: "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
        lines: &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
            (":status", "302"),
        ],
    },
    Step {
        wire: "4883640effc1c0bf",
        lines: &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("location", "https://www.example.com"),
        ],
        table: &[
            (":status", "307"),
            ("location", "https://www.example.com"),
            ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
            ("cache-control", "private"),
        ],
    },
    Step {
        wire: "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
        lines: &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
            ("location", "https://www.example.com"),
            ("content-encoding", "gzip"),
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
        ],
        table: &[
            ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            ("content-encoding", "gzip"),
            ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ],
    },
];

type Decoded = Vec<(Vec<u8>, Vec<u8>)>;

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 26).expect("not zero"))
}

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

/// A decoder and the lines that it decodes into.
struct Peer {
    decoder: Decoder,
    lines: Lines,
}

impl Peer {
    fn new(limits: Limits, budget: &Budget) -> Self {
        Self {
            decoder: Decoder::new(limits, budget).expect("the budget pays for the decoder"),
            lines: Lines::new(limits, budget).expect("the budget pays for the lines"),
        }
    }

    fn decode(&mut self, block: &[u8]) -> Result<Block<'_>, DecodeError> {
        self.decoder.decode(block, &mut self.lines)
    }
}

fn decoder(table_bytes: usize, budget: &Budget) -> Peer {
    let limits = Limits {
        table_bytes,
        list_bytes: 1 << 16,
        work: 1 << 20,
    };
    Peer::new(limits, budget)
}

fn lines(block: Block<'_>) -> Decoded {
    block
        .lines()
        .map(|line| (line.name.to_vec(), line.value.to_vec()))
        .collect()
}

fn expected(lines: &[(&str, &str)]) -> Decoded {
    lines
        .iter()
        .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

fn line<'a>(name: &'a [u8], value: &'a [u8]) -> FieldLine<'a> {
    FieldLine {
        name,
        value,
        never_indexed: false,
    }
}

/// Encodes `lines` as one block into a new region of 64 KiB.
fn encode<'a>(encoder: &mut Encoder, lines: impl Iterator<Item = FieldLine<'a>> + Clone) -> Vec<u8> {
    let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(1 << 16)));
    encoder.encode(lines, &mut out).expect("the region holds the block");
    out.filled().to_vec()
}

/// Decodes the blocks of `steps` in order, each sequence on a new decoder of `table_bytes`. After
/// each block, it checks the decoded lines, and it reads the dynamic table with indexed lines: each
/// entry of the RFC, newest first, and no other entry.
fn check(steps: &[Step], table_bytes: usize) {
    for end in 0..steps.len() {
        let budget = budget();
        let mut decoder = decoder(table_bytes, &budget);
        for step in &steps[..=end] {
            let block = decoder.decode(&hex(step.wire)).expect("the block decodes");
            assert_eq!(lines(block), expected(step.lines), "the lines of {}", step.wire);
        }
        let table = steps[end].table;
        let index = |position: usize| 0xbe + u8::try_from(position).expect("a short table");
        let references: Vec<u8> = (0..table.len()).map(index).collect();
        let block = decoder.decode(&references).expect("each entry is in the table");
        assert_eq!(lines(block), expected(table), "the table after {}", steps[end].wire);
        let past = [index(table.len())];
        assert_eq!(
            decoder.decode(&past).err(),
            Some(DecodeError::Malformed),
            "an extra entry"
        );
    }
}

#[test]
fn the_examples_of_appendix_c_decode_to_their_lines_and_tables() {
    for step in &C2 {
        check(core::slice::from_ref(step), 4096);
    }
    check(&C3, 4096);
    check(&C4, 4096);
    check(&C5, 256);
    check(&C6, 256);
}

/// Appendix C.2.3: the line is a literal that is never indexed, and the decoder keeps the mark so
/// that a forwarder sends it in the same form.
#[test]
fn a_never_indexed_line_keeps_its_mark() {
    let budget = budget();
    for (step, never_indexed) in C2.iter().zip([false, false, true, false]) {
        let mut decoder = decoder(4096, &budget);
        let block = decoder.decode(&hex(step.wire)).expect("the block decodes");
        let marks: Vec<bool> = block.lines().map(|line| line.never_indexed).collect();
        assert_eq!(marks, [never_indexed], "{}", step.wire);
    }
}

/// The encoder makes the choices of the examples of Appendix C.4 and C.6, with two differences
/// that RFC 7541 permits. A table of 256 bytes is not the initial 4096 of HTTP/2, so the first
/// block of C.6 starts with the size update to 256 (section 6.3): `3f e1 01`. The value `307` of
/// C.6.2 is 3 bytes, and so is its Huffman string `83 64 0e ff`. Thus the encoder sends the bytes
/// with no Huffman coding, which cost the peer less work: `03 33 30 37`.
#[test]
fn the_encoder_gives_the_huffman_examples_of_appendix_c() {
    let budget = budget();
    for (steps, table_bytes, update) in [(&C4, 4096, ""), (&C6, 256, "3fe101")] {
        let mut encoder = Encoder::new(table_bytes, &budget).expect("the budget pays for the encoder");
        for (position, step) in steps.iter().enumerate() {
            let block = encode(
                &mut encoder,
                step.lines
                    .iter()
                    .map(|(name, value)| line(name.as_bytes(), value.as_bytes())),
            );
            let wire = if position == 0 {
                format!("{update}{}", step.wire)
            } else {
                step.wire.to_owned()
            };
            let wire = wire.replace("4883640eff", "4803333037");
            assert_eq!(block, hex(&wire), "{}", step.wire);
        }
    }
}

/// The stories of `tests/hpack-test-case`, by directory and then by file name.
fn stories() -> Vec<(PathBuf, Json)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/hpack-test-case");
    let mut paths: Vec<PathBuf> = fs::read_dir(&root)
        .expect("the corpus directory")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .flat_map(|directory| {
            fs::read_dir(directory)
                .expect("an encoder directory")
                .map(|entry| entry.expect("a directory entry").path())
                .collect::<Vec<_>>()
        })
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let story = Json::parse(&fs::read(&path).expect("a story file"));
            (path, story)
        })
        .collect()
}

/// The cases of a story: the wire bytes and the lines of each.
fn cases(story: &Json) -> Vec<(Vec<u8>, Decoded)> {
    let Some(Json::Array(cases)) = story.get("cases") else {
        panic!("a story has cases")
    };
    cases
        .iter()
        .map(|case| {
            let Some(Json::String(wire)) = case.get("wire") else {
                panic!("a case has wire bytes")
            };
            let Some(Json::Array(headers)) = case.get("headers") else {
                panic!("a case has headers")
            };
            let lines = headers
                .iter()
                .map(|header| match header {
                    Json::Object(members) if members.len() == 1 => match &members[0] {
                        (name, Json::String(value)) => (name.clone(), value.clone()),
                        _ => panic!("a header value is a string"),
                    },
                    _ => panic!("a header is an object of one member"),
                })
                .collect();
            (hex(core::str::from_utf8(wire).expect("hexadecimal")), lines)
        })
        .collect()
}

/// The largest `header_table_size` of a story, and at least the initial 4096 of HTTP/2. A decoder
/// whose table is larger than the encoder's table decodes the same lines.
fn table_bytes(story: &Json) -> usize {
    let Some(Json::Array(cases)) = story.get("cases") else {
        panic!("a story has cases")
    };
    cases
        .iter()
        .filter_map(|case| match case.get("header_table_size") {
            Some(Json::Number(size)) => Some(usize::try_from(*size).expect("a table size")),
            _ => None,
        })
        .fold(4096, usize::max)
}

/// Each case of each story of 14 independent encoders decodes, in order on one decoder, to the
/// lines of its `headers`. The data has 280 stories with 2590 cases.
#[test]
fn the_hpack_test_case_corpus_decodes_to_its_lines() {
    let budget = budget();
    let (mut stories_read, mut cases_read) = (0, 0);
    for (path, story) in stories() {
        let mut decoder = decoder(table_bytes(&story), &budget);
        for (seqno, (wire, expected)) in cases(&story).into_iter().enumerate() {
            let block = decoder
                .decode(&wire)
                .unwrap_or_else(|error| panic!("{} case {seqno}: {error}", path.display()));
            assert_eq!(lines(block), expected, "{} case {seqno}", path.display());
            cases_read += 1;
        }
        stories_read += 1;
    }
    assert_eq!((stories_read, cases_read), (280, 2590));
}

/// The encoder gives blocks that decode to the lines of each nghttp2 story, with a table of 4096
/// bytes, and with a table of 256 bytes, which evicts often and signals its size first.
#[test]
fn the_corpus_lines_survive_the_encoder() {
    let budget = budget();
    let stories: Vec<_> = stories()
        .into_iter()
        .filter(|(path, _)| path.parent().and_then(Path::file_name) == Some("nghttp2".as_ref()))
        .collect();
    assert_eq!(stories.len(), 20);
    for table in [4096, 256] {
        for (path, story) in &stories {
            let mut encoder = Encoder::new(table, &budget).expect("the budget pays for the encoder");
            let mut decoder = decoder(4096, &budget);
            for (seqno, (_, expected)) in cases(story).into_iter().enumerate() {
                let block = encode(&mut encoder, expected.iter().map(|(name, value)| line(name, value)));
                let decoded = decoder.decode(&block).expect("the block decodes");
                assert_eq!(
                    lines(decoded),
                    expected,
                    "{} case {seqno}, table {table}",
                    path.display()
                );
            }
        }
    }
}

/// Blocks that break RFC 7541. Each refuses with no allocation and no change of the charge, and
/// the decoder then refuses each later block, because the state of its table is not known.
#[test]
fn a_malformed_block_refuses_before_allocation_and_ends_the_decoder() {
    let vectors: [(&str, &[u8]); 11] = [
        ("index 0 (section 6.1)", &[0x80]),
        ("an index past the tables", &[0xbe]),
        ("a name index past the tables", &[0x7e, 0x00]),
        ("a literal with no name", &[0x40]),
        ("a string past the end of the block", &[0x04, 0x05, b'a']),
        ("an integer past the end of the block", &[0xff]),
        (
            "an integer past 64 bits",
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ),
        (
            "a Huffman string with EOS (section 5.2)",
            &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff],
        ),
        ("Huffman padding of more than 7 bits", &[0x04, 0x82, 0x1f, 0xff]),
        ("Huffman padding with a zero bit", &[0x04, 0x81, 0x18]),
        ("a size update after a line (section 4.2)", &[0x82, 0x20]),
    ];
    for (name, block) in vectors {
        let budget = budget();
        let mut decoder = decoder(4096, &budget);
        let available = budget.available();
        let (refused, count) = allocations(|| decoder.decode(block).err());
        assert_eq!(refused, Some(DecodeError::Malformed), "{name}");
        assert_eq!(count, 0, "{name}: allocations");
        assert_eq!(budget.available(), available, "{name}: the charge changed");
        assert_eq!(
            decoder.decode(&[0x82]).err(),
            Some(DecodeError::Malformed),
            "{name}: a later block"
        );
    }
}

/// RFC 7541, section 6.3: a size update above the limit, here 4097 for a limit of 4096, is
/// malformed. The decoder refuses it before its table grows: with no allocation, and with no
/// change of the charge. A size update to the limit itself is valid.
#[test]
fn a_size_update_past_the_limit_refuses_before_the_table_grows() {
    let budget = budget();
    let mut decoder = decoder(4096, &budget);
    let available = budget.available();
    let (refused, count) = allocations(|| decoder.decode(&[0x3f, 0xe2, 0x1f]).err());
    assert_eq!(refused, Some(DecodeError::Malformed));
    assert_eq!(count, 0, "allocations");
    assert_eq!(budget.available(), available, "the charge changed");

    let mut decoder = self::decoder(4096, &budget);
    let block = decoder
        .decode(&[0x3f, 0xe1, 0x1f, 0x82])
        .expect("a size update to the limit");
    assert_eq!(lines(block), expected(&[(":method", "GET")]));
}

/// A literal with incremental indexing and a literal name of `name_len` bytes and a value of
/// `value_len` bytes, each of one repeated byte.
fn indexed_literal(name: u8, name_len: u8, value: u8, value_len: u8) -> Vec<u8> {
    let mut block = vec![0x40, name_len];
    block.extend(core::iter::repeat_n(name, usize::from(name_len)));
    block.push(value_len);
    block.extend(core::iter::repeat_n(value, usize::from(value_len)));
    block
}

/// RFC 9113, section 10.5.1: a block whose lines pass the list limit still changes the table as
/// the encoder expects. The decoder gives `TooLarge` for the stream, and the next block decodes
/// with the entries that the refused block added.
#[test]
fn a_block_past_the_list_limit_refuses_and_keeps_the_table_in_step() {
    let budget = budget();
    let limits = Limits {
        table_bytes: 4096,
        list_bytes: 100,
        work: 1 << 20,
    };
    let mut decoder = Peer::new(limits, &budget);
    // Two lines of 72 bytes each in the size of section 4.1: 144 is past the limit of 100.
    let mut block = indexed_literal(b'a', 10, b'b', 30);
    block.extend(indexed_literal(b'c', 10, b'd', 30));
    let (refused, count) = allocations(|| decoder.decode(&block).err());
    assert_eq!(refused, Some(DecodeError::TooLarge));
    assert_eq!(count, 0, "allocations");
    let newest = decoder.decode(&[0xbe]).expect("the newest entry");
    assert_eq!(lines(newest), [(vec![b'c'; 10], vec![b'd'; 30])]);
    let oldest = decoder.decode(&[0xbf]).expect("the oldest entry");
    assert_eq!(lines(oldest), [(vec![b'a'; 10], vec![b'b'; 30])]);
}

/// A block of one-byte references to a large entry expands 4000 times. After the lines pass the
/// list limit, the decoder copies no more of them, so the block costs its bytes and not more:
/// the stream refuses, and the connection continues.
#[test]
fn references_to_a_large_entry_refuse_the_stream_with_no_copy() {
    let budget = budget();
    let limits = Limits {
        table_bytes: 4096,
        list_bytes: 16 * 1024,
        work: 64 * 1024,
    };
    let mut decoder = Peer::new(limits, &budget);
    let mut entry = vec![0x40, 0x01, b'x', 0x7f];
    // A value of 4000 bytes: 127 and then 3873 in 7-bit groups (section 5.1).
    entry.extend([0xa1, 0x1e]);
    entry.extend(core::iter::repeat_n(b'v', 4000));
    decoder.decode(&entry).expect("one entry of 4033 bytes");
    let bomb = vec![0xbe; 16 * 1024];
    let (refused, count) = allocations(|| decoder.decode(&bomb).err());
    assert_eq!(refused, Some(DecodeError::TooLarge));
    assert_eq!(count, 0, "allocations");
    let block = decoder.decode(&[0xbe]).expect("the connection continues");
    assert_eq!(lines(block), [(b"x".to_vec(), vec![b'v'; 4000])]);
}

/// Each literal with incremental indexing that names a large entry copies the name two times
/// for two bytes of the block. The work limit stops the copies, and the decoder then refuses
/// each later block, because its table can no longer follow the encoder.
#[test]
fn a_block_past_the_work_limit_ends_the_decoder() {
    let budget = budget();
    let limits = Limits {
        table_bytes: 4096,
        list_bytes: 1 << 16,
        work: 32 * 1024,
    };
    let mut decoder = Peer::new(limits, &budget);
    // A name of 3000 bytes, 127 and then 2873 in 7-bit groups, and an empty value.
    let mut entry = vec![0x40, 0x7f, 0xb9, 0x16];
    entry.extend(core::iter::repeat_n(b'n', 3000));
    entry.push(0x00);
    decoder.decode(&entry).expect("one entry with a name of 3000 bytes");
    let block: Vec<u8> = core::iter::repeat_n([0x7e, 0x00], 20).flatten().collect();
    let (refused, count) = allocations(|| decoder.decode(&block).err());
    assert_eq!(refused, Some(DecodeError::Overload));
    assert_eq!(count, 0, "allocations");
    assert_eq!(decoder.decode(&[0x82]).err(), Some(DecodeError::Overload));
}

/// A budget that cannot pay refuses a decoder, its lines, and an encoder with `Overload` and no
/// allocation.
#[test]
fn a_codec_that_the_budget_cannot_pay_allocates_nothing() {
    let budget = Budget::new(NonZeroU64::new(4096).expect("not zero"));
    let limits = Limits {
        table_bytes: 4096,
        list_bytes: 16 * 1024,
        work: 64 * 1024,
    };
    let (decoder, count) = allocations(|| Decoder::new(limits, &budget).err().map(|error| error.kind()));
    assert_eq!((decoder, count), (Some(rsnetwork::drive::Kind::Overload), 0));
    let (lines, count) = allocations(|| Lines::new(limits, &budget).err().map(|error| error.kind()));
    assert_eq!((lines, count), (Some(rsnetwork::drive::Kind::Overload), 0));
    let (encoder, count) = allocations(|| Encoder::new(4096, &budget).err().map(|error| error.kind()));
    assert_eq!((encoder, count), (Some(rsnetwork::drive::Kind::Overload), 0));
    assert_eq!(budget.available(), 4096);
}

/// The sensitive-field rule: a credential, and a short cookie, whose low entropy a peer on the
/// same connection can guess, go as literals that are never indexed (RFC 7541, sections 6.2.3 and
/// 7.1.3). The same holds for each line that the caller marks. None of them enters the dynamic
/// table, so the second block is the same as the first, and the peer's table stays empty.
#[test]
fn a_sensitive_line_never_enters_the_dynamic_table() {
    let budget = budget();
    let lines: [(&[u8], &[u8], bool); 6] = [
        (b"authorization", b"Basic YWxhZGRpbjpvcGVuc2VzYW1l", false),
        (b"proxy-authorization", b"Basic dXNlcjpwYXNzd29yZA==", false),
        (b"Authorization", b"Bearer mF_9.B5f-4.1JqM", false),
        (b"cookie", b"sid=31d4d96e407a", false),
        (b"set-cookie", b"sid=31d4d96e407a; Secure"[..16].as_ref(), false),
        (b"x-api-key", b"d41d8cd98f00b204e9800998ecf8427e", true),
    ];
    for (name, value, never_indexed) in lines {
        let mut encoder = Encoder::new(4096, &budget).expect("the budget pays for the encoder");
        let mut decoder = decoder(4096, &budget);
        let line = FieldLine {
            name,
            value,
            never_indexed,
        };
        let first = encode(&mut encoder, [line].into_iter());
        let second = encode(&mut encoder, [line].into_iter());
        assert_eq!(
            first,
            second,
            "{}: the second block names a table entry",
            line.name.escape_ascii()
        );
        assert_eq!(
            first[0] & 0xf0,
            0x10,
            "{}: not a never-indexed literal",
            line.name.escape_ascii()
        );
        for block in [first, second] {
            let decoded = decoder.decode(&block).expect("the block decodes");
            let marks: Vec<_> = decoded
                .lines()
                .map(|line| (line.value.to_vec(), line.never_indexed))
                .collect();
            assert_eq!(marks, [(value.to_vec(), true)]);
        }
        assert_eq!(
            decoder.decode(&[0xbe]).err(),
            Some(DecodeError::Malformed),
            "the peer's table has an entry"
        );
    }
}

/// A cookie of 20 bytes or more has the entropy of a long value, so the rule indexes it, and the
/// second block names it with one byte.
#[test]
fn a_long_cookie_is_indexed() {
    let budget = budget();
    let mut encoder = Encoder::new(4096, &budget).expect("the budget pays for the encoder");
    let cookie = line(b"cookie", b"sid=31d4d96e407aad42");
    encode(&mut encoder, [cookie].into_iter());
    assert_eq!(encode(&mut encoder, [cookie].into_iter()), [0xbe]);
}

/// An encode that does not fit in the region refuses with the size that it needs, and writes and
/// changes nothing: the next encode gives the block of a new encoder.
#[test]
fn an_encode_into_a_short_region_refuses_and_changes_nothing() {
    let budget = budget();
    let lines = [line(b"custom-key", b"custom-value")];
    let mut encoder = Encoder::new(4096, &budget).expect("the budget pays for the encoder");
    let mut out = WriteLoan::new(Backing::from(Vec::with_capacity(8)));
    let refused = encoder.encode(lines.iter().copied(), &mut out);
    assert!(matches!(refused, Err(EncodeError::Full { needed, available: 8 }) if needed > 8));
    assert!(out.filled().is_empty());
    let mut fresh = Encoder::new(4096, &budget).expect("the budget pays for the encoder");
    assert_eq!(
        encode(&mut encoder, lines.iter().copied()),
        encode(&mut fresh, lines.iter().copied())
    );
}

/// RFC 7541, section 4.2: when the maximum size goes down and then up between two blocks, the
/// next block signals the smallest size and then the final size, so the peer evicts as the
/// encoder did. 1024 is `3f e1 07`, and 4096 is `3f e1 1f`.
#[test]
fn a_smaller_and_then_larger_peer_limit_signals_both_sizes() {
    let budget = budget();
    let mut encoder = Encoder::new(4096, &budget).expect("the budget pays for the encoder");
    encoder.set_peer_limit(1024);
    encoder.set_peer_limit(4096);
    let block = encode(&mut encoder, [line(b":method", b"GET")].into_iter());
    assert_eq!(block, [0x3f, 0xe1, 0x07, 0x3f, 0xe1, 0x1f, 0x82]);
}

/// Lines that a pool made for smaller limits cannot hold a line on its way to the table, so the
/// decoder refuses them before it reads the block, and its table does not change. The same block
/// then decodes into lines for its limits.
#[test]
fn lines_smaller_than_the_limits_refuse_and_change_nothing() {
    let budget = budget();
    let limits = Limits {
        table_bytes: 4096,
        list_bytes: 1024,
        work: 1 << 20,
    };
    let mut decoder = Decoder::new(limits, &budget).expect("the budget pays for the decoder");
    let small = Limits {
        table_bytes: 256,
        list_bytes: 256,
        ..limits
    };
    let mut small = Lines::new(small, &budget).expect("the budget pays for the lines");
    let block = hex(C3[0].wire);
    assert_eq!(decoder.decode(&block, &mut small).err(), Some(DecodeError::Misuse));
    let mut lines = Lines::new(limits, &budget).expect("the budget pays for the lines");
    let decoded = decoder.decode(&block, &mut lines).expect("the block decodes");
    assert_eq!(self::lines(decoded), expected(C3[0].lines));
    let table = decoder.decode(&[0xbe], &mut lines).expect("one entry");
    assert_eq!(self::lines(table), expected(C3[0].table));
}
