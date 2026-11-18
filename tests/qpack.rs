//! QPACK: the examples of RFC 9204, Appendix B, the outputs of six independent encoders in the
//! qifs corpus, blocked streams and their limit, cancellations, refusals before allocation, and
//! the sensitive-field rule.

mod counting;

use core::assert_matches;
use core::num::NonZeroU64;
use std::fs;
use std::path::Path;

use rsnetwork::buffer::{Backing, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Kind;
use rsnetwork::qpack::{
    DecodeError, Decoder, EncodeError, Encoder, EncoderLimits, FieldLine, Full, Limits, Lines, Settings, StreamError,
};

use counting::allocations;

type Section = Vec<(Vec<u8>, Vec<u8>)>;

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 26).expect("not zero"))
}

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

fn region(capacity: usize) -> WriteLoan<Backing> {
    WriteLoan::new(Backing::from(Vec::with_capacity(capacity)))
}

fn line<'a>(name: &'a [u8], value: &'a [u8]) -> FieldLine<'a> {
    FieldLine {
        name,
        value,
        never_indexed: false,
    }
}

fn owned(lines: &[(&str, &str)]) -> Section {
    lines
        .iter()
        .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

fn limits(table_bytes: usize, blocked_streams: usize) -> Limits {
    Limits {
        table_bytes,
        blocked_streams,
        list_bytes: 1 << 16,
        work: 1 << 20,
    }
}

/// An encoder of `table_bytes` for a peer with the same capacity and `blocked_streams`.
fn encoder(table_bytes: usize, blocked_streams: u64, budget: &Budget) -> Encoder {
    let limits = EncoderLimits {
        table_bytes,
        sections: 64,
    };
    let mut encoder = Encoder::new(limits, budget).expect("the budget pays for the encoder");
    let peer = Settings {
        table_bytes: table_bytes as u64,
        blocked_streams,
    };
    encoder.set_peer(peer).expect("the first settings");
    encoder
}

/// Encodes `lines` as the section of `stream`, and gives its prefix, its lines, and the bytes of
/// the encoder stream.
fn encode(encoder: &mut Encoder, stream: u64, lines: &[FieldLine<'_>]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (mut section, mut instructions) = (region(1 << 16), region(1 << 16));
    let prefix = encoder
        .encode(stream, lines.iter().copied(), &mut section, &mut instructions)
        .expect("the region holds the section");
    (
        prefix.bytes().to_vec(),
        section.filled().to_vec(),
        instructions.filled().to_vec(),
    )
}

/// A decoder, the lines that it decodes into, and the bytes that it wrote on the decoder stream.
struct Peer {
    decoder: Decoder,
    lines: Lines,
    stream: WriteLoan<Backing>,
}

impl Peer {
    fn new(limits: Limits, budget: &Budget) -> Self {
        Self {
            decoder: Decoder::new(limits, budget).expect("the budget pays for the decoder"),
            lines: Lines::new(limits, budget).expect("the budget pays for the lines"),
            stream: region(1 << 20),
        }
    }

    /// Reads all of `bytes` from the encoder stream, in calls that each stop at the work limit.
    fn read(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut rest = bytes;
        while !rest.is_empty() {
            let read = self.decoder.receive(rest, &mut self.stream)?;
            assert!(read > 0, "a read made no progress");
            rest = &rest[read..];
        }
        Ok(())
    }

    fn receive(&mut self, bytes: &[u8]) {
        self.read(bytes).expect("the encoder stream is valid");
    }

    fn decode(&mut self, stream: u64, section: &[u8]) -> Result<Section, DecodeError> {
        let block = self
            .decoder
            .decode(stream, section, &mut self.lines, &mut self.stream)?;
        Ok(block
            .lines()
            .map(|line| (line.name.to_vec(), line.value.to_vec()))
            .collect())
    }

    /// The decoder stream since the last call.
    fn written(&mut self) -> Vec<u8> {
        let written = self.stream.filled().to_vec();
        self.stream = region(1 << 20);
        written
    }
}

#[test]
fn the_examples_of_appendix_b_decode_and_give_their_decoder_instructions() {
    let budget = budget();
    // The examples set a capacity of 220, so the maximum capacity of the decoder is 220: the
    // encoded Required Insert Counts of the examples need its 6 entries.
    let mut peer = Peer::new(limits(220, 1), &budget);
    // B.1: a literal with a static name reference.
    let lines = peer.decode(0, &hex("0000 510b 2f69 6e64 6578 2e68 746d 6c"));
    assert_eq!(lines, Ok(owned(&[(":path", "/index.html")])));
    assert_eq!(
        peer.written(),
        b"",
        "a section with no dynamic reference needs no acknowledgement"
    );
    // B.2: the capacity, two insertions with a static name reference, and a section with
    // post-Base indices.
    peer.receive(&hex(
        "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468",
    ));
    let lines = peer.decode(4, &hex("0381 10 11"));
    assert_eq!(
        lines,
        Ok(owned(&[(":authority", "www.example.com"), (":path", "/sample/path")]))
    );
    // The decoder sends an Insert Count Increment as soon as entries arrive (RFC 9204, section
    // 2.2.2.3), so the Section Acknowledgment 84 of the example follows an increment of 2.
    assert_eq!(peer.written(), [0x02, 0x84]);
    // B.3: an insertion with a literal name, and its Insert Count Increment of 1.
    peer.receive(&hex("4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565"));
    assert_eq!(peer.written(), [0x01]);
    // B.4: the section names a duplicate that did not arrive, so its stream blocks. The stream
    // is cancelled before the duplicate arrives.
    assert_eq!(peer.decode(8, &hex("0500 80 c1 81")), Err(DecodeError::Blocked));
    peer.decoder.cancel(8, &mut peer.stream).expect("the region has room");
    assert_eq!(peer.written(), [0x48]);
    peer.receive(&hex("02"));
    assert_eq!(peer.written(), [0x01]);
    assert_eq!(peer.decoder.unblocked(), None, "a cancelled stream does not wait");
    // B.5: an insertion with a dynamic name reference that evicts the oldest entry.
    peer.receive(&hex("810d 6375 7374 6f6d 2d76 616c 7565 32"));
    assert_eq!(peer.written(), [0x01]);
    // The table of the RFC after B.5, newest first: Base 5, relative indices 0 to 3.
    let lines = peer.decode(12, &hex("0600 80 81 82 83"));
    let table = [
        ("custom-key", "custom-value2"),
        (":authority", "www.example.com"),
        ("custom-key", "custom-value"),
        (":path", "/sample/path"),
    ];
    assert_eq!(lines, Ok(owned(&table)));
    // Absolute index 0 was evicted.
    assert_eq!(peer.decode(16, &hex("0200 80")), Err(DecodeError::Malformed));
}

/// The header lists of a QIF file, in their order: lines of a name, a tab, and a value, with an
/// empty line after each list, and comment lines that start with `#`.
fn qif(path: &Path) -> Vec<Section> {
    let text = fs::read(path).expect("the QIF file is readable");
    let mut lists = vec![Vec::new()];
    for line in text.split(|&byte| byte == b'\n') {
        if line.starts_with(b"#") {
            continue;
        }
        if line.is_empty() {
            if lists.last().is_some_and(|list: &Section| !list.is_empty()) {
                lists.push(Vec::new());
            }
            continue;
        }
        let (name, value) = line.split_once(|&byte| byte == b'\t').expect("a tab after the name");
        lists.last_mut().expect("a list").push((name.to_vec(), value.to_vec()));
    }
    lists.retain(|list| !list.is_empty());
    lists
}

/// The records of an output of the QPACK offline interop: a stream ID of 8 bytes and a length of
/// 4 bytes, both big-endian, and then the bytes.
fn records(bytes: &[u8]) -> Vec<(u64, &[u8])> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while let Some((head, after)) = rest.split_first_chunk::<12>() {
        let stream = u64::from_be_bytes(head[..8].try_into().expect("8 bytes"));
        let len = u32::from_be_bytes(head[8..].try_into().expect("4 bytes"));
        let (record, after) = after.split_at(usize::try_from(len).expect("a length"));
        records.push((stream, record));
        rest = after;
    }
    assert!(rest.is_empty(), "the file ends in a record");
    records
}

/// The Set Dynamic Table Capacity instruction of `capacity` (RFC 9204, section 4.3.1): `001` and
/// the capacity as an integer with a prefix of 5 bits (RFC 7541, section 5.1).
fn set_capacity(capacity: usize) -> Vec<u8> {
    if capacity < 31 {
        return vec![0x20 | u8::try_from(capacity).expect("less than 31")];
    }
    let mut bytes = vec![0x3f];
    let mut rest = capacity - 31;
    while rest >= 0x80 {
        bytes.push(u8::try_from(rest & 0x7f).expect("7 bits") | 0x80);
        rest >>= 7;
    }
    bytes.push(u8::try_from(rest).expect("7 bits"));
    bytes
}

fn corpus() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/qifs"))
}

#[test]
fn the_qifs_outputs_of_six_encoders_decode_to_their_qifs() {
    let (mut files, mut blocked) = (0, 0);
    for encoder in fs::read_dir(corpus().join("encoded/qpack-06")).expect("the corpus is here") {
        let encoder = encoder.expect("a directory entry").path();
        for file in fs::read_dir(&encoder).expect("an encoder directory") {
            let file = file.expect("a directory entry").path();
            let name = file.file_name().and_then(|name| name.to_str()).expect("a name");
            let (source, settings) = name.split_once(".out.").expect("an output name");
            let settings: Vec<usize> = settings
                .split('.')
                .map(|number| number.parse().expect("a number"))
                .collect();
            let expected = qif(&corpus().join("qifs").join(format!("{source}.qif")));
            let budget = budget();
            // A small work limit makes each read of the encoder stream stop and continue.
            let limits = Limits {
                work: 256,
                ..limits(settings[0], settings[1])
            };
            let mut peer = Peer::new(limits, &budget);
            // The outputs follow draft 06 of QPACK, whose table starts at its maximum capacity.
            // In RFC 9204 it starts at zero (section 3.2.2), so the decoder first reads the
            // instruction that gives the start state of the draft.
            if settings[0] > 0 {
                peer.receive(&set_capacity(settings[0]));
            }
            let mut decoded = vec![None; expected.len()];
            let mut waiting = Vec::new();
            let bytes = fs::read(&file).expect("the output is readable");
            for (index, (stream, record)) in records(&bytes).into_iter().enumerate() {
                if stream == 0 {
                    // Pieces of 1 to 13 bytes cut the instructions at each position.
                    for piece in record.chunks(1 + index % 13) {
                        let read = peer.read(piece);
                        assert_eq!(read, Ok(()), "{}: record {index}", file.display());
                    }
                    while let Some(stream) = peer.decoder.unblocked() {
                        let at = waiting
                            .iter()
                            .position(|&(waits, _)| waits == stream)
                            .expect("a stream that waits");
                        let (_, section): (u64, &[u8]) = waiting.swap_remove(at);
                        decoded[usize::try_from(stream - 1).expect("an index")] =
                            Some(peer.decode(stream, section).expect("the section decodes"));
                    }
                    continue;
                }
                match peer.decode(stream, record) {
                    Ok(lines) => decoded[usize::try_from(stream - 1).expect("an index")] = Some(lines),
                    Err(DecodeError::Blocked) => {
                        waiting.push((stream, record));
                        blocked += 1;
                    }
                    Err(error) => panic!("{}: stream {stream}: {error}", file.display()),
                }
            }
            assert!(waiting.is_empty(), "{}: a section still waits", file.display());
            for (stream, (decoded, expected)) in decoded.iter().zip(&expected).enumerate() {
                assert_eq!(
                    decoded.as_ref(),
                    Some(expected),
                    "{}: stream {}",
                    file.display(),
                    stream + 1
                );
            }
            files += 1;
        }
    }
    assert_eq!(files, 188, "each output of the subset");
    // Some encoders write a section before its insertions, so the blocked path ran.
    assert!(blocked > 0, "no section waited");
}

#[test]
fn the_qifs_lists_survive_the_encoder() {
    for source in ["netbsd", "netbsd-hq", "fb-req", "fb-resp"] {
        let expected = qif(&corpus().join("qifs").join(format!("{source}.qif")));
        for (table_bytes, blocked_streams) in [(0, 0), (256, 0), (256, 100), (4096, 0), (4096, 100)] {
            let budget = budget();
            let mut peer = Peer::new(limits(table_bytes, blocked_streams), &budget);
            let mut encoder = encoder(table_bytes, blocked_streams as u64, &budget);
            let case = format!("{source} with {table_bytes} bytes and {blocked_streams} blocked streams");
            for (index, list) in expected.iter().enumerate() {
                let stream = 4 * index as u64;
                let lines: Vec<_> = list.iter().map(|(name, value)| line(name, value)).collect();
                let (prefix, lines, instructions) = encode(&mut encoder, stream, &lines);
                let bytes = [prefix, lines].concat();
                // The section arrives before its insertions, so a section that names them waits.
                let decoded = match peer.decode(stream, &bytes) {
                    Err(DecodeError::Blocked) => {
                        peer.receive(&instructions);
                        assert_eq!(peer.decoder.unblocked(), Some(stream), "{case}");
                        peer.decode(stream, &bytes)
                    }
                    decoded => {
                        peer.receive(&instructions);
                        decoded
                    }
                };
                assert_eq!(decoded.as_ref(), Ok(list), "{case}: list {index}");
                encoder
                    .receive(&peer.written())
                    .expect("the encoder reads the decoder stream");
            }
        }
    }
}

/// A section that names absolute index 0 with a decoder of 4096 bytes: a Required Insert Count of
/// 1, encoded as 2; a Base of 0; and an indexed line with post-Base index 0.
const NAMES_THE_FIRST_ENTRY: [u8; 3] = [0x02, 0x80, 0x10];

#[test]
fn a_blocked_stream_past_the_limit_refuses_with_decompression_failed() {
    let budget = budget();
    let mut peer = Peer::new(limits(4096, 1), &budget);
    assert_eq!(peer.decode(0, &NAMES_THE_FIRST_ENTRY), Err(DecodeError::Blocked));
    // The same stream again is still one blocked stream.
    assert_eq!(peer.decode(0, &NAMES_THE_FIRST_ENTRY), Err(DecodeError::Blocked));
    assert_eq!(peer.decode(4, &NAMES_THE_FIRST_ENTRY), Err(DecodeError::TooManyBlocked));

    let mut peer = Peer::new(limits(4096, 0), &budget);
    assert_eq!(peer.decode(0, &NAMES_THE_FIRST_ENTRY), Err(DecodeError::TooManyBlocked));
}

#[test]
fn a_cancelled_stream_keeps_the_insert_counts_in_step() {
    let budget = budget();
    // A capacity of 64 holds one entry of 36 bytes, so the second entry evicts the first.
    let mut peer = Peer::new(limits(64, 1), &budget);
    let mut encoder = encoder(64, 1, &budget);
    // With 2 entries, the Required Insert Count 1 is encoded as 2. The Base is 0, so the line is
    // the post-Base index 0.
    let (prefix, lines, instructions) = encode(&mut encoder, 0, &[line(b"x-a", b"1")]);
    assert_eq!((&prefix[..], &lines[..]), (&[0x02, 0x80][..], &[0x10][..]));
    let section = [prefix, lines].concat();
    // The section arrives before its insertion, and the stream is reset while it waits.
    assert_eq!(peer.decode(0, &section), Err(DecodeError::Blocked));
    peer.decoder.cancel(0, &mut peer.stream).expect("the region has room");
    peer.receive(&instructions);
    assert_eq!(peer.decoder.unblocked(), None, "the cancelled stream does not wait");
    // The Stream Cancellation of stream 0, and the Insert Count Increment of 1.
    let written = peer.written();
    assert_eq!(written, [0x40, 0x01]);
    encoder.receive(&written).expect("the encoder reads the decoder stream");

    // The encoder evicts the first entry only when the decoder acknowledged it and no section
    // references it. Then the second entry has absolute index 1: the Required Insert Count is
    // 2, encoded as 3, after a Base of 1.
    let (prefix, lines, instructions) = encode(&mut encoder, 4, &[line(b"x-b", b"2")]);
    assert_eq!((&prefix[..], &lines[..]), (&[0x03, 0x80][..], &[0x10][..]));
    let section = [prefix, lines].concat();
    // The cancelled stream left its blocked slot, so this stream can wait.
    assert_eq!(peer.decode(4, &section), Err(DecodeError::Blocked));
    peer.receive(&instructions);
    assert_eq!(peer.decoder.unblocked(), Some(4));
    assert_eq!(peer.decode(4, &section), Ok(owned(&[("x-b", "2")])));
}

#[test]
fn malformed_instructions_refuse_before_allocation_and_end_the_decoder() {
    // Each input sets a capacity of 4096, except where the case sets another.
    let cases = [
        ("a capacity above the limit", "3fe21f"),
        ("a static name past the table", "3fe11f ff24 00"),
        ("a dynamic name that is not in the table", "3fe11f 80 00"),
        ("a duplicate of no entry", "3fe11f 00"),
        ("an entry larger than the capacity", "3f01 4161 00"),
        ("a Huffman name with EOS", "3fe11f 64ff ffff ff 00"),
        ("a Huffman name with a zero bit in its padding", "3fe11f 6118 00"),
        ("an integer past 64 bits", "3fff ffff ffff ffff ffff ff01"),
    ];
    for (case, input) in cases {
        let budget = budget();
        let mut peer = Peer::new(limits(4096, 1), &budget);
        let input = hex(input);
        let available = budget.available();
        let (result, count) = allocations(|| peer.decoder.receive(&input, &mut peer.stream));
        assert_eq!(result, Err(StreamError::Encoder), "{case}");
        assert_eq!(count, 0, "{case}: allocations");
        assert_eq!(budget.available(), available, "{case}: the charge");
        assert_eq!(
            peer.decoder.receive(b"", &mut peer.stream),
            Err(StreamError::Encoder),
            "{case}"
        );
        assert_eq!(peer.decode(0, &[0, 0]), Err(DecodeError::Malformed), "{case}");
    }
}

#[test]
fn malformed_sections_refuse_before_allocation() {
    // The table holds two entries of 4096 bytes in all: absolute index 0 `a: 1` and 1 `b: 2`.
    // With 128 entries, a Required Insert Count of 1 is encoded as 2, and of 2 as 3.
    let cases = [
        ("a prefix with no Base", "00"),
        ("a Required Insert Count past the full range", "ff02 00"),
        ("a Base below zero", "0281 10"),
        ("a static index past the table", "0000 ff24"),
        ("a relative index at the Base", "0000 80"),
        ("a reference at the Required Insert Count", "0200 80 10"),
        ("a Required Insert Count larger than the references", "0300 81"),
        ("a Required Insert Count with no reference", "0200 d1"),
        ("a value past the end of the section", "0000 5105 61"),
        ("a Huffman value with EOS", "0000 5184 ffff ffff"),
    ];
    for (case, section) in cases {
        let budget = budget();
        let mut peer = Peer::new(limits(4096, 1), &budget);
        peer.receive(&hex("3fe11f 4161 0131 4162 0132"));
        let section = hex(section);
        let available = budget.available();
        let (result, count) = allocations(|| peer.decode(0, &section).map(|_| ()));
        assert_eq!(result, Err(DecodeError::Malformed), "{case}");
        assert_eq!(count, 0, "{case}: allocations");
        assert_eq!(budget.available(), available, "{case}: the charge");
    }
    // An entry that the capacity evicted: a capacity of 34 holds one entry of 34 bytes.
    let budget = budget();
    let mut peer = Peer::new(limits(4096, 1), &budget);
    peer.receive(&hex("3f03 4161 0131 4162 0132"));
    assert_eq!(peer.decode(0, &hex("0200 80")), Err(DecodeError::Malformed));
    assert_eq!(peer.decode(4, &hex("0300 80")), Ok(owned(&[("b", "2")])));
}

#[test]
fn a_section_past_the_list_limit_refuses_the_stream_and_keeps_the_tables_in_step() {
    let budget = budget();
    let limits = Limits {
        list_bytes: 100,
        ..limits(4096, 1)
    };
    let mut peer = Peer::new(limits, &budget);
    // `a: 1` and `bb: 22`: each line has 34 or 36 bytes.
    peer.receive(&hex("3fe11f 4161 0131 4262 6202 3232"));
    assert_eq!(peer.written(), [0x02]);
    // Base 2: `bb: 22` three times is 108 bytes, past the limit of 100.
    assert_eq!(peer.decode(4, &hex("0300 80 80 80")), Err(DecodeError::TooLarge));
    // The decoder acknowledged the refused section, so the encoder can evict its entries.
    assert_eq!(peer.written(), [0x84]);
    assert_eq!(
        peer.decode(8, &hex("0300 81 80")),
        Ok(owned(&[("a", "1"), ("bb", "22")]))
    );
}

#[test]
fn a_sensitive_line_never_enters_the_dynamic_table() {
    let budget = budget();
    let mut encoder = encoder(4096, 8, &budget);
    let mut peer = Peer::new(limits(4096, 8), &budget);
    let secret = FieldLine {
        never_indexed: true,
        ..line(b"x-api-key", b"k-4f1c")
    };
    let lines = [
        line(b"authorization", b"Bearer mF_9.B5f-4.1JqM"),
        line(b"cookie", b"id=a3fWa"),
        secret,
    ];
    for stream in [0, 4] {
        let (prefix, section, instructions) = encode(&mut encoder, stream, &lines);
        // Only the capacity goes on the encoder stream: no line goes into the table.
        let expected: &[u8] = if stream == 0 { &[0x3f, 0xe1, 0x1f] } else { &[] };
        assert_eq!(instructions, expected);
        let bytes = [prefix, section].concat();
        peer.receive(&instructions);
        let block = peer
            .decoder
            .decode(stream, &bytes, &mut peer.lines, &mut peer.stream)
            .expect("the section decodes");
        let marks: Vec<_> = block.lines().map(|line| (line.name, line.never_indexed)).collect();
        assert_eq!(
            marks,
            [
                (&b"authorization"[..], true),
                (&b"cookie"[..], true),
                (&b"x-api-key"[..], true)
            ]
        );
    }
}

#[test]
fn the_encoder_names_unacknowledged_entries_only_within_the_blocked_limit() {
    let budget = budget();
    let mut encoder = encoder(4096, 0, &budget);
    let section = |encoder: &mut Encoder, stream| {
        let (prefix, lines, instructions) = encode(encoder, stream, &[line(b"x-a", b"1")]);
        ([prefix, lines].concat(), instructions)
    };
    // The line goes into the table, but no stream can block, so the section has a literal.
    let (first, instructions) = section(&mut encoder, 0);
    assert_eq!(instructions, hex("3fe11f 4378 2d61 0131"));
    assert_eq!(first, hex("0000 2378 2d61 0131"));
    // Before the decoder acknowledges the entry, the encoder neither names it nor inserts it again.
    let (again, nothing) = section(&mut encoder, 4);
    assert_eq!((again, nothing), (first, Vec::new()));
    // After the Insert Count Increment, the line is the relative index 0 from Base 1.
    encoder.receive(&[0x01]).expect("an increment of the one insertion");
    let (indexed, nothing) = section(&mut encoder, 8);
    assert_eq!((indexed, nothing), (hex("0200 80"), Vec::new()));
}

#[test]
fn an_encode_into_a_short_region_refuses_and_changes_nothing() {
    let budget = budget();
    let new = || encoder(4096, 8, &budget);
    let lines = [line(b"x-trace", b"7f3a"), line(b":path", b"/notes")];
    let encode = |encoder: &mut Encoder, capacity| {
        let (mut section, mut instructions) = (region(capacity), region(256));
        let prefix = encoder.encode(0, lines.iter().copied(), &mut section, &mut instructions)?;
        Ok::<_, EncodeError>([prefix.bytes(), section.filled(), instructions.filled()].concat())
    };
    let mut encoder = new();
    let refused = encode(&mut encoder, 4);
    assert_matches!(refused, Err(EncodeError::Full(Full { available: 4, .. })));
    assert_eq!(encode(&mut encoder, 256), encode(&mut new(), 256));
}

#[test]
fn a_decoder_stream_that_breaks_rfc_9204_ends_the_encoder() {
    let budget = budget();
    let cases = [
        ("an acknowledgement of a stream with no section", [0x80]),
        ("an increment of zero", [0x00]),
        ("an increment past the insertions", [0x01]),
    ];
    for (case, input) in cases {
        let mut encoder = Encoder::new(
            EncoderLimits {
                table_bytes: 4096,
                sections: 8,
            },
            &budget,
        )
        .expect("the budget pays for the encoder");
        assert_eq!(encoder.receive(&input), Err(StreamError::Decoder), "{case}");
        assert_eq!(
            encoder.receive(&[0x41]),
            Err(StreamError::Decoder),
            "{case}: a later call"
        );
    }
}

#[test]
fn a_read_of_the_encoder_stream_stops_at_its_work_limit() {
    let budget = budget();
    let limits = Limits {
        work: 10_000,
        ..limits(4096, 1)
    };
    let mut peer = Peer::new(limits, &budget);
    // An entry of 1 + 1967 + 32 = 2000 bytes: name `a` and a value of 1967 bytes `v`.
    let mut insert = hex("3fe11f 4161 7f b00e");
    insert.extend([b'v'; 1967]);
    peer.receive(&insert);
    // Each duplicate is 1 byte that copies the entry two times: 1 + 2 * 1968 = 3937 work. A call
    // stops at the first step after its work reaches 10,000: after three duplicates.
    let duplicates = [0x00; 10];
    let read = peer
        .decoder
        .receive(&duplicates, &mut peer.stream)
        .expect("duplicates are valid");
    assert_eq!(read, 3);
    peer.receive(&duplicates[read..]);
    // 11 insertions, and the table holds the newest two.
    let lines = peer.decode(0, &hex("0c00 80 81"));
    let value = "v".repeat(1967);
    assert_eq!(lines, Ok(owned(&[("a", &value), ("a", &value)])));
    assert_eq!(peer.decode(4, &hex("0c00 82")), Err(DecodeError::Malformed));
}

#[test]
fn a_codec_that_the_budget_cannot_pay_allocates_nothing() {
    let budget = Budget::new(NonZeroU64::new(64).expect("not zero"));
    let (decoder, count) = allocations(|| Decoder::new(limits(4096, 16), &budget).map(|_| ()));
    assert_eq!((decoder.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));
    let (lines, count) = allocations(|| Lines::new(limits(4096, 16), &budget).map(|_| ()));
    assert_eq!((lines.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));
    let encoder_limits = EncoderLimits {
        table_bytes: 4096,
        sections: 8,
    };
    let (encoder, count) = allocations(|| Encoder::new(encoder_limits, &budget).map(|_| ()));
    assert_eq!((encoder.map_err(|error| error.kind()), count), (Err(Kind::Overload), 0));
}

#[test]
fn a_decoder_stream_with_no_room_refuses_and_changes_nothing() {
    let budget = budget();
    let mut peer = Peer::new(limits(4096, 1), &budget);
    peer.receive(&hex("3fe11f 4161 0131"));
    assert_eq!(peer.written(), [0x01]);
    let full = Err(Full {
        needed: 1,
        available: 0,
    });
    // A section that needs a Section Acknowledgment refuses with no room for it.
    let section = hex("0200 80");
    let refused = peer
        .decoder
        .decode(4, &section, &mut peer.lines, &mut region(0))
        .map(|_| ());
    assert_eq!(refused, full.map_err(DecodeError::Full));
    assert_eq!(peer.decode(4, &section), Ok(owned(&[("a", "1")])));
    assert_eq!(peer.written(), [0x84]);
    // A cancellation with no room leaves the stream waiting.
    assert_eq!(peer.decode(8, &hex("0300 80")), Err(DecodeError::Blocked));
    assert_eq!(peer.decoder.cancel(8, &mut region(0)), full);
    peer.receive(&hex("4162 0132"));
    assert_eq!(peer.decoder.unblocked(), Some(8));
    peer.decoder.cancel(8, &mut peer.stream).expect("the region has room");
    assert_eq!(peer.written(), [0x01, 0x48]);
}
