//! The differential reading of a request head and its chunked body by rsnetwork and by an
//! independent parser.
//!
//! A reading is the list of parts that a parser accepted, in order, and how it ended. Each part is
//! text in which each byte of the peer has one form, so two readings are equal only when the two
//! parsers gave the same meaning to the same bytes. [`judge`] classifies two readings of one
//! input. Here the independent parser is `httparse`: its head parser, its chunk-size parser, and
//! its field-line parser for the trailer section. `tests/h1_differential.rs` and the
//! `differential` fuzz target include this module.

use rsnetwork::h1::{BodyLimits, ChunkDecoder, ChunkStep, Framing, Limits, RequestParser};
use rsnetwork::message::Version;

/// The head limits of the conformance suite.
pub(crate) const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

/// The body limits of the conformance suite.
pub(crate) const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1 << 10,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

/// The field lines that `httparse` can give. A head that rsnetwork accepts has at most
/// `LIMITS.fields`, so `httparse` never refuses it for the count.
const HTTPARSE_FIELDS: usize = 64;

/// How a reading ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The parser read the input to its end, or to the bytes of another protocol.
    Done,
    /// The input ended inside a part, and the parser waits for more bytes.
    Cut,
    /// The parser refused the input after its parts.
    Refused,
}

/// The parts that a parser accepted, in order, and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reading {
    pub(crate) parts: Vec<String>,
    pub(crate) end: End,
}

/// The class of two readings of one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The two readings are equal.
    Same,
    /// rsnetwork gave no meaning to the bytes after its parts: it refused them, or it waits for
    /// more. The other parser gave the same meaning to each part of rsnetwork.
    RsnetworkRefuses,
    /// The other parser refused a part that rsnetwork accepted, and it gave the same meaning to
    /// each part before it.
    OtherRefuses,
    /// The two parsers gave two meanings to the same bytes.
    Differ,
}

/// Classifies the reading of rsnetwork and the reading of another parser of the same input.
pub(crate) fn judge(rsnetwork: &Reading, other: &Reading) -> Verdict {
    if rsnetwork == other {
        Verdict::Same
    } else if rsnetwork.end != End::Done && other.parts.starts_with(&rsnetwork.parts) {
        Verdict::RsnetworkRefuses
    } else if other.end == End::Refused && rsnetwork.parts.starts_with(&other.parts) {
        Verdict::OtherRefuses
    } else {
        Verdict::Differ
    }
}

/// The bytes as text. Each visible ASCII byte stays, except `%`, `,`, and `=`. Each other byte
/// becomes `%` and two hexadecimal digits.
pub(crate) fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| match byte {
            b'%' | b',' | b'=' => format!("%{byte:02X}"),
            0x21..=0x7e => char::from(byte).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// Field lines as text: `name=value` for each line, in order, with a comma between them.
pub(crate) fn fields<'a>(lines: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> String {
    lines
        .map(|(name, value)| format!("{}={}", text(name), text(value)))
        .collect::<Vec<_>>()
        .join(",")
}

/// The reading of rsnetwork and of `httparse` of the request head at the start of `input`, and
/// of its body when rsnetwork reads chunked framing.
///
/// A head part is `method target version fields length`. A body part is `data trailers length`,
/// where `trailers` is the trailer field lines with their line ends. The length is the number of
/// bytes that the part takes, so it gives where the next part starts.
pub(crate) fn heads_and_chunks(input: &[u8]) -> (Reading, Reading) {
    let (rsnetwork, chunked) = rsnetwork(input);
    (rsnetwork, httparse(input, chunked))
}

fn rsnetwork(input: &[u8]) -> (Reading, bool) {
    let mut parts = Vec::new();
    let head = match RequestParser::new(LIMITS).parse(input) {
        Ok(Some(head)) => head,
        Ok(None) => return (Reading { parts, end: End::Cut }, false),
        Err(_) => {
            return (
                Reading {
                    parts,
                    end: End::Refused,
                },
                false,
            );
        }
    };
    let version = match head.version() {
        Version::Http10 => "HTTP/1.0",
        Version::Http11 => "HTTP/1.1",
        Version::Http2 => panic!("an HTTP/1.1 head has no HTTP/2 version"),
    };
    let lines = fields(head.fields().map(|field| (field.name(), field.value())));
    let (method, target) = (text(head.method().as_bytes()), text(head.target().as_bytes()));
    parts.push(format!("{method} {target} {version} {lines} {}", head.consumed()));
    if head.framing() != Framing::Chunked {
        return (Reading { parts, end: End::Done }, false);
    }
    let body = &input[head.consumed()..];
    let mut decoder = ChunkDecoder::new(BODY, LIMITS);
    let (mut data, mut at) = (Vec::new(), 0);
    let end = loop {
        match decoder.decode(&body[at..]) {
            Ok(ChunkStep::Data { framing, data: len }) if framing + len > 0 => {
                data.extend_from_slice(&body[at + framing..at + framing + len]);
                at += framing + len;
            }
            Ok(ChunkStep::End { len, trailers }) => {
                let trailers = &body[at..][trailers];
                parts.push(format!("{} {} {}", text(&data), text(trailers), at + len));
                break End::Done;
            }
            Ok(ChunkStep::Data { .. } | ChunkStep::More) => break End::Cut,
            Err(_) => break End::Refused,
        }
    };
    (Reading { parts, end }, true)
}

fn httparse(input: &[u8], chunked: bool) -> Reading {
    let mut parts = Vec::new();
    let mut headers = [httparse::EMPTY_HEADER; HTTPARSE_FIELDS];
    let mut request = httparse::Request::new(&mut headers);
    let consumed = match request.parse(input) {
        Ok(httparse::Status::Complete(consumed)) => consumed,
        Ok(httparse::Status::Partial) => return Reading { parts, end: End::Cut },
        Err(_) => {
            return Reading {
                parts,
                end: End::Refused,
            };
        }
    };
    let version = match request.version {
        Some(0) => "HTTP/1.0",
        Some(1) => "HTTP/1.1",
        _ => {
            return Reading {
                parts,
                end: End::Refused,
            };
        }
    };
    let (Some(method), Some(target)) = (request.method, request.path) else {
        return Reading {
            parts,
            end: End::Refused,
        };
    };
    let lines = fields(
        request
            .headers
            .iter()
            .map(|header| (header.name.as_bytes(), header.value)),
    );
    parts.push(format!(
        "{} {} {version} {lines} {consumed}",
        text(method.as_bytes()),
        text(target.as_bytes())
    ));
    if !chunked {
        return Reading { parts, end: End::Done };
    }
    let body = &input[consumed..];
    let (mut data, mut at) = (Vec::new(), 0);
    let end = loop {
        let (line, size) = match httparse::parse_chunk_size(&body[at..]) {
            Ok(httparse::Status::Complete(chunk)) => chunk,
            Ok(httparse::Status::Partial) => break End::Cut,
            Err(_) => break End::Refused,
        };
        at += line;
        if size == 0 {
            let mut trailers = [httparse::EMPTY_HEADER; HTTPARSE_FIELDS];
            match httparse::parse_headers(&body[at..], &mut trailers) {
                Ok(httparse::Status::Complete((len, _))) => {
                    // The trailer field lines, without the empty line that ends them.
                    let lines = &body[at..at + len.saturating_sub(2)];
                    parts.push(format!("{} {} {}", text(&data), text(lines), at + len));
                    break End::Done;
                }
                Ok(httparse::Status::Partial) => break End::Cut,
                Err(_) => break End::Refused,
            }
        }
        // The chunk data, then its CR LF (RFC 9112, section 7.1).
        let Some(len) = usize::try_from(size).ok().filter(|&len| len <= body.len() - at) else {
            break End::Cut;
        };
        data.extend_from_slice(&body[at..at + len]);
        at += len;
        match &body[at..] {
            [b'\r', b'\n', ..] => at += 2,
            [] | [b'\r'] => break End::Cut,
            _ => break End::Refused,
        }
    };
    Reading { parts, end }
}
