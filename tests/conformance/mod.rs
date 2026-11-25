//! The H1 conformance suite: framing and request-smuggling vectors, each with the outcomes that
//! RFC 9112 and RFC 9110 permit, and the schedules that cut the input, the output, and the time.
//!
//! A runner drives the H1 engines over one transport ([`Carry`]), with each schedule, and gives a
//! [`Run`] for each vector. [`serve`] and [`fetch`] are the application, and [`Memory`] is the
//! transport in memory. The runner of the caller-driven host is `tests/h1_conformance.rs`. A
//! binding includes this module in its own runner and checks the same vectors over its own
//! transport.
//! Each permitted outcome comes from the RFC section that the vector names, never from the code
//! under test. Where the RFC gives a choice, the vector lists each outcome that it permits. Where
//! it recommends one outcome, the vector permits only that one.

use core::cell::Cell;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::{NonZeroU64, NonZeroUsize};

use rsnetwork::body::Outcome as BodyOutcome;
use rsnetwork::buffer::{Backing, Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Ecn, Endpoint, Error, Inbound, Kind, Outbound, Received, TurnLimits};
use rsnetwork::h1::{BodyLimits, Client, ClientEvent, Framing, Limits, Server, ServerEvent};
use rsnetwork::host::{Connection, Engine, Io as _, Wait};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::value::{Authority, Method, Status, Target};

/// One message as the application saw it: its head, its body bytes, and the end of its body.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Exchange {
    /// `METHOD target` of a request, or the status code of a response.
    pub(crate) head: Vec<u8>,
    pub(crate) body: Vec<u8>,
    /// The end of the body, or `None` when the engine gave no end.
    pub(crate) end: Option<End>,
}

/// The bytes of a message as text, so that a failure shows them.
impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (head, body) = (self.head.escape_ascii(), self.body.escape_ascii());
        match &self.end {
            Some(End::Complete(trailers)) => write!(f, "{head} \"{body}\" complete \"{}\"", trailers.escape_ascii()),
            end => write!(f, "{head} \"{body}\" {end:?}"),
        }
    }
}

/// The end of a body as the application saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// Complete, with each trailer field line as `name: value\r\n`.
    Complete(Vec<u8>),
    Truncated,
    Malformed,
}

/// The result of one connection: what the application saw, the status of each response that the
/// server sent, and the end of the connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) exchanges: Vec<Exchange>,
    /// The status of each response that the server sent. A client outcome has none.
    pub(crate) statuses: Vec<u16>,
    pub(crate) end: Result<(), Kind>,
}

impl Outcome {
    /// Whether `actual` is this outcome. The body of a message that is not complete can stop at
    /// any byte, because the RFC does not decide where an engine finds the error.
    pub(crate) fn admits(&self, actual: &Self) -> bool {
        self.statuses == actual.statuses
            && self.end == actual.end
            && self.exchanges.len() == actual.exchanges.len()
            && self.exchanges.iter().zip(&actual.exchanges).all(|(expected, actual)| {
                expected.head == actual.head
                    && expected.end == actual.end
                    && (!matches!(expected.end, Some(End::Complete(_))) || expected.body == actual.body)
            })
    }
}

/// One step of a run, in order: what the transport received, each drive, and each write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The transport received these bytes.
    Region(Vec<u8>),
    /// The transport received the end of input.
    End,
    /// A drive at this time, in nanoseconds, and the wait that it gave.
    Turn(u64, Wait),
    /// The transport accepted these bytes of the output.
    Write(Vec<u8>),
}

/// The result of one vector over one schedule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Run {
    pub(crate) outcome: Outcome,
    /// Each byte that the transport accepted from the engine, in order.
    pub(crate) sent: Vec<u8>,
    /// Each step of the run. Two runs with the same schedule have the same steps.
    pub(crate) steps: Vec<Step>,
}

/// The sizes of the regions that the transport receives or the writes that it accepts.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Sizes {
    /// All available bytes at once.
    Whole,
    /// All available bytes, but no region or write crosses this position of the byte stream.
    Cut(usize),
    /// At most this many bytes each time.
    Each(usize),
    /// From 1 to this many bytes, from the seed of the schedule.
    Seeded(usize),
}

/// How the transport cuts the input, the output, and the time of one run.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Schedule {
    pub(crate) regions: Sizes,
    pub(crate) writes: Sizes,
    /// The longest time step between two drives, in nanoseconds, from the seed. Zero keeps the
    /// time at the start of the clock.
    pub(crate) step: u64,
    /// The state of SplitMix64, from the seed.
    state: u64,
}

impl Schedule {
    /// The whole input in one region, the whole output in one write, and no time step.
    pub(crate) const WHOLE: Self = Self::new(Sizes::Whole, Sizes::Whole);

    pub(crate) const fn new(regions: Sizes, writes: Sizes) -> Self {
        Self {
            regions,
            writes,
            step: 0,
            state: 0,
        }
    }

    /// Regions and writes of 1 to 8 bytes, and time steps of 0 to 50 ms, from `seed`. A head of
    /// up to 400 bytes thus arrives in less than the 30-second head timeout of the server.
    pub(crate) const fn seeded(seed: u64) -> Self {
        Self {
            regions: Sizes::Seeded(8),
            writes: Sizes::Seeded(8),
            step: 50_000_000,
            state: seed,
        }
    }

    /// The size of the next region, which starts at `position` of the input.
    pub(crate) fn region(&mut self, position: usize) -> usize {
        let sizes = self.regions;
        self.size(sizes, position)
    }

    /// The size of the next write, which starts at `position` of the output.
    pub(crate) fn write(&mut self, position: usize) -> usize {
        let sizes = self.writes;
        self.size(sizes, position)
    }

    /// The time step before the next drive, in nanoseconds.
    pub(crate) fn time_step(&mut self) -> u64 {
        if self.step == 0 {
            0
        } else {
            self.next() % (self.step + 1)
        }
    }

    fn size(&mut self, sizes: Sizes, position: usize) -> usize {
        match sizes {
            Sizes::Whole => usize::MAX,
            Sizes::Cut(cut) if position < cut => cut - position,
            Sizes::Cut(_) => usize::MAX,
            Sizes::Each(size) => size,
            Sizes::Seeded(most) => 1 + usize::try_from(self.next() % most as u64).expect("below `most`"),
        }
    }

    /// The next number of SplitMix64.
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// The status of each response in `sent`. Each response of the suite has no body, so each one
/// ends at its first empty line.
pub(crate) fn statuses(sent: &[u8]) -> Vec<u16> {
    let mut statuses = Vec::new();
    let mut rest = sent;
    while !rest.is_empty() {
        let end = rest
            .array_windows()
            .position(|window| window == b"\r\n\r\n")
            .expect("each response ends at an empty line");
        let line = rest.strip_prefix(b"HTTP/1.1 ").expect("an HTTP/1.1 status line");
        let code = core::str::from_utf8(&line[..3]).expect("three digits");
        statuses.push(code.parse().expect("three digits"));
        rest = &rest[end + 4..];
    }
    statuses
}

/// One vector: the bytes of the peer, and each outcome that the RFC permits for them.
#[derive(Debug)]
pub(crate) struct Vector {
    pub(crate) name: &'static str,
    /// The RFC sections that decide the outcomes.
    pub(crate) rfc: &'static str,
    pub(crate) input: Vec<u8>,
    pub(crate) permitted: Vec<Outcome>,
}

/// A request that a smuggling vector hides. A server that sees it read a framing wrong.
const SMUGGLED: &[u8] = b"GET /smuggled HTTP/1.1\r\nHost: a\r\n\r\n";

/// A complete message with `body` and no trailers.
fn complete(head: &str, body: &[u8]) -> Exchange {
    Exchange {
        head: head.into(),
        body: body.into(),
        end: Some(End::Complete(Vec::new())),
    }
}

/// A message whose body framing is malformed.
fn malformed(head: &str) -> Exchange {
    Exchange {
        head: head.into(),
        body: Vec::new(),
        end: Some(End::Malformed),
    }
}

/// The server answers each exchange with 200, and the connection then ends with no error.
fn served(exchanges: Vec<Exchange>) -> Outcome {
    Outcome {
        statuses: vec![200; exchanges.len()],
        exchanges,
        end: Ok(()),
    }
}

/// The server answers each complete exchange with 200, then refuses with `status` and closes.
fn refused(exchanges: Vec<Exchange>, status: u16, kind: Kind) -> Outcome {
    let complete = exchanges
        .iter()
        .filter(|exchange| matches!(exchange.end, Some(End::Complete(_))))
        .count();
    let mut statuses = vec![200; complete];
    statuses.push(status);
    Outcome {
        exchanges,
        statuses,
        end: Err(kind),
    }
}

/// The head of `POST /` with the field lines `fields`, each with its CR LF, then `body`.
fn post(fields: &str, body: &[u8]) -> Vec<u8> {
    [b"POST / HTTP/1.1\r\nHost: a\r\n", fields.as_bytes(), b"\r\n", body].concat()
}

/// The server vectors: request smuggling, line ends, chunk sizes, HTTP/1.0, and pipelining.
pub(crate) fn server() -> Vec<Vector> {
    let bad = || refused(Vec::new(), 400, Kind::Malformed);
    // The POST and the request that it hides, each served.
    let both = |body: &[u8]| served(vec![complete("POST /", body), complete("GET /smuggled", b"")]);
    let gets = || served(vec![complete("GET /", b""), complete("GET /smuggled", b"")]);
    let chunked = |chunks: &[u8]| [post("Transfer-Encoding: chunked\r\n", chunks), SMUGGLED.to_vec()].concat();
    let bad_chunk = || refused(vec![malformed("POST /")], 400, Kind::Malformed);
    let size_line = format!("{:x}\r\n", SMUGGLED.len());
    let te_cl = format!("Transfer-Encoding: chunked\r\nContent-Length: {}\r\n", size_line.len());
    let cl_te = format!(
        "Content-Length: {}\r\nTransfer-Encoding: chunked\r\n",
        5 + SMUGGLED.len()
    );
    let two_lengths = format!("Content-Length: 5\r\nContent-Length: {}\r\n", 5 + SMUGGLED.len());
    let length_list = format!("Content-Length: 5, {}\r\n", 5 + SMUGGLED.len());
    // RFC 9112, section 6.1: a server can refuse a request with both fields, or read the body
    // by Transfer-Encoding alone. Then it closes the connection after the response.
    let te_alone = |body: &[u8]| served(vec![complete("POST /", body)]);
    let host_refused = || {
        [
            bad(),
            Outcome {
                exchanges: vec![complete("GET /smuggled", b"")],
                statuses: vec![400, 200],
                end: Ok(()),
            },
        ]
    };

    vec![
        Vector {
            name: "CL.TE: Content-Length covers the request that chunked framing finds after it",
            rfc: "RFC 9112, sections 6.1, 6.3 item 3, and 11.2",
            input: [post(&cl_te, b"0\r\n\r\n"), SMUGGLED.to_vec()].concat(),
            permitted: vec![bad(), te_alone(b"")],
        },
        Vector {
            name: "TE.CL: the chunk covers the request that Content-Length finds after it",
            rfc: "RFC 9112, sections 6.1, 6.3 item 3, and 11.2",
            input: [
                post(&te_cl, &[size_line.as_bytes(), SMUGGLED, b"\r\n0\r\n\r\n"].concat()),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad(), te_alone(SMUGGLED)],
        },
        Vector {
            name: "two Content-Length lines with different values",
            rfc: "RFC 9112, section 6.3 item 5",
            input: [post(&two_lengths, b"hello"), SMUGGLED.to_vec()].concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "a Content-Length list with different values",
            rfc: "RFC 9112, section 6.3 item 5",
            input: [post(&length_list, b"hello"), SMUGGLED.to_vec()].concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "two Content-Length lines with the same value",
            rfc: "RFC 9110, section 8.6",
            input: [
                post("Content-Length: 5\r\nContent-Length: 5\r\n", b"hello"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad(), both(b"hello")],
        },
        Vector {
            name: "a Content-Length with a sign",
            rfc: "RFC 9110, section 8.6, and RFC 9112, section 6.3 item 5",
            input: [post("Content-Length: +5\r\n", b"hello"), SMUGGLED.to_vec()].concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "a Content-Length past u64 that wraps to 5",
            rfc: "RFC 9110, section 8.6",
            input: [
                post("Content-Length: 18446744073709551621\r\n", b"hello"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad(), refused(Vec::new(), 413, Kind::Overload)],
        },
        Vector {
            name: "TE.TE: a coding that only contains chunked",
            rfc: "RFC 9112, section 6.3 item 4",
            input: [
                post("Transfer-Encoding: xchunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "TE.TE: chunked in quotes",
            rfc: "RFC 9112, sections 6.3 item 4 and 7",
            input: [
                post("Transfer-Encoding: \"chunked\"\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "TE.TE: a second Transfer-Encoding line after chunked",
            rfc: "RFC 9112, section 6.3 item 4, and RFC 9110, section 5.3",
            input: [
                post(
                    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n",
                    b"5\r\nhello\r\n0\r\n\r\n",
                ),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "TE.TE: whitespace between the field name and the colon",
            rfc: "RFC 9112, section 5.1",
            input: [
                post(
                    "Transfer-Encoding : chunked\r\nContent-Length: 5\r\n",
                    b"hello",
                ),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "TE.TE: a tab before chunked",
            rfc: "RFC 9112, section 5.1",
            input: [
                post("Transfer-Encoding:\tchunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![both(b"hello")],
        },
        Vector {
            name: "TE.TE: chunked in capital letters",
            rfc: "RFC 9112, section 7",
            input: [
                post("Transfer-Encoding: CHUNKED\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![both(b"hello")],
        },
        Vector {
            name: "TE.TE: an empty list element before chunked",
            rfc: "RFC 9110, section 5.6.1",
            input: [
                post("Transfer-Encoding: , chunked\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![both(b"hello")],
        },
        Vector {
            name: "obsolete line folding",
            rfc: "RFC 9112, section 5.2",
            input: [b"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n", SMUGGLED].concat(),
            permitted: vec![bad(), gets()],
        },
        Vector {
            name: "obsolete line folding that hides Transfer-Encoding",
            rfc: "RFC 9112, section 5.2",
            input: [
                post(
                    "Content-Length: 5\r\nX: a\r\n Transfer-Encoding: chunked\r\n",
                    b"hello",
                ),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![bad(), both(b"hello")],
        },
        Vector {
            name: "whitespace before the first field line",
            rfc: "RFC 9112, section 2.2",
            input: [
                b"POST / HTTP/1.1\r\n Transfer-Encoding: chunked\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
                SMUGGLED,
            ]
            .concat(),
            permitted: vec![bad(), both(b"hello")],
        },
        Vector {
            name: "bare LF line ends in a head",
            rfc: "RFC 9112, section 2.2",
            input: [b"GET / HTTP/1.1\nHost: a\n\n", SMUGGLED].concat(),
            permitted: vec![bad(), gets()],
        },
        Vector {
            name: "a bare LF that hides Transfer-Encoding",
            rfc: "RFC 9112, sections 2.2 and 6.1",
            input: [
                post(
                    "Content-Length: 5\r\nX: a\nTransfer-Encoding: chunked\r\n",
                    b"hello",
                ),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            // A recipient that reads the bare LF as a line end reads both framing fields, and
            // then it refuses, or it reads `hello` as a chunk size.
            permitted: vec![bad(), bad_chunk()],
        },
        Vector {
            name: "a bare CR in a field value",
            rfc: "RFC 9112, section 2.2",
            input: [b"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n", SMUGGLED].concat(),
            permitted: vec![bad(), gets()],
        },
        Vector {
            name: "a bare LF after a chunk size",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"5\nhello\r\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "a bare LF after chunk data",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"5\r\nhello\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "chunk data longer than its size",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"5\r\nhelloX\r\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "a chunk size with 0x",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"0x5\r\nhello\r\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "an empty chunk size",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"\r\nhello\r\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "a negative chunk size",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"-5\r\nhello\r\n0\r\n\r\n"),
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "a chunk size past u64 that wraps to 5",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"10000000000000005\r\nhello\r\n0\r\n\r\n"),
            permitted: vec![
                bad_chunk(),
                refused(vec![malformed("POST /")], 413, Kind::Overload),
            ],
        },
        Vector {
            name: "chunk sizes with leading zeros and both letter cases",
            rfc: "RFC 9112, section 7.1",
            input: chunked(b"000A\r\n0123456789\r\na\r\n0123456789\r\n000\r\n\r\n"),
            permitted: vec![both(b"01234567890123456789")],
        },
        Vector {
            name: "chunk extensions with a token and a quoted value",
            rfc: "RFC 9112, section 7.1.1",
            input: chunked(b"5;a=b;c=\"d e\"\r\nhello\r\n0;x\r\n\r\n"),
            permitted: vec![both(b"hello")],
        },
        Vector {
            name: "whitespace before a chunk extension",
            rfc: "RFC 9112, section 7.1.1",
            input: chunked(b"5 ;a=b\r\nhello\r\n0\r\n\r\n"),
            permitted: vec![both(b"hello")],
        },
        Vector {
            name: "a Content-Length trailer field",
            rfc: "RFC 9110, section 6.5.1",
            input: chunked(b"5\r\nhello\r\n0\r\nContent-Length: 50\r\n\r\n"),
            // A sender must not send a framing field as a trailer field. A peer that merges the
            // trailers could frame by it, so the body refuses.
            permitted: vec![bad_chunk()],
        },
        Vector {
            name: "Transfer-Encoding and Content-Length in HTTP/1.0",
            rfc: "RFC 9112, section 6.1",
            input: [
                &b"POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello"[..],
                b"GET /smuggled HTTP/1.0\r\n\r\n",
            ]
            .concat(),
            permitted: vec![bad()],
        },
        Vector {
            name: "HTTP/1.0 with no Host and no keep-alive",
            rfc: "RFC 9112, sections 3.2 and 9.3",
            input: [b"GET / HTTP/1.0\r\n\r\n", SMUGGLED].concat(),
            permitted: vec![served(vec![complete("GET /", b"")])],
        },
        Vector {
            name: "HTTP/1.0 with keep-alive",
            rfc: "RFC 9112, section 9.3, and appendix C.2.2",
            input: [
                &b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"[..],
                b"GET /smuggled HTTP/1.0\r\n\r\n",
            ]
            .concat(),
            permitted: vec![gets(), served(vec![complete("GET /", b"")])],
        },
        Vector {
            name: "HTTP/1.1 with no Host",
            rfc: "RFC 9112, section 3.2",
            input: [b"GET / HTTP/1.1\r\n\r\n", SMUGGLED].concat(),
            permitted: host_refused().into(),
        },
        Vector {
            name: "two Host lines",
            rfc: "RFC 9112, section 3.2",
            input: [b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", SMUGGLED].concat(),
            permitted: host_refused().into(),
        },
        Vector {
            name: "four pipelined requests",
            rfc: "RFC 9112, section 9.3.2",
            input: [
                &b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n"[..],
                b"POST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
                b"POST /3 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                b"HEAD /4 HTTP/1.1\r\nHost: a\r\n\r\n",
            ]
            .concat(),
            permitted: vec![served(vec![
                complete("GET /1", b""),
                complete("POST /2", b"hello"),
                complete("POST /3", b"hello"),
                complete("HEAD /4", b""),
            ])],
        },
        Vector {
            name: "a close option in the second of three pipelined requests",
            rfc: "RFC 9112, section 9.6",
            input: [
                &b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n"[..],
                b"GET /2 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
                b"GET /3 HTTP/1.1\r\nHost: a\r\n\r\n",
            ]
            .concat(),
            permitted: vec![served(vec![complete("GET /1", b""), complete("GET /2", b"")])],
        },
        Vector {
            // With an output queue of two entries, the two responses before the refusal fill it.
            name: "CL.TE after two pipelined requests",
            rfc: "RFC 9112, sections 6.1 and 9.3.2",
            input: [
                b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),
                post(&cl_te, b"0\r\n\r\n"),
                SMUGGLED.to_vec(),
            ]
            .concat(),
            permitted: vec![
                refused(
                    vec![complete("GET /1", b""), complete("GET /2", b"")],
                    400,
                    Kind::Malformed,
                ),
                served(vec![
                    complete("GET /1", b""),
                    complete("GET /2", b""),
                    complete("POST /", b""),
                ]),
            ],
        },
        Vector {
            name: "an empty line before a pipelined request line",
            rfc: "RFC 9112, section 2.2",
            input: [
                &b"POST /1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello\r\n"[..],
                b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n",
            ]
            .concat(),
            permitted: vec![served(vec![complete("POST /1", b"hello"), complete("GET /2", b"")])],
        },
        Vector {
            name: "an empty line after the last request, then the end of input",
            rfc: "RFC 9112, section 2.2",
            input: b"GET / HTTP/1.1\r\nHost: a\r\n\r\n\r\n".to_vec(),
            permitted: vec![served(vec![complete("GET /", b"")])],
        },
        Vector {
            name: "a bare LF before a pipelined request line",
            // A recipient can read a bare LF as a line end, or refuse it.
            rfc: "RFC 9112, section 2.2",
            input: [
                &b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n\n"[..],
                b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n",
            ]
            .concat(),
            permitted: vec![
                refused(vec![complete("GET /1", b"")], 400, Kind::Malformed),
                served(vec![complete("GET /1", b""), complete("GET /2", b"")]),
            ],
        },
    ]
}

/// A client vector: the requests that the client sends, one after each response, and the bytes
/// of each response. The bytes of a response arrive after its request.
#[derive(Debug)]
pub(crate) struct Fetch {
    /// The responses in order, as one input.
    pub(crate) vector: Vector,
    /// The method of each request, and the length of the bytes of its response in the input.
    pub(crate) requests: Vec<(Method<'static>, usize)>,
}

impl Fetch {
    fn new(
        name: &'static str,
        rfc: &'static str,
        responses: &[(Method<'static>, &[u8])],
        permitted: Vec<Outcome>,
    ) -> Self {
        Self {
            vector: Vector {
                name,
                rfc,
                input: responses.iter().flat_map(|(_, bytes)| bytes.iter().copied()).collect(),
                permitted,
            },
            requests: responses.iter().map(|(method, bytes)| (*method, bytes.len())).collect(),
        }
    }
}

/// The client vectors: response framing, which is the desync risk of a client. The head of each
/// response is its status code and then each field line as `\r\nname: value`.
pub(crate) fn client() -> Vec<Fetch> {
    let bad = |exchanges| Outcome {
        exchanges,
        statuses: Vec::new(),
        end: Err(Kind::Malformed),
    };
    let ok = |exchanges| Outcome {
        exchanges,
        statuses: Vec::new(),
        end: Ok(()),
    };
    let chunked = "200\r\nTransfer-Encoding: chunked";
    vec![
        Fetch::new(
            "two Content-Length values in a response",
            // The user agent closes the connection and discards the response.
            "RFC 9112, section 6.3 item 5",
            &[(
                Method::GET,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhelloHTTP/1.1 200 OK\r\n\r\n",
            )],
            vec![bad(Vec::new())],
        ),
        Fetch::new(
            "Content-Length and Transfer-Encoding in a response",
            // Transfer-Encoding overrides Content-Length, and the message is an error. Never the
            // Content-Length body.
            "RFC 9112, section 6.3 item 3",
            &[(
                Method::GET,
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )],
            vec![
                bad(Vec::new()),
                ok(vec![complete(
                    "200\r\nContent-Length: 5\r\nTransfer-Encoding: chunked",
                    b"hello",
                )]),
            ],
        ),
        Fetch::new(
            "a response to HEAD with a Content-Length, then the next response",
            "RFC 9112, section 6.3 item 1",
            &[
                (Method::HEAD, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
                (Method::GET, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
            ],
            vec![ok(vec![
                complete("200\r\nContent-Length: 5", b""),
                complete("200\r\nContent-Length: 5", b"hello"),
            ])],
        ),
        Fetch::new(
            "bytes after a response to HEAD, in its region, in the form of a response",
            // A response comes after its request, so bytes that arrive with an earlier response
            // are not the response to a later request.
            "RFC 9112, sections 6.3 item 1 and 9.3",
            &[
                (
                    Method::HEAD,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 44\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged",
                ),
                (Method::GET, b""),
            ],
            vec![bad(vec![complete("200\r\nContent-Length: 44", b"")])],
        ),
        Fetch::new(
            "obsolete line folding in a response",
            // A user agent replaces each obs-fold with one or more SP before it reads the value.
            "RFC 9112, section 5.2",
            &[(
                Method::GET,
                b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 5\r\n\r\nhello",
            )],
            vec![
                ok(vec![complete("200\r\nX: a b\r\nContent-Length: 5", b"hello")]),
                ok(vec![complete("200\r\nX: a   b\r\nContent-Length: 5", b"hello")]),
            ],
        ),
        Fetch::new(
            "a response chunk size past u64 that wraps to 5",
            "RFC 9112, section 7.1",
            &[(
                Method::GET,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000005\r\nhello\r\n0\r\n\r\n",
            )],
            vec![
                bad(vec![malformed(chunked)]),
                Outcome {
                    end: Err(Kind::Overload),
                    ..bad(vec![malformed(chunked)])
                },
            ],
        ),
        Fetch::new(
            "a bare LF after a response chunk size",
            "RFC 9112, section 7.1",
            &[(
                Method::GET,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n0\r\n\r\n",
            )],
            vec![bad(vec![malformed(chunked)])],
        ),
    ]
}

// The application and the transport in memory, which each runner shares.

pub(crate) const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

pub(crate) const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1 << 10,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

pub(crate) const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
    visits: 1 << 12,
};

pub(crate) const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

pub(crate) const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The most rounds of one run. A run that needs more makes no progress.
pub(crate) const ROUNDS: usize = 10_000;

/// The queues of one connection. The output queue has two entries, so a pipelined exchange
/// meets output backpressure.
pub(crate) fn queues() -> (Inbound, Outbound, Budget) {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    (
        Inbound::new(NonZeroUsize::new(16).unwrap(), &budget).unwrap(),
        Outbound::new(NonZeroUsize::new(2).unwrap(), &budget).unwrap(),
        budget,
    )
}

/// The end of a body as the application saw it.
pub(crate) fn end(outcome: BodyOutcome) -> End {
    match outcome {
        BodyOutcome::Complete(trailers) => End::Complete(
            trailers
                .map(|trailers| {
                    trailers
                        .fields()
                        .flat_map(|field| [field.name(), b": ", field.value(), b"\r\n"].concat())
                        .collect()
                })
                .unwrap_or_default(),
        ),
        BodyOutcome::Truncated => End::Truncated,
        BodyOutcome::Malformed => End::Malformed,
        other => panic!("no vector gives {other:?}"),
    }
}

/// What the application saw: each message, with its body and its end.
#[derive(Default)]
pub(crate) struct Seen(Vec<Exchange>);

impl Seen {
    fn head(&mut self, head: Vec<u8>) {
        self.0.push(Exchange {
            head,
            body: Vec::new(),
            end: None,
        });
    }

    fn data(&mut self, data: &Lease) {
        self.last().body.extend_from_slice(data.bytes());
    }

    /// Records the end of the body, and gives whether the body is complete.
    fn end(&mut self, outcome: BodyOutcome) -> bool {
        let end = end(outcome);
        let complete = matches!(end, End::Complete(_));
        self.last().end = Some(end);
        complete
    }

    fn last(&mut self) -> &mut Exchange {
        self.0.last_mut().expect("a head before its body")
    }
}

/// Runs `connection` over `input` with `schedule`, and gives the bytes that the transport
/// accepted, each step, and the end of the connection.
///
/// Each round, the transport receives one region of the first `available` bytes of `input`, or
/// the end of input after the last byte, and `read` counts the bytes that it received. Then the
/// host drives until the connection waits, with the time of the round, and `answer` sees each
/// drive: it gives whether the application acted. Then the transport makes one write. A host reads
/// its socket and writes to it in the same way.
pub(crate) fn run<E: Engine>(
    mut connection: Connection<E>,
    input: &[u8],
    (available, read): (&Cell<usize>, &Cell<usize>),
    mut schedule: Schedule,
    mut answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
    let (mut ended, mut now) = (false, 0);
    let (mut sent, mut steps) = (Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        if read.get() < available.get() {
            let size = schedule.region(read.get()).min(available.get() - read.get());
            let region = &input[read.get()..read.get() + size];
            let received = Received {
                region: Lease::from(region.to_vec()),
                endpoint: ENDPOINT,
                capacity: 1 << 16,
            };
            // A full queue gives the region back, and the transport gives it again later.
            if connection.receive(received).is_ok() {
                read.set(read.get() + size);
                steps.push(Step::Region(region.to_vec()));
            }
        } else if read.get() == input.len() && !ended {
            connection.end_input();
            ended = true;
            steps.push(Step::End);
        }
        turns(&mut connection, Instant::new(CLOCK, now), &mut answer, &mut steps);
        if let Some(output) = connection.output() {
            let size = schedule.write(sent.len()).min(output.region.initialized());
            let accepted = &output.region.bytes()[..size];
            sent.extend_from_slice(accepted);
            steps.push(Step::Write(accepted.to_vec()));
            connection.ack(output.id, size).unwrap();
        }
        if let Some(end) = connection.release() {
            return (sent, steps, end.map_err(|error| error.kind()));
        }
        now += schedule.time_step();
    }
    panic!(
        "the connection made no progress in {ROUNDS} rounds, with input {}",
        input.escape_ascii()
    );
}

/// Drives `connection` at `now` until it waits, gives each drive to `answer`, and records each
/// turn in `steps`.
pub(crate) fn turns<E: Engine>(
    connection: &mut Connection<E>,
    now: Instant,
    answer: &mut impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    steps: &mut Vec<Step>,
) {
    loop {
        let event = connection.drive(Some(now)).unwrap();
        let gave = event.is_some();
        let acted = answer(connection, event);
        steps.push(Step::Turn(now.as_nanos(), connection.wait()));
        if !gave && !acted && connection.wait() != Wait::Now {
            break;
        }
    }
}

/// The response that the application owes, which it sends when the output queue has space.
/// Gives whether it sent it. The queue refuses with `Overload` when it is full.
pub(crate) fn send(owed: &mut bool, queue: impl FnOnce() -> Result<(), Error>) -> bool {
    if !*owed {
        return false;
    }
    match queue() {
        Ok(()) => {
            *owed = false;
            true
        }
        Err(error) if error.kind() == Kind::Overload => false,
        Err(error) => panic!("{error}"),
    }
}

/// Serves the request bytes `input` over `transport`. The application answers each complete
/// request with 200 and no body.
pub(crate) fn serve(input: &[u8], transport: impl Carry, schedule: Schedule) -> Run {
    let (inbound, outbound, budget) = queues();
    let server = Server::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    let connection = Connection::new(server, inbound, outbound, Some(transport.clock())).unwrap();
    let (mut seen, mut owed) = (Seen::default(), false);
    let (available, read) = (Cell::new(input.len()), Cell::new(0));
    let (sent, steps, end) = transport.carry(
        (connection, input, (&available, &read), schedule),
        |connection, event| {
            match event {
                Some(ServerEvent::Request(request)) => {
                    let head = request.head();
                    seen.head([head.method().as_bytes(), b" ", head.target().as_bytes()].concat());
                }
                Some(ServerEvent::Data(data)) => seen.data(&data),
                Some(ServerEvent::End(outcome)) => owed = seen.end(outcome),
                Some(ServerEvent::Handoff) => panic!("no vector changes the protocol"),
                None => {}
            }
            send(&mut owed, || {
                let (server, outbound) = connection.parts();
                let head = Backing::from(Vec::with_capacity(256));
                server.respond(outbound, Status::new(200).unwrap(), &[], Framing::Length(0), head)?;
                server.finish(outbound)
            })
        },
    );
    Run {
        outcome: Outcome {
            exchanges: seen.0,
            statuses: statuses(&sent),
            end,
        },
        sent,
        steps,
    }
}

/// Queues a request with `method` for `/` and no body.
pub(crate) fn request(client: &mut Client, outbound: &mut Outbound, method: Method<'_>) -> Result<(), Error> {
    let head = Backing::from(Vec::with_capacity(256));
    let (target, authority) = (Target::new(b"/").unwrap(), Authority::new(b"a").unwrap());
    client.request(outbound, method, target, authority, &[], Framing::Length(0), head)?;
    client.finish(outbound)
}

/// Sends the requests of `fetch` and reads their responses. The bytes of each response become
/// available after its request. The client sends its next request in answer to the end of a
/// response, or later: only after it received each byte that the server sent before the request.
/// A cut thus never moves bytes of the server after a later request. An engine that ended the
/// connection refuses the next request, and the client then sends no more.
pub(crate) fn fetch(fetch: &Fetch, transport: impl Carry, schedule: Schedule) -> Run {
    let (inbound, mut outbound, budget) = queues();
    let mut client = Client::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    let mut requests = fetch.requests.iter();
    let (method, length) = requests.next().expect("a client vector has a request");
    request(&mut client, &mut outbound, *method).unwrap();
    let (available, read) = (Cell::new(*length), Cell::new(0));
    let connection = Connection::new(client, inbound, outbound, Some(transport.clock())).unwrap();
    let (mut seen, mut owed) = (Seen::default(), false);
    let input = &fetch.vector.input;
    let (sent, steps, end) = transport.carry(
        (connection, input, (&available, &read), schedule),
        |connection, event| {
            match event {
                Some(ClientEvent::Response(response)) => {
                    let head = response.head();
                    let mut text = head.status().code().to_string().into_bytes();
                    for field in head.fields() {
                        text.extend_from_slice(&[b"\r\n", field.name(), b": ", field.value()].concat());
                    }
                    seen.head(text);
                }
                Some(ClientEvent::Data(data)) => seen.data(&data),
                Some(ClientEvent::End(outcome)) => owed = seen.end(outcome) && requests.len() > 0,
                Some(ClientEvent::Informational(_) | ClientEvent::Handoff) => {
                    panic!("no vector has an informational response or a protocol change")
                }
                None => {}
            }
            let (client, outbound) = connection.parts();
            let Some(&(method, length)) = requests.as_slice().first() else {
                return false;
            };
            if !owed || read.get() < available.get() {
                return false;
            }
            match request(client, outbound, method) {
                Ok(()) => {
                    owed = false;
                    requests.next();
                    available.set(available.get() + length);
                    true
                }
                Err(error) if error.kind() == Kind::Overload => false,
                Err(error) if error.kind() == Kind::Misuse => {
                    owed = false;
                    false
                }
                Err(error) => panic!("{error}"),
            }
        },
    );
    Run {
        outcome: Outcome {
            exchanges: seen.0,
            statuses: Vec::new(),
            end,
        },
        sent,
        steps,
    }
}

/// The connection, its input, the bytes that can arrive and that arrived, and the schedule of a
/// run.
pub(crate) type Input<'a, E> = (Connection<E>, &'a [u8], (&'a Cell<usize>, &'a Cell<usize>), Schedule);

/// The transport of a runner: it carries a connection, as [`run`] does in memory.
pub(crate) trait Carry: Copy {
    /// The clock domain of the times that this transport gives each drive.
    fn clock(self) -> ClockDomain;

    /// Runs `input` over this transport, with `answer` as the application, and gives the bytes
    /// that the transport accepted, each step, and the end of the connection.
    fn carry<E: Engine>(
        self,
        input: Input<'_, E>,
        answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    ) -> (Vec<u8>, Vec<Step>, Result<(), Kind>);
}

/// Regions and writes in memory, cut as the schedule says.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Memory;

impl Carry for Memory {
    fn clock(self) -> ClockDomain {
        CLOCK
    }

    fn carry<E: Engine>(
        self,
        (connection, input, cells, schedule): Input<'_, E>,
        answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    ) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
        run(connection, input, cells, schedule, answer)
    }
}

/// Runs `check` on each vector, with the run of its side for each transport and schedule, and
/// fails with each vector that it refuses, its RFC sections, and the reason.
pub(crate) fn check_each<T: Carry>(check: impl Fn(&Vector, &dyn Fn(T, Schedule) -> Run) -> Result<(), String>) {
    let mut failures = Vec::new();
    let mut record = |vector: &Vector, result: Result<(), String>| {
        if let Err(reason) = result {
            failures.push(format!("{} ({}): {reason}", vector.name, vector.rfc));
        }
    };
    for vector in server() {
        record(
            &vector,
            check(&vector, &|transport, schedule| {
                serve(&vector.input, transport, schedule)
            }),
        );
    }
    for client in client() {
        record(
            &client.vector,
            check(&client.vector, &|transport, schedule| {
                fetch(&client, transport, schedule)
            }),
        );
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Whether `run` gives the outcome and the bytes of `whole`, and if not, why.
pub(crate) fn same(whole: &Run, run: &Run, schedule: &str) -> Result<(), String> {
    if run.outcome == whole.outcome && run.sent == whole.sent {
        Ok(())
    } else {
        Err(format!(
            "{schedule}: {:?} and {:?}, not {:?} and {:?}",
            run.outcome,
            String::from_utf8_lossy(&run.sent),
            whole.outcome,
            String::from_utf8_lossy(&whole.sent),
        ))
    }
}
