//! The client engine reads response bytes from a peer. The first byte of the input sets the size
//! of each received region and the second the size of each write, with zero for whole. The third
//! selects the first request: GET, HEAD, CONNECT, or GET with an upgrade. The rest is the bytes
//! that the peer sends for each request: two bytes of length, and then that many bytes.
//!
//! After each complete response, the client sends a GET, up to eight requests. The peer sends
//! the bytes for a request only after the request, as a server does. Thus the bytes that arrive
//! with a response do not race with the next request: the regression tests of the client cover
//! those bytes. The run of the cut input must give the run of the whole input: the same messages,
//! the same output, the same end, and the same bytes after a handoff. Each complete body has the
//! length of its framing. The transport checks the bounds.

#![no_main]

use core::cell::Cell;

use rsnetwork::buffer::{Backing, Buffer as _};
use rsnetwork::drive::{Error, Outbound};
use rsnetwork::h1::{Client, ClientEvent, Framing, ResponseHead};
use rsnetwork::value::{Authority, Field, Method, Target};
use rsnetwork_fuzz::{Act, BODY, Cut, LIMITS, Moment, Run, Seen, TURN, call, data, end, run};

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [regions, writes, first, rest @ ..] = input else {
        return;
    };
    let first = Request::ALL[usize::from(*first) % Request::ALL.len()];
    let (mut peer, mut lengths, mut rest) = (Vec::new(), Vec::new(), rest);
    while let [high, low, after @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low])).min(after.len());
        peer.extend_from_slice(&after[..length]);
        lengths.push(length);
        rest = &after[length..];
    }
    let (peer, lengths) = (peer.as_slice(), lengths.as_slice());
    let whole = fetch(peer, lengths, first, Cut::Whole, Cut::Whole);
    let (regions, writes) = (Cut::from_byte(*regions), Cut::from_byte(*writes));
    if (regions, writes) != (Cut::Whole, Cut::Whole) {
        assert_eq!(
            fetch(peer, lengths, first, regions, writes),
            whole,
            "a cut input changed the run"
        );
    }
});

/// The most requests of one run. The bytes after the last response arrive with no request.
const REQUESTS: usize = 8;

/// A request that the client sends, with no body.
#[derive(Clone, Copy)]
enum Request {
    Get,
    Head,
    Connect,
    Upgrade,
}

impl Request {
    const ALL: [Self; 4] = [Self::Get, Self::Head, Self::Connect, Self::Upgrade];

    /// Queues the request head.
    fn send(self, client: &mut Client, outbound: &mut Outbound) -> Result<(), Error> {
        let (method, target, authority) = match self {
            Self::Connect => (Method::CONNECT, b"a:80".as_slice(), b"a:80".as_slice()),
            Self::Head => (Method::HEAD, b"/".as_slice(), b"a".as_slice()),
            Self::Get | Self::Upgrade => (Method::GET, b"/".as_slice(), b"a".as_slice()),
        };
        let upgrade = [
            Field::new(b"Connection", b"upgrade").expect("a valid field"),
            Field::new(b"Upgrade", b"fuzz").expect("a valid field"),
        ];
        let fields = if matches!(self, Self::Upgrade) {
            upgrade.as_slice()
        } else {
            &[]
        };
        let target = Target::new(target).expect("a valid target");
        let authority = Authority::new(authority).expect("a valid authority");
        let head = Backing::from(Vec::with_capacity(256));
        client.request(outbound, method, target, authority, fields, Framing::Length(0), head)
    }
}

/// The request that the application owes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owed {
    Nothing,
    /// A response ended, and the application sends the next request when the connection is
    /// quiet.
    Next,
    Request,
    Finish,
}

/// The facts of the current response that its body needs.
#[derive(Clone, Copy)]
struct Current {
    framing: Framing,
    body: u64,
}

/// Sends `first` and reads `peer` with the cuts, and gives the run with what the application saw.
/// The peer sends the first `lengths[n]` bytes after the request `n`.
fn fetch(peer: &[u8], lengths: &[usize], first: Request, regions: Cut, writes: Cut) -> (Run, Vec<Seen>) {
    let mut seen = Vec::new();
    let mut current = None::<Current>;
    let (mut owed, mut sent) = (Owed::Nothing, 1);
    let available = Cell::new(lengths.first().copied().unwrap_or(0));
    let run = run(
        peer,
        &available,
        regions,
        writes,
        |outbound, budget| {
            let mut client = Client::new(LIMITS, BODY, TURN, outbound, budget).expect("the budget admits the engine");
            first
                .send(&mut client, outbound)
                .expect("an idle client sends its first request");
            client.finish(outbound).expect("the output queue has space");
            client
        },
        |client, outbound, moment| {
            let event = match moment {
                Moment::Event(event) => event,
                Moment::Quiet if owed == Owed::Next => {
                    owed = Owed::Request;
                    None
                }
                Moment::Quiet => return Act::Idle,
            };
            match event {
                Some(ClientEvent::Informational(response)) => {
                    seen.push(Seen::Head(format!("informational {}", describe(&response.head()))));
                }
                Some(ClientEvent::Response(response)) => {
                    let head = response.head();
                    seen.push(Seen::Head(describe(&head)));
                    current = Some(Current {
                        framing: head.framing(),
                        body: 0,
                    });
                }
                Some(ClientEvent::Data(bytes)) => {
                    let current = current.as_mut().expect("a head before its body");
                    current.body += bytes.initialized() as u64;
                    data(&mut seen, bytes.bytes());
                }
                Some(ClientEvent::End(outcome)) => {
                    let (text, complete) = end(&outcome);
                    seen.push(text);
                    let current = current.expect("a head before its end");
                    if let (true, Framing::Length(length)) = (complete, current.framing) {
                        assert_eq!(
                            current.body, length,
                            "a complete body has another length than its framing"
                        );
                    }
                    if complete && sent < REQUESTS {
                        owed = Owed::Next;
                    }
                }
                Some(ClientEvent::Handoff) => {
                    seen.push(Seen::Handoff);
                    return Act::Handoff;
                }
                None => {}
            }
            let mut acted = false;
            if owed == Owed::Request {
                match call(&mut seen, Request::Get.send(client, outbound)) {
                    Some(()) => {
                        let length = lengths.get(sent).copied().unwrap_or(0);
                        available.set(available.get() + length);
                        (owed, sent, acted) = (Owed::Finish, sent + 1, true);
                    }
                    None => return Act::Wait,
                }
            }
            if owed == Owed::Finish {
                match call(&mut seen, client.finish(outbound)) {
                    Some(()) => (owed, acted) = (Owed::Nothing, true),
                    None => return Act::Wait,
                }
            }
            if acted { Act::Acted } else { Act::Idle }
        },
    );
    (run, seen)
}

/// The facts of a response head that the engine gives.
fn describe(head: &ResponseHead<'_>) -> String {
    let mut text = format!(
        "{} {} {:?} {:?} persistent {}",
        head.status().code(),
        head.reason().escape_ascii(),
        head.version(),
        head.framing(),
        head.persistent(),
    );
    for field in head.fields() {
        text.push_str(&format!(
            " | {}: {}",
            field.name().escape_ascii(),
            field.value().escape_ascii()
        ));
    }
    text
}
