//! The server engine reads request bytes from a peer. The first byte of the input sets the size of
//! each received region and the second the size of each write, with zero for whole. The rest is
//! the bytes of the peer.
//!
//! The application accepts each body that waits for `100 Continue`. It answers each complete
//! request with 200 and no body, an upgrade with 101, and a CONNECT with a tunnel. The run of
//! the cut input must give the run of the whole input: the same messages, the same output, the
//! same end, and the same bytes after a handoff. Each complete body has the length of its framing.
//! A refusal that the engine sends is its last response. The transport checks the bounds.

#![no_main]

use core::cell::Cell;

use rsnetwork::buffer::{Backing, Buffer as _};
use rsnetwork::drive::{Error, Outbound};
use rsnetwork::h1::{Framing, RequestHead, Server, ServerEvent};
use rsnetwork::value::{Field, Method, Status};
use rsnetwork_fuzz::{Act, BODY, Cut, LIMITS, Moment, Run, Seen, TURN, call, data, end, run};

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let [regions, writes, peer @ ..] = input else {
        return;
    };
    let whole = serve(peer, Cut::Whole, Cut::Whole);
    let (regions, writes) = (Cut::from_byte(*regions), Cut::from_byte(*writes));
    if (regions, writes) != (Cut::Whole, Cut::Whole) {
        assert_eq!(serve(peer, regions, writes), whole, "a cut input changed the run");
    }
});

/// The response that the application owes to the current request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owed {
    Nothing,
    Respond,
    Finish,
}

/// The facts of the current request that its body and its response need.
#[derive(Clone, Copy)]
struct Current {
    framing: Framing,
    connect: bool,
    upgrade: bool,
    body: u64,
}

/// Serves `peer` with the cuts, and gives the run with what the application saw.
fn serve(peer: &[u8], regions: Cut, writes: Cut) -> (Run, Vec<Seen>) {
    let mut seen = Vec::new();
    let mut current = None::<Current>;
    let (mut continue_owed, mut owed) = (false, Owed::Nothing);
    let run = run(
        peer,
        &Cell::new(peer.len()),
        regions,
        writes,
        |outbound, budget| Server::new(LIMITS, BODY, TURN, outbound, budget).expect("the budget admits the engine"),
        |server, outbound, moment| {
            let Moment::Event(event) = moment else {
                return Act::Idle;
            };
            match event {
                Some(ServerEvent::Request(request)) => {
                    let head = request.head();
                    seen.push(Seen::Head(describe(&head)));
                    current = Some(Current {
                        framing: head.framing(),
                        connect: head.method() == Method::CONNECT,
                        upgrade: head.upgrade(),
                        body: 0,
                    });
                    continue_owed = head.expects_continue();
                }
                Some(ServerEvent::Data(bytes)) => {
                    let current = current.as_mut().expect("a head before its body");
                    current.body += bytes.initialized() as u64;
                    data(&mut seen, bytes.bytes());
                }
                Some(ServerEvent::End(outcome)) => {
                    let (text, complete) = end(&outcome);
                    seen.push(text);
                    let current = current.expect("a head before its end");
                    if let (true, Framing::Length(length)) = (complete, current.framing) {
                        assert_eq!(
                            current.body, length,
                            "a complete body has another length than its framing"
                        );
                    }
                    if complete {
                        owed = Owed::Respond;
                    }
                }
                Some(ServerEvent::Handoff) => {
                    seen.push(Seen::Handoff);
                    return Act::Handoff;
                }
                None => {}
            }
            let mut acted = false;
            if continue_owed {
                match call(&mut seen, server.accept_body(outbound)) {
                    Some(()) => (continue_owed, acted) = (false, true),
                    None => return Act::Wait,
                }
            }
            if owed == Owed::Respond {
                let current = current.expect("a request before its response");
                match call(&mut seen, respond(server, outbound, current)) {
                    Some(()) => (owed, acted) = (Owed::Finish, true),
                    None => return Act::Wait,
                }
            }
            if owed == Owed::Finish {
                match call(&mut seen, server.finish(outbound)) {
                    Some(()) => (owed, acted) = (Owed::Nothing, true),
                    None => return Act::Wait,
                }
            }
            if acted { Act::Acted } else { Act::Idle }
        },
    );
    check_refusals(&run.sent);
    (run, seen)
}

/// Answers an upgrade with 101, a CONNECT with 200 and a tunnel, and each other request with 200
/// and no body.
fn respond(server: &mut Server, outbound: &mut Outbound, current: Current) -> Result<(), Error> {
    let upgrade = [Field::new(b"Upgrade", b"fuzz").expect("a valid field")];
    let (status, fields) = if current.upgrade && !current.connect {
        (101, upgrade.as_slice())
    } else {
        (200, [].as_slice())
    };
    let status = Status::new(status).expect("a valid status");
    let head = Backing::from(Vec::with_capacity(256));
    server.respond(outbound, status, fields, Framing::Length(0), head)
}

/// The facts of a request head that the engine gives.
fn describe(head: &RequestHead<'_>) -> String {
    let mut text = format!(
        "{} {} {:?} {:?} persistent {} continue {} upgrade {}",
        head.method().as_bytes().escape_ascii(),
        head.target().as_bytes().escape_ascii(),
        head.version(),
        head.framing(),
        head.persistent(),
        head.expects_continue(),
        head.upgrade(),
    );
    if let Some(authority) = head.authority() {
        text.push_str(&format!(" authority {}", authority.as_bytes().escape_ascii()));
    }
    for field in head.fields() {
        text.push_str(&format!(
            " | {}: {}",
            field.name().escape_ascii(),
            field.value().escape_ascii()
        ));
    }
    text
}

/// Checks that no response follows a refusal that the engine sent: a status of 400 or more,
/// because the application sends only 100, 101, and 200. A response after a refusal is a
/// response that a pipelined peer can read as the answer to another request. Each response of
/// the run has no body, so each one ends at its first empty line.
fn check_refusals(sent: &[u8]) {
    let mut rest = sent;
    while !rest.is_empty() {
        let line = rest
            .strip_prefix(b"HTTP/1.1 ")
            .expect("each response has an HTTP/1.1 status line");
        let status = line
            .get(..3)
            .and_then(|code| core::str::from_utf8(code).ok()?.parse::<u16>().ok());
        let status = status.expect("each status line has a status of three digits");
        let head = rest
            .array_windows()
            .position(|window| window == b"\r\n\r\n")
            .expect("each response head ends at an empty line");
        rest = &rest[head + 4..];
        assert!(
            status < 400 || rest.is_empty(),
            "a response follows the refusal {status}"
        );
    }
}
