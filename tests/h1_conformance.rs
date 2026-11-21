//! The H1 conformance suite on the caller-driven host. The server and client engines read each
//! vector of `conformance` through a `host::Connection`, with the whole input, with the input cut
//! at each byte, with the output cut at each byte, and with seeded schedules of bytes and time.
//! Each outcome must be one that the RFC permits, and each schedule must give the outcome and the
//! bytes of the whole input. With the `tcp` feature, each vector also runs over a loopback TCP
//! socket through `host::Tcp`.

use core::cell::Cell;
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

mod conformance;

use conformance::{End, Exchange, Fetch, Outcome, Run, Schedule, Sizes, Step, Vector};

const LIMITS: Limits = Limits {
    head_bytes: 1024,
    fields: 16,
    name_bytes: 64,
    value_bytes: 256,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 1 << 20,
    drain_bytes: 1 << 10,
    extension_bytes: 64,
    trailer_bytes: 256,
    trailer_fields: 4,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
};

const CLOCK: ClockDomain = ClockDomain::new(1, Suspend::Pauses);

const ENDPOINT: Endpoint = Endpoint {
    peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 50_000),
    local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    ecn: Ecn::NotEct,
    segment: None,
};

/// The most rounds of one run. A run that needs more makes no progress.
const ROUNDS: usize = 10_000;

/// The seeds of the replay test.
const SEEDS: u64 = 64;

/// The queues of one connection. The output queue has two entries, so a pipelined exchange
/// meets output backpressure.
fn queues() -> (Inbound, Outbound, Budget) {
    let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
    (
        Inbound::new(NonZeroUsize::new(16).unwrap(), &budget).unwrap(),
        Outbound::new(NonZeroUsize::new(2).unwrap(), &budget).unwrap(),
        budget,
    )
}

/// The end of a body as the application saw it.
fn end(outcome: BodyOutcome) -> End {
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
struct Seen(Vec<Exchange>);

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

/// The transport of a run.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// Regions and writes in memory, cut as the schedule says.
    Memory,
    /// A loopback TCP socket through `host::Tcp`.
    #[cfg(feature = "tcp")]
    Tcp,
}

/// Runs `connection` over `input` with `schedule`, and gives the bytes that the transport
/// accepted, each step, and the end of the connection.
///
/// Each round, the transport receives one region of the first `available` bytes of `input`, or
/// the end of input after the last byte, and `read` counts the bytes that it received. Then the
/// host drives until the connection waits, with the time of the round, and `answer` sees each
/// drive: it gives whether the application acted. Then the transport makes one write. A host reads
/// its socket and writes to it in the same way.
fn run<E: Engine>(
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
        turns(&mut connection, now, &mut answer, &mut steps);
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
fn turns<E: Engine>(
    connection: &mut Connection<E>,
    now: u64,
    answer: &mut impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    steps: &mut Vec<Step>,
) {
    loop {
        let event = connection.drive(Some(Instant::new(CLOCK, now))).unwrap();
        let gave = event.is_some();
        let acted = answer(connection, event);
        steps.push(Step::Turn(now, connection.wait()));
        if !gave && !acted && connection.wait() != Wait::Now {
            break;
        }
    }
}

/// The response that the application owes, which it sends when the output queue has space.
/// Gives whether it sent it. The queue refuses with `Overload` when it is full.
fn send(owed: &mut bool, queue: impl FnOnce() -> Result<(), Error>) -> bool {
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
fn serve(input: &[u8], transport: Transport, schedule: Schedule) -> Run {
    let (inbound, outbound, budget) = queues();
    let server = Server::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    let connection = Connection::new(server, inbound, outbound, Some(CLOCK)).unwrap();
    let (mut seen, mut owed) = (Seen::default(), false);
    let (available, read) = (Cell::new(input.len()), Cell::new(0));
    let (sent, steps, end) = carry(
        transport,
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
            statuses: conformance::statuses(&sent),
            end,
        },
        sent,
        steps,
    }
}

/// Queues a request with `method` for `/` and no body.
fn request(client: &mut Client, outbound: &mut Outbound, method: Method<'_>) -> Result<(), Error> {
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
fn fetch(fetch: &Fetch, transport: Transport, schedule: Schedule) -> Run {
    let (inbound, mut outbound, budget) = queues();
    let mut client = Client::new(LIMITS, BODY, TURN, &outbound, &budget).unwrap();
    let mut requests = fetch.requests.iter();
    let (method, length) = requests.next().expect("a client vector has a request");
    request(&mut client, &mut outbound, *method).unwrap();
    let (available, read) = (Cell::new(*length), Cell::new(0));
    let connection = Connection::new(client, inbound, outbound, Some(CLOCK)).unwrap();
    let (mut seen, mut owed) = (Seen::default(), false);
    let input = &fetch.vector.input;
    let (sent, steps, end) = carry(
        transport,
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
type Input<'a, E> = (Connection<E>, &'a [u8], (&'a Cell<usize>, &'a Cell<usize>), Schedule);

/// Runs `input` over `transport`, with `answer` as the application.
fn carry<E: Engine>(
    transport: Transport,
    (connection, input, cells, schedule): Input<'_, E>,
    answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
    match transport {
        Transport::Memory => run(connection, input, cells, schedule, answer),
        #[cfg(feature = "tcp")]
        Transport::Tcp => tcp::run(connection, input, cells, schedule, answer),
    }
}

/// Runs `check` on each vector, with the run of its side for each transport and schedule, and
/// fails with each vector that it refuses, its RFC sections, and the reason.
fn check_each(check: impl Fn(&Vector, &dyn Fn(Transport, Schedule) -> Run) -> Result<(), String>) {
    let mut failures = Vec::new();
    let mut record = |vector: &Vector, result: Result<(), String>| {
        if let Err(reason) = result {
            failures.push(format!("{} ({}): {reason}", vector.name, vector.rfc));
        }
    };
    for vector in conformance::server() {
        record(
            &vector,
            check(&vector, &|transport, schedule| {
                serve(&vector.input, transport, schedule)
            }),
        );
    }
    for client in conformance::client() {
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
fn same(whole: &Run, run: &Run, schedule: &str) -> Result<(), String> {
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

/// With the whole input in one region and each output in one write, each vector gives an outcome
/// that its RFC sections permit.
#[test]
fn each_vector_gives_an_outcome_that_its_rfc_permits() {
    check_each(|vector, run| {
        let run = run(Transport::Memory, Schedule::WHOLE);
        if vector.permitted.iter().any(|permitted| permitted.admits(&run.outcome)) {
            Ok(())
        } else {
            Err(format!("{:?}", run.outcome))
        }
    });
}

/// The input in two regions, cut at each byte, and the input one byte at a time, each give the
/// outcome and the output of the whole input.
#[test]
fn each_split_of_the_input_gives_the_result_of_the_whole_input() {
    check_each(|vector, run| {
        let whole = run(Transport::Memory, Schedule::WHOLE);
        let cuts = (1..vector.input.len()).map(|cut| (Sizes::Cut(cut), format!("a cut at byte {cut}")));
        for (regions, schedule) in cuts.chain([(Sizes::Each(1), "one byte at a time".into())]) {
            same(
                &whole,
                &run(Transport::Memory, Schedule::new(regions, Sizes::Whole)),
                &schedule,
            )?;
        }
        Ok(())
    });
}

/// A short write at each byte of the output, and writes of one byte, each give the outcome and
/// the output of whole writes. The host drives between two writes, so the engine meets output
/// that the transport has not accepted.
#[test]
fn each_short_write_gives_the_result_of_whole_writes() {
    check_each(|_vector, run| {
        let whole = run(Transport::Memory, Schedule::WHOLE);
        let cuts = (1..whole.sent.len()).map(|cut| (Sizes::Cut(cut), format!("a short write at byte {cut}")));
        for (writes, schedule) in cuts.chain([(Sizes::Each(1), "one byte at a time".into())]) {
            same(
                &whole,
                &run(Transport::Memory, Schedule::new(Sizes::Whole, writes)),
                &schedule,
            )?;
        }
        Ok(())
    });
}

/// A seed gives the sizes of the regions, the sizes of the writes, and the time of each drive.
/// Two runs with the same seed give the same steps: each region, each turn with its time and
/// deadline, and each written byte. Each seeded run gives the result of the whole input.
#[test]
fn a_replay_with_the_same_seed_gives_the_same_bytes_and_times() {
    check_each(|_vector, run| {
        let whole = run(Transport::Memory, Schedule::WHOLE);
        for seed in 0..SEEDS {
            let (first, second) = (
                run(Transport::Memory, Schedule::seeded(seed)),
                run(Transport::Memory, Schedule::seeded(seed)),
            );
            if first != second {
                return Err(format!("seed {seed} gave two runs: {first:?} and {second:?}"));
            }
            same(&whole, &first, &format!("seed {seed}"))?;
        }
        Ok(())
    });
}

/// Over a loopback TCP socket through `host::Tcp`, each vector gives an outcome that its RFC
/// permits, and the outcome and the bytes of the whole input in memory: with the whole input in
/// regions of 64 KiB, and with regions of one byte, which split the input at each byte.
#[cfg(feature = "tcp")]
#[test]
fn over_a_loopback_socket_each_vector_gives_the_result_of_the_whole_input() {
    check_each(|vector, run| {
        let whole = run(Transport::Memory, Schedule::WHOLE);
        for (regions, schedule) in [
            (Sizes::Whole, "the whole input"),
            (Sizes::Each(1), "regions of one byte"),
        ] {
            let socket = run(Transport::Tcp, Schedule::new(regions, Sizes::Whole));
            if !vector
                .permitted
                .iter()
                .any(|permitted| permitted.admits(&socket.outcome))
            {
                return Err(format!("over a socket with {schedule}: {:?}", socket.outcome));
            }
            same(&whole, &socket, &format!("over a socket with {schedule}"))?;
        }
        Ok(())
    });
}

/// The suite over a loopback TCP socket, through `host::Tcp`.
#[cfg(feature = "tcp")]
mod tcp {
    use core::alloc::Layout;
    use core::cell::Cell;
    use core::num::{NonZeroU32, NonZeroU64};
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::net::{Shutdown, TcpListener, TcpStream};

    use rsnetwork::buffer::Pool;
    use rsnetwork::capacity::Budget;
    use rsnetwork::drive::Kind;
    use rsnetwork::host::{Connection, Engine, Io as _, Next, Tcp};

    use super::{Schedule, Sizes, Step, turns};

    /// The most rounds of one run. A run that needs more makes no progress.
    const ROUNDS: usize = 1_000_000;

    /// Runs `connection` over a loopback socket, as `super::run` does in memory. A peer socket
    /// writes the first `available` bytes of `input`, and the end of input after its last byte. It
    /// reads each byte that the connection sends, until the end of the stream. Each receive region
    /// of the connection is one byte when the schedule cuts the input into bytes, and 64 KiB else.
    /// The time of each drive is the time of the host since the start.
    ///
    /// The peer writes each part of the input in one write, so one segment carries it, and the run
    /// waits until the part arrived. A pump that then finds no byte in the socket proves that the
    /// connection received each byte that the peer wrote before it. Only then does `read` count
    /// those bytes.
    pub(super) fn run<E: Engine>(
        mut connection: Connection<E>,
        input: &[u8],
        (available, read): (&Cell<usize>, &Cell<usize>),
        schedule: Schedule,
        mut answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    ) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.set_nodelay(true).unwrap();
        let size = match schedule.regions {
            Sizes::Each(size) => size,
            _ => 1 << 16,
        };
        let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
        let slot = Layout::array::<u8>(size).unwrap();
        let pool = Pool::new(&budget, NonZeroU32::new(64).unwrap(), slot).unwrap();
        let mut socket = Tcp::new(near, pool).unwrap();
        let start = std::time::Instant::now();
        let (mut written, mut ended, mut released) = (0, false, false);
        let (mut sent, mut steps) = (Vec::new(), Vec::new());
        for _ in 0..ROUNDS {
            if written < available.get() {
                let part = &input[written..available.get()];
                let count = peer.write(part).unwrap();
                assert_eq!(count, part.len(), "one write carries each part");
                written += count;
                arrive(socket.socket());
            } else if written == input.len() && !ended {
                peer.shutdown(Shutdown::Write).unwrap();
                ended = true;
            }
            let mut bytes = [0; 4096];
            match peer.read(&mut bytes) {
                Ok(0) => {
                    assert!(released, "the socket ended its output before the release");
                    let end = connection.release().unwrap();
                    let outstanding = socket.close(&connection);
                    assert!(outstanding.is_empty(), "{outstanding:?} did not go");
                    return (sent, steps, end.map_err(|error| error.kind()));
                }
                Ok(count) => sent.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => panic!("the peer cannot read: {error}"),
            }
            if !released {
                let now = u64::try_from(start.elapsed().as_nanos()).unwrap();
                turns(&mut connection, now, &mut answer, &mut steps);
                match socket.pump(&mut connection).unwrap() {
                    Next::Released => released = true,
                    Next::Wait { read: true, .. } => read.set(written),
                    Next::Now | Next::Wait { .. } => {}
                }
            }
        }
        panic!(
            "the connection made no progress in {ROUNDS} rounds over a socket, with input {}",
            input.escape_ascii()
        );
    }

    /// Waits until a byte that the peer wrote is in `socket`, with no read. A loopback socket can
    /// deliver a segment after the write that sent it.
    fn arrive(socket: &TcpStream) {
        for _ in 0..ROUNDS {
            match socket.peek(&mut [0]) {
                Ok(count) if count > 0 => return,
                Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                other => panic!("the socket gave {other:?} before the bytes of the peer"),
            }
        }
        panic!("the bytes of the peer did not arrive in {ROUNDS} rounds");
    }
}
