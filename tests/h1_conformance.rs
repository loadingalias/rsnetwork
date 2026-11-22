//! The H1 conformance suite on the caller-driven host. The server and client engines read each
//! vector of `conformance` through a `host::Connection`, with the whole input, with the input cut
//! at each byte, with the output cut at each byte, and with seeded schedules of bytes and time.
//! Each outcome must be one that the RFC permits, and each schedule must give the outcome and the
//! bytes of the whole input. With the `tcp` feature, each vector also runs over a loopback TCP
//! socket through `host::Tcp`.

mod conformance;

use conformance::{Carry, Input, Memory, Schedule, Sizes, Step, check_each, same};
use rsnetwork::drive::Kind;
use rsnetwork::host::{Connection, Engine};
use rsnetwork::time::ClockDomain;

/// The seeds of the replay test.
const SEEDS: u64 = 64;

/// The transport of a run.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// Regions and writes in memory, cut as the schedule says.
    Memory,
    /// A loopback TCP socket through `host::Tcp`.
    #[cfg(feature = "tcp")]
    Tcp,
}

impl Carry for Transport {
    fn clock(self) -> ClockDomain {
        conformance::CLOCK
    }

    fn carry<E: Engine>(
        self,
        input: Input<'_, E>,
        answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    ) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
        match self {
            Self::Memory => Memory.carry(input, answer),
            #[cfg(feature = "tcp")]
            Self::Tcp => {
                let (connection, input, cells, schedule) = input;
                tcp::run(connection, input, cells, schedule, answer)
            }
        }
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
    use rsnetwork::time::Instant;

    use super::conformance::{CLOCK, Schedule, Sizes, Step, turns};

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
                turns(&mut connection, Instant::new(CLOCK, now), &mut answer, &mut steps);
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
