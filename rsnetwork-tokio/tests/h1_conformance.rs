//! The H1 conformance suite on the Tokio binding (N010 through N107). Each vector of
//! `conformance` runs over a loopback TCP socket through `rsnetwork_tokio::Socket`, on a
//! current-thread and on a multi-thread runtime, with receive regions of 64 KiB and of one byte.
//! Each outcome must be one that its RFC permits, and the outcome and the bytes of the whole input
//! in memory.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[path = "../../tests/conformance/mod.rs"]
#[expect(
    dead_code,
    reason = "a socket runs the whole input and regions of one byte, not the cut and the seeded schedules"
)]
mod conformance;

use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::num::{NonZeroU32, NonZeroU64};
use core::time::Duration;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use conformance::{Carry, Input, Memory, ROUNDS, Schedule, Sizes, Step, check_each, same, turns};
use rsnetwork::buffer::Pool;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Kind;
use rsnetwork::host::{Connection, Engine, Io as _};
use rsnetwork::time::ClockDomain;
use rsnetwork_tokio::{Clock, Socket};
use socket2::SockRef;
use tokio::runtime::{Builder, Runtime};

/// The longest wait for bytes of the peer to arrive. A run that needs more makes no progress.
const ARRIVAL: Duration = Duration::from_secs(10);

/// The kind of Tokio runtime of a run.
#[derive(Clone, Copy, Debug)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

impl Flavor {
    /// The runtime of this kind, which each run of the process shares.
    fn runtime(self) -> &'static Runtime {
        static CURRENT: OnceLock<Runtime> = OnceLock::new();
        static MULTI: OnceLock<Runtime> = OnceLock::new();
        match self {
            Self::CurrentThread => CURRENT.get_or_init(|| Builder::new_current_thread().enable_all().build().unwrap()),
            Self::MultiThread => MULTI.get_or_init(|| Builder::new_multi_thread().enable_all().build().unwrap()),
        }
    }
}

/// The transport of a run.
#[derive(Clone, Copy, Debug)]
enum Transport {
    /// Regions and writes in memory: the result of the whole input.
    Memory,
    /// A loopback TCP socket through the Tokio binding.
    Tokio(Flavor),
}

impl Carry for Transport {
    fn clock(self) -> ClockDomain {
        match self {
            Self::Memory => conformance::CLOCK,
            Self::Tokio(_) => Clock.domain(),
        }
    }

    fn carry<E: Engine>(
        self,
        input: Input<'_, E>,
        answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
    ) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
        match self {
            Self::Memory => Memory.carry(input, answer),
            Self::Tokio(flavor) => flavor.runtime().block_on(run(input, answer)),
        }
    }
}

/// Runs `connection` over a loopback socket through the Tokio binding, as the runner in memory
/// does. The peer is a std socket in a thread of its own. It writes each part of the input that
/// becomes available, and reads each byte that the connection sends, until the end of the stream.
///
/// The connection asks the peer for each part in a call, and the call waits until the part
/// arrived: no read of the socket runs in that time. A later call counts those bytes as received
/// when the socket holds no byte, so the binding moved each of them to the connection. Between
/// the calls, the binding moves the bytes and waits as it does for each application.
async fn run<E: Engine>(
    (connection, input, (available, read), schedule): Input<'_, E>,
    mut answer: impl FnMut(&mut Connection<E>, Option<E::Event>) -> bool,
) -> (Vec<u8>, Vec<Step>, Result<(), Kind>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let near = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (far, _) = listener.accept().unwrap();
    // A second handle of the socket of the connection, which only peeks.
    let probe = SockRef::from(&near).try_clone().unwrap();
    probe.set_nonblocking(true).unwrap();
    let size = match schedule.regions {
        Sizes::Each(size) => size,
        _ => 1 << 16,
    };
    let budget = Budget::new(NonZeroU64::new(1 << 24).unwrap());
    let pool = Pool::new(
        &budget,
        NonZeroU32::new(64).unwrap(),
        Layout::array::<u8>(size).unwrap(),
    )
    .unwrap();
    let mut socket = Socket::new(connection, near, pool).unwrap();
    let (asks, asked) = mpsc::channel();
    let (arrivals, arrived) = mpsc::channel();
    let peer = {
        let (input, probe) = (input.to_vec(), probe.try_clone().unwrap());
        thread::spawn(move || peer(far, &input, &asked, &arrivals, &probe))
    };
    let (mut written, mut steps) = (0, Vec::new());
    let released = socket.until(|connection, now| {
        if written > read.get() && drained(&probe) {
            read.set(written);
        }
        turns(connection, now, &mut answer, &mut steps);
        if written < available.get() {
            written = available.get();
            asks.send(written).unwrap();
            arrived.recv_timeout(ARRIVAL).expect("the part of the peer arrives");
        }
        Ok(connection.release())
    });
    let end = released.await.unwrap().expect("the connection released");
    let outstanding = socket.close();
    assert!(outstanding.is_empty(), "{outstanding:?} did not go");
    let sent = peer.join().unwrap();
    (sent, steps, end.map_err(|error| error.kind()))
}

/// The peer of a run. It writes the input up to each end that `asked` gives, each part in one
/// write, and tells `arrivals` when the part is in the socket of the connection. After the last
/// byte, it shuts down its write side. It reads each byte of the output until the end of the
/// stream, and gives them.
fn peer(
    mut far: std::net::TcpStream,
    input: &[u8],
    asked: &Receiver<usize>,
    arrivals: &Sender<()>,
    probe: &socket2::Socket,
) -> Vec<u8> {
    far.set_nonblocking(true).unwrap();
    far.set_nodelay(true).unwrap();
    let (mut written, mut shut, mut sent) = (0, false, Vec::new());
    for _ in 0..ROUNDS * 100 {
        if let Ok(end) = asked.try_recv() {
            let part = &input[written..end];
            if !part.is_empty() {
                assert_eq!(far.write(part).unwrap(), part.len(), "one write carries each part");
                arrive(probe);
            }
            written = end;
            arrivals.send(()).unwrap();
        }
        if written == input.len() && !shut {
            far.shutdown(Shutdown::Write).unwrap();
            shut = true;
        }
        let mut bytes = [0; 4096];
        match far.read(&mut bytes) {
            Ok(0) => return sent,
            Ok(count) => sent.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => panic!("the peer cannot read: {error}"),
        }
    }
    panic!("the peer saw no end of the stream in {} rounds", ROUNDS * 100);
}

/// Waits until a byte that the peer wrote is in the socket of the connection. A loopback socket
/// can deliver a segment after the write that sent it.
fn arrive(probe: &socket2::Socket) {
    for _ in 0..ROUNDS * 100 {
        match probe.peek(&mut [MaybeUninit::uninit()]) {
            Ok(count) if count > 0 => return,
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            other => panic!("the socket gave {other:?} before the bytes of the peer"),
        }
    }
    panic!("the bytes of the peer did not arrive");
}

/// Whether the socket of the connection holds no byte: the binding moved each byte that arrived.
fn drained(probe: &socket2::Socket) -> bool {
    match probe.peek(&mut [MaybeUninit::uninit()]) {
        Ok(count) => count == 0,
        Err(error) => error.kind() == ErrorKind::WouldBlock,
    }
}

/// Over a loopback socket through the Tokio binding, on each kind of runtime, each vector gives
/// an outcome that its RFC permits, and the outcome and the bytes of the whole input in memory:
/// with the whole input in regions of 64 KiB, and with regions of one byte.
#[test]
fn over_tokio_each_vector_gives_the_result_of_the_whole_input() {
    for flavor in [Flavor::CurrentThread, Flavor::MultiThread] {
        check_each(|vector, run| {
            let whole = run(Transport::Memory, Schedule::WHOLE);
            for (regions, schedule) in [
                (Sizes::Whole, "the whole input"),
                (Sizes::Each(1), "regions of one byte"),
            ] {
                let socket = run(Transport::Tokio(flavor), Schedule::new(regions, Sizes::Whole));
                let context = format!("on {flavor:?} with {schedule}");
                if !vector
                    .permitted
                    .iter()
                    .any(|permitted| permitted.admits(&socket.outcome))
                {
                    return Err(format!("{context}: {:?}", socket.outcome));
                }
                same(&whole, &socket, &context)?;
            }
            Ok(())
        });
    }
}
