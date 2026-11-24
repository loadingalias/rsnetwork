//! Drive one QUIC connection from a nonblocking UDP socket and the host clock.

use core::net::SocketAddr;
use core::time::Duration;
use std::io;
use std::net::UdpSocket;
use std::time::Instant as HostInstant;

use rsnetwork::buffer::Backing;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::{Blocked, Progress, Turn};
use rsnetwork::quic::packet::{Datagrams, Header};
use rsnetwork::quic::{Connection, Event, Limits};
use rsnetwork::time::{ClockDomain, Instant, Suspend};
use rsnetwork::tls::{ClientConfig, ServerConfig};

use super::Result;

/// The longest UDP payload fits in this receive region.
const RECEIVE_BYTES: usize = 65_535;
const RUN_LIMIT: Duration = Duration::from_secs(15);
/// The standard library has no socket readiness poller.
const POLL: Duration = Duration::from_micros(250);
/// Return to the socket and timers after each batch.
const SEND_BATCH: usize = 16;

pub(super) enum Endpoint<'a> {
    Client(&'a ClientConfig, &'a str, SocketAddr),
    Server(&'a ServerConfig),
}

fn ready<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Give the application each event and a turn after the handshake. Keep a blocked send until the socket takes it.
pub(super) fn run(
    socket: &UdpSocket,
    endpoint: Endpoint<'_>,
    limits: Limits,
    budget: &Budget,
    mut application: impl FnMut(&mut Connection, Option<Event>) -> Result<()>,
) -> Result<Connection> {
    socket.set_nonblocking(true)?;
    let start = HostInstant::now();
    let now = || {
        Instant::new(
            ClockDomain::new(1, Suspend::Pauses),
            start
                .elapsed()
                .as_nanos()
                .try_into()
                .expect("a bounded run fits in nanoseconds"),
        )
    };
    let mut input = vec![0; RECEIVE_BYTES];
    let (mut connection, mut first) = match endpoint {
        Endpoint::Client(config, name, address) => {
            socket.connect(address)?;
            (Connection::client(config, name, limits, budget, now())?, None)
        }
        Endpoint::Server(config) => loop {
            if start.elapsed() >= RUN_LIMIT {
                return Err("the server waited too long for the first datagram".into());
            }
            if let Some((len, peer)) = ready(socket.recv_from(&mut input))? {
                let header = Header::parse(&input[..len], 0).map_err(|_| "invalid first packet header")?;
                socket.connect(peer)?;
                break (Connection::server(config, &header, limits, budget, now())?, Some(len));
            }
            std::thread::sleep(POLL);
        },
    };

    let cid_len = connection.local_cid().as_bytes().len();
    let mut output = vec![0; limits.datagram_bytes_max];
    let mut unsent = None;
    while start.elapsed() < RUN_LIMIT {
        let received = match first.take() {
            Some(len) => Some(len),
            None => ready(socket.recv(&mut input))?,
        };
        let mut datagrams = received.map(|len| {
            let mut region = core::mem::replace(&mut input, vec![0; RECEIVE_BYTES]);
            region.truncate(len);
            Datagrams::new(Backing::from(region), None, cid_len)
        });
        let turn = loop {
            if start.elapsed() >= RUN_LIMIT {
                return Err("the connection exceeded the run deadline".into());
            }
            let (event, turn) = match &mut datagrams {
                Some(region) => connection.receive(region, now()),
                None => connection.drive(now()),
            };
            if let Progress::Terminal(result) = turn.progress {
                result.map_err(|error| format!("{error}, peer close {:?}", connection.peer_close()))?;
                return Ok(connection);
            }
            let more = event.is_some() || turn.progress == Progress::Pending;
            application(&mut connection, event)?;
            if !more {
                break turn;
            }
        };
        if let Progress::Blocked(Blocked::Capacity(units)) = turn.progress {
            return Err(format!("the endpoint needs {units} more capacity units").into());
        }
        let mut sent = false;
        for _ in 0..SEND_BATCH {
            let len = match unsent {
                Some(len) => len,
                None => match connection.transmit(&mut output, now())? {
                    Some(len) => len,
                    None => break,
                },
            };
            match ready(socket.send(&output[..len]))? {
                Some(written) if written == len => {
                    unsent = None;
                    sent = true;
                }
                Some(_) => return Err("the socket sent a partial datagram".into()),
                None => {
                    unsent = Some(len);
                    break;
                }
            }
        }
        if !sent && received.is_none() {
            let Turn { deadline, .. } = turn;
            let wait = deadline.map_or(POLL, |d| {
                Duration::from_nanos(d.instant().as_nanos().saturating_sub(now().as_nanos())).min(POLL)
            });
            std::thread::sleep(wait);
        }
    }
    Err(format!(
        "the connection exceeded the run deadline, recovery {:?}",
        connection.recovery()
    )
    .into())
}
