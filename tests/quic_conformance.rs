//! The QUIC conformance cells of the core (N310) on the deterministic path of `quic_path`: a seeded
//! run that replays byte for byte, a transfer through seeded loss and reordering, an idle end that
//! takes a deadline when its application gives it work, connections that share one bottleneck,
//! and an established transfer under a flood of new handshakes. Each expected result comes from
//! the RFC or from a run of the same engines with the flood or the fault off, never from the code
//! under test. The other cells are path tests of their own engine tasks: the conformance page of
//! the documentation names each one.

#[expect(
    dead_code,
    reason = "only the memory test of `tests/quic_streams.rs` reads the client budget"
)]
mod quic_path;

use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use core::time::Duration;
use std::sync::Arc;

use quic_path::*;
use rsnetwork::buffer::Buffer as _;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Ecn;
use rsnetwork::quic::frame::Direction;
use rsnetwork::quic::{
    Connection, Endpoint, EndpointKeys, EndpointLimits, Event, Handle, Limits, Path, REDEEMED_BYTES_DEFAULT, Route,
    StreamId,
};
use rsnetwork::time::Instant;

/// A path with each fault that draws from the seed: 10 ms of delay, 2 ms of jitter, 2% loss,
/// and 5% of the datagrams 15 ms late.
fn faulty() -> Link {
    Link {
        delay: Duration::from_millis(10),
        jitter: Duration::from_millis(2),
        loss_per_mille: 20,
        late_per_mille: 50,
        late: Duration::from_millis(15),
        ..Link::default()
    }
}

/// The datagrams of a seeded run: an upload over a faulty path whose uplink clears ECN marks, a
/// search for a datagram size of 1,452 bytes, and then a second upload after the path stops
/// carrying datagrams above 1,200 bytes.
fn seeded_run(seed: u64) -> Transcript {
    let limits = Limits {
        datagram_bytes_max: 1452,
        ..Limits::DEFAULT
    };
    let mut pair = Pair::with(Setup {
        client: limits,
        server: limits,
        seed: Some(seed),
        up: Link {
            marks: Marks::Clear,
            ..faulty()
        },
        down: faulty(),
        marking: Marking::Ecn,
    });
    let mut at = ms(0);
    for (len, path_bytes) in [(200_000, usize::MAX), (100_000, 1200)] {
        pair.path_bytes = path_bytes;
        let stream = pair.open(Direction::Unidirectional);
        feed(&mut pair.client, stream, 0, len, len / 4);
        at = pair.run_until(at, |pair| pair.at_server.complete(stream, len));
    }
    pair.transcript.take().unwrap()
}

#[test]
fn a_seeded_run_replays_each_byte_and_time_and_another_seed_changes_them() {
    let first = seeded_run(1);
    assert!(first.len() > 300, "the run sent {} datagrams", first.len());
    let again = seeded_run(1);
    let differs = first.iter().zip(&again).position(|(a, b)| a != b);
    assert_eq!(
        (differs, again.len()),
        (None, first.len()),
        "the first datagram that differs"
    );
    // Another seed gives other bytes, so the seed and not a constant made them.
    assert!(first != seeded_run(2), "the second seed sent the same datagrams");
}

#[test]
fn a_transfer_through_seeded_loss_and_reordering_delivers_each_byte_once_in_order() {
    const LEN: usize = 1 << 20;
    // 3% loss in each direction, and 10% of the datagrams 20 ms late: more than the packet
    // threshold passes them, so a late datagram can look lost.
    let link = Link {
        delay: Duration::from_millis(15),
        jitter: Duration::from_millis(1),
        loss_per_mille: 30,
        late_per_mille: 100,
        late: Duration::from_millis(20),
        ..Link::default()
    };
    let mut pair = Pair::with(Setup {
        client: Limits::DEFAULT,
        server: Limits::DEFAULT,
        seed: Some(11),
        up: link.clone(),
        down: link,
        marking: Marking::Off,
    });
    let stream = pair.open(Direction::Unidirectional);
    feed(&mut pair.client, stream, 0, LEN, LEN / 4);
    pair.run_until(ms(0), |pair| pair.at_server.complete(stream, LEN));
    let closed = |events: &[Event]| events.iter().any(|event| matches!(event, Event::Closed { .. }));
    assert!(!closed(&pair.at_client.other) && !closed(&pair.at_server.other));
}

#[test]
fn an_idle_end_takes_the_deadline_of_new_work_at_once_and_acts_at_it() {
    let limits = Limits {
        idle_timeout: Some(Duration::from_secs(5)),
        ..Limits::DEFAULT
    };
    let mut pair = Pair::new(limits, limits);
    // With no traffic since the handshake, the next deadline is the idle timeout (RFC 9000,
    // section 10.1).
    let idle = pair.client.drive(ms(1000)).1.deadline.unwrap().instant();
    assert_eq!(idle, ms(5000));
    // The application gives the idle end work, and no datagram arrives: the PING leaves at once.
    pair.client.ping();
    assert_eq!(sent_at(&mut pair.client, ms(1000)).len(), 1);
    let deadline = pair.client.drive(ms(1000)).1.deadline.unwrap().instant();
    assert!(ms(1000).as_nanos() < deadline.as_nanos() && deadline.as_nanos() < idle.as_nanos());
    // Nothing leaves before that deadline, and the probe leaves at it (RFC 9002, section 6.2).
    let early = Instant::new(deadline.domain(), deadline.as_nanos() - 1);
    assert!(driven_at(&mut pair.client, early).is_empty());
    assert!(sent_at(&mut pair.client, early).is_empty());
    driven_at(&mut pair.client, deadline);
    assert!(
        !sent_at(&mut pair.client, deadline).is_empty(),
        "the probe after the deadline"
    );
}

#[test]
fn connections_that_share_a_bottleneck_each_get_their_fair_share_within_25_percent() {
    // 600 KB/s, a queue of 24 KB, and a 40 ms round trip: a window of one bandwidth-delay
    // product and one queue is 48 KB, about ten datagrams for each of four connections.
    const RATE: u64 = 600_000;
    let bottleneck = Bottleneck::new(RATE, 24_000);
    let server = Limits {
        send_bytes_max: 16 << 20,
        ..Limits::DEFAULT
    };
    let mut pairs: Vec<Pair> = (1..=4)
        .map(|seed| {
            Pair::with(Setup {
                client: Limits::DEFAULT,
                server,
                seed: Some(seed),
                up: Link {
                    delay: Duration::from_millis(20),
                    ..Link::default()
                },
                down: Link {
                    delay: Duration::from_millis(20),
                    jitter: Duration::from_millis(1),
                    bottleneck: Some(bottleneck.clone()),
                    ..Link::default()
                },
                marking: Marking::Off,
            })
        })
        .collect();
    let streams: Vec<StreamId> = pairs
        .iter_mut()
        .map(|pair| {
            let stream = pair.server.open(Direction::Unidirectional).unwrap().unwrap();
            feed(&mut pair.server, stream, 0, 16 << 20, 4 << 20);
            stream
        })
        .collect();
    let received = |pairs: &[Pair]| -> Vec<usize> {
        pairs
            .iter()
            .zip(&streams)
            .map(|(pair, stream)| pair.at_client.bytes(*stream))
            .collect()
    };
    // The windows converge in the first 5 s, and the shares count in the next 20 s: about 500
    // round trips, so that the sawtooth of each window averages out.
    let warm = run_together(&mut pairs, ms(0), ms(5000));
    let before = received(&pairs);
    run_together(&mut pairs, warm, ms(25_000));
    let shares: Vec<usize> = received(&pairs)
        .iter()
        .zip(&before)
        .map(|(after, before)| after - before)
        .collect();
    let total: usize = shares.iter().sum();
    assert!(
        total as u64 >= RATE * 20 * 9 / 10,
        "the bottleneck carried {total} bytes in 20 s"
    );
    let fair = total / shares.len();
    for share in &shares {
        assert!(
            share.abs_diff(fair) * 4 <= fair,
            "the shares {shares:?} of a fair share of {fair}"
        );
    }
}

/// The server address of the flood cell, and the address of the flood datagram `index`.
fn flood_address(index: u32) -> SocketAddr {
    let [a, b] = u16::try_from(index / 60_000).unwrap().to_be_bytes();
    let port = u16::try_from(1024 + index % 60_000).unwrap();
    SocketAddr::from((Ipv4Addr::new(203, 0, a, b), port))
}

/// The bytes of an established upload that the server takes from 100 ms to 1,100 ms, with a
/// 20 ms round trip and an uplink of 1 MB/s, and with 1,000 client handshakes in each second of
/// that time when `flood`.
/// Each datagram of the flood is a copy of the first datagram of one of eight clients, from an
/// address of its own, and nothing answers the server there. Gives the bytes and the flood
/// datagrams that the listener answered with a Retry.
fn upload_beside(flood: bool) -> (usize, usize) {
    const LEN: usize = 4 << 20;
    let (client_config, server_config) = configs(Some(7));
    let keys = Arc::new(EndpointKeys::generate(&server_config, 1, REDEEMED_BYTES_DEFAULT).unwrap());
    let endpoint_budget = Budget::new(NonZeroU64::new(1 << 34).unwrap());
    let server_limits = Limits {
        stream_bytes_max: LEN as u64,
        data_bytes_max: LEN as u64,
        ..Limits::DEFAULT
    };
    let mut endpoint = Endpoint::new(
        &server_config,
        keys,
        0,
        EndpointLimits::default(),
        server_limits,
        &endpoint_budget,
    )
    .unwrap();
    let route = Path {
        local: client_address(4301),
        peer: SERVER_ADDRESS,
    };
    let mut client =
        Connection::client(&client_config, "server.test", route, Limits::DEFAULT, &budget(), ms(0)).unwrap();
    // The first datagram of each of eight other clients.
    let initials: Vec<Vec<u8>> = (0..8)
        .map(|port| {
            let route = Path {
                local: client_address(5000 + port),
                peer: SERVER_ADDRESS,
            };
            let mut other =
                Connection::client(&client_config, "server.test", route, Limits::DEFAULT, &budget(), ms(0)).unwrap();
            sent(&mut other).swap_remove(0)
        })
        .collect();
    let down = Link {
        delay: Duration::from_millis(10),
        ..Link::default()
    };
    let up = Link {
        bottleneck: Some(Bottleneck::new(1_000_000, 50_000)),
        ..down
    };
    let mut faults = root(7);
    let mut wire = Wire::default();
    let (mut established, mut flooded) = (None::<Handle>, Vec::<Handle>::new());
    let (mut stream, mut received, mut retries) = (None::<StreamId>, 0, 0);
    let mut reply = [0; 1200];
    let (start, end) = (ms(100), ms(1100));
    let mut next_flood = flood.then_some(0_u32);
    let mut at = ms(0);
    let mut counted = None;
    for _ in 0..1 << 20 {
        // The client: its events, the upload after its handshake, and its datagrams.
        driven_at(&mut client, at);
        if stream.is_none() && client.is_confirmed() {
            let opened = client.open(Direction::Unidirectional).unwrap().unwrap();
            feed(&mut client, opened, 0, LEN, LEN / 4);
            stream = Some(opened);
        }
        for datagram in sent_at(&mut client, at) {
            if let Some((arrival, mark)) = up.pass(at.as_nanos(), datagram.len(), Ecn::NotEct, &mut faults) {
                wire.push(arrival, End::Server, from_server(client_address(4301)), datagram, mark);
            }
        }
        // The flood: one datagram each millisecond from `start` to `end`.
        while let Some(index) = next_flood
            && ms(100 + u64::from(index)).as_nanos() <= at.as_nanos()
            && index < 1000
        {
            let path = from_server(flood_address(index));
            match endpoint
                .route(path, &initials[index as usize % 8], &mut reply, at)
                .unwrap()
            {
                Route::Accepted(handle) => {
                    endpoint.with_connection(handle, |server| {
                        give_on(server, path, &initials[index as usize % 8], at, Ecn::NotEct)
                    });
                    flooded.push(handle);
                }
                Route::Reply(_) => retries += 1,
                Route::Refused | Route::Dropped => {}
                other => panic!("a new address routes to {other:?}"),
            }
            next_flood = Some(index + 1);
        }
        // The listener: the datagrams of the client, and the work of each connection.
        while let Some(flight) = wire.pop(End::Server, at.as_nanos()) {
            let handle = match endpoint.route(flight.path, &flight.bytes, &mut reply, at).unwrap() {
                Route::Accepted(handle) => *established.insert(handle),
                Route::Existing(handle) => handle,
                other => panic!("the established client routes to {other:?}"),
            };
            let events = endpoint
                .with_connection(handle, |server| {
                    give_on(server, flight.path, &flight.bytes, at, flight.mark)
                })
                .unwrap();
            received += uploaded(&mut endpoint, handle, events);
        }
        for handle in established.iter().chain(&flooded).copied().collect::<Vec<_>>() {
            let (events, datagrams) = endpoint
                .with_connection(handle, |server| (driven_at(server, at), routed_at(server, at)))
                .unwrap();
            received += uploaded(&mut endpoint, handle, events);
            for (path, datagram) in datagrams {
                // Nothing answers the server at a flood address.
                if path.peer == client_address(4301)
                    && let Some((arrival, mark)) = down.pass(at.as_nanos(), datagram.len(), Ecn::NotEct, &mut faults)
                {
                    wire.push(arrival, End::Client, client.path(), datagram, mark);
                }
            }
        }
        while let Some(flight) = wire.pop(End::Client, at.as_nanos()) {
            give_on(&mut client, flight.path, &flight.bytes, at, flight.mark);
        }
        if counted.is_none() && at.as_nanos() >= start.as_nanos() {
            counted = Some(received);
        }
        if at.as_nanos() >= end.as_nanos() {
            return (received - counted.unwrap(), retries);
        }
        let flood_at = next_flood
            .filter(|&index| index < 1000)
            .map(|index| ms(100 + u64::from(index)));
        let deadlines = established.iter().chain(&flooded).filter_map(|&handle| {
            endpoint
                .with_connection(handle, |server| server.drive(at).1.deadline)
                .flatten()
        });
        at = deadlines
            .map(|deadline| deadline.instant())
            .chain(client.drive(at).1.deadline.map(|deadline| deadline.instant()))
            .chain(wire.next().map(|nanos| Instant::new(at.domain(), nanos)))
            .chain(flood_at)
            .chain([start, end].into_iter().filter(|time| time.as_nanos() > at.as_nanos()))
            .min_by_key(|instant| instant.as_nanos())
            .unwrap();
    }
    panic!("the upload does not reach 1,100 ms");
}

/// The stream bytes of `events` of the connection `handle`, which the server releases.
fn uploaded(endpoint: &mut Endpoint, handle: Handle, events: Vec<Event>) -> usize {
    let mut bytes = 0;
    for event in events {
        if let Event::Stream { stream, data, .. } = event {
            let len = data.initialized();
            endpoint.with_connection(handle, |server| server.release(stream, len as u64).unwrap());
            bytes += len;
        }
    }
    bytes
}

#[test]
fn a_flood_of_new_handshakes_leaves_an_established_upload_within_1_percent() {
    let (calm, _) = upload_beside(false);
    let (flooded, retries) = upload_beside(true);
    // The uplink of 1 MB/s limits the upload.
    assert!(calm >= 900_000, "the upload took {calm} bytes in 1 s");
    // The flood passed the Retry threshold of the listener.
    assert!(retries > 900, "the listener sent {retries} Retry packets to the flood");
    assert!(
        calm.abs_diff(flooded) * 100 <= calm,
        "{flooded} bytes beside the flood, {calm} with none"
    );
}
