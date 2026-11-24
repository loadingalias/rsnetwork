//! The live packet bound applies even when one old packet remains in the store. Each path takes
//! only the feedback of its own packets (RFC 9000, section 9.4).

use core::num::NonZeroU64;

use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Instant, Suspend};

use core::net::{Ipv4Addr, SocketAddr};

use super::{
    Ack, CongestionControl, ConnectionId, Controller, Duration, Ecn, Frame, History, Mtu, Path, PathState, Paths,
    Record, Records, Sent, Settlement, Validation,
};

fn at(ms: u64) -> Instant {
    Instant::new(ClockDomain::new(1, Suspend::Pauses), ms * 1_000_000)
}

/// The path to a peer on the network `network`.
fn route(network: u8) -> Path {
    Path {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
        peer: SocketAddr::from((Ipv4Addr::new(192, 0, network, 1), 4301)),
    }
}

/// A connection on its first path, with the round trip `rtt` there.
fn connection(budget: &Budget, rtt: Duration) -> Paths {
    let mut paths = Paths::new(
        PathState::new(route(1), ConnectionId::EMPTY, 1200, CongestionControl::Cubic),
        budget,
    );
    paths.active.sample(rtt, Duration::ZERO, at(0));
    paths
}

/// Moves the connection to a path on another network, with the round trip `rtt` there. The path
/// that it leaves stays as the fallback path.
fn migrate(paths: &mut Paths, rtt: Duration) {
    let mut next = paths
        .active
        .next(route(2), ConnectionId::EMPTY, 1200, CongestionControl::Cubic);
    next.sample(rtt, Duration::ZERO, at(0));
    let fallback = paths.switch(next);
    paths.validation = Some(Validation::new(fallback, at(60_000), false));
}

/// An ack-eliciting packet of 1,200 bytes with the mark `mark`.
fn packet(number: u64, time: Instant, mark: Ecn) -> Sent {
    Sent {
        number,
        mark,
        time,
        bytes: 1200,
        eliciting: true,
        records: Records::default(),
    }
}

fn ack(bytes: &[u8]) -> Ack<'_> {
    let (Frame::Ack(ack), len) = Frame::parse(bytes).unwrap() else {
        panic!("an ACK frame")
    };
    assert_eq!(len, bytes.len());
    ack
}

#[test]
fn an_acknowledgement_of_a_packet_of_the_path_that_the_connection_left_is_no_feedback_for_the_new_path() {
    let budget = Budget::new(NonZeroU64::new(1 << 16).unwrap());
    let mut paths = connection(&budget, Duration::from_millis(20));
    let mut history = History::new();
    // A marked packet leaves on the first path. Then the new path sends only an acknowledgement.
    history.insert(&mut paths, packet(0, at(0), Ecn::Ect0)).unwrap();
    history.ect_sent = 1;
    migrate(&mut paths, Duration::from_millis(20));
    let bare = Sent {
        bytes: 0,
        eliciting: false,
        ..packet(1, at(10), Ecn::NotEct)
    };
    history.insert(&mut paths, bare).unwrap();
    let before = paths.active.stats();
    // The peer acknowledges both packets, and reports a congestion mark on the marked one.
    let acked = history
        .ack(
            &ack(&[3, 1, 0, 0, 1, 0, 0, 1]),
            &mut paths,
            at(40),
            Duration::ZERO,
            |_| {},
        )
        .unwrap();
    let path = paths.active.stats();
    assert!(!acked.eliciting, "no ack-eliciting packet of the new path arrived");
    assert_eq!(
        path.latest_rtt, before.latest_rtt,
        "an acknowledgement alone gives no sample"
    );
    assert_eq!(
        (path.congestion_window, path.ecn_counts.ce),
        (12_000, 0),
        "the mark is on the packet of the first path"
    );
    assert_eq!(paths.validation.unwrap().fallback.stats().bytes_in_flight, 0);
}

#[test]
fn a_packet_of_the_path_that_the_connection_left_is_lost_at_the_time_threshold_of_that_path() {
    let budget = Budget::new(NonZeroU64::new(1 << 16).unwrap());
    // The first path has a round trip of 100 ms, and the new path one of 8 ms.
    let mut paths = connection(&budget, Duration::from_millis(100));
    let mut history = History::new();
    history.insert(&mut paths, packet(0, at(0), Ecn::NotEct)).unwrap();
    migrate(&mut paths, Duration::from_millis(8));
    for number in 1..=4 {
        history.insert(&mut paths, packet(number, at(10), Ecn::NotEct)).unwrap();
    }
    // The acknowledgement of packets 2 to 4 comes on the fast path, before the answer for packet 0
    // can come from the slow one. Packet 1 is three packets below the largest on its own path.
    history
        .ack(&ack(&[2, 4, 0, 0, 2]), &mut paths, at(20), Duration::ZERO, |_| {})
        .unwrap();
    history.detect(&mut paths, at(20), |_| Ok(())).unwrap();
    let fallback = |paths: &Paths| paths.validation.as_ref().unwrap().fallback.stats().bytes_in_flight;
    assert_eq!(paths.active.stats().packets_lost, 1, "packet 1, behind packet 0");
    assert_eq!(fallback(&paths), 1200, "packet 0 waits for the round trip of its path");
    // Nine eighths of 100 ms after packet 0 left (RFC 9002, section 6.1.2).
    let due = at(0).checked_add(Duration::from_micros(112_500)).unwrap();
    assert_eq!(history.loss_time, Some(due));
    history.detect(&mut paths, due, |_| Ok(())).unwrap();
    assert_eq!(fallback(&paths), 0);
    assert_eq!(
        paths.active.stats().packets_lost,
        1,
        "the new path did not lose packet 0"
    );
}

#[test]
fn a_loss_run_of_the_path_that_the_connection_left_does_not_join_a_loss_on_the_new_path() {
    let budget = Budget::new(NonZeroU64::new(1 << 16).unwrap());
    let rtt = Duration::from_millis(10);
    let mut paths = connection(&budget, rtt);
    let mut history = History::new();
    // The first path loses its last two packets.
    history.insert(&mut paths, packet(0, at(1), Ecn::NotEct)).unwrap();
    history.insert(&mut paths, packet(1, at(2), Ecn::NotEct)).unwrap();
    history
        .ack(&ack(&[2, 5, 0, 0, 0]), &mut paths, at(3), Duration::ZERO, |_| {})
        .unwrap();
    history.detect(&mut paths, at(3), |_| Ok(())).unwrap();
    assert_eq!(paths.active.stats().packets_lost, 2);
    // One second later, the new path loses its first packet. That is one loss, and no persistent
    // congestion: persistent congestion needs a run of losses on one path (RFC 9002, section 7.6).
    migrate(&mut paths, rtt);
    history.insert(&mut paths, packet(6, at(1000), Ecn::NotEct)).unwrap();
    history
        .ack(&ack(&[2, 9, 0, 0, 0]), &mut paths, at(1001), Duration::ZERO, |_| {})
        .unwrap();
    history.detect(&mut paths, at(1001), |_| Ok(())).unwrap();
    let path = paths.active.stats();
    assert_eq!((path.packets_lost, path.congestion_window), (1, 8400));
}

#[test]
fn one_old_packet_and_a_million_number_span_fit_the_live_entry_budget() {
    // This store has at most three live packets. One KiB covers the slots and their directory.
    let budget = Budget::new(NonZeroU64::new(1024).unwrap());
    let mut history = History::new();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
    let addresses = Path {
        local: address,
        peer: address,
    };
    let state = PathState::new(addresses, ConnectionId::EMPTY, 1200, CongestionControl::Cubic);
    let mut path = Paths::new(state, &budget);
    let time = Instant::new(ClockDomain::new(1, Suspend::Pauses), 0);
    let packet = |number| Sent {
        number,
        mark: Ecn::NotEct,
        time,
        bytes: 1200,
        eliciting: true,
        records: Records::default(),
    };
    history.insert(&mut path, packet(0)).unwrap();
    for number in (1..1_000_000).step_by(2) {
        history
            .insert(&mut path, packet(number))
            .expect("the live entries fit one KiB");
        let middle = history.last;
        history
            .insert(&mut path, packet(number + 1))
            .expect("the live entries fit one KiB");
        assert_eq!(history.remove(&mut path, middle, Settlement::Delivered).number, number);
        assert_eq!(
            history.remove(&mut path, history.last, Settlement::Delivered).number,
            number + 1
        );
    }
    assert_eq!(
        history.remove(&mut path, history.first, Settlement::Delivered).number,
        0
    );
    assert_eq!(history.bytes, 0);
    drop(path);
    assert_eq!(budget.available(), 1024);
}

#[test]
fn cubic_recovers_on_its_curve_without_counting_idle_time() {
    let at = |ms| Instant::new(ClockDomain::new(1, Suspend::Pauses), ms * 1_000_000u64);
    let rtt = Duration::from_millis(100);
    let mut controller = Controller::new(1200, CongestionControl::Cubic);
    controller.acknowledged(800, at(10), rtt);
    assert!(controller.congestion(at(11), at(12)));
    // W_max = 12,800 bytes, beta = 0.7, and K = exactly two seconds.
    assert_eq!(controller.window, 8960);
    controller.acknowledged(1200, at(20), rtt);
    assert_eq!(
        controller.window, 9045,
        "Reno-friendly increase of 9/17 MSS² per window"
    );
    controller.acknowledged(1200, at(1020), rtt);
    assert_eq!(controller.window, 9496, "the concave curve targets 12,450 bytes");
    controller.limited(at(1020), false);
    controller.limited(at(21_020), true);
    controller.acknowledged(1200, at(21_020), rtt);
    assert_eq!(controller.window, 9870, "twenty idle seconds do not advance the curve");
    controller.acknowledged(1200, at(25_020), rtt);
    assert_eq!(controller.window, 10_470, "the convex target is capped at 1.5 windows");
}

#[test]
fn hystart_slows_growth_on_sustained_delay_and_resumes_on_a_transient_spike() {
    let now = Instant::new(ClockDomain::new(1, Suspend::Pauses), 0);
    let baseline = Duration::from_millis(32);
    let inflated = Duration::from_millis(36);
    for transient in [true, false] {
        let mut controller = Controller::new(1200, CongestionControl::Cubic);
        controller.round_sample(0, baseline);
        for _ in 0..8 {
            controller.round_sample(0, inflated);
        }
        controller.acknowledged(1200, now, inflated);
        assert_eq!(controller.window, 12_300, "conservative slow start adds a quarter");
        controller.round_sample(1, inflated);
        if transient {
            for _ in 0..8 {
                controller.round_sample(1, baseline);
            }
            controller.acknowledged(1200, now, baseline);
            assert_eq!(controller.window, 13_500);
        } else {
            for round in 2..=5 {
                controller.round_sample(round, inflated);
            }
            controller.acknowledged(1200, now, inflated);
            // With K = 0 and W_est at the exit window, RFC 9438 starts Reno-friendly growth.
            assert_eq!(controller.window, 12_417);
        }
    }
}

#[test]
fn a_probe_of_the_datagram_size_settles_on_its_path_after_the_connection_left_that_path() {
    for delivered in [true, false] {
        let budget = Budget::new(NonZeroU64::new(1 << 16).unwrap());
        let rtt = Duration::from_millis(10);
        let mut paths = connection(&budget, rtt);
        let mut history = History::new();
        // The first path searches up to 1,452 bytes, and its first probe is out.
        paths.active.mtu = Mtu::new(1452);
        let size = paths.active.mtu.next().expect("the first probe");
        paths.active.mtu.sent(size);
        let mut records = Records::default();
        records.push(Record::Mtu(size), &budget).unwrap();
        let probe = Sent {
            records,
            ..packet(0, at(1), Ecn::NotEct)
        };
        history.insert(&mut paths, probe).unwrap();
        // The connection moves, and the probe settles while its path is the fallback path.
        migrate(&mut paths, rtt);
        let acked: &[u8] = if delivered { &[2, 0, 0, 0, 0] } else { &[2, 5, 0, 0, 0] };
        history
            .ack(&ack(acked), &mut paths, at(5), Duration::ZERO, |_| {})
            .unwrap();
        history.detect(&mut paths, at(1000), |_| Ok(())).unwrap();
        // The search of that path goes on when the connection returns: no probe waits with no end.
        let mtu = paths.validation.as_ref().unwrap().fallback.mtu;
        if delivered {
            assert_eq!(mtu.size(), 1452);
        } else {
            assert_eq!((mtu.size(), mtu.next()), (1200, Some(1452)));
        }
    }
}

#[test]
fn the_window_holds_two_datagrams_when_the_datagram_size_of_the_path_grows() {
    // Persistent congestion leaves the smallest window: two datagrams (RFC 9002, sections 7.2
    // and 7.6). Then the search finds that the path carries datagrams of twice the size.
    let mut controller = Controller::new(1200, CongestionControl::NewReno);
    controller.persistent();
    assert_eq!(controller.window, 2400);
    controller.datagram_limit(2400);
    assert_eq!(controller.window, 4800);
}
