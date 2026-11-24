//! The live packet bound applies even when one old packet remains in the store.

use core::num::NonZeroU64;

use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Instant, Suspend};

use super::{CongestionControl, Controller, Duration, Ecn, History, Path, Records, Sent, Settlement};

#[test]
fn one_old_packet_and_a_million_number_span_fit_the_live_entry_budget() {
    // This store has at most three live packets. One KiB covers the slots and their directory.
    let budget = Budget::new(NonZeroU64::new(1024).unwrap());
    let mut history = History::new();
    let mut path = Path::new(1200, CongestionControl::Cubic, &budget);
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
