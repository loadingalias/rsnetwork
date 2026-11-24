//! The live packet bound applies even when one old packet remains in the store.

use core::num::NonZeroU64;

use rstypes::capacity::Budget;
use rstypes::time::{ClockDomain, Instant, Suspend};

use super::{History, Records, Sent};

#[test]
fn one_old_packet_and_a_million_number_span_fit_the_live_entry_budget() {
    // This store has at most three live packets. One KiB covers the slots and their directory.
    let budget = Budget::new(NonZeroU64::new(1024).unwrap());
    let mut history = History::new(&budget);
    let time = Instant::new(ClockDomain::new(1, Suspend::Pauses), 0);
    let packet = |number| Sent {
        number,
        time,
        bytes: 1200,
        eliciting: true,
        records: Records::default(),
    };
    history.insert(packet(0)).unwrap();
    for number in (1..1_000_000).step_by(2) {
        history.insert(packet(number)).expect("the live entries fit one KiB");
        let middle = history.last;
        history
            .insert(packet(number + 1))
            .expect("the live entries fit one KiB");
        assert_eq!(history.remove(middle).number, number);
        assert_eq!(history.remove(history.last).number, number + 1);
    }
    assert_eq!(history.remove(history.first).number, 0);
    assert_eq!(history.bytes, 0);
    drop(history);
    assert_eq!(budget.available(), 1024);
}
