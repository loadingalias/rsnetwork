//! The address order, attempt ownership, and time of the caller-driven TCP race.

use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use core::num::{NonZeroU64, NonZeroUsize};
use core::task::Poll;
use std::assert_matches;
use std::io;

use rsnetwork::capacity::{Budget, Permit};
use rsnetwork::client::Operation;
use rsnetwork::client::establish::{ConnectError, Dial, Step};
use rsnetwork::drive::Kind;
use rsnetwork::time::{ClockDomain, Deadline, Instant, Suspend};

fn at(ms: u64) -> Instant {
    Instant::new(ClockDomain::new(9, Suspend::Pauses), ms * 1_000_000)
}
fn memory() -> Budget {
    Budget::new(NonZeroU64::new(8192).unwrap())
}

#[test]
fn failed_addresses_interleave_in_resolver_order_and_spend_the_shared_work_once() {
    let v6 = |scope| SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, scope));
    let v4 = |port| SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let addresses = [v6(1), v6(1), v6(2), v6(3), v4(80), v4(443)];
    let mut op = Operation::new(Deadline::at(at(1_000)), NonZeroUsize::new(4).unwrap());
    let mem = memory();
    let mut order = Vec::new();
    let mut start = |addr, place| {
        order.push(addr);
        Ok(place)
    };
    let refused = |_: &mut Permit| Poll::Ready(Err::<(), _>(io::ErrorKind::ConnectionRefused));
    let mut race = Dial::default().race(&addresses, &mut op, at(0), &mem).unwrap();
    for (now, wake) in [(0, 10), (9, 10), (10, 20), (20, 30)] {
        assert_matches!(race.advance(at(now), &mut start, refused),Ok(Step::Wait(t)) if t==Deadline::at(at(wake)));
    }
    assert_matches!(race.advance(at(30), &mut start, refused),Err(ConnectError::Operation(e)) if e.kind()==Kind::Overload);
    drop(race);
    assert_eq!(order, [v6(1), v4(80), v6(2), v4(443)]);
    assert_eq!(mem.available(), mem.bound());
    assert_eq!(op.occupied(), 0);
    assert_matches!(Dial::default().race::<Permit>(&addresses,&mut op,at(40),&mem),Err(ConnectError::Operation(e)) if e.kind()==Kind::Overload);
}

#[test]
fn a_deadline_drops_the_wait_and_uncancellable_host_work_stays_occupied() {
    let addresses = [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
    ];
    let mut op = Operation::new(Deadline::at(at(400)), NonZeroUsize::new(2).unwrap());
    let mut jobs = Vec::new();
    let mut start = |_, place| {
        jobs.push(place);
        Ok(())
    };
    let mut race = Dial::default().race(&addresses, &mut op, at(0), &memory()).unwrap();
    for (now, wake) in [(0, 250), (250, 400)] {
        assert_matches!(race.advance(at(now), &mut start, |_|Poll::<Result<(),_>>::Pending),Ok(Step::Wait(t)) if t==Deadline::at(at(wake)));
    }
    assert_matches!(race.advance(at(400), &mut start, |_|Poll::Ready(Ok(()))),Err(ConnectError::Operation(e)) if e.kind()==Kind::Deadline);
    drop(race);
    assert_eq!(op.occupied(), 2);
    drop(jobs.pop().unwrap());
    assert_eq!(op.occupied(), 1);
    drop(jobs);
    assert_eq!(op.occupied(), 0);
    assert_eq!(op.remaining(), 0);
}
