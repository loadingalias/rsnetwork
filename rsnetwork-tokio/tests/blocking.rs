//! The bounded blocking service of the Tokio binding (N107): a full bound refuses with a typed
//! overload, and a job keeps its place until it returns, also when its caller stopped waiting.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(
    dead_code,
    reason = "these cases need only the runtimes and the configurations of the support"
)]
mod support;

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::mpsc;

use rsnetwork::client::Operation;
use rsnetwork::client::establish::{ConnectError, Dial};
use rsnetwork::drive::Kind;
use rsnetwork_tokio::{Blocking, Clock, client::connect};
use support::{PATIENCE, on_each_runtime};

#[test]
fn a_full_bound_refuses_with_overload_and_an_abandoned_job_keeps_its_place_until_it_returns() {
    on_each_runtime(|| async {
        let blocking = Blocking::new(NonZeroUsize::MIN);
        let (started, start) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        {
            // The caller stops waiting after the job started.
            let mut running = pin!(blocking.run(move || {
                started.send(()).unwrap();
                released.recv_timeout(PATIENCE).unwrap();
            }));
            poll_fn(|cx| {
                assert!(running.as_mut().poll(cx).is_pending(), "the job waits for the test");
                Poll::Ready(())
            })
            .await;
            start.recv_timeout(PATIENCE).unwrap();
        }
        let error = blocking.run(|| ()).await.unwrap_err();
        assert_eq!(
            (error.kind(), error.reason()),
            (Kind::Overload, "each place for a blocking job is in use")
        );
        release.send(()).unwrap();
        // The place comes back when the job returns.
        let mut answer = None;
        for _ in 0..1000 {
            match blocking.run(|| 7).await {
                Ok(seven) => {
                    answer = Some(seven);
                    break;
                }
                Err(error) => assert_eq!(error.kind(), Kind::Overload),
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(answer, Some(7));
    });
}

#[test]
fn a_lookup_of_localhost_gives_loopback_addresses_with_the_port() {
    on_each_runtime(|| async {
        let blocking = Blocking::new(NonZeroUsize::MIN);
        let addresses = blocking
            .lookup("localhost", 8080, NonZeroUsize::new(4).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(!addresses.is_empty() && addresses.len() <= 4, "{addresses:?}");
        assert!(
            addresses
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() == 8080),
            "{addresses:?}"
        );
    });
}

#[test]
fn a_dropped_lookup_wait_keeps_its_place_while_the_job_is_queued() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (entered, started) = mpsc::channel();
        let (release, hold) = mpsc::channel::<()>();
        let worker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            hold.recv_timeout(PATIENCE).unwrap();
        });
        started.recv_timeout(PATIENCE).unwrap();
        let blocking = Blocking::new(NonZeroUsize::MIN);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut wait = pin!(blocking.lookup("localhost", 443, NonZeroUsize::MIN));
            assert!(wait.as_mut().poll(&mut cx).is_pending());
        }
        let mut other = pin!(blocking.lookup("127.0.0.1", 443, NonZeroUsize::MIN));
        let outcome = other.as_mut().poll(&mut cx);
        release.send(()).unwrap();
        worker.await.unwrap();
        assert!(
            matches!(outcome, Poll::Ready(Err(e)) if e.kind() == Kind::Overload),
            "{outcome:?}"
        );
    });
}

#[test]
fn a_lookup_outside_a_tokio_runtime_reports_an_unsupported_host() {
    let blocking = Blocking::new(NonZeroUsize::MIN);
    let mut wait = pin!(blocking.lookup("localhost", 443, NonZeroUsize::MIN));
    let outcome = wait.as_mut().poll(&mut Context::from_waker(Waker::noop()));
    assert!(matches!(outcome, Poll::Ready(Err(e)) if e.kind() == Kind::Unsupported));
}

#[test]
fn a_connect_deadline_during_dns_leaves_the_lookup_and_its_memory_with_the_worker() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
        .block_on(async {
            let (release, hold) = mpsc::channel::<()>();
            let (started, active) = tokio::sync::oneshot::channel();
            let worker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                hold.recv_timeout(PATIENCE).unwrap();
            });
            active.await.unwrap();
            let resolver = Blocking::new(NonZeroUsize::MIN);
            let mem = support::budget();
            let mut op = Operation::new(
                Clock.deadline(Duration::from_millis(100)),
                NonZeroUsize::new(2).unwrap(),
            );
            let result = connect("127.0.0.1", 80, &resolver, Dial::default(), &mut op, &mem).await;
            assert!(
                matches!(result,Err(ConnectError::Operation(e)) if e.kind()==Kind::Deadline),
                "{result:?}"
            );
            assert_eq!((op.occupied(), op.remaining()), (1, 1));
            assert!(mem.available() < mem.bound());
            let refused = resolver.run(|| ()).await.unwrap_err();
            assert_eq!(refused.kind(), Kind::Overload);
            release.send(()).unwrap();
            worker.await.unwrap();
            // This worker runs after the abandoned lookup in the single-thread blocking queue.
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert_eq!((op.occupied(), op.remaining(), mem.available()), (0, 1, mem.bound()));
        });
}

#[test]
fn repeated_lookup_errors_spend_the_original_work_budget() {
    on_each_runtime(|| async {
        let resolver = Blocking::new(NonZeroUsize::MIN);
        let mem = support::budget();
        let mut op = Operation::new(Clock.deadline(PATIENCE), NonZeroUsize::new(3).unwrap());
        for left in [2, 1] {
            // A system resolver cannot accept a NUL in the host name.
            let result = connect("bad\0host", 443, &resolver, Dial::default(), &mut op, &mem).await;
            assert!(matches!(result, Err(ConnectError::Io(_))), "{result:?}");
            assert_eq!((op.remaining(), op.occupied(), mem.available()), (left, 0, mem.bound()));
        }
        let result = connect("127.0.0.1", 443, &resolver, Dial::default(), &mut op, &mem).await;
        assert!(matches!(result, Err(ConnectError::Operation(error)) if error.kind() == Kind::Overload));
        assert_eq!(op.remaining(), 1, "a refused lookup spends no unit");
    });
}
