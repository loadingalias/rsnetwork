//! Readiness, memory ownership, and terminal outcomes at the optional Tower boundary.
#![cfg(test)]
#![cfg(feature = "tower")]

use core::cell::Cell;
use core::future::{Ready, ready};
use core::num::NonZeroU64;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use std::assert_matches;

use rsnetwork::body::Part;
use rsnetwork::buffer::Buffer as _;
use rsnetwork::capacity::Budget;
use rsnetwork::drive::Kind;
use rsnetwork::h1::Limits;
use rsnetwork::http::{Adapter, Body as _, HeaderMap, Request};
use rsnetwork::tower::{Body, Bytes, Frame, Service, dispatch};

fn immediate<F: Future>(future: F) -> F::Output {
    let Poll::Ready(result) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("the supplied frames are ready");
    };
    result
}

struct Frames(std::vec::IntoIter<Result<Frame<Bytes>, ()>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = ();
    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, ()>>> {
        Poll::Ready(self.0.next())
    }
}

const HEAD: Limits = Limits {
    head_bytes: 1024,
    fields: 8,
    name_bytes: 64,
    value_bytes: 128,
};

#[test]
fn tower_retains_unique_storage_and_releases_the_true_charge_after_the_last_view() {
    let budget = Budget::new(NonZeroU64::new(4096).unwrap());
    let adapter = Adapter::new(HEAD, &budget);
    let mut owned = Vec::with_capacity(1024);
    owned.extend_from_slice(b"payload");
    let pointer = owned.as_ptr();
    let large = Bytes::from(vec![9; 65536]);
    let slice = large.slice(9..16);
    let opaque = slice.as_ptr();
    let mut spare = Vec::with_capacity(65536);
    spare.extend_from_slice(b"fits");
    let mut source = pin!(Frames(
        vec![
            Ok(Frame::data(Bytes::from(owned))),
            Ok(Frame::data(slice)),
            Ok(Frame::data(Bytes::from(spare))),
            Ok(Frame::data(large)),
        ]
        .into_iter()
    ));
    let mut body = adapter.tower_body(source.as_mut());
    let Part::Data(owned) = immediate(body.next()).unwrap() else {
        panic!("expected the owned data")
    };
    assert_eq!(owned.bytes(), b"payload");
    assert_eq!(owned.as_ptr(), pointer);
    assert_eq!(owned.allocation_size(), 1024);
    let view = owned.view(1..).unwrap();
    drop(owned);
    assert!(budget.available() <= budget.bound() - 1024);
    drop(view);
    assert_eq!(budget.available(), budget.bound());
    let Part::Data(copied) = immediate(body.next()).unwrap() else {
        panic!("expected the shared slice")
    };
    assert_eq!(copied.bytes(), &[9; 7]);
    assert_ne!(copied.as_ptr(), opaque);
    assert_eq!(copied.allocation_size(), 7);
    drop(copied);
    let Part::Data(compact) = immediate(body.next()).unwrap() else {
        panic!("the visible data fits the budget")
    };
    assert_eq!(compact.bytes(), b"fits");
    assert_eq!(compact.allocation_size(), 4);
    drop(compact);
    assert_eq!(immediate(body.next()).unwrap_err().kind(), Kind::Overload);
    assert_eq!(budget.available(), budget.bound());
}

#[test]
fn tower_refuses_a_producer_error_or_data_after_trailers_before_clean_completion() {
    let budget = Budget::new(NonZeroU64::new(4096).unwrap());
    let adapter = Adapter::new(HEAD, &budget);
    for (extra, expected) in [
        (Err(()), Kind::Partial),
        (Ok(Frame::data(Bytes::from_static(b"late"))), Kind::Malformed),
    ] {
        let mut fields = HeaderMap::new();
        fields.insert("x-final", "yes".parse().unwrap());
        let mut source = pin!(Frames(vec![Ok(Frame::trailers(fields)), extra].into_iter()));
        assert_eq!(
            immediate(adapter.tower_body(source.as_mut()).next())
                .unwrap_err()
                .kind(),
            expected
        );
        assert_eq!(budget.available(), budget.bound());
    }
}

#[test]
fn tower_keeps_received_trailers_when_a_pending_read_is_cancelled() {
    struct Paused {
        trailers: Option<HeaderMap>,
        waited: bool,
    }
    impl Body for Paused {
        type Data = Bytes;
        type Error = ();
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, ()>>> {
            if let Some(fields) = self.trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(fields))));
            }
            if !core::mem::replace(&mut self.waited, true) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(None)
        }
    }
    let budget = Budget::new(NonZeroU64::new(4096).unwrap());
    let adapter = Adapter::new(HEAD, &budget);
    let mut fields = HeaderMap::new();
    fields.insert("x-final", "done".parse().unwrap());
    let mut source = pin!(Paused {
        trailers: Some(fields),
        waited: false
    });
    let mut body = adapter.tower_body(source.as_mut());
    assert!(
        pin!(body.next())
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(budget.available() < budget.bound());
    let Part::End(rsnetwork::body::Outcome::Complete(Some(trailers))) = immediate(body.next()).unwrap() else {
        panic!("the next read must receive the trailers")
    };
    assert!(
        trailers
            .fields()
            .eq([rsnetwork::value::Field::new(b"x-final", b"done").unwrap()])
    );
    drop(trailers);
    assert_eq!(budget.available(), budget.bound());
}

#[test]
fn tower_dispatch_waits_for_the_same_service_instance_before_calling_once() {
    struct Limited<'a> {
        open: &'a Cell<bool>,
        reserved: bool,
        calls: u32,
    }
    impl Service<Request<()>> for Limited<'_> {
        type Response = u32;
        type Error = ();
        type Future = Ready<Result<u32, ()>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), ()>> {
            if self.open.get() {
                self.reserved = true;
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
        fn call(&mut self, _: Request<()>) -> Self::Future {
            assert!(core::mem::take(&mut self.reserved));
            self.calls += 1;
            ready(Ok(self.calls))
        }
    }
    let open = Cell::new(false);
    let mut service = Limited {
        open: &open,
        reserved: false,
        calls: 0,
    };
    let cx = &mut Context::from_waker(Waker::noop());
    {
        let mut cancelled = pin!(dispatch(&mut service, Request::new(())));
        assert!(cancelled.as_mut().poll(cx).is_pending());
    }
    assert_eq!(service.calls, 0);
    let mut active = pin!(dispatch(&mut service, Request::new(())));
    assert!(active.as_mut().poll(cx).is_pending());
    open.set(true);
    assert_matches!(active.as_mut().poll(cx), Poll::Ready(Ok(1)));
}
