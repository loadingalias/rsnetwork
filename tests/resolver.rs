//! The caller owns the worker. A lookup owns its place until the backend returns.
#![cfg(feature = "os-resolver")]

use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::time::Duration;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::mpsc;

use rsnetwork::drive::Kind;
use rsnetwork::host::Blocking;

#[test]
fn the_worker_keeps_its_lookup_place_after_the_caller_drops_its_wait() {
    struct Waiting {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        address: SocketAddr,
    }
    impl ToSocketAddrs for Waiting {
        type Iter = core::iter::Once<SocketAddr>;
        fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
            self.entered.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(10)).unwrap();
            Ok(core::iter::once(self.address))
        }
    }
    let service = Blocking::new(NonZeroUsize::MIN);
    let lookup = service.reserve_lookup(NonZeroUsize::MIN).unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], 443));
    let (entered, started) = mpsc::channel();
    let (finish, release) = mpsc::channel();
    let (answer, wait) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            answer.send(lookup.run(Waiting {
                entered,
                release,
                address,
            }))
        });
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(wait);
        let next = service.clone().reserve_lookup(NonZeroUsize::MIN);
        finish.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap_err().0.unwrap(), [address]);
        assert_eq!(next.unwrap_err().kind(), Kind::Overload);
    });
    let next = service.reserve_lookup(NonZeroUsize::MIN).unwrap();
    assert_eq!(next.run(("127.0.0.1", 443)).unwrap(), [address]);
}

#[test]
fn a_lookup_preserves_endpoint_order_and_scope_within_the_candidate_limit() {
    let addresses: [SocketAddr; 3] = [
        "[fe80::1%7]:443".parse().unwrap(),
        "192.0.2.10:443".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
    ];
    let service = Blocking::new(NonZeroUsize::MIN);
    let lookup = service.reserve_lookup(NonZeroUsize::new(2).unwrap()).unwrap();
    assert_eq!(lookup.run(&addresses[..]).unwrap(), &addresses[..2]);
    let absent = Blocking::default().reserve_lookup(NonZeroUsize::MIN).unwrap_err();
    assert_eq!(absent.kind(), Kind::Unsupported);
}
