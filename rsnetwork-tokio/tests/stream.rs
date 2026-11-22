//! The TLS stream on the Tokio binding (N105 through N107): bytes in each direction, and an end
//! that the `close_notify` of the peer proves complete.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(
    dead_code,
    reason = "these cases need only the runtimes and the configurations of the support"
)]
mod support;

use core::num::NonZeroUsize;

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::tls::{self, Closure, StreamLimits};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::tls::Stream;
use support::{PATIENCE, TLS, on_each_runtime};

const LIMITS: StreamLimits = StreamLimits {
    tls: TLS,
    queue: NonZeroUsize::new(16).unwrap(),
    handshake_timeout: Some(PATIENCE),
};

/// Reads from `stream` until it holds `length` bytes.
async fn read(stream: &mut Stream, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < length {
        match stream.next().await.unwrap() {
            Part::Data(data) => bytes.extend_from_slice(data.bytes()),
            Part::End(outcome) => panic!("the stream ended with {outcome:?} after {bytes:?}"),
        }
    }
    bytes
}

#[test]
fn a_tls_stream_carries_bytes_each_way_and_ends_complete_after_close_notify() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let serving = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let budget = support::budget();
            let core = tls::Stream::accept(&support::server_config(), LIMITS, Clock.domain(), &budget).unwrap();
            let mut stream = Stream::new(core, tcp, support::pool(&budget)).unwrap();
            assert_eq!(read(&mut stream, 4).await, b"ping");
            stream.write(&Lease::from(&b"pong"[..])).await.unwrap();
            let end = stream.next().await.unwrap();
            assert!(matches!(end, Part::End(Outcome::Complete(None))), "{end:?}");
            assert_eq!(stream.closure(), Some(Closure::Notified));
            stream.close().await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let budget = support::budget();
        let config = support::client_config();
        let core = tls::Stream::connect(&config, "server.test", LIMITS, Clock.domain(), &budget).unwrap();
        let mut stream = Stream::new(core, tcp, support::pool(&budget)).unwrap();
        assert!(stream.handshake().await.unwrap().peer.is_some());
        stream.write(&Lease::from(&b"ping"[..])).await.unwrap();
        assert_eq!(read(&mut stream, 4).await, b"pong");
        assert_eq!(stream.written(), 4);
        stream.close().await.unwrap();
        serving.await.unwrap();
    });
}
