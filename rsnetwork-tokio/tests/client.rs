//! The HTTP/1.1 client on the Tokio binding: the N103 cases whose result depends on the socket or
//! the timer (N107). Each case runs on a current-thread and on a multi-thread runtime.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(
    dead_code,
    reason = "the client cases read through the binding, never through a raw socket"
)]
mod support;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use rsnetwork::body::{Collect, Outcome, Part, Read};
use rsnetwork::buffer::{Buffer as _, Lease, WriteLoan};
use rsnetwork::drive::Kind;
use rsnetwork::h1::Framing;
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::client::Http1;
use support::{ALERT_RECORD, Last, PATIENCE, Proxy, Transport, get, ok, on_each_runtime};

/// The deadline of the exchanges whose peer stops.
const DEADLINE: Duration = Duration::from_millis(300);

/// The body that the close of the connection delimits.
const UNTIL_CLOSE: &[u8] = b"until the close";

/// Reads the response body of `client` until it holds `length` bytes.
async fn body(client: &mut Http1, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while bytes.len() < length {
        match client.next().await.unwrap() {
            Part::Data(data) => bytes.extend_from_slice(data.bytes()),
            Part::End(outcome) => panic!("the body ended with {outcome:?} after {bytes:?}"),
        }
    }
    bytes
}

/// A server of the binding over `transport` that answers one request with `UNTIL_CLOSE`, a body
/// that the close delimits, and then closes.
fn until_close(transport: Transport, listener: tokio::net::TcpListener) {
    tokio::spawn(async move {
        let mut server = support::server(transport, &listener).await;
        server.request().await.unwrap().expect("a request");
        server.respond(&ok(Framing::Close)).await.unwrap();
        server.write(&Lease::from(UNTIL_CLOSE)).await.unwrap();
        server.finish().await.unwrap();
        // A proxy can cut or reset the stream, so the end of this server is not checked here.
        let _closed = server.close().await;
    });
}

#[test]
fn a_slow_body_meets_its_original_deadline_with_its_partial_progress() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            // A body of 100 bytes, of which the server sends 10, and then nothing.
            let (listener, address) = support::listener().await;
            tokio::spawn(async move {
                let mut server = support::server(transport, &listener).await;
                server.request().await.unwrap().expect("a request");
                server.respond(&ok(Framing::Length(100))).await.unwrap();
                server.write(&Lease::from(&b"0123456789"[..])).await.unwrap();
                core::future::pending::<()>().await;
            });
            let mut client = support::client(transport, address).await;
            let started = Instant::now();
            client.send(&get(), Clock.deadline(DEADLINE)).await.unwrap();
            client.response().await.unwrap();
            let mut region = WriteLoan::new(Vec::with_capacity(256));
            while region.filled().len() < 10 {
                assert!(matches!(client.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
            }
            assert_eq!(region.filled(), b"0123456789", "{transport:?}");
            let error = client.read_into(&mut region).await.unwrap_err();
            assert_eq!(
                (error.kind(), error.reason()),
                (Kind::Deadline, "the deadline came before the end of the response"),
                "{transport:?}"
            );
            assert!(started.elapsed() >= DEADLINE, "{transport:?}: {:?}", started.elapsed());
            assert_eq!(client.delivered(), 10, "{transport:?}");
        }
    });
}

#[test]
fn over_tls_the_deadline_covers_the_handshake() {
    on_each_runtime(|| async {
        // The server accepts the connection, and never answers.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done, ended) = mpsc::channel::<()>();
        let silent = thread::spawn(move || {
            let _socket = listener.accept().unwrap();
            ended.recv_timeout(PATIENCE).unwrap();
        });
        let mut client = support::client(Transport::Tls, address).await;
        let started = Instant::now();
        client.send(&get(), Clock.deadline(DEADLINE)).await.unwrap();
        let error = client.response().await.unwrap_err();
        assert_eq!(
            (error.kind(), error.reason()),
            (Kind::Deadline, "the deadline came before the response head")
        );
        assert!(started.elapsed() >= DEADLINE, "{:?}", started.elapsed());
        done.send(()).unwrap();
        silent.join().unwrap();
    });
}

#[test]
fn an_unread_body_drains_before_the_next_request_or_the_connection_closes() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            // The rest of the first body, 32 bytes, is within the drain of 64 bytes, so the
            // connection carries the next request, and its response is exactly its own.
            let (listener, address) = support::listener().await;
            let requests = Arc::new(AtomicUsize::new(0));
            let serving = {
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    let mut server = support::server(transport, &listener).await;
                    while server.request().await.unwrap().is_some() {
                        if requests.fetch_add(1, Ordering::Relaxed) == 0 {
                            server.respond(&ok(Framing::Length(40))).await.unwrap();
                            server.write(&Lease::from(vec![b'a'; 8])).await.unwrap();
                            server.write(&Lease::from(vec![b'b'; 32])).await.unwrap();
                        } else {
                            server.respond(&ok(Framing::Length(6))).await.unwrap();
                            server.write(&Lease::from(&b"second"[..])).await.unwrap();
                        }
                        server.finish().await.unwrap();
                    }
                    server.close().await.unwrap()
                })
            };
            let mut client = support::client(transport, address).await;
            let deadline = Clock.deadline(PATIENCE);
            client.send(&get(), deadline).await.unwrap();
            client.response().await.unwrap();
            assert!(body(&mut client, 8).await.starts_with(&[b'a'; 8]), "{transport:?}");
            client.send(&get(), deadline).await.unwrap();
            client.response().await.unwrap();
            let mut region = WriteLoan::new(Vec::with_capacity(64));
            let collected = client.collect(&mut region).await.unwrap();
            assert!(
                matches!(collected, Collect::Complete(None)),
                "{transport:?}: {collected:?}"
            );
            assert_eq!(region.filled(), b"second", "{transport:?}");
            client.close().await.unwrap();
            assert_eq!(serving.await.unwrap().result, Ok(()), "{transport:?}");
            assert_eq!(requests.load(Ordering::Relaxed), 2, "{transport:?}");

            // Here the rest of the body, 992 bytes, is still to come, and longer than the drain:
            // the connection closes, and carries no other request.
            let (listener, address) = support::listener().await;
            let requests = Arc::new(AtomicUsize::new(0));
            {
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    let mut server = support::server(transport, &listener).await;
                    server.request().await.unwrap().expect("a request");
                    requests.fetch_add(1, Ordering::Relaxed);
                    server.respond(&ok(Framing::Length(1000))).await.unwrap();
                    server.write(&Lease::from(vec![b'a'; 8])).await.unwrap();
                    core::future::pending::<()>().await;
                });
            }
            let mut client = support::client(transport, address).await;
            client.send(&get(), deadline).await.unwrap();
            client.response().await.unwrap();
            assert!(matches!(client.next().await.unwrap(), Part::Data(_)), "{transport:?}");
            let error = client.send(&get(), deadline).await.unwrap_err();
            assert_eq!(
                (error.kind(), error.reason()),
                (Kind::Misuse, "the connection ended: make a new client"),
                "{transport:?}"
            );
            assert_eq!(requests.load(Ordering::Relaxed), 1, "{transport:?}");
        }
    });
}

#[test]
fn over_tls_a_body_that_the_close_delimits_is_complete_only_after_close_notify() {
    on_each_runtime(|| async {
        // The server sends `close_notify` after the body.
        let (listener, address) = support::listener().await;
        until_close(Transport::Tls, listener);
        let mut client = support::client(Transport::Tls, address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        assert_eq!(body(&mut client, UNTIL_CLOSE.len()).await, UNTIL_CLOSE);
        let end = client.next().await.unwrap();
        assert!(matches!(end, Part::End(Outcome::Complete(None))), "{end:?}");

        // The stream ends before the `close_notify` record, the last record of the server.
        let (listener, address) = support::listener().await;
        until_close(Transport::Tls, listener);
        let proxy = Proxy::new(address, Last::Cut);
        let mut client = support::client(Transport::Tls, proxy.address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        assert_eq!(body(&mut client, UNTIL_CLOSE.len()).await, UNTIL_CLOSE);
        let end = client.next().await.unwrap();
        assert!(matches!(end, Part::End(Outcome::Truncated)), "{end:?}");
        drop(client);
        assert_eq!(proxy.last_records().1, Some(ALERT_RECORD));
    });
}

#[test]
fn a_close_after_the_exchange_sends_close_notify_and_releases_the_client() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let serving = tokio::spawn(async move {
            let mut server = support::server(Transport::Tls, &listener).await;
            server.request().await.unwrap().expect("a request");
            server.respond(&ok(Framing::Length(4))).await.unwrap();
            server.write(&Lease::from(&b"done"[..])).await.unwrap();
            server.finish().await.unwrap();
            assert!(server.request().await.unwrap().is_none());
            server.close().await.unwrap()
        });
        let proxy = Proxy::new(address, Last::Forward);
        let mut client = support::client(Transport::Tls, proxy.address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        assert!(matches!(
            client.collect(&mut region).await.unwrap(),
            Collect::Complete(None)
        ));
        assert_eq!(client.close().await, Ok(()));
        assert_eq!(serving.await.unwrap().result, Ok(()));
        // The last record of the client before the end of its stream is an alert: close_notify.
        assert_eq!(proxy.last_records().0, Some(ALERT_RECORD));
    });
}

#[test]
fn a_reset_ends_a_body_that_the_close_delimits_as_reset_not_complete() {
    on_each_runtime(|| async {
        // Over TCP, the server resets the connection after the bytes of the body.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (reset, resets) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            socket.write_all(UNTIL_CLOSE).unwrap();
            resets.recv_timeout(PATIENCE).unwrap();
            socket2::SockRef::from(&socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        });
        let mut client = support::client(Transport::Plain, address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        assert_eq!(body(&mut client, UNTIL_CLOSE.len()).await, UNTIL_CLOSE);
        reset.send(()).unwrap();
        server.join().unwrap();
        let end = client.next().await.unwrap();
        assert!(matches!(end, Part::End(Outcome::Reset(None))), "TCP: {end:?}");

        // Over TLS, the connection resets before the `close_notify` record.
        let (listener, address) = support::listener().await;
        until_close(Transport::Tls, listener);
        let proxy = Proxy::new(address, Last::Reset);
        let mut client = support::client(Transport::Tls, proxy.address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        assert_eq!(body(&mut client, UNTIL_CLOSE.len()).await, UNTIL_CLOSE);
        proxy.reset.send(()).unwrap();
        let end = client.next().await.unwrap();
        assert!(matches!(end, Part::End(Outcome::Reset(None))), "TLS: {end:?}");
        drop(client);
        proxy.last_records();
    });
}
