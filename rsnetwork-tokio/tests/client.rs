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
use rsnetwork::buffer::{Backing, Buffer as _, Lease, WriteLoan};
use rsnetwork::client::Request;
use rsnetwork::drive::{Inbound, Kind, Outbound};
use rsnetwork::h1::{self, Framing, ServerEvent};
use rsnetwork::host::{Connection, Io as _};
use rsnetwork::tls::Tls;
use rsnetwork::value::{Authority, Field, Method, Status, Target};
use rsnetwork_tokio::client::Http1;
use rsnetwork_tokio::{Clock, Socket};
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

/// A server over TLS that answers one request with `UNTIL_CLOSE`, a body that the close
/// delimits, and then closes. It is the HTTP/1.1 engine of the core on the socket of the binding,
/// because the server vocabulary sends a body of unknown length in chunks.
fn until_close(listener: tokio::net::TcpListener) {
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let budget = support::budget();
        let queues = || {
            (
                Inbound::new(support::QUEUE, &budget).unwrap(),
                Outbound::new(support::QUEUE, &budget).unwrap(),
            )
        };
        let (inbound, outbound) = queues();
        let engine = h1::Server::new(support::HEAD, support::BODY, support::TURN, &outbound, &budget).unwrap();
        let tls = Tls::server(
            &support::server_config(),
            engine,
            (inbound, outbound),
            support::TLS,
            &budget,
        )
        .unwrap();
        let (inbound, outbound) = queues();
        let connection = Connection::new(tls, inbound, outbound, Some(Clock.domain())).unwrap();
        let mut socket = Socket::new(connection, stream, support::pool(&budget)).unwrap();
        // A proxy can cut or reset the stream, so the end of this server is not checked here.
        let _released = socket
            .until(|connection, now| {
                if let Some(ServerEvent::Request(_)) = connection.drive(Some(now))? {
                    let (server, plaintext) = connection.parts().0.parts();
                    let head = Backing::from(Vec::with_capacity(256));
                    let ok = Status::new(200).unwrap();
                    server.respond(plaintext, ok, &[], Framing::Close, head)?;
                    server.send(plaintext, &Lease::from(UNTIL_CLOSE))?;
                    server.finish(plaintext)?;
                }
                Ok(connection.release())
            })
            .await;
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
                let mut exchange = server.request().await.unwrap().expect("a request");
                exchange.respond(&ok(Some(100))).await.unwrap();
                exchange.write(&Lease::from(&b"0123456789"[..])).await.unwrap();
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
                    while let Some(mut exchange) = server.request().await.unwrap() {
                        if requests.fetch_add(1, Ordering::Relaxed) == 0 {
                            exchange.respond(&ok(Some(40))).await.unwrap();
                            exchange.write(&Lease::from(vec![b'a'; 8])).await.unwrap();
                            exchange.write(&Lease::from(vec![b'b'; 32])).await.unwrap();
                        } else {
                            exchange.respond(&ok(Some(6))).await.unwrap();
                            exchange.write(&Lease::from(&b"second"[..])).await.unwrap();
                        }
                        exchange.finish().await.unwrap();
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
                    let mut exchange = server.request().await.unwrap().expect("a request");
                    requests.fetch_add(1, Ordering::Relaxed);
                    exchange.respond(&ok(Some(1000))).await.unwrap();
                    exchange.write(&Lease::from(vec![b'a'; 8])).await.unwrap();
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
        until_close(listener);
        let mut client = support::client(Transport::Tls, address).await;
        client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        assert_eq!(body(&mut client, UNTIL_CLOSE.len()).await, UNTIL_CLOSE);
        let end = client.next().await.unwrap();
        assert!(matches!(end, Part::End(Outcome::Complete(None))), "{end:?}");

        // The stream ends before the `close_notify` record, the last record of the server.
        let (listener, address) = support::listener().await;
        until_close(listener);
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
            let mut exchange = server.request().await.unwrap().expect("a request");
            exchange.respond(&ok(Some(4))).await.unwrap();
            exchange.write(&Lease::from(&b"done"[..])).await.unwrap();
            exchange.finish().await.unwrap();
            drop(exchange);
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
        until_close(listener);
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

#[test]
fn a_trailer_section_larger_than_the_head_region_refuses_at_once_and_does_not_wait() {
    on_each_runtime(|| async {
        // The peer accepts the connection and reads nothing: the refusal needs no byte of it.
        let (listener, address) = support::listener().await;
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = support::client(Transport::Plain, address).await;
        let request = Request {
            method: Method::POST,
            target: Target::new(b"/long").unwrap(),
            authority: Authority::new(b"server.test").unwrap(),
            fields: &[],
            length: None,
        };
        client.send(&request, Clock.deadline(PATIENCE)).await.unwrap();
        const VALUE: &[u8] = &[b'v'; 200];
        let trailers: Vec<_> = (0..6).map(|_| Field::new(b"x-long", VALUE).unwrap()).collect();
        let finish = client.finish_with_trailers(&trailers);
        let refused = tokio::time::timeout(PATIENCE, finish).await.unwrap().unwrap_err();
        assert_eq!(refused.kind(), Kind::Overload, "{refused:?}");
        drop(accept.await.unwrap());
    });
}

#[test]
fn the_tokio_stagger_starts_ipv4_while_ipv6_waits_and_closes_the_losing_socket() {
    use core::num::NonZeroUsize;
    use rsnetwork::client::{Operation, establish::Dial};
    use rsnetwork_tokio::client::connect_with;
    use tokio::net::{TcpListener as Listener, TcpStream};

    on_each_runtime(|| async {
        let first = Listener::bind("[::1]:0").await.unwrap();
        let second = Listener::bind("127.0.0.1:0").await.unwrap();
        let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let mut held = Some(TcpStream::connect(addresses[0]).await.unwrap());
        let (loser, _) = first.accept().await.unwrap();
        let dial = Dial {
            delay: Duration::from_millis(50),
            ..Dial::default()
        };
        let mut op = Operation::new(Clock.deadline(PATIENCE), NonZeroUsize::new(2).unwrap());
        let mem = support::budget();
        let before = Clock.now();
        let mut starts = Vec::new();
        let winner = connect_with(&addresses, dial, &mut op, &mem, |address| {
            starts.push((address, Clock.now()));
            let pending = held.take();
            async move {
                if let Some(socket) = pending {
                    // The host withholds this connect completion. Cancellation must close its socket.
                    core::future::pending::<()>().await;
                    Ok(socket)
                } else {
                    TcpStream::connect(address).await
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(starts.len(), 2);
        assert_eq!([starts[0].0, starts[1].0], addresses);
        assert!(starts[1].1.duration_since(before).unwrap() >= dial.delay);
        assert_eq!(winner.peer_addr().unwrap(), addresses[1]);
        assert_eq!(second.accept().await.unwrap().1, winner.local_addr().unwrap());
        let read = tokio::time::timeout(PATIENCE, loser.peek(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        assert_eq!((op.remaining(), op.occupied(), mem.available()), (0, 0, mem.bound()));
    });
}

#[test]
fn lookup_and_connect_share_the_work_budget_with_the_ensuing_http_exchange() {
    use core::num::NonZeroUsize;
    use rsnetwork::client::{Operation, establish::Dial};
    use rsnetwork_tokio::client::connect;
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let peer = tokio::spawn(async move {
            let mut server = support::server(Transport::Plain, &listener).await;
            let mut exchange = server.request().await.unwrap().unwrap();
            exchange.respond(&ok(Some(2))).await.unwrap();
            exchange.write(&Lease::from(&b"ok"[..])).await.unwrap();
            exchange.finish().await.unwrap();
            exchange
        });
        let resolver = rsnetwork_tokio::Blocking::new(NonZeroUsize::MIN);
        let mem = support::budget();
        let mut op = Operation::new(Clock.deadline(PATIENCE), NonZeroUsize::new(2).unwrap());
        let socket = connect("127.0.0.1", address.port(), &resolver, Dial::default(), &mut op, &mem)
            .await
            .unwrap();
        assert_eq!((op.remaining(), op.occupied()), (0, 0));
        let mut http = Http1::new(support::core_client(Transport::Plain), socket, support::pool(&mem)).unwrap();
        http.send(&get(), &op).await.unwrap();
        assert_eq!(http.response().await.unwrap().status().code(), 200);
        let mut data = WriteLoan::new(Vec::with_capacity(2));
        assert!(matches!(
            http.collect(&mut data).await.unwrap(),
            Collect::Complete(None)
        ));
        assert_eq!(data.filled(), b"ok");
        peer.await.unwrap();
    });
}
