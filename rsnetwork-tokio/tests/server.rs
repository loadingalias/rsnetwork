//! The HTTP/1.1 server on the Tokio binding: the N104 cases whose result depends on the socket,
//! the timer, or the tasks (N107), and the close of a server, which joins each task that it
//! spawned. Each case runs on a current-thread and on a multi-thread runtime.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(
    dead_code,
    reason = "the server cases forward each record; the client cases cut and reset"
)]
mod support;

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::io::Write as _;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use rsnetwork::body::{Outcome, Read};
use rsnetwork::buffer::{Backing, Lease, WriteLoan};
use rsnetwork::drive::Kind;
use rsnetwork::h1::Framing;
use rsnetwork::server::{self, Closed, Delivery, Linger, Response};
use rsnetwork::value::Status;
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::{Report, Server};
use support::{ALERT_RECORD, HEAD_TIMEOUT, Last, PATIENCE, Proxy, Transport, ok, on_each_runtime, read_to_end};
use tokio::sync::{Notify, mpsc as channel, oneshot};

/// A body larger than the socket buffers of loopback: 16 parts of 1 MiB.
const PART: usize = 1 << 20;
const PARTS: usize = 16;

#[test]
fn a_reset_after_the_handler_finished_gives_a_partial_delivery_apart_from_the_finish() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            let (listener, address) = support::listener().await;
            let (finished, finish) = oneshot::channel();
            let serving = tokio::spawn(async move {
                let mut server = support::server(transport, &listener).await;
                server.request().await.unwrap().expect("a request");
                let total = (PART * PARTS) as u64;
                server.respond(&ok(Framing::Length(total))).await.unwrap();
                for _ in 0..PARTS {
                    server.write(&Lease::from(vec![b'x'; PART])).await.unwrap();
                }
                server.finish().await.unwrap();
                // The handler is complete, and the client reads nothing: the delivery goes on.
                let Some(Delivery::Sending {
                    finished: true,
                    accepted,
                }) = server.delivery()
                else {
                    panic!("{transport:?}: {:?}", server.delivery());
                };
                assert!(accepted < total, "{transport:?}: {accepted}");
                finished.send(()).unwrap();
                let closed = server.release().await.unwrap();
                (closed, server.delivery(), total)
            });
            let mut client = support::client(transport, address).await;
            client.send(&support::get(), Clock.deadline(PATIENCE)).await.unwrap();
            client.response().await.unwrap();
            finish.await.unwrap();
            // A client that drops before its release resets the connection.
            drop(client);
            let (closed, delivery, total) = serving.await.unwrap();
            assert!(
                matches!(closed, Closed { result: Err(error), .. } if error.kind() == Kind::Partial),
                "{transport:?}: {closed:?}"
            );
            assert!(
                matches!(
                    delivery,
                    Some(Delivery::Partial { finished: true, accepted, error })
                        if accepted < total && error.kind() == Kind::Partial
                ),
                "{transport:?}: {delivery:?}"
            );
        }
    });
}

#[test]
fn a_complete_delivery_needs_each_byte_of_the_response() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let (collected, collect) = oneshot::channel();
        let serving = tokio::spawn(async move {
            let mut server = support::server(Transport::Plain, &listener).await;
            server.request().await.unwrap().expect("a request");
            server.respond(&ok(Framing::Chunked)).await.unwrap();
            server.write(&Lease::from(&b"hello"[..])).await.unwrap();
            server.finish().await.unwrap();
            collect.await.unwrap();
            server.delivery()
        });
        let mut client = support::client(Transport::Plain, address).await;
        client.send(&support::get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        client.collect(&mut region).await.unwrap();
        assert_eq!(region.filled(), b"hello");
        collected.send(()).unwrap();
        // The client read each byte, and the chunk framing does not count as body bytes.
        assert_eq!(serving.await.unwrap(), Some(Delivery::Complete { accepted: 5 }));
    });
}

/// What a handler of the close test tells the test.
#[derive(Debug, PartialEq, Eq)]
enum Event {
    /// A connection started.
    Started,
    /// The handler finished the response to `/a`, and waits.
    First,
}

#[test]
fn a_close_drains_the_request_in_flight_refuses_the_one_that_the_handler_did_not_see_and_joins_each_task() {
    on_each_runtime(|| async {
        let metrics = tokio::runtime::Handle::current().metrics();
        let before = metrics.num_alive_tasks();
        let (listener, address) = support::listener().await;
        let (events, mut seen) = channel::unbounded_channel();
        let proceed = Arc::new(Notify::new());
        let handler = {
            let proceed = Arc::clone(&proceed);
            move |mut connection: rsnetwork_tokio::server::Http1| {
                let (events, proceed) = (events.clone(), Arc::clone(&proceed));
                async move {
                    events.send(Event::Started).unwrap();
                    while let Some(request) = connection.request().await? {
                        connection.respond(&ok(Framing::Length(2))).await?;
                        connection.write(&Lease::from(&b"ok"[..])).await?;
                        connection.finish().await?;
                        // The close comes before the handler asks for `/b`.
                        if request.head().target().as_bytes() == b"/a" {
                            events.send(Event::First).unwrap();
                            proceed.notified().await;
                        }
                    }
                    Ok(())
                }
            }
        };
        let make = || {
            let budget = support::budget();
            Ok((support::core_server(Transport::Plain), support::pool(&budget)))
        };
        let server = Server::serve(listener, NonZeroUsize::new(4).unwrap(), make, handler);
        // Two pipelined requests on one connection, and a connection with no request.
        let pipelined = thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket
                .write_all(b"GET /a HTTP/1.1\r\nhost: a\r\n\r\nGET /b HTTP/1.1\r\nhost: a\r\n\r\n")
                .unwrap();
            read_to_end(&mut socket)
        });
        let idle = thread::spawn(move || read_to_end(&mut TcpStream::connect(address).unwrap()));
        // Both connections started, and the handler finished the response to `/a`.
        let (mut started, mut first) = (0, false);
        while started < 2 || !first {
            match seen.recv().await.unwrap() {
                Event::Started => started += 1,
                Event::First => first = true,
            }
        }
        // The close starts, and then the handler asks for the next request.
        let mut closing = pin!(server.close(Clock.deadline(Duration::from_secs(5))));
        poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending(), "the close waits for its tasks");
            Poll::Ready(())
        })
        .await;
        proceed.notify_one();
        let report = closing.await;
        assert_eq!(
            report,
            Report {
                accepted: 2,
                refused: 0,
                failed: 0,
                aborted: 0
            }
        );
        // The close joined each task that the server spawned.
        assert_eq!(metrics.num_alive_tasks(), before);
        let bytes = pipelined.join().unwrap();
        let ok_end = bytes
            .windows(2)
            .position(|pair| pair == b"ok")
            .expect("the first response")
            + 2;
        let (first, refusal) = bytes.split_at(ok_end);
        assert!(first.starts_with(b"HTTP/1.1 200 "), "{}", first.escape_ascii());
        assert!(refusal.starts_with(b"HTTP/1.1 503 "), "{}", refusal.escape_ascii());
        assert!(refusal.windows(17).any(|line| line == b"connection: close"));
        assert_eq!(idle.join().unwrap(), b"");
    });
}

#[test]
fn over_tls_a_shutdown_sends_close_notify_before_the_linger() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let proxy = Proxy::new(address, Last::Forward);
        let serving = tokio::spawn(async move {
            let mut server = support::server(Transport::Tls, &listener).await;
            server.request().await.unwrap().expect("a request");
            server.shutdown(Clock.deadline(Duration::from_secs(5))).unwrap();
            server.respond(&ok(Framing::Length(2))).await.unwrap();
            server.write(&Lease::from(&b"ok"[..])).await.unwrap();
            server.finish().await.unwrap();
            assert!(server.request().await.unwrap().is_none());
            server.close().await.unwrap()
        });
        let mut client = support::client(Transport::Tls, proxy.address).await;
        client.send(&support::get(), Clock.deadline(PATIENCE)).await.unwrap();
        client.response().await.unwrap();
        let mut region = WriteLoan::new(Vec::with_capacity(64));
        client.collect(&mut region).await.unwrap();
        assert_eq!(region.filled(), b"ok");
        client.close().await.unwrap();
        assert_eq!(serving.await.unwrap().result, Ok(()));
        // The last record of the server before the end of its stream is an alert: close_notify.
        let (_, server_last) = proxy.last_records();
        assert_eq!(server_last, Some(ALERT_RECORD));
    });
}

/// How the client of the linger test ends.
#[derive(Clone, Copy, Debug)]
enum Late {
    /// It sends 600 bytes, and then the end of its stream.
    Ended,
    /// It sends 1001 bytes, more than the linger takes.
    Flooded,
    /// It sends 600 bytes, and then nothing.
    Slow,
}

#[test]
fn the_linger_discards_late_bytes_and_ends_at_the_end_of_input_its_bytes_or_its_time() {
    const LINGER: Linger = Linger {
        time: Duration::from_secs(1),
        bytes: 1000,
    };
    on_each_runtime(|| async {
        for late in [Late::Ended, Late::Flooded, Late::Slow] {
            let (listener, address) = support::listener().await;
            let (done, ended) = mpsc::channel::<()>();
            let client = thread::spawn(move || {
                let mut socket = TcpStream::connect(address).unwrap();
                socket
                    .write_all(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 100000\r\n\r\nfirst bytes")
                    .unwrap();
                // The server sends its response and the end of its stream, and then lingers.
                let response = read_to_end(&mut socket);
                socket.write_all(&[b'x'; 600]).unwrap();
                match late {
                    Late::Ended => socket.shutdown(std::net::Shutdown::Write).unwrap(),
                    // The server can close after the bytes of its limit, so this write can fail.
                    Late::Flooded => drop(socket.write_all(&[b'x'; 401])),
                    Late::Slow => {}
                }
                // The socket stays open until the server ended.
                ended.recv_timeout(PATIENCE).unwrap();
                response
            });
            let (stream, _) = listener.accept().await.unwrap();
            let limits = server::Limits {
                linger: LINGER,
                ..support::server_limits()
            };
            let core = server::Http1::plain(limits, Clock.domain(), &support::budget()).unwrap();
            let mut server =
                rsnetwork_tokio::server::Http1::new(core, stream, support::pool(&support::budget())).unwrap();
            server.request().await.unwrap().expect("a request");
            let started = Instant::now();
            // The server does not read the body, which is longer than the drain.
            let too_large = Response {
                status: Status::new(413).unwrap(),
                fields: &[],
                body: Framing::Length(0),
            };
            server.respond(&too_large).await.unwrap();
            assert!(server.request().await.unwrap().is_none());
            let closed = server.close().await.unwrap();
            let elapsed = started.elapsed();
            done.send(()).unwrap();
            assert_eq!(closed.result, Ok(()), "{late:?}");
            match late {
                Late::Ended | Late::Flooded => assert!(elapsed < LINGER.time, "{late:?}: {elapsed:?}"),
                Late::Slow => assert!(elapsed >= LINGER.time, "{late:?}: {elapsed:?}"),
            }
            let response = client.join().unwrap();
            assert!(response.starts_with(b"HTTP/1.1 413 "), "{}", response.escape_ascii());
            assert!(response.windows(17).any(|line| line == b"connection: close"));
        }
    });
}

#[test]
fn a_reset_inside_the_request_body_ends_it_reset_not_truncated() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let (reset, resets) = mpsc::channel();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            (&socket)
                .write_all(b"POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 10\r\n\r\nfour")
                .unwrap();
            resets.recv_timeout(PATIENCE).unwrap();
            socket2::SockRef::from(&socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
        });
        let mut server = support::server(Transport::Plain, &listener).await;
        server.request().await.unwrap().expect("a request");
        let mut region = WriteLoan::new(Backing::from(Vec::with_capacity(16)));
        while region.filled().len() < 4 {
            assert!(matches!(server.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
        }
        reset.send(()).unwrap();
        client.join().unwrap();
        let read = server.read_into(&mut region).await.unwrap();
        assert!(matches!(read, Read::Done(Outcome::Reset(None))), "{read:?}");
        let closed = server.close().await.unwrap();
        assert!(
            matches!(closed, Closed { result: Err(error), .. } if error.kind() == Kind::Partial),
            "{closed:?}"
        );
    });
}

#[test]
fn over_tls_the_head_timeout_bounds_the_handshake() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        // A part of a record header, and then nothing.
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket.write_all(&[22, 3, 1]).unwrap();
            read_to_end(&mut socket)
        });
        let started = Instant::now();
        let mut server = support::server(Transport::Tls, &listener).await;
        assert!(server.request().await.unwrap().is_none());
        let closed = server.close().await.unwrap();
        assert!(started.elapsed() >= HEAD_TIMEOUT, "{:?}", started.elapsed());
        assert!(
            matches!(closed, Closed { result: Err(error), .. } if error.kind() == Kind::Deadline),
            "{closed:?}"
        );
        client.join().unwrap();
    });
}
