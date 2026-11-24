//! HTTP/2 on the Tokio binding (N213): streams of one connection in tasks of their own, the N103
//! and N104 cases whose result depends on the socket, the timer, or the tasks, the close of a
//! server, which joins each handler task, and the N203 floods. Each case runs on a current-thread
//! and on a multi-thread runtime.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(dead_code, reason = "the HTTP/2 cases use only the HTTP/2 helpers and the proxy")]
mod support;

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Poll;
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use rsnetwork::body::{Collect, Outcome, Read};
use rsnetwork::buffer::{Lease, WriteLoan};
use rsnetwork::client::Request;
use rsnetwork::drive::Kind;
use rsnetwork::server::{Closed, Delivery};
use rsnetwork::value::{Authority, Method, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::{Exchange, Report, Server};
use support::{ALERT_RECORD, Last, PATIENCE, Proxy, Transport, ok, on_each_runtime};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

/// The deadline of the exchanges whose peer stops.
const DEADLINE: Duration = Duration::from_millis(300);

/// The stream limit of the servers of the tests.
const STREAMS: usize = support::H2.settings.max_concurrent_streams as usize;

fn request(target: &'static [u8], length: Option<u64>) -> Request<'static> {
    Request {
        method: if length == Some(0) { Method::GET } else { Method::POST },
        target: Target::new(target).unwrap(),
        authority: Authority::new(b"server.test").unwrap(),
        fields: &[],
        length,
    }
}

/// A server of the binding that serves HTTP/2 over `transport`, with `handler` for each request.
fn serve<H, F>(transport: Transport, listener: tokio::net::TcpListener, handler: H) -> Server
where
    H: Fn(Exchange) -> F + Send + Sync + 'static,
    F: Future<Output = Result<(), rsnetwork::drive::Error>> + Send + 'static,
{
    let make = move || Ok((support::core_h2_server(transport), support::pool(&support::budget())));
    Server::serve(listener, NonZeroUsize::new(4).unwrap(), make, handler)
}

/// Awaits `future`, which a correct binding ends within [`PATIENCE`].
async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("the future ends within its patience")
}

/// Collects the body of `exchange`: its result and its bytes.
async fn collect(exchange: &mut rsnetwork_tokio::client::Exchange) -> (Collect, Vec<u8>) {
    let mut region = WriteLoan::new(Vec::with_capacity(64));
    let collected = exchange.collect(&mut region).await.unwrap();
    (collected, region.filled().to_vec())
}

#[test]
fn two_tasks_share_one_connection_and_a_stalled_body_holds_back_only_its_own_stream() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            let (listener, address) = support::listener().await;
            let release = Arc::new(Notify::new());
            let handler = {
                let release = Arc::clone(&release);
                move |mut exchange: Exchange| {
                    let release = Arc::clone(&release);
                    async move {
                        if exchange.head().target().as_bytes() == b"/slow" {
                            exchange.respond(&ok(Some(8))).await?;
                            exchange.write(&Lease::from(&b"slow"[..])).await?;
                            release.notified().await;
                            exchange.write(&Lease::from(&b"rest"[..])).await?;
                        } else {
                            exchange.respond(&ok(Some(5))).await?;
                            exchange.write(&Lease::from(&b"quick"[..])).await?;
                        }
                        exchange.finish().await
                    }
                }
            };
            let server = serve(transport, listener, handler);
            let client = support::h2_client(transport, address).await;
            let (read, first) = oneshot::channel();
            let slow = tokio::spawn({
                let client = client.clone();
                async move {
                    let mut exchange = client
                        .send(&request(b"/slow", Some(0)), Clock.deadline(PATIENCE))
                        .await
                        .unwrap();
                    exchange.response().await.unwrap();
                    let mut region = WriteLoan::new(Vec::with_capacity(64));
                    while region.filled().len() < 4 {
                        assert!(matches!(exchange.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
                    }
                    read.send(()).unwrap();
                    // This read waits: the rest comes after the other stream completed.
                    let collected = exchange.collect(&mut region).await.unwrap();
                    (collected, region.filled().to_vec())
                }
            });
            within(first).await.unwrap();
            let quick = tokio::spawn({
                let client = client.clone();
                async move {
                    let mut exchange = client
                        .send(&request(b"/quick", Some(0)), Clock.deadline(PATIENCE))
                        .await
                        .unwrap();
                    exchange.response().await.unwrap();
                    collect(&mut exchange).await
                }
            });
            let (collected, body) = within(quick).await.unwrap();
            assert!(
                matches!(collected, Collect::Complete(None)),
                "{transport:?}: {collected:?}"
            );
            assert_eq!(body, b"quick", "{transport:?}");
            assert!(!slow.is_finished(), "{transport:?}: the slow stream waits for its rest");
            release.notify_one();
            let (collected, body) = within(slow).await.unwrap();
            assert!(
                matches!(collected, Collect::Complete(None)),
                "{transport:?}: {collected:?}"
            );
            assert_eq!(body, b"slowrest", "{transport:?}");
            within(client.close()).await.unwrap();
            let report = within(server.close(Clock.deadline(PATIENCE))).await;
            assert_eq!(
                report,
                Report {
                    accepted: 1,
                    refused: 0,
                    failed: 0,
                    aborted: 0
                },
                "{transport:?}"
            );
        }
    });
}

#[test]
fn a_slow_body_meets_its_deadline_on_its_stream_while_another_task_drives_the_connection() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            // A body of 100 bytes, of which the server sends 10, and then nothing.
            let (listener, address) = support::listener().await;
            let release = Arc::new(Notify::new());
            let handler = {
                let release = Arc::clone(&release);
                move |mut exchange: Exchange| {
                    let release = Arc::clone(&release);
                    async move {
                        if exchange.head().target().as_bytes() == b"/slow" {
                            exchange.respond(&ok(Some(100))).await?;
                            exchange.write(&Lease::from(&b"0123456789"[..])).await?;
                            release.notified().await;
                            return Ok(());
                        }
                        exchange.respond(&ok(Some(2))).await?;
                        exchange.write(&Lease::from(&b"ok"[..])).await?;
                        exchange.finish().await
                    }
                }
            };
            let server = serve(transport, listener, handler);
            let client = support::h2_client(transport, address).await;
            // This task drives the connection while the exchanges of the test wait.
            let driving = tokio::spawn({
                let client = client.clone();
                async move { client.drive().await }
            });
            let started = Instant::now();
            let mut slow = client
                .send(&request(b"/slow", Some(0)), Clock.deadline(DEADLINE))
                .await
                .unwrap();
            slow.response().await.unwrap();
            let mut region = WriteLoan::new(Vec::with_capacity(256));
            while region.filled().len() < 10 {
                assert!(matches!(slow.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
            }
            let error = within(slow.read_into(&mut region)).await.unwrap_err();
            assert_eq!(
                (error.kind(), error.reason()),
                (Kind::Deadline, "the deadline came before the end of the response"),
                "{transport:?}"
            );
            assert!(started.elapsed() >= DEADLINE, "{transport:?}: {:?}", started.elapsed());
            assert_eq!(slow.delivered(), 10, "{transport:?}");
            drop(slow);
            // The connection goes on.
            let mut quick = client
                .send(&request(b"/quick", Some(0)), Clock.deadline(PATIENCE))
                .await
                .unwrap();
            quick.response().await.unwrap();
            let (collected, body) = collect(&mut quick).await;
            assert!(
                matches!(collected, Collect::Complete(None)),
                "{transport:?}: {collected:?}"
            );
            assert_eq!(body, b"ok", "{transport:?}");
            drop(quick);
            release.notify_one();
            within(client.close()).await.unwrap();
            assert_eq!(within(driving).await.unwrap(), Ok(()), "{transport:?}");
            within(server.close(Clock.deadline(PATIENCE))).await;
        }
    });
}

#[test]
fn over_tls_the_deadline_covers_the_handshake() {
    on_each_runtime(|| async {
        // The server accepts the connection, and sends nothing.
        let (listener, address) = support::listener().await;
        let silent = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            core::future::pending::<()>().await;
            drop(socket);
        });
        let client = support::h2_client(Transport::Tls, address).await;
        let started = Instant::now();
        let mut exchange = client
            .send(&request(b"/", Some(0)), Clock.deadline(DEADLINE))
            .await
            .unwrap();
        let error = within(exchange.response()).await.unwrap_err();
        assert_eq!(error.kind(), Kind::Deadline, "{error:?}");
        assert!(started.elapsed() >= DEADLINE, "{:?}", started.elapsed());
        silent.abort();
    });
}

#[test]
fn a_close_after_the_exchange_sends_close_notify_and_releases_both_ends() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let serving = tokio::spawn(async move {
            let mut server = support::h2_server(Transport::Tls, &listener).await;
            let mut exchange = server.request().await.unwrap().expect("a request");
            exchange.respond(&ok(Some(4))).await.unwrap();
            exchange.write(&Lease::from(&b"done"[..])).await.unwrap();
            exchange.finish().await.unwrap();
            drop(exchange);
            assert!(server.request().await.unwrap().is_none());
            server.close().await.unwrap()
        });
        let proxy = Proxy::new(address, Last::Forward);
        let client = support::h2_client(Transport::Tls, proxy.address).await;
        let mut exchange = client
            .send(&request(b"/", Some(0)), Clock.deadline(PATIENCE))
            .await
            .unwrap();
        exchange.response().await.unwrap();
        let (collected, body) = collect(&mut exchange).await;
        assert!(matches!(collected, Collect::Complete(None)), "{collected:?}");
        assert_eq!(body, b"done");
        drop(exchange);
        assert_eq!(within(client.close()).await, Ok(()));
        assert_eq!(within(serving).await.unwrap().result, Ok(()));
        // The last record of the client before the end of its stream is an alert: close_notify.
        assert_eq!(proxy.last_records().0, Some(ALERT_RECORD));
    });
}

#[test]
fn a_reset_of_the_transport_ends_each_body_in_flight_as_reset_not_complete() {
    on_each_runtime(|| async {
        // The server resets the connection after 10 bytes of each of two bodies.
        let (listener, address) = support::listener().await;
        let (sent, reset) = oneshot::channel::<()>();
        let resetting = tokio::spawn(async move {
            let mut server = support::h2_server(Transport::Plain, &listener).await;
            let mut exchanges = Vec::new();
            for _ in 0..2 {
                let mut exchange = server.request().await.unwrap().expect("a request");
                exchange.respond(&ok(Some(100))).await.unwrap();
                exchange.write(&Lease::from(&b"0123456789"[..])).await.unwrap();
                exchanges.push(exchange);
            }
            reset.await.unwrap();
            // The last handle drops before the release of the connection: it resets.
            drop((server, exchanges));
        });
        let client = support::h2_client(Transport::Plain, address).await;
        let mut readers = Vec::new();
        let (read, mut reads) = mpsc::unbounded_channel();
        for target in [&b"/a"[..], b"/b"] {
            let (client, read) = (client.clone(), read.clone());
            readers.push(tokio::spawn(async move {
                let mut exchange = client
                    .send(&request(target, Some(0)), Clock.deadline(PATIENCE))
                    .await
                    .unwrap();
                exchange.response().await.unwrap();
                let mut region = WriteLoan::new(Vec::with_capacity(256));
                while region.filled().len() < 10 {
                    assert!(matches!(exchange.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
                }
                read.send(()).unwrap();
                let end = exchange.read_into(&mut region).await.unwrap();
                assert!(matches!(end, Read::Done(Outcome::Reset(None))), "client: {end:?}");
            }));
        }
        for _ in 0..2 {
            within(reads.recv()).await.unwrap();
        }
        sent.send(()).unwrap();
        for reader in readers {
            within(reader).await.unwrap();
        }
        resetting.await.unwrap();

        // The client resets the connection inside each of two request bodies.
        let (listener, address) = support::listener().await;
        let (read, mut reads) = mpsc::unbounded_channel();
        let serving = tokio::spawn(async move {
            let mut server = support::h2_server(Transport::Plain, &listener).await;
            let mut readers = Vec::new();
            for _ in 0..2 {
                let mut exchange = server.request().await.unwrap().expect("a request");
                let read = read.clone();
                readers.push(tokio::spawn(async move {
                    let mut region = WriteLoan::new(Vec::with_capacity(256));
                    while region.filled().len() < 4 {
                        assert!(matches!(exchange.read_into(&mut region).await.unwrap(), Read::Bytes(_)));
                    }
                    read.send(()).unwrap();
                    let end = exchange.read_into(&mut region).await.unwrap();
                    assert!(matches!(end, Read::Done(Outcome::Reset(None))), "server: {end:?}");
                }));
            }
            for reader in readers {
                reader.await.unwrap();
            }
            server.close().await.unwrap()
        });
        let client = support::h2_client(Transport::Plain, address).await;
        let mut exchanges = Vec::new();
        for target in [&b"/a"[..], b"/b"] {
            let mut exchange = client
                .send(&request(target, Some(10)), Clock.deadline(PATIENCE))
                .await
                .unwrap();
            exchange.write(&Lease::from(&b"four"[..])).await.unwrap();
            exchanges.push(exchange);
        }
        // The client drives the connection until the server read both parts.
        let driving = tokio::spawn({
            let client = client.clone();
            async move { client.drive().await }
        });
        for _ in 0..2 {
            within(reads.recv()).await.unwrap();
        }
        driving.abort();
        drop((client, exchanges, driving.await));
        let closed = within(serving).await.unwrap();
        assert!(
            matches!(closed, Closed { result: Err(error), .. } if error.kind() == Kind::Partial),
            "{closed:?}"
        );
    });
}

#[test]
fn a_delivery_needs_each_byte_and_a_reset_after_the_finish_makes_it_partial() {
    on_each_runtime(|| async {
        // The client reads each byte: the delivery is complete.
        let (listener, address) = support::listener().await;
        let (collected, collect_done) = oneshot::channel();
        let serving = tokio::spawn(async move {
            let mut server = support::h2_server(Transport::Plain, &listener).await;
            let mut exchange = server.request().await.unwrap().expect("a request");
            exchange.respond(&ok(None)).await.unwrap();
            exchange.write(&Lease::from(&b"hello"[..])).await.unwrap();
            exchange.finish().await.unwrap();
            // The connection drives the rest of the delivery after the handler finished.
            let mut request = pin!(server.request());
            let mut collect_done = pin!(collect_done);
            poll_fn(|cx| {
                assert!(
                    request.as_mut().poll(cx).is_pending(),
                    "the client sends no other request"
                );
                collect_done.as_mut().poll(cx)
            })
            .await
            .unwrap();
            exchange.delivery()
        });
        let client = support::h2_client(Transport::Plain, address).await;
        let mut exchange = client
            .send(&request(b"/", Some(0)), Clock.deadline(PATIENCE))
            .await
            .unwrap();
        exchange.response().await.unwrap();
        let (_, body) = collect(&mut exchange).await;
        assert_eq!(body, b"hello");
        collected.send(()).unwrap();
        assert_eq!(within(serving).await.unwrap(), Some(Delivery::Complete { accepted: 5 }));
        drop((exchange, client));

        // The client reads nothing, so the stream window holds back the rest, and then the client
        // resets the connection after the handler finished.
        let (listener, address) = support::listener().await;
        let (finished, finish) = oneshot::channel();
        let total = 1 << 20;
        let serving = tokio::spawn(async move {
            let mut server = support::h2_server(Transport::Plain, &listener).await;
            let mut exchange = server.request().await.unwrap().expect("a request");
            exchange.respond(&ok(Some(total))).await.unwrap();
            exchange.write(&Lease::from(vec![b'x'; 1 << 20])).await.unwrap();
            exchange.finish().await.unwrap();
            let delivery = exchange.delivery();
            assert!(
                matches!(delivery, Some(Delivery::Sending { finished: true, accepted }) if accepted < total),
                "{delivery:?}"
            );
            finished.send(()).unwrap();
            let closed = server.close().await.unwrap();
            (closed, exchange.delivery())
        });
        let client = support::h2_client(Transport::Plain, address).await;
        let mut exchange = client
            .send(&request(b"/", Some(0)), Clock.deadline(PATIENCE))
            .await
            .unwrap();
        exchange.response().await.unwrap();
        within(finish).await.unwrap();
        drop((exchange, client));
        let (closed, delivery) = within(serving).await.unwrap();
        assert!(
            matches!(closed, Closed { result: Err(error), .. } if error.kind() == Kind::Partial),
            "{closed:?}"
        );
        assert!(
            matches!(
                delivery,
                Some(Delivery::Partial { finished: true, accepted, error }) if accepted < total && error.kind() == Kind::Partial
            ),
            "{delivery:?}"
        );
    });
}

#[test]
fn a_close_of_the_server_drains_accepted_streams_refuses_new_ones_and_joins_each_handler_task() {
    on_each_runtime(|| async {
        let before = tokio::runtime::Handle::current().metrics().num_alive_tasks();
        let (listener, address) = support::listener().await;
        let (started, mut starts) = mpsc::unbounded_channel();
        let proceed = Arc::new(Notify::new());
        let handler = {
            let proceed = Arc::clone(&proceed);
            move |mut exchange: Exchange| {
                let (started, proceed) = (started.clone(), Arc::clone(&proceed));
                async move {
                    let proceeding = proceed.notified();
                    started.send(()).unwrap();
                    proceeding.await;
                    exchange.respond(&ok(Some(2))).await?;
                    exchange.write(&Lease::from(&b"ok"[..])).await?;
                    exchange.finish().await
                }
            }
        };
        let server = serve(Transport::Plain, listener, handler);
        let client = support::h2_client(Transport::Plain, address).await;
        let mut exchanges = Vec::new();
        for target in [&b"/a"[..], b"/b"] {
            let client = client.clone();
            exchanges.push(tokio::spawn(async move {
                let mut exchange = client
                    .send(&request(target, Some(0)), Clock.deadline(PATIENCE))
                    .await
                    .unwrap();
                exchange.response().await.unwrap();
                collect(&mut exchange).await
            }));
        }
        for _ in 0..2 {
            within(starts.recv()).await.unwrap();
        }
        // The close waits for the two handlers.
        let mut closing = pin!(server.close(Clock.deadline(Duration::from_secs(5))));
        poll_fn(|cx| {
            assert!(closing.as_mut().poll(cx).is_pending(), "the close waits for its tasks");
            Poll::Ready(())
        })
        .await;
        // A new request after the GOAWAY refuses: at the client when the GOAWAY arrived, else at
        // the server, which the client learns as a request that the server did not process.
        let refused = match within(client.send(&request(b"/c", Some(0)), Clock.deadline(PATIENCE))).await {
            Err(error) => error,
            Ok(mut exchange) => within(exchange.response()).await.unwrap_err(),
        };
        assert!(matches!(refused.kind(), Kind::Misuse | Kind::Overload), "{refused:?}");
        proceed.notify_waiters();
        for exchange in exchanges {
            let (collected, body) = within(exchange).await.unwrap();
            assert!(matches!(collected, Collect::Complete(None)), "{collected:?}");
            assert_eq!(body, b"ok");
        }
        let report = within(closing).await;
        assert_eq!(
            report,
            Report {
                accepted: 1,
                refused: 0,
                failed: 0,
                aborted: 0
            }
        );
        drop(client);
        // The close joined each task that the server spawned, also each handler task.
        support::joined(before).await;
    });
}

/// A raw HTTP/2 client: the connection preface with an empty SETTINGS frame, and then `frames`.
/// A second thread reads each byte of the server until the end of its stream, and gives them.
fn raw(address: core::net::SocketAddr, frames: Vec<u8>) -> thread::JoinHandle<Vec<u8>> {
    let socket = TcpStream::connect(address).unwrap();
    // The timeout is set before the first byte goes out: macOS refuses the call on a socket that
    // the server closed.
    socket.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut reader = socket.try_clone().unwrap();
    let reading = thread::spawn(move || {
        let mut bytes = Vec::new();
        drop(reader.read_to_end(&mut bytes));
        bytes
    });
    thread::spawn(move || {
        let mut socket = socket;
        let preface = [&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], &frame(0x4, 0, 0, b"")].concat();
        // The server can end the connection before the last frame, so a write can fail.
        drop(socket.write_all(&[preface, frames].concat()));
        drop(socket.shutdown(Shutdown::Write));
        reading.join().unwrap()
    })
}

/// A frame: its header and its payload (RFC 9113, section 4.1).
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    [&length[1..], &[kind, flags], &stream.to_be_bytes(), payload].concat()
}

/// The frames of `bytes`: the type, the flags, and the payload of each.
fn frames(mut bytes: &[u8]) -> Vec<(u8, u8, Vec<u8>)> {
    let mut frames = Vec::new();
    while let Some((head, rest)) = bytes.split_first_chunk::<9>() {
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let Some((payload, rest)) = rest.split_at_checked(length) else {
            break;
        };
        frames.push((head[3], head[4], payload.to_vec()));
        bytes = rest;
    }
    frames
}

/// The header block of RFC 7541, C.3.1: a GET of `/` at `www.example.com`.
const C31: &[u8] = b"\x82\x86\x84\x41\x0fwww.example.com";

#[test]
fn a_rapid_reset_flood_starts_no_more_handlers_than_the_stream_limit() {
    on_each_runtime(|| async {
        const PAIRS: usize = 100;
        let (listener, address) = support::listener().await;
        let (in_flight, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let gate = Arc::new(Semaphore::new(0));
        let (started, mut starts) = mpsc::unbounded_channel();
        let handler = {
            let (in_flight, most, gate) = (Arc::clone(&in_flight), Arc::clone(&most), Arc::clone(&gate));
            move |exchange: Exchange| {
                let (in_flight, most, gate, started) = (
                    Arc::clone(&in_flight),
                    Arc::clone(&most),
                    Arc::clone(&gate),
                    started.clone(),
                );
                async move {
                    most.fetch_max(in_flight.fetch_add(1, Ordering::AcqRel) + 1, Ordering::AcqRel);
                    started.send(()).unwrap();
                    // The handler holds its stream until the test lets it go.
                    gate.acquire().await.unwrap().forget();
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                    drop(exchange);
                    Ok(())
                }
            }
        };
        let server = serve(Transport::Plain, listener, handler);
        // Each stream opens with a request, and resets at once (CVE-2023-44487).
        let flood: Vec<u8> = (0..PAIRS)
            .flat_map(|index| {
                let stream = u32::try_from(2 * index + 1).unwrap();
                [
                    frame(0x1, 0x5, stream, C31),
                    frame(0x3, 0, stream, &8_u32.to_be_bytes()),
                ]
                .concat()
            })
            .collect();
        let client = raw(address, flood);
        // A handler goes only after the stream limit of handlers started, so each later start
        // waits for a stream that a handler closed.
        for start in 0..PAIRS {
            within(starts.recv()).await.unwrap();
            if start + 1 >= STREAMS {
                gate.add_permits(1);
            }
        }
        gate.add_permits(STREAMS);
        assert_eq!(most.load(Ordering::Acquire), STREAMS);
        within(server.close(Clock.deadline(PATIENCE))).await;
        drop(client.join().unwrap());
    });
}

#[test]
fn a_continuation_flood_ends_the_connection_with_compression_error() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let server = serve(Transport::Plain, listener, |_exchange: Exchange| async { Ok(()) });
        // A HEADERS frame with an empty fragment and no END_HEADERS, and empty CONTINUATION frames.
        let flood = [frame(0x1, 0, 1, b""), frame(0x9, 0, 1, b"").repeat(100_000)].concat();
        let received = within(tokio::task::spawn_blocking(move || raw(address, flood).join().unwrap()))
            .await
            .unwrap();
        let goaway = frames(&received).into_iter().find(|&(kind, ..)| kind == 0x7);
        // GOAWAY with the last stream 0 and COMPRESSION_ERROR (RFC 9113, section 7).
        assert_eq!(goaway, Some((0x7, 0, [0, 0, 0, 0, 0, 0, 0, 9].to_vec())));
        let report = within(server.close(Clock.deadline(PATIENCE))).await;
        assert_eq!((report.accepted, report.failed), (1, 1));
    });
}

#[test]
fn a_ping_and_settings_flood_from_a_peer_that_reads_late_gets_each_answer_in_its_order() {
    on_each_runtime(|| async {
        const PINGS: u64 = 30_000;
        let (listener, address) = support::listener().await;
        let server = serve(Transport::Plain, listener, |_exchange: Exchange| async { Ok(()) });
        // Each PING has its number, and an empty SETTINGS frame follows it.
        let pings: Vec<u8> = (0..PINGS)
            .flat_map(|index| [frame(0x6, 0, 0, &index.to_be_bytes()), frame(0x4, 0, 0, b"")].concat())
            .collect();
        let received = within(tokio::task::spawn_blocking(move || {
            let socket = TcpStream::connect(address).unwrap();
            let mut writer = socket.try_clone().unwrap();
            let writing = thread::spawn(move || {
                let preface = [&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], &frame(0x4, 0, 0, b"")].concat();
                writer.write_all(&[preface, pings].concat()).unwrap();
                writer.shutdown(Shutdown::Write).unwrap();
            });
            // The peer reads nothing for a while, so the output of the server fills.
            thread::sleep(Duration::from_millis(100));
            let mut socket = socket;
            socket.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut bytes = Vec::new();
            drop(socket.read_to_end(&mut bytes));
            writing.join().unwrap();
            bytes
        }))
        .await
        .unwrap();
        let received = frames(&received);
        let answers: Vec<u64> = received
            .iter()
            .filter(|&&(kind, flags, _)| kind == 0x6 && flags == 0x1)
            .map(|(.., payload)| u64::from_be_bytes(payload.as_slice().try_into().unwrap()))
            .collect();
        assert_eq!(answers, (0..PINGS).collect::<Vec<_>>());
        // One acknowledgement for each SETTINGS frame, also the one of the preface.
        let acknowledged = received
            .iter()
            .filter(|&&(kind, flags, _)| kind == 0x4 && flags == 0x1)
            .count();
        assert_eq!(acknowledged as u64, PINGS + 1);
        within(server.close(Clock.deadline(PATIENCE))).await;
    });
}
