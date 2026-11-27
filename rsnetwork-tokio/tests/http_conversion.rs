//! Runs mounted HTTP-typed handlers through the production listener and streaming body paths.
#![cfg(test)]
#![cfg(feature = "http")]

#[expect(dead_code, reason = "these cases use the listener and the cleartext clients")]
mod support;

use core::num::NonZeroUsize;
use std::assert_matches;
use std::sync::Arc;

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::Lease;
use rsnetwork::drive::Error;
use rsnetwork::http::{Adapter, Body, Response};
use rsnetwork::value::{Field, Method, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::Server;
use support::{HEAD, PATIENCE, Transport, on_each_runtime};
use tokio::sync::Notify;

#[test]
fn http_conversion_streams_the_request_body_and_trailers_after_the_handler_returns() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let server = Server::serve_http(
            listener,
            NonZeroUsize::MIN,
            || {
                Ok((
                    support::core_server(Transport::Plain),
                    support::pool(&support::budget()),
                ))
            },
            Adapter::new(HEAD, &support::budget()),
            |request| async move {
                assert_eq!(request.method().as_str(), "Echo-Body");
                assert_eq!(request.uri().path_and_query().unwrap().as_str(), "/p%2f?");
                Ok(Response::builder()
                    .status(207)
                    .header("set-cookie", "a=1")
                    .header("set-cookie", "b=2")
                    .body(request.into_body())
                    .unwrap())
            },
        );
        let mut client = support::client(Transport::Plain, address).await;
        let head = rsnetwork::client::Request {
            method: Method::new(b"Echo-Body").unwrap(),
            target: Target::new(b"/p%2f?").unwrap(),
            length: None,
            ..support::get()
        };
        client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        client.write(&Lease::from(b"after handler".to_vec())).await.unwrap();
        client
            .finish_with_trailers(&[Field::new(b"x-final", b"yes").unwrap()])
            .await
            .unwrap();
        let head = client.response().await.unwrap();
        assert_eq!(head.status().code(), 207);
        assert_eq!(
            head.fields()
                .filter(|f| f.name() == b"set-cookie")
                .map(|f| f.value())
                .collect::<Vec<_>>(),
            [b"a=1", b"b=2"]
        );
        let mut data = Vec::new();
        loop {
            match client.next().await.unwrap() {
                Part::Data(bytes) => data.extend_from_slice(bytes.as_ref()),
                Part::End(Outcome::Complete(Some(trailers))) => {
                    assert_eq!(
                        trailers.fields().map(|f| (f.name(), f.value())).collect::<Vec<_>>(),
                        [(b"x-final".as_slice(), b"yes".as_slice())]
                    );
                    break;
                }
                end => panic!("expected complete trailers, got {end:?}"),
            }
        }
        assert_eq!(data, b"after handler");
        client.close().await.unwrap();
        assert_eq!(server.close(Clock.deadline(PATIENCE)).await.failed, 0);
    });
}

#[test]
fn http_conversion_delivers_the_peer_reset_code_to_the_request_handler() {
    use core::future::poll_fn;
    use core::pin::pin;
    use core::task::Poll;
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let prefix = Arc::new(Notify::new());
        let observed = Arc::new(Notify::new());
        let (received, ended) = (Arc::clone(&prefix), Arc::clone(&observed));
        let server = Server::serve_http(
            listener,
            NonZeroUsize::MIN,
            || {
                Ok((
                    support::core_h2_server(Transport::Plain),
                    support::pool(&support::budget()),
                ))
            },
            Adapter::new(HEAD, &support::budget()),
            move |request| {
                let (received, ended) = (Arc::clone(&received), Arc::clone(&ended));
                async move {
                    if request.uri().path() == "/upload" {
                        let mut body = request.into_body();
                        assert_matches!(body.next().await?, Part::Data(bytes) if bytes.as_ref()==b"prefix");
                        received.notify_one();
                        assert_matches!(body.next().await?, Part::End(Outcome::Reset(Some(8))));
                        ended.notify_one();
                    }
                    Ok(Response::new(()))
                }
            },
        );
        let client = support::h2_client(Transport::Plain, address).await;
        let head = rsnetwork::client::Request {
            method: Method::POST,
            target: Target::new(b"/upload").unwrap(),
            length: None,
            ..support::get()
        };
        let mut upload = client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        upload.write(&Lease::from(b"prefix".to_vec())).await.unwrap();
        {
            let mut waiting = pin!(upload.response());
            let mut seen = pin!(prefix.notified());
            poll_fn(|cx| {
                if seen.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Pending
            })
            .await;
        }
        drop(upload);
        let mut other = client.send(&support::get(), Clock.deadline(PATIENCE)).await.unwrap();
        assert_eq!(other.response().await.unwrap().status().code(), 200);
        tokio::time::timeout(PATIENCE, observed.notified()).await.unwrap();
        assert_matches!(other.next().await.unwrap(), Part::End(Outcome::Complete(None)));
        drop(other);
        client.close().await.unwrap();
        server.close(Clock.deadline(PATIENCE)).await;
    });
}

struct Interrupted {
    prefix: Option<Lease>,
    read: Arc<Notify>,
}

impl Body for Interrupted {
    async fn next(&mut self) -> Result<Part, Error> {
        if let Some(bytes) = self.prefix.take() {
            return Ok(Part::Data(bytes));
        }
        self.read.notified().await;
        Ok(Part::End(Outcome::Reset(Some(0x17))))
    }
}

#[test]
fn http_conversion_exposes_a_reset_after_the_prefix_instead_of_clean_eof() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let read = Arc::new(Notify::new());
        let signal = Arc::clone(&read);
        let server = Server::serve_http(
            listener,
            NonZeroUsize::MIN,
            || {
                Ok((
                    support::core_h2_server(Transport::Plain),
                    support::pool(&support::budget()),
                ))
            },
            Adapter::new(HEAD, &support::budget()),
            move |request| {
                assert_eq!(request.version(), rsnetwork::http::Version::HTTP_2);
                let body = Interrupted {
                    prefix: Some(Lease::from(b"prefix".to_vec())),
                    read: Arc::clone(&signal),
                };
                async move { Ok(Response::new(body)) }
            },
        );
        let client = support::h2_client(Transport::Plain, address).await;
        let mut exchange = client.send(&support::get(), Clock.deadline(PATIENCE)).await.unwrap();
        assert_eq!(exchange.response().await.unwrap().status().code(), 200);
        assert_matches!(exchange.next().await.unwrap(), Part::Data(bytes) if bytes.as_ref()==b"prefix");
        read.notify_one();
        assert_matches!(exchange.next().await.unwrap(), Part::End(Outcome::Reset(_)));
        drop(exchange);
        client.close().await.unwrap();
        assert_eq!(server.close(Clock.deadline(PATIENCE)).await.failed, 1);
    });
}
