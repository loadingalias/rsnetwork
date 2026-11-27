//! Runs Tower and axum on an application-owned Tokio runtime and real TCP connections.
#![cfg(test)]
#![cfg(feature = "tower")]

#[expect(dead_code, reason = "the Tower cases use the cleartext server and client fixtures")]
mod support;

use core::future::{pending, poll_fn};
use core::num::NonZeroUsize;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use core::time::Duration;
use std::assert_matches;
use std::sync::Arc;

use axum::Router;
use axum::body::Body as AxumBody;
use axum::extract::Request;
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::{Lease, Pool};
use rsnetwork::drive::Kind;
use rsnetwork::http::{Adapter, HeaderMap, StatusCode};
use rsnetwork::server::Http;
use rsnetwork::tower::{Body, Bytes, Frame};
use rsnetwork::value::{Field, Method, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::Server;
use support::{HEAD, PATIENCE, Transport, on_each_runtime};
use tokio::sync::Notify;
use tokio::sync::futures::OwnedNotified;

fn connection(make: fn(Transport) -> Http) -> (Http, Pool) {
    (make(Transport::Plain), support::pool(&support::budget()))
}

async fn deadline(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_millis(60), next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

struct AfterReturn {
    release: Option<Pin<Box<OwnedNotified>>>,
    frames: core::array::IntoIter<Frame<Bytes>, 2>,
}

impl Body for AfterReturn {
    type Data = Bytes;
    type Error = !;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, !>>> {
        if let Some(release) = &mut self.release {
            ready!(release.as_mut().poll(cx));
            self.release = None;
        }
        Poll::Ready(self.frames.next().map(Ok))
    }
}

#[test]
fn tower_serves_response_bytes_and_trailers_after_the_router_returns() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let release = Arc::new(Notify::new());
        let producer = Arc::clone(&release);
        let app = Router::new()
            .route(
                "/stream",
                get(move || async move {
                    let mut trailers = HeaderMap::new();
                    trailers.append("x-finish", "first".parse().unwrap());
                    trailers.append("x-finish", "second".parse().unwrap());
                    let stream = AfterReturn {
                        release: Some(Box::pin(producer.notified_owned())),
                        frames: [
                            Frame::data(Bytes::from_static(b"after return")),
                            Frame::trailers(trailers),
                        ]
                        .into_iter(),
                    };
                    (StatusCode::ACCEPTED, AxumBody::new(stream))
                }),
            )
            .route("/wait", get(pending::<StatusCode>))
            .layer(from_fn(deadline));
        let server = Server::serve_tower(
            listener,
            NonZeroUsize::MIN,
            || Ok(connection(support::core_server)),
            Adapter::new(HEAD, &support::budget()),
            app,
        );
        let mut client = support::client(Transport::Plain, address).await;
        let head = rsnetwork::client::Request {
            target: Target::new(b"/stream").unwrap(),
            ..support::get()
        };
        client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        assert_eq!(client.response().await.unwrap().status().code(), 202);
        release.notify_one();
        let mut received = Vec::new();
        loop {
            match client.next().await.unwrap() {
                Part::Data(data) => received.extend_from_slice(data.as_ref()),
                Part::End(Outcome::Complete(Some(trailers))) => {
                    assert!(trailers.fields().eq([
                        Field::new(b"x-finish", b"first").unwrap(),
                        Field::new(b"x-finish", b"second").unwrap()
                    ]));
                    break;
                }
                end => panic!("expected the streamed body and its trailers, got {end:?}"),
            }
        }
        assert_eq!(received, b"after return");
        let head = rsnetwork::client::Request {
            target: Target::new(b"/wait").unwrap(),
            ..support::get()
        };
        client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        assert_eq!(client.response().await.unwrap().status().code(), 504);
        assert_matches!(client.next().await.unwrap(), Part::End(Outcome::Complete(None)));
        client.close().await.unwrap();
        assert_eq!(server.close(Clock.deadline(PATIENCE)).await.failed, 0);
    });
}

#[test]
fn tower_echoes_http2_request_data_and_trailers_and_contains_a_handler_panic() {
    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        async fn broken() -> StatusCode {
            panic!("application panic");
        }
        let app = Router::new()
            .route("/echo", post(|request: Request| async move { request.into_body() }))
            .route("/panic", get(broken));
        let server = Server::serve_tower(
            listener,
            NonZeroUsize::MIN,
            || Ok(connection(support::core_h2_server)),
            Adapter::new(HEAD, &support::budget()),
            app,
        );
        let client = support::h2_client(Transport::Plain, address).await;
        let head = rsnetwork::client::Request {
            target: Target::new(b"/panic").unwrap(),
            ..support::get()
        };
        let mut broken = client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        assert_eq!(broken.response().await.unwrap_err().kind(), Kind::Uncertain);
        drop(broken);
        let head = rsnetwork::client::Request {
            method: Method::POST,
            target: Target::new(b"/echo").unwrap(),
            length: None,
            ..support::get()
        };
        let mut exchange = client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        exchange.write(&Lease::from(b"from peer".as_slice())).await.unwrap();
        exchange
            .finish_with_trailers(&[Field::new(b"x-final", b"yes").unwrap()])
            .await
            .unwrap();
        assert_eq!(exchange.response().await.unwrap().status().code(), 200);
        let mut seen = Vec::new();
        loop {
            match exchange.next().await.unwrap() {
                Part::Data(bytes) => seen.extend_from_slice(bytes.as_ref()),
                Part::End(Outcome::Complete(Some(trailers))) => {
                    assert!(trailers.fields().eq([Field::new(b"x-final", b"yes").unwrap()]));
                    break;
                }
                other => panic!("expected the echoed trailers, got {other:?}"),
            }
        }
        assert_eq!(seen, b"from peer");
        drop(exchange);
        client.close().await.unwrap();
        let report = server.close(Clock.deadline(PATIENCE)).await;
        assert_eq!(report.accepted, 1);
        assert_eq!(report.failed, 1);
    });
}

#[test]
fn tower_delivers_a_peer_reset_to_the_axum_handler_after_its_first_frame() {
    use core::pin::pin;
    use rsnetwork::tower::BodyError;

    on_each_runtime(|| async {
        let (listener, address) = support::listener().await;
        let prefix = Arc::new(Notify::new());
        let terminal = Arc::new(Notify::new());
        let (seen, ended) = (Arc::clone(&prefix), Arc::clone(&terminal));
        let app = Router::new()
            .route(
                "/upload",
                post(move |request: Request| async move {
                    let mut body = request.into_body();
                    let first = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await.unwrap().unwrap();
                    assert_eq!(first.into_data().unwrap(), b"prefix"[..]);
                    seen.notify_one();
                    let err = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                        .await
                        .unwrap()
                        .unwrap_err();
                    assert_matches!(
                        *err.into_inner().downcast::<BodyError>().unwrap(),
                        BodyError::Reset(Some(8))
                    );
                    assert!(poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await.is_none());
                    ended.notify_one();
                    StatusCode::NO_CONTENT
                }),
            )
            .route("/", get(|| async { StatusCode::NO_CONTENT }));
        let server = Server::serve_tower(
            listener,
            NonZeroUsize::MIN,
            || Ok(connection(support::core_h2_server)),
            Adapter::new(HEAD, &support::budget()),
            app,
        );
        let client = support::h2_client(Transport::Plain, address).await;
        let head = rsnetwork::client::Request {
            method: Method::POST,
            target: Target::new(b"/upload").unwrap(),
            length: None,
            ..support::get()
        };
        let mut upload = client.send(&head, Clock.deadline(PATIENCE)).await.unwrap();
        upload.write(&Lease::from(b"prefix".as_slice())).await.unwrap();
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
        assert_eq!(other.response().await.unwrap().status().code(), 204);
        assert_matches!(other.next().await.unwrap(), Part::End(Outcome::Complete(None)));
        tokio::time::timeout(PATIENCE, terminal.notified()).await.unwrap();
        drop(other);
        client.close().await.unwrap();
        server.close(Clock.deadline(PATIENCE)).await;
    });
}
