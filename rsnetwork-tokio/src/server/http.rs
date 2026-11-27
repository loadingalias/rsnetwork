//! Mounts an HTTP-typed handler on the existing Tokio server.

use core::num::NonZeroUsize;
use std::sync::{Arc, Weak};

use rsnetwork::body::{Outcome, Part};
use rsnetwork::buffer::Pool;
use rsnetwork::drive::{Error, Kind};
use rsnetwork::http::{Adapter, Body, Request, Response};
use rsnetwork::message::Stream;
use rsnetwork::server::Http as Core;
use tokio::net::TcpListener;

use super::{ENDED, Exchange, Server, next_part};
use crate::shared::Shared;

/// The streaming request body given to a mounted handler. Its exchange owns the connection.
#[derive(Debug)]
pub struct Incoming {
    shared: Weak<Shared<Core>>,
    stream: Stream,
}

impl Body for Incoming {
    async fn next(&mut self) -> Result<Part, Error> {
        let shared = self.shared.upgrade().ok_or(ENDED)?;
        next_part(&shared, self.stream).await
    }
}

impl Server {
    /// Serves an `http`-typed handler with the task ownership and shutdown rules of [`Self::serve`].
    /// A handler can return its request body, an empty body, a region, or its own streaming [`Body`].
    pub fn serve_http<M, H, F, B>(
        listener: TcpListener,
        connections_max: NonZeroUsize,
        make: M,
        adapter: Adapter,
        handler: H,
    ) -> Self
    where
        M: FnMut() -> Result<(Core, Pool), Error> + Send + 'static,
        H: Fn(Request<Incoming>) -> F + Send + Sync + 'static,
        F: Future<Output = Result<Response<B>, Error>> + Send + 'static,
        B: Body<next(..): Send> + Send + 'static,
    {
        Self::serve(listener, connections_max, make, move |exchange| {
            let body = Incoming {
                shared: Arc::downgrade(&exchange.shared),
                stream: exchange.stream,
            };
            let result = adapter.handle(exchange.head(), body, &handler);
            let adapter = adapter.clone();
            async move {
                let response = result?.await?;
                exchange.respond_http(&adapter, response).await
            }
        })
    }
}

impl Exchange {
    /// Sends the converted head and drives the response body until its terminal outcome.
    /// A failed body cancels the exchange. Only a complete body can send the end of the response.
    pub async fn respond_http<B: Body>(mut self, adapter: &Adapter, response: Response<B>) -> Result<(), Error> {
        let (parts, mut body) = response.into_parts();
        {
            let response = Response::from_parts(parts, ());
            let head = adapter.native_response(&response, body.length())?;
            self.respond(&head.head()).await?;
        }
        loop {
            match body.next().await {
                Ok(Part::Data(bytes)) => self.write(&bytes).await?,
                Ok(Part::End(Outcome::Complete(None))) => return self.finish().await,
                Ok(Part::End(Outcome::Complete(Some(trailers)))) => {
                    let fields = adapter.trailers(&trailers)?;
                    return self.finish_with_trailers(fields.as_slice()).await;
                }
                Ok(Part::End(outcome)) => {
                    self.cancel();
                    let kind = match outcome {
                        Outcome::Cancelled => Kind::Cancelled,
                        Outcome::Malformed => Kind::Malformed,
                        _ => Kind::Partial,
                    };
                    return Err(Error::new(kind, "the response body ended before completion"));
                }
                Err(error) => {
                    self.cancel();
                    return Err(error);
                }
            }
            tokio::task::consume_budget().await;
        }
    }
}
