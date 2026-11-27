//! Mounts an HTTP-typed handler on the existing Tokio server.

use core::num::NonZeroUsize;
use core::ops::ControlFlow::{self, Break, Continue};
use std::sync::{Arc, Weak};

use rsnetwork::body::{Outcome, Part, Trailers};
use rsnetwork::buffer::{Lease, Pool};
use rsnetwork::drive::{Error, Kind};
use rsnetwork::http::{Adapter, Body, Request, Response, header};
use rsnetwork::message::{Stream, Version};
use rsnetwork::server::Http as Core;
use rsnetwork::value::Method;
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
        let (mut parts, mut body) = response.into_parts();
        let version = self.head().version();
        let http1 = matches!(version, Version::Http10 | Version::Http11);
        let bodiless = self.head().method() == Method::HEAD || matches!(parts.status.as_u16(), 204 | 304);
        parts.version = version.into();
        let mut remaining;
        {
            let response = Response::from_parts(parts, ());
            let view = adapter.native_response(&response, body.length())?;
            let mut head = view.head();
            if bodiless || head.length == Some(0) {
                // The peer can see completion as soon as it receives these headers.
                if let Some(trailers) = end(&mut body).await? {
                    if bodiless
                        || (http1
                            && (version != Version::Http11 || response.headers().contains_key(header::CONTENT_LENGTH)))
                    {
                        return Err(FRAMING);
                    }
                    if http1 {
                        // Only the size hint selected a length. Use chunks to carry the trailers.
                        head.length = None;
                    }
                    let fields = adapter.trailers(&trailers)?;
                    self.respond_streaming(&head).await?;
                    return self.finish_with_trailers(fields.as_slice()).await;
                }
                self.respond(&head).await?;
                if http1 && head.length != Some(0) {
                    self.finish().await?;
                }
                return Ok(());
            }
            remaining = if http1 { head.length } else { None };
            self.respond(&head).await?;
        }
        loop {
            match next_frame(&mut body).await? {
                Continue(bytes) => {
                    if let Some(left) = &mut remaining {
                        *left = left.checked_sub(bytes.as_ref().len() as u64).ok_or(FRAMING)?;
                        if *left == 0 {
                            // HTTP/1 completes a fixed-length response at its last byte.
                            if end(&mut body).await?.is_some() {
                                return Err(FRAMING);
                            }
                            self.write(&bytes).await?;
                            return self.finish().await;
                        }
                    }
                    self.write(&bytes).await?;
                }
                Break(None) => return self.finish().await,
                Break(Some(trailers)) => {
                    let fields = adapter.trailers(&trailers)?;
                    return self.finish_with_trailers(fields.as_slice()).await;
                }
            }
        }
    }
}

const FRAMING: Error = Error::new(Kind::Misuse, "the response framing forbids more data or trailers");

async fn end(body: &mut impl Body) -> Result<Option<Trailers>, Error> {
    match next_frame(body).await? {
        Break(trailers) => Ok(trailers),
        Continue(_) => Err(FRAMING),
    }
}

async fn next_frame(body: &mut impl Body) -> Result<ControlFlow<Option<Trailers>, Lease>, Error> {
    loop {
        tokio::task::consume_budget().await;
        let kind = match body.next().await? {
            Part::Data(bytes) if bytes.as_ref().is_empty() => continue,
            Part::Data(bytes) => return Ok(Continue(bytes)),
            Part::End(Outcome::Complete(trailers)) => return Ok(Break(trailers)),
            Part::End(Outcome::Cancelled) => Kind::Cancelled,
            Part::End(Outcome::Malformed) => Kind::Malformed,
            Part::End(Outcome::Reset(_) | Outcome::Truncated) => Kind::Partial,
        };
        return Err(Error::new(kind, "the response body ended before completion"));
    }
}
