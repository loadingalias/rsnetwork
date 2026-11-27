//! Mounts a Tower service on the existing server and its runtime.

use core::num::NonZeroUsize;
use core::pin::{Pin, pin};
use core::task::{Context, Poll};
use std::sync::{Arc, Weak};

use rsnetwork::body::Part;
use rsnetwork::buffer::Pool;
use rsnetwork::drive::Error;
use rsnetwork::http::{Adapter, Request, Response};
use rsnetwork::message::Stream;
use rsnetwork::server::Http as Core;
use rsnetwork::tower::{Body, ReadBody, RequestBody, Service, dispatch};
use tokio::net::TcpListener;
use tokio::time::Sleep;

use super::{ENDED, Server};
use crate::shared::{Registration, Shared, Waits};

/// The request reader used by [`Server::serve_tower`]. Its exchange owns the connection.
#[derive(Debug)]
pub struct TowerReader {
    shared: Weak<Shared<Core>>,
    stream: Stream,
    wait: Option<(Registration, Pin<Box<Option<Sleep>>>)>,
}

impl ReadBody for TowerReader {
    fn poll_part(&mut self, cx: &mut Context<'_>) -> Poll<Result<Part, Error>> {
        let shared = self.shared.upgrade().ok_or(ENDED)?;
        let stream = self.stream;
        let (wait, timer) = self
            .wait
            .get_or_insert_with(|| (shared.register(Waits::Stream(stream)), Box::pin(None)));
        let result = shared.poll_until(cx, wait, &mut |core, now| core.next(stream, now), timer.as_mut());
        if result.is_ready() {
            timer.as_mut().set(None);
        }
        result.map(|part| part?.ok_or(ENDED))
    }
}

impl Drop for TowerReader {
    fn drop(&mut self) {
        if let Some((wait, _)) = &self.wait
            && let Some(shared) = self.shared.upgrade()
        {
            shared.unregister(wait.key);
        }
    }
}

impl Server {
    /// Serves a Tower service on the caller's Tokio runtime.
    /// Each exchange polls readiness on its own service clone and owns the response through the last frame.
    pub fn serve_tower<M, S, B>(
        listener: TcpListener,
        connections_max: NonZeroUsize,
        make: M,
        adapter: Adapter,
        service: S,
    ) -> Self
    where
        M: FnMut() -> Result<(Core, Pool), Error> + Send + 'static,
        S: Service<Request<RequestBody<TowerReader>>, Response = Response<B>> + Clone + Send + Sync + 'static,
        S::Future: Send,
        B: Body + Send + 'static,
    {
        let mount = Arc::new((adapter, service));
        Self::serve(listener, connections_max, make, move |exchange| {
            let mount = Arc::clone(&mount);
            async move {
                let (adapter, service) = &*mount;
                let reader = TowerReader {
                    shared: Arc::downgrade(&exchange.shared),
                    stream: exchange.stream,
                    wait: None,
                };
                let request = adapter.tower_request(exchange.head(), reader)?;
                let (parts, body) = {
                    let mut service = service.clone();
                    dispatch(&mut service, request).await?.into_parts()
                };
                let body = pin!(body);
                exchange
                    .respond_http(adapter, Response::from_parts(parts, adapter.tower_body(body)))
                    .await
            }
        })
    }
}
