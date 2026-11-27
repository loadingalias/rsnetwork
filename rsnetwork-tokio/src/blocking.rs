//! Blocking jobs, such as host lookups, admitted under a bound before the blocking pool of Tokio.

use core::net::SocketAddr;
use core::num::NonZeroUsize;
use std::io;
use std::panic;

use rsnetwork::drive::{Error, Kind};
use rsnetwork::host;
use tokio::runtime::Handle;

/// The refusal of a job that the runtime dropped before it ran, at its shutdown.
const DROPPED: Error = Error::new(Kind::Cancelled, "the runtime shut down before the blocking job ended");

/// Blocking jobs, for example host lookups, under a bound of `jobs_max` at a time. A job runs on
/// the blocking pool of Tokio, whose queue has no bound of its own.
///
/// A job keeps its place until it returns, also when its caller drops the future: the blocking
/// pool cannot stop a job that runs, so a lookup that its caller abandoned stays occupied until
/// the resolver of the system answers. Clones share the places.
#[derive(Clone, Debug)]
pub struct Blocking {
    service: host::Blocking,
}

impl Blocking {
    /// Places for at most `jobs_max` jobs at a time.
    pub fn new(jobs_max: NonZeroUsize) -> Self {
        Self {
            service: host::Blocking::new(jobs_max),
        }
    }

    /// Runs `job` on the blocking pool of Tokio, and gives its result. Refuses with
    /// [`Kind::Overload`] when each place is in use. Outside a Tokio runtime it gives
    /// [`Kind::Unsupported`]. A job that panics panics in the caller.
    pub async fn run<T: Send + 'static>(&self, job: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
        let place = self.service.reserve()?;
        run(move || {
            let _place = place;
            job()
        })
        .await
    }

    /// Looks up the addresses of `host` with the resolver of the system, as one blocking job.
    /// Gives at most `addresses_max` addresses, in the order of the resolver, with `port`. The
    /// outer result is the admission of the job, as [`run`](Self::run) says. The inner result is
    /// the answer of the resolver.
    pub async fn lookup(
        &self,
        host: &str,
        port: u16,
        addresses_max: NonZeroUsize,
    ) -> Result<io::Result<Vec<SocketAddr>>, Error> {
        Ok(self
            .lookup_with(host, port, addresses_max, || Ok(()))
            .await?
            .map(|(addresses, ())| addresses))
    }

    /// Keeps the caller's admission with the worker and then its result, also after cancellation.
    pub(crate) async fn lookup_with<T: Send + 'static>(
        &self,
        host: &str,
        port: u16,
        addresses_max: NonZeroUsize,
        admit: impl FnOnce() -> Result<T, Error>,
    ) -> Result<io::Result<(Vec<SocketAddr>, T)>, Error> {
        let lookup = self.service.reserve_lookup(addresses_max)?;
        let held = admit()?;
        let mut name = String::new();
        if name.try_reserve_exact(host.len()).is_err() {
            return Ok(Err(io::ErrorKind::OutOfMemory.into()));
        }
        name.push_str(host);
        run(move || lookup.run((name.as_str(), port)).map(|addresses| (addresses, held))).await
    }
}

async fn run<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
    let runtime = Handle::try_current().map_err(|_| Error::new(Kind::Unsupported, "no Tokio runtime is active"))?;
    match runtime.spawn_blocking(job).await {
        Ok(result) => Ok(result),
        Err(error) if error.is_panic() => panic::resume_unwind(error.into_panic()),
        Err(_) => Err(DROPPED),
    }
}
