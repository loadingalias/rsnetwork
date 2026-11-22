//! Blocking jobs, such as host lookups, admitted under a bound before the blocking pool of Tokio.

use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::io;
use std::net::ToSocketAddrs as _;
use std::panic;
use std::sync::Arc;

use rsnetwork::drive::{Error, Kind};

/// The refusal of a job when the bound is full.
const FULL: Error = Error::new(Kind::Overload, "each place for a blocking job is in use");

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
    running: Arc<AtomicUsize>,
    jobs_max: usize,
}

/// The place of one job, which it gives back when it returns.
struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Blocking {
    /// Places for at most `jobs_max` jobs at a time.
    pub fn new(jobs_max: NonZeroUsize) -> Self {
        Self {
            running: Arc::default(),
            jobs_max: jobs_max.get(),
        }
    }

    /// Runs `job` on the blocking pool of Tokio, and gives its result. Refuses with
    /// [`Kind::Overload`], and runs nothing, when `jobs_max` jobs run. Call it in a task of the
    /// runtime. A job that panics panics in the caller.
    pub async fn run<T: Send + 'static>(&self, job: impl FnOnce() -> T + Send + 'static) -> Result<T, Error> {
        let admitted = self.running.try_update(Ordering::AcqRel, Ordering::Acquire, |running| {
            (running < self.jobs_max).then_some(running + 1)
        });
        if admitted.is_err() {
            return Err(FULL);
        }
        let place = Place(Arc::clone(&self.running));
        let ran = tokio::task::spawn_blocking(move || {
            let _place = place;
            job()
        });
        match ran.await {
            Ok(result) => Ok(result),
            Err(error) if error.is_panic() => panic::resume_unwind(error.into_panic()),
            Err(_) => Err(DROPPED),
        }
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
        let host = host.to_owned();
        self.run(move || {
            let addresses = (host.as_str(), port).to_socket_addrs()?;
            Ok(addresses.take(addresses_max.get()).collect())
        })
        .await
    }
}
