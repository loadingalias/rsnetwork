//! Admission for a host's blocking service and its operating system resolver.

use core::net::SocketAddr;
use core::num::{NonZeroU64, NonZeroUsize};
use std::io;
use std::net::ToSocketAddrs;

use crate::capacity::{Budget, Permit};
use crate::drive::{Error, Kind};

/// The places on a host's blocking service. Clones share the bound. The host runs the work.
/// Use `Blocking::default()` when the host has no blocking service.
#[derive(Clone, Debug, Default)]
pub struct Blocking {
    places: Option<Budget>,
}

impl Blocking {
    /// Admits at most `jobs_max` queued and running jobs together.
    pub fn new(jobs_max: NonZeroUsize) -> Self {
        let bound = NonZeroU64::try_from(jobs_max).expect("a job count fits in 64 bits");
        Self {
            places: Some(Budget::new(bound)),
        }
    }

    /// Reserves one place. Move the permit into the job and keep it until the job returns.
    /// A full service gives [`Kind::Overload`]. An absent service gives [`Kind::Unsupported`].
    pub fn reserve(&self) -> Result<Permit, Error> {
        self.places
            .as_ref()
            .ok_or(Error::new(Kind::Unsupported, "the host has no blocking service"))?
            .reserve(1)
            .map_err(|_| Error::new(Kind::Overload, "each place for a blocking job is in use"))
    }

    /// Reserves a lookup before submission. Move it and the name to the host's blocking worker.
    ///
    /// ```
    /// use core::net::SocketAddr;
    /// use core::num::NonZeroUsize;
    /// use rsnetwork::host::Blocking;
    ///
    /// let service = Blocking::new(NonZeroUsize::MIN);
    /// let lookup = service.reserve_lookup(NonZeroUsize::MIN)?;
    /// let job = move || lookup.run(("127.0.0.1", 443));
    /// let addresses = std::thread::scope(|scope| scope.spawn(job).join().expect("the worker returned"))?;
    /// assert_eq!(addresses, [SocketAddr::from(([127, 0, 0, 1], 443))]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn reserve_lookup(&self, addresses_max: NonZeroUsize) -> Result<Lookup, Error> {
        Ok(Lookup {
            _place: self.reserve()?,
            addresses_max,
        })
    }
}

/// One admitted lookup. The worker owns its place until the resolver returns.
#[derive(Debug)]
pub struct Lookup {
    _place: Permit,
    addresses_max: NonZeroUsize,
}

impl Lookup {
    /// Resolves on this thread. Pass `(host, port)` to use the operating system resolver.
    /// The result preserves resolver order and contains at most the admitted number of addresses.
    pub fn run(self, source: impl ToSocketAddrs) -> io::Result<Vec<SocketAddr>> {
        let limit = self.addresses_max.get();
        let addresses = source.to_socket_addrs()?.take(limit);
        // The system can return more addresses than the caller wants. Retain only the admitted result.
        let mut result = Vec::new();
        result
            .try_reserve_exact(addresses.size_hint().0)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for address in addresses {
            if result.len() == result.capacity() {
                let grow = result.len().max(1).min(limit - result.len());
                result.try_reserve_exact(grow).map_err(|_| io::ErrorKind::OutOfMemory)?;
            }
            result.push(address);
        }
        Ok(result)
    }
}
