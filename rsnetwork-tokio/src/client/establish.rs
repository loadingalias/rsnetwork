//! TCP address races on the caller's Tokio runtime.

use core::future::poll_fn;
use core::net::SocketAddr;
use core::pin::pin;
use core::task::{Poll, ready};
use std::io;

use rsnetwork::capacity::Budget;
use rsnetwork::client::Operation;
use rsnetwork::client::establish::{ConnectError, Dial, Step};
use rsnetwork::drive::{Error, Kind};
use tokio::net::TcpStream;

use crate::{Blocking, Clock};

/// Resolves a host on the admitted blocking service and races its TCP addresses.
/// The operation's lifetime includes the lookup. An unfinished lookup retains its worker place.
pub async fn connect(
    host: &str,
    port: u16,
    resolver: &Blocking,
    dial: Dial,
    operation: &mut Operation,
    memory: &Budget,
) -> Result<TcpStream, ConnectError> {
    dial.check(operation, Clock.now())?;
    if operation.remaining() < 2 {
        return Err(Error::new(Kind::Overload, "lookup and connection each need a work unit").into());
    }
    let deadline = operation.deadline();
    runtime()?;
    let size = core::alloc::Layout::array::<SocketAddr>(dial.addresses_max.get())
        .map_err(|_| NO_ROOM)?
        .size()
        .checked_add(host.len())
        .ok_or(NO_ROOM)?;
    let lookup = resolver.lookup_with(host, port, dial.addresses_max, || {
        let bytes = memory.reserve(size as u64).map_err(|_| NO_ROOM)?;
        Ok((operation.attempt(Clock.now())?, bytes))
    });
    let result = tokio::time::timeout_at(Clock.tokio(deadline), lookup)
        .await
        .map_err(|_| Error::new(Kind::Deadline, "the deadline came during address lookup"))?;
    operation.check(Clock.now())?;
    let (addresses, (lookup, mut bytes)) = result?.map_err(|e| ConnectError::Io(e.kind()))?;
    drop(lookup);
    let retained = core::alloc::Layout::array::<SocketAddr>(addresses.capacity())
        .map_err(|_| NO_ROOM)?
        .size();
    let _addresses = bytes.split(retained as u64).map_err(|_| NO_ROOM)?;
    drop(bytes);
    connect_addresses(&addresses, dial, operation, memory).await
}

/// Races an already resolved list in its resolver order. Each pending connect owns its socket.
/// Selecting a winner, reaching the deadline, or dropping this future closes each losing socket.
pub async fn connect_addresses(
    addresses: &[SocketAddr],
    dial: Dial,
    operation: &mut Operation,
    memory: &Budget,
) -> Result<TcpStream, ConnectError> {
    connect_with(addresses, dial, operation, memory, TcpStream::connect).await
}

fn runtime() -> Result<(), Error> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| Error::new(Kind::Unsupported, "no Tokio runtime is active"))
}

const NO_ROOM: Error = Error::new(Kind::Overload, "the budget refused the TCP address race");

/// Races TCP connects from a supplied socket factory, for example one that binds a source address.
/// Each future must own its socket and cancel its connect on drop.
pub async fn connect_with<F: Future<Output = io::Result<TcpStream>>>(
    addresses: &[SocketAddr],
    dial: Dial,
    operation: &mut Operation,
    memory: &Budget,
    mut connect: impl FnMut(SocketAddr) -> F,
) -> Result<TcpStream, ConnectError> {
    let mut armed = operation.deadline();
    let mut race = dial.race(addresses, operation, Clock.now(), memory)?;
    runtime()?;
    let mut timer = pin!(tokio::time::sleep_until(Clock.tokio(armed)));
    poll_fn(|cx| {
        let start = |address, place| {
            let charge = memory.reserve(size_of::<F>() as u64).map_err(|_| NO_ROOM)?;
            let future = Box::try_new(connect(address)).map_err(|_| NO_ROOM)?;
            Ok((Box::into_pin(future), place, charge))
        };
        match race.advance(Clock.now(), start, |(future, _, _)| {
            Poll::Ready(ready!(future.as_mut().poll(cx)).map_err(|error| error.kind()))
        }) {
            Ok(Step::Wait(deadline)) => {
                if deadline != armed {
                    timer.as_mut().reset(Clock.tokio(deadline));
                    armed = deadline;
                }
                if timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Ok(Step::Connected(socket)) => Poll::Ready(Ok(socket)),
            Err(error) => Poll::Ready(Err(error)),
        }
    })
    .await
}
