//! A Tokio TCP stream as the socket of [`host::Tcp`](rsnetwork::host::Tcp).
//!
//! Tokio keeps the readiness of each socket that it registered, and clears it only when a read or
//! a write through Tokio finds no byte. So each read and write goes through Tokio, and the next
//! wait sleeps until the socket is ready again.

use core::mem::MaybeUninit;
use core::net::SocketAddr;
use std::io;
use std::net::Shutdown;

use rsnetwork::host::Socket;
use socket2::SockRef;
use tokio::io::Interest;
use tokio::net::TcpStream;

/// A Tokio TCP stream, which [`host::Tcp`](rsnetwork::host::Tcp) reads and writes.
#[derive(Debug)]
pub(crate) struct Stream(pub(crate) TcpStream);

impl Socket for Stream {
    fn open(&mut self) -> io::Result<(SocketAddr, SocketAddr)> {
        // A Tokio stream is nonblocking already.
        self.0.set_nodelay(true)?;
        Ok((self.0.peer_addr()?, self.0.local_addr()?))
    }

    fn read<'a>(&mut self, spare: &'a mut [MaybeUninit<u8>]) -> io::Result<&'a mut [u8]> {
        self.0.try_io(Interest::READABLE, || receive(&self.0, spare))
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.try_write(bytes)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        SockRef::from(&self.0).shutdown(Shutdown::Write)
    }

    fn reset_at_close(&mut self) -> io::Result<()> {
        self.0.set_zero_linger()
    }
}

/// Receives from `stream` into `spare` with no zeroing, and gives the bytes that it received.
#[expect(
    unsafe_code,
    reason = "recv(2) initialized the first `count` bytes of `spare`, and `count` is at most its length"
)]
fn receive<'a>(stream: &TcpStream, spare: &'a mut [MaybeUninit<u8>]) -> io::Result<&'a mut [u8]> {
    let count = SockRef::from(stream).recv(spare)?;
    let received = &mut spare[..count];
    // SAFETY: the receive that gave `count` wrote each of the first `count` bytes of `spare`.
    Ok(unsafe { received.assume_init_mut() })
}
