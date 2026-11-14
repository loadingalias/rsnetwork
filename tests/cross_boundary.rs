//! The cross-boundary proof of Phase 0 (P0.4): the runtime family's buffer types carry the bytes of
//! a request and of its response between I/O and the protocol core with no copy and no conversion.
//!
//! Three servers serve the same clients with the same core code ([`respond`]): the io_uring driver
//! of rsasync on Linux, a plain `Vec<u8>` loop on std TCP, and Tokio. Each server answers a request
//! with its target as the body, so the response shows what the parser read. The clients are the
//! host's own `curl` and fixed requests. Each server gives the expected bytes to each client.
//!
//! [`respond`] parses the received bytes and writes the response head with no allocation, and it
//! checks that the target is a view of the received bytes. The io_uring server also checks the
//! other boundary: the region that the serializer wrote is the region that the driver sends, and
//! the body that it sends is a view of the received region.

use core::net::SocketAddr;
use core::ops::Range;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;

use rsnetwork::buffer::{BufferMut, WriteLoan};
use rsnetwork::h1::{Framing, Limits, ParseError, RequestParser, write_head};
use rsnetwork::value::{Field, Status};

mod counting;

use counting::allocations;

/// The limits of each request head. A slot of the io_uring buffer pools holds one head.
const LIMITS: Limits = Limits {
    head_bytes: 4096,
    fields: 32,
    name_bytes: 4096,
    value_bytes: 4096,
};

/// The target that `curl` requests, and the response that it must print with `--include`.
const CURL_TARGET: &str = "/n002";
const CURL_RESPONSE: &[u8] = b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 5\r\n\r\n/n002";

/// The fixed requests, each on its own connection, and the response that each server must give.
const EXCHANGES: [(&[u8], &[u8]); 3] = [
    (
        b"GET /n002 HTTP/1.1\r\nHost: proof\r\n\r\n",
        b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 5\r\n\r\n/n002",
    ),
    (
        b"PURGE /cache?key=7 HTTP/1.1\r\nHost: proof\r\nX-Tag: a\r\nx-tag: b\r\n\r\n",
        b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 12\r\n\r\n/cache?key=7",
    ),
    (
        b"GET /n002 HTTP/1.0\r\n\r\n",
        b"HTTP/1.1 200 \r\nconnection: close\r\ncontent-length: 5\r\n\r\n/n002",
    ),
];

/// The number of connections that each client run makes: `curl`, then each fixed request.
const CONNECTIONS: usize = 1 + EXCHANGES.len();

/// Runs each client against the server at `address`, and gives each response.
fn clients(address: SocketAddr) -> Vec<Vec<u8>> {
    let curl = Command::new("curl")
        .args(["--silent", "--show-error", "--include", "--http1.1", "--max-time", "10"])
        .arg(format!("http://{address}{CURL_TARGET}"))
        .output()
        .expect("the host has `curl`");
    assert!(curl.status.success(), "curl: {}", String::from_utf8_lossy(&curl.stderr));
    let mut responses = vec![curl.stdout];
    for (request, _) in EXCHANGES {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        responses.push(response);
    }
    responses
}

/// The responses that [`clients`] must get.
fn expected() -> Vec<Vec<u8>> {
    let fixed = EXCHANGES.iter().map(|(_, response)| response.to_vec());
    [CURL_RESPONSE.to_vec()].into_iter().chain(fixed).collect()
}

/// The core code of each server. It parses the received bytes of one request and, for a complete
/// head or a refusal, writes the response head into `out`. It gives the range of `received` that is
/// the body of the response: the target of the request, or nothing after a refusal. It gives `None`
/// while the head is not complete.
///
/// It allocates nothing, and it checks that the parser read the target in place.
fn respond<B: BufferMut>(parser: &mut RequestParser, received: &[u8], out: &mut WriteLoan<B>) -> Option<Range<usize>> {
    let (body, count) = allocations(|| {
        let (status, body) = match parser.parse(received) {
            Ok(None) => return None,
            Ok(Some(head)) => {
                let target = head.target().as_bytes();
                let start = target
                    .as_ptr()
                    .addr()
                    .checked_sub(received.as_ptr().addr())
                    .expect("the target is in the received bytes");
                let body = start..start + target.len();
                assert!(
                    core::ptr::eq(&raw const received[body.clone()], target),
                    "the parser read in place"
                );
                (200, body)
            }
            Err(error) => (status(error), 0..0),
        };
        let fields = [Field::new(b"connection", b"close").unwrap()];
        write_head(
            out,
            Status::new(status).unwrap(),
            &fields,
            Framing::Length(body.len() as u64),
        )
        .unwrap();
        Some(body)
    });
    assert_eq!(count, 0, "the parser and the serializer allocated");
    body
}

/// The response status for a refused head, as the documentation of `ParseError` names it.
fn status(error: ParseError) -> u16 {
    match error {
        ParseError::HeadTooLarge | ParseError::TooManyFields | ParseError::FieldTooLarge => 431,
        ParseError::Malformed | ParseError::Framing => 400,
        ParseError::Version => 505,
        ParseError::TransferCoding => 501,
    }
}

/// A server on a plain `Vec<u8>` loop over std TCP, for `connections` connections.
fn serve_vec(listener: TcpListener, connections: usize) {
    for _ in 0..connections {
        let (mut stream, _) = listener.accept().unwrap();
        let mut parser = RequestParser::new(LIMITS);
        let mut received = vec![0; LIMITS.head_bytes];
        let mut len = 0;
        let mut out = WriteLoan::new(Vec::with_capacity(256));
        let body = loop {
            let count = stream.read(&mut received[len..]).unwrap();
            assert_ne!(count, 0, "the client closed before the end of the head");
            len += count;
            if let Some(body) = respond(&mut parser, &received[..len], &mut out) {
                break body;
            }
        };
        stream.write_all(out.filled()).unwrap();
        stream.write_all(&received[body]).unwrap();
    }
}

/// A server on a Tokio current-thread runtime, for `connections` connections.
fn serve_tokio(listener: TcpListener, connections: usize) {
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        for _ in 0..connections {
            let (stream, _) = listener.accept().await.unwrap();
            let mut parser = RequestParser::new(LIMITS);
            let mut received = vec![0; LIMITS.head_bytes];
            let mut len = 0;
            let mut out = WriteLoan::new(Vec::with_capacity(256));
            let body = loop {
                stream.readable().await.unwrap();
                let count = match stream.try_read(&mut received[len..]) {
                    Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                    count => count.unwrap(),
                };
                assert_ne!(count, 0, "the client closed before the end of the head");
                len += count;
                if let Some(body) = respond(&mut parser, &received[..len], &mut out) {
                    break body;
                }
            };
            for mut bytes in [out.filled(), &received[body]] {
                while !bytes.is_empty() {
                    stream.writable().await.unwrap();
                    match stream.try_write(bytes) {
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                        sent => bytes = &bytes[sent.unwrap()..],
                    }
                }
            }
        }
    });
}

/// The `Vec<u8>` loop and the Tokio server give the expected bytes to `curl` and to each fixed
/// request: the same parser and serializer, with no runtime type in them.
#[test]
fn the_vec_loop_and_tokio_serve_curl_and_each_request_with_the_expected_bytes() {
    for serve in [serve_vec, serve_tokio] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || serve(listener, CONNECTIONS));
        assert_eq!(clients(address), expected());
        server.join().unwrap();
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod uring {
    //! The io_uring server. The driver side names the buffer types through `rsasync` and the core
    //! side through `rsnetwork`. Both paths are the rstypes types, so the values pass between them
    //! with no conversion: this code does not compile otherwise.

    use core::alloc::Layout;
    use core::future::Future;
    use core::num::{NonZeroU32, NonZeroU64};
    use core::ops::Range;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream as StdStream;
    use std::sync::mpsc;
    use std::thread;

    use rsasync::buffer::{Backing, Buffer as _, Lease, Pool, WriteLoan};
    use rsasync::capacity::Budget;
    use rsasync::driver::{Config, Driver, TcpListener, TcpStream};

    use super::{CONNECTIONS, EXCHANGES, LIMITS, RequestParser, allocations, clients, expected, respond};

    /// Turns the driver and polls `future` on this thread until it gives its output, as the
    /// driver-only guide of rsasync shows.
    fn drive<F: Future + Unpin>(driver: &mut Driver, mut future: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            let more = driver.turn().unwrap().more();
            if let Poll::Ready(output) = Pin::new(&mut future).poll(&mut cx) {
                return output;
            }
            if !more {
                driver.wait().unwrap();
            }
        }
    }

    /// A pool of `slots` buffers of one head each, charged to a budget of its own.
    fn pool(slots: u32) -> Pool {
        let budget = Budget::new(NonZeroU64::new(1 << 20).unwrap());
        let slot = Layout::from_size_align(LIMITS.head_bytes, 4096).unwrap();
        Pool::new(&budget, NonZeroU32::new(slots).unwrap(), slot).unwrap()
    }

    /// Sends all of `lease`. After a partial send, it sends a view of the rest, with no copy.
    fn send_all(driver: &mut Driver, stream: &TcpStream, mut lease: Lease) {
        while lease.initialized() > 0 {
            let send = driver.send(stream, lease).unwrap();
            let (sent, back) = drive(driver, send).unwrap();
            lease = back.view(sent.unwrap()..).unwrap();
        }
    }

    /// Sends the response head that the serializer wrote into `out`, then the body: the `body`
    /// range of `received`. The head goes out from the region that the serializer wrote, and the
    /// body is a view of the received region.
    fn reply(driver: &mut Driver, stream: &TcpStream, out: WriteLoan<Backing>, received: Lease, body: Range<usize>) {
        let written = out.filled().as_ptr();
        let (head, count) = allocations(|| Lease::from(out.into_inner()));
        assert_eq!(
            (head.as_ptr(), count),
            (written, 0),
            "the send buffer is the serializer's region"
        );
        send_all(driver, stream, head);
        send_all(driver, stream, received.view(body).unwrap());
    }

    /// Accepts one connection, receives its request into an owned buffer until the head is
    /// complete, and replies.
    fn serve_owned(driver: &mut Driver, listener: &TcpListener, buffers: &mut Pool) {
        let accept = driver.accept(listener).unwrap();
        let (stream, _) = drive(driver, accept).unwrap().unwrap();
        let mut parser = RequestParser::new(LIMITS);
        let mut received = buffers.acquire().unwrap();
        let mut out = WriteLoan::new(buffers.acquire().unwrap());
        let body = loop {
            let receive = driver.recv(&stream, received).unwrap();
            let (count, back) = drive(driver, receive).unwrap();
            received = back;
            assert_ne!(count.unwrap(), 0, "the client closed before the end of the head");
            if let Some(body) = respond(&mut parser, received.bytes(), &mut out) {
                break body;
            }
        };
        let (received, count) = allocations(|| Lease::from(received));
        assert_eq!(count, 0);
        reply(driver, &stream, out, received, body);
        driver.close(stream).unwrap();
    }

    /// The driver serves `curl` and each fixed request with the expected bytes. Each request
    /// arrives in an owned buffer, the parser reads it there, and the response leaves from the
    /// buffer that the serializer wrote, with no allocation, copy, or conversion between them.
    #[test]
    fn the_io_uring_driver_serves_curl_and_each_request_with_no_copy_at_either_boundary() {
        let mut driver = Driver::new(Config::new()).unwrap();
        let listener = driver.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr();
        let client = thread::spawn(move || clients(address));
        let mut buffers = pool(2);
        for _ in 0..CONNECTIONS {
            serve_owned(&mut driver, &listener, &mut buffers);
        }
        assert_eq!(client.join().unwrap(), expected());
        driver.teardown().unwrap();
    }

    /// A request in a buffer that the kernel selected is parsed in place. The last view of that
    /// buffer drops on another thread, and the buffer then returns to the kernel ring: the pool has
    /// one slot, and the next request arrives in the same slot.
    #[test]
    fn a_kernel_selected_buffer_is_parsed_in_place_and_returns_to_its_ring_after_its_last_view_drops_elsewhere() {
        let mut driver = Driver::new(Config::new()).unwrap();
        driver.provide(pool(1)).unwrap();
        let listener = driver.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr();
        let (next, wait) = mpsc::channel::<()>();
        let client = thread::spawn(move || {
            let mut responses = Vec::new();
            for (request, _) in &EXCHANGES[..2] {
                wait.recv().unwrap();
                let mut stream = StdStream::connect(address).unwrap();
                stream.write_all(request).unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                responses.push(response);
            }
            responses
        });
        let mut buffers = pool(1);
        let mut slot = None;
        for _ in 0..2 {
            // The slot is in the ring before the request comes.
            driver.turn().unwrap();
            next.send(()).unwrap();
            let accept = driver.accept(&listener).unwrap();
            let (stream, _) = drive(&mut driver, accept).unwrap().unwrap();
            let receive = driver.recv_selected(&stream).unwrap();
            let received = drive(&mut driver, receive).unwrap().unwrap();
            assert_eq!(
                *slot.get_or_insert_with(|| received.as_ptr()),
                received.as_ptr(),
                "the same slot"
            );
            let mut out = WriteLoan::new(buffers.acquire().unwrap());
            let body = respond(&mut RequestParser::new(LIMITS), received.bytes(), &mut out).expect("a whole head");
            let last = received.view(..).unwrap();
            reply(&mut driver, &stream, out, received, body);
            driver.close(stream).unwrap();
            thread::spawn(move || drop(last)).join().unwrap();
        }
        let fixed: Vec<Vec<u8>> = EXCHANGES[..2].iter().map(|(_, response)| response.to_vec()).collect();
        assert_eq!(client.join().unwrap(), fixed);
        driver.teardown().unwrap();
    }
}
