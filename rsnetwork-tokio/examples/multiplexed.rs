//! The multiplexed connection: one HTTP/2 connection over TLS 1.3 on the Tokio binding. The body
//! of `/idle` waits, and meanwhile the other streams of the connection go on, also when one of
//! them is cancelled or meets its deadline. One thread runs the server, the client, each stream,
//! and each deadline.
//!
//! Run it with `cargo run -p rsnetwork-tokio --example multiplexed`. Each case checks its outcome
//! and prints one line. The page `docs/content/multiplexed-example.md` tells what each case shows.

use core::alloc::Layout;
use core::error::Error as StdError;
use core::future::poll_fn;
use core::net::SocketAddr;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::sync::Arc;

use rsnetwork::body::{Body, Collect, Outcome, Part, Read};
use rsnetwork::buffer::{Buffer as _, Lease, Pool, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::{Error, Kind, TurnLimits};
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2::{self, frame::ErrorCode};
use rsnetwork::server::{self, Cleartext, Linger, Response};
use rsnetwork::time::Deadline;
use rsnetwork::tls::{
    self, CertificateDer, ClientConfig, ClientOptions, DefaultTimeProvider, Entropy, Identity, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions,
};
use rsnetwork::value::{Authority, Method, Status, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::client::Http2;
use rsnetwork_tokio::server::{Exchange, Report, Server};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

type Result<T> = core::result::Result<T, Box<dyn StdError + Send + Sync>>;

/// The certificates of the tests of the repository: the root `ca`, the certificate of
/// `server.test` that `ca` signs, and its key. `other-ca` is a root that signs neither.
const CA: &[u8] = include_bytes!("../../tests/tls/ca.der");
const OTHER_CA: &[u8] = include_bytes!("../../tests/tls/other-ca.der");
const SERVER: (&[u8], &[u8]) = (
    include_bytes!("../../tests/tls/server.der"),
    include_bytes!("../../tests/tls/server.key.der"),
);
const NAME: &str = "server.test";

const HEAD: h1::Limits = h1::Limits {
    head_bytes: 8 * 1024,
    fields: 64,
    name_bytes: 64,
    value_bytes: 4 * 1024,
};

const BODY: BodyLimits = BodyLimits {
    body_bytes: 2 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};

/// At most 100 streams at a time. Each stream starts with the initial window of RFC 9113.
const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 100,
        max_header_list_size: 16 * 1024,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 1 << 20,
};

const TURN: TurnLimits = TurnLimits {
    bytes: 256 * 1024,
    frames: 1024,
    visits: 4096,
};

const QUEUE: NonZeroUsize = NonZeroUsize::new(16).expect("not zero");

/// The connections that the server serves at a time.
const CONNECTIONS: NonZeroUsize = NonZeroUsize::new(16).expect("not zero");

const TLS: tls::Limits = tls::Limits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};

/// A TLS connection lends its own input region, so one small receive region is enough.
const SLOT: Layout = Layout::new::<[u8; 1024]>();

/// The deadline of each exchange but `/late`, and of the close of the server.
const PATIENCE: Duration = Duration::from_secs(10);

/// The most time that the example runs before it fails.
const GUARD: Duration = Duration::from_secs(30);

/// The deadline of `/late`.
const LATE: Duration = Duration::from_millis(200);

/// The body of `/large` and `/cancel`: chunks that are each a view of one 16 KiB region.
const CHUNK: usize = 16 * 1024;
const CHUNKS: usize = 64;
const LARGE: usize = CHUNK * CHUNKS;

/// The chunks that the server can queue before the window of the stream stops it: the chunks
/// that the window holds, and the chunk that waits for the rest of the window.
const WINDOW_CHUNKS: usize = (h2::Settings::INITIAL.initial_window_size as usize).div_ceil(CHUNK);

/// The buffered request body of `/echo`, and the size of the region that the client reads its
/// echo into.
const ECHO: &[u8] = b"one buffered request body";
const READ: usize = 7;

fn main() -> Result<()> {
    // One thread runs the server, the client, each stream, and each deadline.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async { tokio::time::timeout(GUARD, run()).await? })
}

#[expect(clippy::print_stdout, reason = "an example prints the outcome of each case")]
fn report(line: &str) {
    println!("{line}");
}

/// Runs each case. The cases after the first share one connection, and the body of `/idle`
/// waits until the last of them.
async fn run() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (saw, mut seen) = mpsc::unbounded_channel();
    let signals = Arc::new(Signals {
        idle: Notify::new(),
        drain: Notify::new(),
        large: watch::Sender::new(0),
        saw,
    });
    let server = serve(listener, &signals)?;
    report(&trust_failure(address).await?);

    let client = connect(address, CA).await?;
    let (idle, first) = idle(&client).await?;
    // The borrow of the negotiated protocol is valid only during the call.
    let h2 = client.negotiated(|negotiated| negotiated.and_then(|negotiated| negotiated.protocol) == Some(&b"h2"[..]));
    check(h2, "TLS selected h2")?;
    report(&format!(
        "idle: TLS selected h2, /idle got its head and {first} bytes, and then its body waits"
    ));
    report(&partial_io(&client).await?);
    waits(&idle)?;
    report(&backpressure(&client, &signals).await?);
    waits(&idle)?;
    report(&cancellation(&client, &mut seen).await?);
    waits(&idle)?;
    report(&timeout(&client, &mut seen).await?);
    waits(&idle)?;
    signals.idle.notify_one();
    let views = idle.await??;
    let bytes: usize = views.iter().map(|view| view.bytes().len()).sum();
    report(&format!(
        "idle: the rest of /idle came after its release, and the client kept its {bytes} bytes as {} views",
        views.len()
    ));
    report(&shutdown(server, client, &signals).await?);
    Ok(())
}

/// A client that trusts only another root refuses the certificate of the server, and sends no
/// request.
async fn trust_failure(address: SocketAddr) -> Result<String> {
    let client = connect(address, OTHER_CA).await?;
    let refused = refusal(&client).await?;
    check(refused.kind() == Kind::Trust, "a trust failure")?;
    Ok(format!(
        "trust failure: a client that trusts another root refused the server: {}",
        refused.reason()
    ))
}

/// The server sends each part of the buffered request body of `/echo` back as a view of its
/// received region, with no copy. The client reads the echo into a region of 7 bytes, so each
/// read gives a part of it.
async fn partial_io(client: &Http2) -> Result<String> {
    let sent = Lease::from(ECHO);
    // A buffered body is in one region now, so a client can send it again.
    let body = Body::Buffered(sent.clone());
    let request = Request {
        method: Method::POST,
        length: body.length(),
        ..get(b"/echo")?
    };
    let mut echo = client.send(&request, deadline()).await?;
    echo.write(&sent).await?;
    echo.finish().await?;
    echo.response().await?;
    let (mut echoed, mut reads) = (Vec::new(), 0_usize);
    let mut region = WriteLoan::new(Vec::with_capacity(READ));
    loop {
        match echo.read_into(&mut region).await? {
            Read::Bytes(count) => {
                check(count <= READ, "a read fits its region")?;
                echoed.extend_from_slice(region.filled());
                reads = reads.saturating_add(1);
                let mut bytes = region.into_inner();
                bytes.clear();
                region = WriteLoan::new(bytes);
            }
            Read::Done(Outcome::Complete(None)) => break,
            read => return Err(format!("the echo did not complete: {read:?}").into()),
        }
    }
    check(echoed == ECHO, "the echo holds each byte of the request body")?;
    Ok(format!(
        "partial I/O: the server echoed the buffered body of /echo as views, and the client read its {} \
         bytes in {reads} reads of at most {READ} bytes",
        echoed.len()
    ))
}

/// The client does not read `/large` at first. The server queues chunks until the window of the
/// stream is full, and its next write waits, while `/quick` completes on the same connection.
/// Then the client counts each byte of the one-shot body as it comes, and keeps none of them.
async fn backpressure(client: &Http2, signals: &Signals) -> Result<String> {
    let mut queued = signals.large.subscribe();
    let mut large = client.send(&get(b"/large")?, deadline()).await?;
    large.response().await?;
    queued.wait_for(|&queued| queued >= WINDOW_CHUNKS).await?;
    quick(client).await?;
    check(
        *queued.borrow() == WINDOW_CHUNKS,
        "the server waits for the window of /large",
    )?;
    let mut bytes = 0_usize;
    loop {
        match large.next().await? {
            // The read gives the credit of the bytes back to the server, and the view drops here.
            Part::Data(view) => bytes = bytes.saturating_add(view.bytes().len()),
            Part::End(Outcome::Complete(None)) => break,
            Part::End(outcome) => return Err(format!("/large did not complete: {outcome:?}").into()),
        }
    }
    check(bytes == LARGE, "the client counted each byte of /large")?;
    Ok(format!(
        "backpressure: /large waited for its window after {WINDOW_CHUNKS} of {CHUNKS} chunks, /quick completed \
         meanwhile, and the client counted its {bytes} bytes with no collection"
    ))
}

/// The client drops the exchange of `/cancel` after its first part. The stream resets, the
/// server sees it, and the connection goes on.
async fn cancellation(client: &Http2, seen: &mut mpsc::UnboundedReceiver<Seen>) -> Result<String> {
    let mut cancel = client.send(&get(b"/cancel")?, deadline()).await?;
    cancel.response().await?;
    check(
        matches!(cancel.next().await?, Part::Data(_)),
        "the first part of /cancel",
    )?;
    drop(cancel);
    quick(client).await?;
    let saw = seen.recv().await.ok_or("the server ended")?;
    check(
        matches!(saw, Seen::Cancel(Kind::Partial)),
        "the server saw the reset of /cancel",
    )?;
    Ok(
        "early cancellation: the client dropped /cancel after its first part, the server saw the reset, and /quick \
        completed after it"
            .into(),
    )
}

/// The client sends part of the request body of `/late`, and then calls nothing on its stream.
/// At its deadline, the connection resets the stream, while only `/idle` awaits a call.
async fn timeout(client: &Http2, seen: &mut mpsc::UnboundedReceiver<Seen>) -> Result<String> {
    // A request body of no known length, which the client never ends.
    let request = Request {
        method: Method::POST,
        length: None,
        ..get(b"/late")?
    };
    let mut late = client.send(&request, Clock.deadline(LATE)).await?;
    late.write(&Lease::from(&b"late"[..])).await?;
    let saw = seen.recv().await.ok_or("the server ended")?;
    let cancel = u64::from(ErrorCode::CANCEL.0);
    check(
        matches!(saw, Seen::Late(Outcome::Reset(Some(code))) if code == cancel),
        "the server saw the reset of /late",
    )?;
    let error = late.response().await.err().ok_or("/late has a response")?;
    check(error.kind() == Kind::Deadline, "/late met its deadline")?;
    Ok(
        "timeout: the deadline reset /late while no call of /late ran, the server saw the reset, and the next call \
        of /late gave Kind::Deadline"
            .into(),
    )
}

/// The close of the server waits for `/drain`, which is in flight, and refuses a new request.
/// Then the client ends its connection, and the close joins each task of the server.
async fn shutdown(server: Server, client: Http2, signals: &Signals) -> Result<String> {
    let mut drain = client.send(&get(b"/drain")?, deadline()).await?;
    drain.response().await?;
    let mut closing = pin!(server.close(Clock.deadline(PATIENCE)));
    // The first poll of the close stops the accepts, and the connection starts to drain.
    let waiting = poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_pending())).await;
    check(waiting, "the close waits for /drain")?;
    // The server did not process the request, so the client can send it on a new connection.
    let refused = refusal(&client).await?;
    check(
        matches!(refused.kind(), Kind::Misuse | Kind::Overload),
        "a new request after the close is not processed",
    )?;
    signals.drain.notify_one();
    let mut region = WriteLoan::new(Vec::with_capacity(16));
    let collected = drain.collect(&mut region).await?;
    check(
        matches!(collected, Collect::Complete(None)) && region.filled() == b"drained",
        "/drain completed",
    )?;
    drop(drain);
    client.close().await?;
    let closed = closing.await;
    // The connection of the trust failure ended with its error.
    let expected = Report {
        accepted: 2,
        refused: 0,
        failed: 1,
        aborted: 0,
    };
    check(closed == expected, "the report of the server")?;
    Ok(format!(
        "shutdown: the close waited for /drain and refused a new request, the client released, and the report \
         counts {} accepted, {} failed, {} aborted",
        closed.accepted, closed.failed, closed.aborted
    ))
}

/// Sends `/quick` and collects its small body.
async fn quick(client: &Http2) -> Result<()> {
    let mut quick = client.send(&get(b"/quick")?, deadline()).await?;
    quick.response().await?;
    let mut region = WriteLoan::new(Vec::with_capacity(16));
    let collected = quick.collect(&mut region).await?;
    check(
        matches!(collected, Collect::Complete(None)) && region.filled() == b"quick",
        "/quick completed",
    )
}

/// Sends `/quick`, and gives the error of a request that the client or the server refused.
async fn refusal(client: &Http2) -> Result<Error> {
    match client.send(&get(b"/quick")?, deadline()).await {
        Err(error) => Ok(error),
        Ok(mut exchange) => Ok(exchange.response().await.err().ok_or("the request has a response")?),
    }
}

/// The task that reads the rest of the body of `/idle`. It gives each part of the body as a view.
type Idle = JoinHandle<Result<Vec<Lease>>>;

/// Sends `/idle`, and reads its head and the first part of its body. Then a task of its own reads
/// the rest, and keeps each part as a view. Gives the task and the bytes of the first part.
async fn idle(client: &Http2) -> Result<(Idle, usize)> {
    let mut idle = client.send(&get(b"/idle")?, deadline()).await?;
    idle.response().await?;
    let Part::Data(first) = idle.next().await? else {
        return Err("/idle has no first part".into());
    };
    let bytes = first.bytes().len();
    let task = tokio::spawn(async move {
        let mut views = vec![first];
        loop {
            match idle.next().await? {
                // An owned view keeps its received region after the call, with no copy.
                Part::Data(view) => views.push(view),
                Part::End(Outcome::Complete(None)) => return Ok(views),
                Part::End(outcome) => return Err(format!("/idle did not complete: {outcome:?}").into()),
            }
        }
    });
    Ok((task, bytes))
}

/// The body of `/idle` still waits for its release.
fn waits(idle: &Idle) -> Result<()> {
    check(!idle.is_finished(), "the body of /idle waits")
}

/// The error of a step whose receiver ended.
const ENDED: Error = Error::new(Kind::Cancelled, "the example ended");

/// What the cases and the handlers of the server share.
#[derive(Debug)]
struct Signals {
    /// Releases the rest of the body of `/idle`.
    idle: Notify,
    /// Releases the body of `/drain`.
    drain: Notify,
    /// The chunks of `/large` that the server queued.
    large: watch::Sender<usize>,
    /// What the server saw of each stream that the client ended.
    saw: mpsc::UnboundedSender<Seen>,
}

/// What the server saw of a stream that the client ended.
#[derive(Debug)]
enum Seen {
    /// A write of `/cancel` refused with this kind.
    Cancel(Kind),
    /// The request body of `/late` ended with this outcome.
    Late(Outcome),
}

/// Serves HTTP/2 over TLS on `listener`: each request runs [`handle`] in a task of its own.
fn serve(listener: TcpListener, signals: &Arc<Signals>) -> Result<Server> {
    let (chain, key) = SERVER;
    let budget = budget()?;
    let config = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(chain.to_vec())],
            key: PrivateKeyDer::try_from(key.to_vec())?,
        },
        client_roots: None,
        protocols: &[b"h2"],
        resumption: Resumption::Off,
        budget: &budget,
        clock: Arc::new(DefaultTimeProvider),
        entropy: Entropy::System,
    })?;
    let limits = server::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: QUEUE,
        head_timeout: Some(PATIENCE),
        linger: Linger {
            time: Duration::from_secs(5),
            bytes: 64 * 1024,
        },
        cleartext: Cleartext::Http2,
    };
    let make = move || {
        Ok((
            server::Http::tls(&config, (limits, TLS), Clock.domain(), &budget)?,
            pool(&budget)?,
        ))
    };
    let signals = Arc::clone(signals);
    let handler = move |exchange| handle(exchange, Arc::clone(&signals));
    Ok(Server::serve(listener, CONNECTIONS, make, handler))
}

/// Serves one request on its route.
async fn handle(mut exchange: Exchange, signals: Arc<Signals>) -> core::result::Result<(), Error> {
    let target = exchange.head().target().as_bytes().to_vec();
    match target.as_slice() {
        b"/idle" => {
            exchange.respond(&ok(Some(8))).await?;
            exchange.write(&Lease::from(&b"idle"[..])).await?;
            signals.idle.notified().await;
            exchange.write(&Lease::from(&b"done"[..])).await?;
            exchange.finish().await
        }
        b"/quick" => {
            exchange.respond(&ok(Some(5))).await?;
            exchange.write(&Lease::from(&b"quick"[..])).await?;
            exchange.finish().await
        }
        b"/echo" => {
            exchange.respond(&ok(exchange.head().length())).await?;
            loop {
                match exchange.next().await? {
                    Part::Data(view) => exchange.write(&view).await?,
                    Part::End(Outcome::Complete(_)) => return exchange.finish().await,
                    Part::End(_) => return Err(Error::new(Kind::Partial, "the body of /echo did not complete")),
                }
            }
        }
        b"/large" => {
            // A one-shot body: the server makes its bytes once, in their order.
            let body = Body::OneShot {
                length: u64::try_from(LARGE).ok(),
            };
            exchange.respond(&ok(body.length())).await?;
            let chunk = chunk();
            for queued in 1..=CHUNKS {
                exchange.write(&chunk).await?;
                signals.large.send_replace(queued);
            }
            exchange.finish().await
        }
        b"/cancel" => {
            exchange.respond(&ok(None)).await?;
            let chunk = chunk();
            for _ in 0..CHUNKS {
                if let Err(error) = exchange.write(&chunk).await {
                    return signals.saw.send(Seen::Cancel(error.kind())).map_err(|_| ENDED);
                }
            }
            exchange.finish().await
        }
        b"/late" => loop {
            if let Part::End(outcome) = exchange.next().await? {
                return signals.saw.send(Seen::Late(outcome)).map_err(|_| ENDED);
            }
        },
        b"/drain" => {
            exchange.respond(&ok(Some(7))).await?;
            signals.drain.notified().await;
            exchange.write(&Lease::from(&b"drained"[..])).await?;
            exchange.finish().await
        }
        _ => {
            let missing = Response {
                status: Status::new(404).expect("404 is a status code"),
                fields: &[],
                length: Some(0),
            };
            exchange.respond(&missing).await?;
            exchange.finish().await
        }
    }
}

/// A client for `server.test` at `address` that trusts only `root`.
async fn connect(address: SocketAddr, root: &[u8]) -> Result<Http2> {
    let budget = budget()?;
    let config = ClientConfig::new(ClientOptions {
        roots: &[CertificateDer::from(root.to_vec())],
        identity: None,
        protocols: &[b"h2"],
        resumption: Resumption::Off,
        budget: &budget,
        clock: Arc::new(DefaultTimeProvider),
        entropy: Entropy::System,
    })?;
    let limits = client::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: QUEUE,
    };
    let core = client::Http2::tls(&config, NAME, (limits, TLS), Clock.domain(), &budget)?;
    let stream = TcpStream::connect(address).await?;
    Ok(Http2::new(core, stream, pool(&budget)?)?)
}

/// A GET request for `target` on `server.test`.
fn get(target: &'static [u8]) -> Result<Request<'static>> {
    Ok(Request {
        method: Method::GET,
        target: Target::new(target)?,
        authority: Authority::new(NAME.as_bytes())?,
        fields: &[],
        length: Some(0),
    })
}

fn ok(length: Option<u64>) -> Response<'static> {
    Response {
        status: Status::new(200).expect("200 is a status code"),
        fields: &[],
        length,
    }
}

/// One chunk of `/large` and `/cancel`. Each write queues a view of it, with no copy.
fn chunk() -> Lease {
    Lease::from(vec![b'x'; CHUNK])
}

fn deadline() -> Deadline {
    Clock.deadline(PATIENCE)
}

/// The budget of one side, which pays for its connections and its TLS configuration.
fn budget() -> Result<Budget> {
    Ok(Budget::new(NonZeroU64::new(1 << 24).ok_or("zero budget")?))
}

fn pool(budget: &Budget) -> core::result::Result<Pool, Error> {
    Ok(Pool::new(budget, NonZeroU32::MIN, SLOT)?)
}

fn check(holds: bool, what: &str) -> Result<()> {
    if holds {
        Ok(())
    } else {
        Err(format!("expected: {what}").into())
    }
}

#[cfg(test)]
mod tests {
    /// Each case of the example gives its expected outcome.
    #[test]
    fn each_case_gives_its_outcome() {
        super::main().unwrap();
    }
}
