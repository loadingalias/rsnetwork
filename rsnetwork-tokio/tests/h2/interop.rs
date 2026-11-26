//! The rsnetwork endpoint of the HTTP/2 interop runs with independent peers (N206). Each peer and
//! each check are in `run.sh`, next to this file.
//!
//! `server <address> <tls-dir>` serves HTTP/2 over TLS 1.3, ALPN `h2` only, with the certificate of
//! `server.test` in `<tls-dir>` (`server.der` and `server.key.der`). It prints `LISTEN <address>`,
//! one `TLS` line for the first exchange of each connection, and one line for each exchange:
//!
//! - `/`: 16 bytes, for h2spec, which needs at least 5 bytes of DATA. It discards a request body.
//! - `/echo`: sends each part of the request body back as it arrives, and then the trailers
//!   `x-echo-bytes` and `x-echo-trailers`, the names of the request trailers. `ECHO <bytes> <names>`.
//! - `/trailers`: 64 KiB, and then the trailer `x-trailer: done`.
//! - `/reset`: 16 KiB, and then a reset of the stream with `CANCEL`. `RESET /reset`.
//! - `/slow`: 10 parts of 1 KiB, one each 200 ms. `DONE /slow` after the last part, or
//!   `PEER-RESET /slow <parts> <kind>` when the peer reset the stream.
//! - `/shutdown`: `closing`, and then the close of the server: a GOAWAY on each connection, the
//!   exchanges in flight end, and `REPORT accepted=<n> failed=<n> aborted=<n>`.
//! - `/urgency/<name>`: 16 MiB in one chunk, after two of these requests arrived, so both bodies
//!   wait together and only their priorities (RFC 9218) order them (N212).
//! - `/1k`: 1024 bytes, a view of one static region, for the small-response probe of N211. It
//!   discards a request body.
//! - `/browser` and `/goaway`: the pages of the browser cells. `POST /report` prints `BROWSER <body>`.
//!
//! `client <address> <tls-dir> <case>...` connects to an independent server for `server.test` at
//! `<address>`, verifies it with `<tls-dir>/ca.der`, and runs each case. It prints
//! `CASE <case> PASS <detail>` or `CASE <case> FAIL <detail>`, and exits with 1 after a failure:
//!
//! - `upload=<path>`: a PUT of 1 MiB in 16 parts with the trailer `x-trailer: done`; a 2xx status.
//! - `stream=<path>`: the same PUT with no trailers, for a server that refuses request trailers.
//! - `trailers=<path>`: a GET whose body ends with trailers.
//! - `cancel=<path>`: a GET of a large body, a reset after its first part, and then a GET of `/` on
//!   the same connection.
//! - `refused=<path>`: a PUT of 2 MiB to a path whose limit is lower: the status comes, and `/` on the
//!   same connection still answers.
//! - `goaway=<path>:<n>`: `n` GET requests in a row. When the server sends GOAWAY, the next request
//!   goes on a new connection. It passes when each request completed and a GOAWAY came.
//! - `drain=<path>`: a GET of a slow body. After its head it prints `READY drain`, so that the
//!   caller closes the server, which sends GOAWAY. It passes when the body completes after it.

use core::alloc::Layout;
use core::error::Error;
use core::net::SocketAddr;
use core::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::Arc;

use rsnetwork::body::{Collect, Outcome, Part};
use rsnetwork::buffer::{Buffer as _, Lease, Pool, WriteLoan};
use rsnetwork::capacity::Budget;
use rsnetwork::client::{self, Request};
use rsnetwork::drive::{self, Kind, TurnLimits};
use rsnetwork::h1::{self, BodyLimits};
use rsnetwork::h2;
use rsnetwork::server::{self, Cleartext, Linger, Response};
use rsnetwork::tls::{
    self, CertificateDer, ClientConfig, ClientOptions, DefaultTimeProvider, Entropy, Identity, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions,
};
use rsnetwork::value::{Authority, Field, Method, Status, Target};
use rsnetwork_tokio::Clock;
use rsnetwork_tokio::server::{Exchange, Server};
use tokio::sync::{Barrier, Notify};

type Result<T> = core::result::Result<T, Box<dyn Error + Send + Sync>>;

const HEAD: h1::Limits = h1::Limits {
    head_bytes: 16 * 1024,
    fields: 128,
    name_bytes: 256,
    value_bytes: 8 * 1024,
};
const BODY: BodyLimits = BodyLimits {
    body_bytes: 64 << 20,
    drain_bytes: 64 * 1024,
    extension_bytes: 256,
    trailer_bytes: 4 * 1024,
    trailer_fields: 16,
};
const H2: h2::Limits = h2::Limits {
    settings: h2::Settings {
        max_concurrent_streams: 128,
        max_header_list_size: 16 * 1024,
        ..h2::Settings::INITIAL
    },
    work: 64 * 1024,
    encoder_table_bytes: 4096,
    connection_window: 1 << 20,
};
const TURN: TurnLimits = TurnLimits {
    bytes: 1 << 20,
    frames: 1 << 10,
    visits: 1 << 12,
};
const QUEUE: NonZeroUsize = NonZeroUsize::new(64).expect("not zero");
const TLS: tls::Limits = tls::Limits {
    input_bytes: 32 * 1024,
    key_records_max: u64::MAX,
    turn: TURN,
};
/// The body of each `/urgency` response.
const URGENCY_BYTES: usize = 16 << 20;
/// The body of each `/1k` response.
static KIB: [u8; 1024] = [b'k'; 1024];
/// The time of each exchange of the client cases.
const PATIENCE: Duration = Duration::from_secs(20);

/// Writes one line of the record to standard output.
fn line(text: &str) {
    let mut out = io::stdout().lock();
    // A run that cannot write its record fails at its checks, which read the record.
    drop(writeln!(out, "{text}").and_then(|()| out.flush()));
}

fn budget() -> Budget {
    Budget::new(NonZeroU64::new(1 << 30).expect("not zero"))
}

/// The receive regions of one connection: 16 of 16 KiB.
fn pool(budget: &Budget) -> core::result::Result<Pool, drive::Error> {
    let slot = Layout::array::<u8>(16 * 1024).map_err(|_| drive::Error::new(Kind::Misuse, "the slot layout"))?;
    Ok(Pool::new(budget, NonZeroU32::new(16).expect("not zero"), slot)?)
}

fn read(directory: &Path, name: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(directory.join(name))?)
}

fn field(name: &'static [u8], value: &'static [u8]) -> Field<'static> {
    Field::new(name, value).expect("a valid field line")
}

fn main() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(start())
}

async fn start() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [role, address, directory, cases @ ..] = args.as_slice() else {
        return Err("expected server|client, an address, the TLS directory, and the cases".into());
    };
    let address: SocketAddr = address.parse()?;
    let directory = Path::new(directory);
    match role.as_str() {
        "server" => serve(address, directory).await,
        "client" => {
            let config = client_config(directory)?;
            let mut failed = false;
            for case in cases {
                let (name, argument) = case.split_once('=').ok_or("a case is <name>=<argument>")?;
                let outcome = run(&config, address, name, argument).await;
                failed |= outcome.is_err();
                match outcome {
                    Ok(detail) => line(&format!("CASE {case} PASS {detail}")),
                    Err(error) => line(&format!("CASE {case} FAIL {error}")),
                }
            }
            if failed {
                return Err("a case failed".into());
            }
            Ok(())
        }
        _ => Err("expected server or client".into()),
    }
}

async fn serve(address: SocketAddr, directory: &Path) -> Result<()> {
    let config = ServerConfig::new(ServerOptions {
        identity: Identity {
            chain: vec![CertificateDer::from(read(directory, "server.der")?)],
            key: PrivateKeyDer::try_from(read(directory, "server.key.der")?)?,
        },
        client_roots: None,
        protocols: &[b"h2"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(DefaultTimeProvider),
        entropy: Entropy::System,
    })?;
    let limits = server::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: QUEUE,
        head_timeout: Some(Duration::from_secs(30)),
        linger: Linger {
            time: Duration::from_secs(5),
            bytes: 64 * 1024,
        },
        cleartext: Cleartext::Http2,
    };
    let listener = tokio::net::TcpListener::bind(address).await?;
    line(&format!("LISTEN {}", listener.local_addr()?));
    let shutdown = Arc::new(Notify::new());
    let make = move || {
        let budget = budget();
        Ok((
            server::Http::tls(&config, (limits, TLS), Clock.domain(), &budget)?,
            pool(&budget)?,
        ))
    };
    let both = Arc::new(Barrier::new(2));
    let handler = {
        let shutdown = Arc::clone(&shutdown);
        move |exchange: Exchange| handle(exchange, Arc::clone(&shutdown), Arc::clone(&both))
    };
    let server = Server::serve(listener, NonZeroUsize::new(256).expect("not zero"), make, handler);
    shutdown.notified().await;
    let report = server.close(Clock.deadline(Duration::from_secs(10))).await;
    line(&format!(
        "REPORT accepted={} failed={} aborted={}",
        report.accepted, report.failed, report.aborted
    ));
    Ok(())
}

/// The pattern of the bodies: a byte out of its place shows.
fn pattern(bytes: usize) -> Vec<u8> {
    (0..=250_u8).cycle().take(bytes).collect()
}

fn ok(length: Option<u64>) -> Response<'static> {
    Response {
        status: Status::new(200).expect("a valid status"),
        fields: &[],
        length,
    }
}

/// Serves one exchange on its route, and prints the error of a route that failed.
async fn handle(
    exchange: Exchange,
    shutdown: Arc<Notify>,
    both: Arc<Barrier>,
) -> core::result::Result<(), drive::Error> {
    let path = String::from_utf8_lossy(exchange.head().target().as_bytes()).into_owned();
    let result = route(exchange, shutdown, both).await;
    if let Err(error) = &result {
        line(&format!("ERROR {path} {:?} {error}", error.kind()));
    }
    result
}

async fn route(
    mut exchange: Exchange,
    shutdown: Arc<Notify>,
    both: Arc<Barrier>,
) -> core::result::Result<(), drive::Error> {
    // h2load and curl print the group of their own side, so only the routes of the other peers
    // print it here.
    if matches!(exchange.head().target().as_bytes(), b"/" | b"/echo" | b"/browser") {
        exchange.negotiated(|negotiated| {
            if let Some(negotiated) = negotiated {
                let protocol = negotiated.protocol.map(String::from_utf8_lossy);
                line(&format!("TLS group={:?} alpn={protocol:?}", negotiated.group));
            }
        });
    }
    let path = exchange.head().target().as_bytes().to_vec();
    match path.as_slice() {
        b"/echo" => echo(&mut exchange).await,
        b"/trailers" => {
            exchange.respond(&ok(None)).await?;
            exchange.write(&Lease::from(pattern(64 * 1024))).await?;
            exchange.finish_with_trailers(&[field(b"x-trailer", b"done")]).await
        }
        b"/reset" => {
            exchange.respond(&ok(None)).await?;
            exchange.write(&Lease::from(pattern(16 * 1024))).await?;
            exchange.cancel();
            line("RESET /reset");
            Ok(())
        }
        b"/slow" => {
            exchange.respond(&ok(Some(10 * 1024))).await?;
            for part in 0..10 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if let Err(error) = exchange.write(&Lease::from(pattern(1024))).await {
                    line(&format!("PEER-RESET /slow {part} {:?}", error.kind()));
                    return Ok(());
                }
            }
            exchange.finish().await?;
            line("DONE /slow");
            Ok(())
        }
        b"/shutdown" => {
            exchange.respond(&ok(Some(7))).await?;
            exchange.write(&Lease::from(&b"closing"[..])).await?;
            exchange.finish().await?;
            shutdown.notify_one();
            Ok(())
        }
        b"/1k" => {
            discard(&mut exchange).await?;
            exchange.respond(&ok(Some(1024))).await?;
            exchange.write(&Lease::from(&KIB[..])).await?;
            exchange.finish().await
        }
        b"/urgency/high" | b"/urgency/low" => {
            both.wait().await;
            exchange.respond(&ok(u64::try_from(URGENCY_BYTES).ok())).await?;
            exchange.write(&Lease::from(vec![b'u'; URGENCY_BYTES])).await?;
            exchange.finish().await
        }
        b"/browser" => page(&mut exchange, BROWSER).await,
        b"/goaway" => page(&mut exchange, GOAWAY).await,
        b"/report" => {
            let mut region = WriteLoan::new(Vec::with_capacity(16 * 1024));
            exchange.collect(&mut region).await?;
            line(&format!("BROWSER {}", String::from_utf8_lossy(region.filled())));
            exchange.respond(&ok(Some(0))).await
        }
        b"/" => {
            discard(&mut exchange).await?;
            exchange.respond(&ok(Some(16))).await?;
            exchange.write(&Lease::from(&b"rsnetwork h2spec"[..])).await?;
            exchange.finish().await
        }
        _ => {
            discard(&mut exchange).await?;
            let missing = Response {
                status: Status::new(404).expect("a valid status"),
                fields: &[],
                length: Some(0),
            };
            exchange.respond(&missing).await
        }
    }
}

/// Reads the request body to its end, and keeps no byte.
async fn discard(exchange: &mut Exchange) -> core::result::Result<(), drive::Error> {
    while let Part::Data(_) = exchange.next().await? {}
    Ok(())
}

/// Sends each part of the request body back as it arrives, and then the trailers.
async fn echo(exchange: &mut Exchange) -> core::result::Result<(), drive::Error> {
    exchange.respond(&ok(None)).await?;
    let mut bytes = 0_usize;
    let outcome = loop {
        match exchange.next().await? {
            Part::Data(data) => {
                bytes += data.initialized();
                exchange.write(&data).await?;
            }
            Part::End(outcome) => break outcome,
        }
    };
    let Outcome::Complete(trailers) = outcome else {
        line(&format!("ECHO-INCOMPLETE {bytes} {outcome:?}"));
        exchange.cancel();
        return Ok(());
    };
    let names: Vec<String> = trailers
        .iter()
        .flat_map(|trailers| trailers.fields())
        .map(|field| String::from_utf8_lossy(field.name()).into_owned())
        .collect();
    let names = names.join(",");
    line(&format!("ECHO {bytes} {names}"));
    let count = bytes.to_string();
    let echoed = [
        Field::new(b"x-echo-bytes", count.as_bytes()).map_err(|_| drive::Error::new(Kind::Misuse, "a count"))?,
        Field::new(b"x-echo-trailers", names.as_bytes())
            .map_err(|_| drive::Error::new(Kind::Misuse, "the trailer names"))?,
    ];
    exchange.finish_with_trailers(&echoed).await
}

/// Sends one HTML page.
async fn page(exchange: &mut Exchange, html: &'static str) -> core::result::Result<(), drive::Error> {
    discard(exchange).await?;
    let length = u64::try_from(html.len()).map_err(|_| drive::Error::new(Kind::Misuse, "the page length"))?;
    let page = Response {
        status: Status::new(200).expect("a valid status"),
        fields: &[field(b"content-type", b"text/html; charset=utf-8")],
        length: Some(length),
    };
    exchange.respond(&page).await?;
    exchange.write(&Lease::from(html.as_bytes())).await?;
    exchange.finish().await
}

/// The browser cells: a streamed upload, a response with trailers, a reset of the server, and a
/// reset of the browser. The page posts its results to `/report`.
const BROWSER: &str = r#"<!doctype html><title>rsnetwork h2 interop</title><script>
const results = {};
async function cell(name, run) {
  try { results[name] = await run(); } catch (error) { results[name] = "error: " + error; }
}
(async () => {
  await cell("upload", async () => {
    const parts = 16, size = 64 * 1024;
    const body = new ReadableStream({
      pull(controller) {
        if (this.sent === undefined) this.sent = 0;
        if (this.sent === parts) { controller.close(); return; }
        controller.enqueue(new Uint8Array(size).fill(this.sent % 251));
        this.sent += 1;
      }
    });
    const response = await fetch("/echo", { method: "POST", body, duplex: "half" });
    const echoed = new Uint8Array(await response.arrayBuffer());
    // A page cannot read trailers, so it checks the bytes and their order.
    const ordered = echoed.every((byte, index) => byte === Math.floor(index / size) % 251);
    return response.status + " " + echoed.byteLength + " " + (ordered ? "ordered" : "disordered");
  });
  await cell("trailers", async () => {
    const response = await fetch("/trailers");
    return response.status + " " + (await response.arrayBuffer()).byteLength;
  });
  await cell("server-reset", async () => {
    try {
      const response = await fetch("/reset");
      await response.arrayBuffer();
      return "complete";
    } catch (error) {
      return "rejected " + error.name;
    }
  });
  await cell("browser-reset", async () => {
    const controller = new AbortController();
    const response = await fetch("/slow", { signal: controller.signal });
    const reader = response.body.getReader();
    await reader.read();
    controller.abort();
    try { while (!(await reader.read()).done) {} return "complete"; } catch (error) { return "aborted " + error.name; }
  });
  await cell("after", async () => (await fetch("/")).status);
  await fetch("/report", { method: "POST", body: JSON.stringify(results) });
})();
</script>"#;

/// The GOAWAY cell of the browser: a slow response in flight when the server closes.
const GOAWAY: &str = r#"<!doctype html><title>rsnetwork h2 goaway</title><script>
(async () => {
  const slow = fetch("/slow").then((response) => response.arrayBuffer());
  await new Promise((resolve) => setTimeout(resolve, 300));
  await fetch("/shutdown");
  await slow;
})();
</script>"#;

fn client_config(directory: &Path) -> Result<ClientConfig> {
    Ok(ClientConfig::new(ClientOptions {
        roots: &[CertificateDer::from(read(directory, "ca.der")?)],
        identity: None,
        protocols: &[b"h2"],
        resumption: Resumption::Off,
        budget: &budget(),
        clock: Arc::new(DefaultTimeProvider),
        entropy: Entropy::System,
    })?)
}

/// A new HTTP/2 client of `server.test` at `address`.
async fn connect(config: &ClientConfig, address: SocketAddr) -> Result<rsnetwork_tokio::client::Http2> {
    let limits = client::Limits {
        head: HEAD,
        h2: H2,
        body: BODY,
        turn: TURN,
        queue: QUEUE,
    };
    let budget = budget();
    let core = client::Http2::tls(config, "server.test", (limits, TLS), Clock.domain(), &budget)?;
    let stream = tokio::net::TcpStream::connect(address).await?;
    Ok(rsnetwork_tokio::client::Http2::new(core, stream, pool(&budget)?)?)
}

fn request<'a>(method: Method<'a>, target: &'a [u8], length: Option<u64>) -> Result<Request<'a>> {
    Ok(Request {
        method,
        target: Target::new(target)?,
        authority: Authority::new(b"server.test")?,
        fields: &[],
        length,
    })
}

/// Runs one client case, and gives its detail.
async fn run(config: &ClientConfig, address: SocketAddr, name: &str, argument: &str) -> Result<String> {
    let path = argument.split(':').next().unwrap_or(argument).as_bytes();
    let client = connect(config, address).await?;
    let detail = match name {
        "upload" | "stream" => {
            let mut exchange = client
                .send(&request(Method::PUT, path, None)?, Clock.deadline(PATIENCE))
                .await?;
            let part = Lease::from(pattern(64 * 1024));
            for _ in 0..16 {
                exchange.write(&part).await?;
            }
            if name == "upload" {
                exchange.finish_with_trailers(&[field(b"x-trailer", b"done")]).await?;
            } else {
                exchange.finish().await?;
            }
            let status = exchange.response().await?.status();
            let mut region = WriteLoan::new(Vec::with_capacity(64 * 1024));
            let collected = exchange.collect(&mut region).await?;
            if !(200..300).contains(&status.code()) || !matches!(collected, Collect::Complete(_)) {
                return Err(format!("status {}, body {collected:?}", status.code()).into());
            }
            format!("status={}", status.code())
        }
        "trailers" => {
            let mut exchange = client
                .send(&request(Method::GET, path, Some(0))?, Clock.deadline(PATIENCE))
                .await?;
            exchange.response().await?;
            let mut region = WriteLoan::new(Vec::with_capacity(4 << 20));
            match exchange.collect(&mut region).await? {
                Collect::Complete(Some(trailers)) => {
                    let names: Vec<String> = trailers
                        .fields()
                        .map(|field| String::from_utf8_lossy(field.name()).into_owned())
                        .collect();
                    format!("bytes={} trailers={}", region.filled().len(), names.join(","))
                }
                collected => return Err(format!("the body ended {collected:?} with no trailers").into()),
            }
        }
        "cancel" => {
            let mut exchange = client
                .send(&request(Method::GET, path, Some(0))?, Clock.deadline(PATIENCE))
                .await?;
            exchange.response().await?;
            let first = exchange.next().await?;
            if !matches!(first, Part::Data(_)) {
                return Err(format!("the body has no first part: {first:?}").into());
            }
            // The drop resets the stream with CANCEL, and the connection goes on.
            drop(exchange);
            let after = after(&client).await?;
            format!("after={after}")
        }
        "refused" => {
            let mut exchange = client
                .send(&request(Method::PUT, path, None)?, Clock.deadline(PATIENCE))
                .await?;
            let part = Lease::from(pattern(64 * 1024));
            let mut written = 0;
            // The server answers before the end, and stops the upload.
            for _ in 0..32 {
                if exchange.write(&part).await.is_err() {
                    break;
                }
                written += 1;
            }
            let status = exchange.response().await?.status();
            drop(exchange);
            let after = after(&client).await?;
            format!("status={} parts={written} after={after}", status.code())
        }
        "goaway" => return goaway(config, address, client, argument).await,
        "drain" => {
            let mut exchange = client
                .send(&request(Method::GET, path, Some(0))?, Clock.deadline(PATIENCE))
                .await?;
            exchange.response().await?;
            line("READY drain");
            let mut region = WriteLoan::new(Vec::with_capacity(16 << 20));
            // The server closed the connection after the body, so the client drops with no close.
            return match exchange.collect(&mut region).await? {
                Collect::Complete(_) => Ok(format!("bytes={}", region.filled().len())),
                collected => Err(format!("the body ended {collected:?}").into()),
            };
        }
        _ => return Err(format!("no case {name}").into()),
    };
    client.close().await?;
    Ok(detail)
}

/// The status of a GET of `/` on `client`.
async fn after(client: &rsnetwork_tokio::client::Http2) -> Result<u16> {
    let mut exchange = client
        .send(&request(Method::GET, b"/", Some(0))?, Clock.deadline(PATIENCE))
        .await?;
    let status = exchange.response().await?.status().code();
    let mut region = WriteLoan::new(Vec::with_capacity(1 << 20));
    exchange.collect(&mut region).await?;
    Ok(status)
}

/// GET requests in a row, on a new connection after each GOAWAY.
async fn goaway(
    config: &ClientConfig,
    address: SocketAddr,
    mut client: rsnetwork_tokio::client::Http2,
    argument: &str,
) -> Result<String> {
    let (path, count) = argument.split_once(':').ok_or("goaway=<path>:<count>")?;
    let count: usize = count.parse()?;
    let (mut connections, mut goaways) = (1, 0);
    for _ in 0..count {
        // A GOAWAY refuses the next request: at `send` when it came before it, or at `response`
        // when the request is above the last stream that the server processes.
        let fetched = match get(&client, path).await {
            Err(error) if matches!(error.kind(), Kind::Misuse | Kind::Overload) => {
                goaways += 1;
                client.close().await?;
                client = connect(config, address).await?;
                connections += 1;
                get(&client, path).await
            }
            fetched => fetched,
        };
        let collected = fetched?;
        if !matches!(collected, Collect::Complete(_)) {
            return Err(format!("a body ended {collected:?}").into());
        }
    }
    client.close().await?;
    if goaways == 0 {
        return Err(format!("no GOAWAY came in {count} requests").into());
    }
    Ok(format!("requests={count} connections={connections} goaways={goaways}"))
}

/// A GET of `path` on `client`, and its body.
async fn get(client: &rsnetwork_tokio::client::Http2, path: &str) -> core::result::Result<Collect, drive::Error> {
    let target = Target::new(path.as_bytes()).map_err(|_| drive::Error::new(Kind::Misuse, "the path"))?;
    let authority = Authority::new(b"server.test").map_err(|_| drive::Error::new(Kind::Misuse, "the authority"))?;
    let request = Request {
        method: Method::GET,
        target,
        authority,
        fields: &[],
        length: Some(0),
    };
    let mut exchange = client.send(&request, Clock.deadline(PATIENCE)).await?;
    exchange.response().await?;
    let mut region = WriteLoan::new(Vec::with_capacity(1 << 20));
    exchange.collect(&mut region).await
}
