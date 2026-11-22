//! The exporter on the Tokio binding (N501): both ends of an HTTP/1.1 connection, of an HTTP/2
//! connection, and of a TLS stream derive the same material over TLS, and a connection over TCP
//! has none. Each case runs on a current-thread and on a multi-thread runtime.
// Clippy applies `allow-unwrap-in-tests` and `allow-panic-in-tests` to the helpers of a test
// outside `tests/` of the workspace root only under `cfg(test)`.
#![cfg(test)]

#[expect(dead_code, reason = "these cases need only the connections of the support")]
mod support;

use core::num::NonZeroUsize;

use rsnetwork::tls::{self, ExportError, StreamLimits};
use rsnetwork_tokio::Clock;
use support::{PATIENCE, TLS, Transport, get, ok, on_each_runtime};
use tokio::sync::oneshot;

const LABEL: &[u8] = b"EXPERIMENTAL-example-possession";
const CONTEXT: &[u8] = b"instance 1";

/// The material of `export`, a derivation into 32 bytes.
fn material(export: impl FnOnce(&mut [u8]) -> Result<(), ExportError>) -> Result<[u8; 32], ExportError> {
    let mut output = [0; 32];
    export(&mut output).map(|()| output)
}

#[test]
fn both_ends_of_each_tls_connection_derive_the_same_material_and_tcp_has_none() {
    on_each_runtime(|| async {
        for transport in [Transport::Plain, Transport::Tls] {
            // HTTP/1.1: the server derives on the exchange, and the client on its connection.
            // The server keeps the connection until the client derived: a client that reads the end
            // of the connection refuses with `Closed`.
            let (listener, address) = support::listener().await;
            let (derived_tx, done) = oneshot::channel::<()>();
            let serving = tokio::spawn(async move {
                let mut server = support::server(transport, &listener).await;
                let mut exchange = server.request().await.unwrap().expect("a request");
                let derived = material(|output| exchange.export(LABEL, CONTEXT, output));
                exchange.respond(&ok(Some(0))).await.unwrap();
                done.await.unwrap();
                derived
            });
            let mut client = support::client(transport, address).await;
            client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
            client.response().await.unwrap();
            let derived = material(|output| client.export(LABEL, CONTEXT, output));
            derived_tx.send(()).unwrap();
            let expected = serving.await.unwrap();
            match transport {
                Transport::Tls => assert!(derived.is_ok() && derived == expected, "HTTP/1.1"),
                Transport::Plain => assert_eq!(
                    (derived, expected),
                    (Err(ExportError::Unavailable), Err(ExportError::Unavailable))
                ),
            }

            // HTTP/2: one connection, which a client handle and a server exchange share.
            let (listener, address) = support::listener().await;
            let (derived_tx, done) = oneshot::channel::<()>();
            let serving = tokio::spawn(async move {
                let mut server = support::h2_server(transport, &listener).await;
                let mut exchange = server.request().await.unwrap().expect("a request");
                let derived = material(|output| exchange.export(LABEL, CONTEXT, output));
                exchange.respond(&ok(Some(0))).await.unwrap();
                done.await.unwrap();
                derived
            });
            let client = support::h2_client(transport, address).await;
            let mut exchange = client.send(&get(), Clock.deadline(PATIENCE)).await.unwrap();
            exchange.response().await.unwrap();
            let derived = material(|output| client.export(LABEL, CONTEXT, output));
            derived_tx.send(()).unwrap();
            let expected = serving.await.unwrap();
            match transport {
                Transport::Tls => assert!(derived.is_ok() && derived == expected, "HTTP/2"),
                Transport::Plain => assert_eq!(
                    (derived, expected),
                    (Err(ExportError::Unavailable), Err(ExportError::Unavailable))
                ),
            }
        }

        // A TLS stream for another protocol.
        const LIMITS: StreamLimits = StreamLimits {
            tls: TLS,
            queue: NonZeroUsize::new(16).unwrap(),
            handshake_timeout: Some(PATIENCE),
        };
        let (listener, address) = support::listener().await;
        let (derived_tx, done) = oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let budget = support::budget();
            let core = tls::Stream::accept(&support::server_config(), LIMITS, Clock.domain(), &budget).unwrap();
            let mut stream = rsnetwork_tokio::tls::Stream::new(core, tcp, support::pool(&budget)).unwrap();
            stream.handshake().await.unwrap();
            let derived = material(|output| stream.export(LABEL, CONTEXT, output));
            done.await.unwrap();
            derived
        });
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let budget = support::budget();
        let core = tls::Stream::connect(
            &support::client_config(),
            "server.test",
            LIMITS,
            Clock.domain(),
            &budget,
        )
        .unwrap();
        let mut stream = rsnetwork_tokio::tls::Stream::new(core, tcp, support::pool(&budget)).unwrap();
        stream.handshake().await.unwrap();
        let derived = material(|output| stream.export(LABEL, CONTEXT, output));
        derived_tx.send(()).unwrap();
        assert!(derived.is_ok() && derived == serving.await.unwrap(), "TLS stream");
    });
}
