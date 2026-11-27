//! Qualifies the TLS key-exchange profiles against an independent OpenSSL peer.
#![cfg(test)]

#[expect(dead_code, reason = "this peer uses only the TLS fixtures")]
mod support;

use core::mem::DropGuard;
use core::net::SocketAddr;
use core::num::NonZeroUsize;
use core::time::Duration;
use std::io::{BufRead as _, BufReader, Read as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use rsnetwork::drive::{Error, Kind};
use rsnetwork::tls::{self, Authentication, ClassicalSelection, Group, Handshake, KeyExchangeProfile, StreamLimits};
use rsnetwork_tokio::{Clock, tls::Stream};
use support::PATIENCE;
use tokio::net::TcpStream;

const LIMITS: StreamLimits = StreamLimits {
    tls: support::TLS,
    queue: NonZeroUsize::new(16).unwrap(),
    handshake_timeout: Some(PATIENCE),
};

fn openssl(command: &str) -> Command {
    let mut peer = Command::new("openssl");
    peer.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/tls"))
        .arg(command)
        .stdin(Stdio::null());
    peer
}

type Peer = DropGuard<Child, fn(Child)>;

fn start(command: &mut Command) -> Peer {
    DropGuard::new(command.spawn().unwrap(), |mut child| {
        drop(child.kill());
        drop(child.wait());
    })
}

fn finished(peer: &mut Child) {
    let end = Instant::now() + PATIENCE;
    loop {
        if let Some(status) = peer.try_wait().unwrap() {
            assert!(status.success(), "OpenSSL exited with {status}");
            return;
        }
        assert!(Instant::now() < end, "OpenSSL did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Let OpenSSL bind an ephemeral port. A readiness connection would consume one of its handshakes.
fn server(groups: &str, connections: &str) -> (Peer, SocketAddr) {
    let mut peer = start(
        openssl("s_server")
            .args([
                "-accept",
                "127.0.0.1:0",
                "-cert",
                "server.der",
                "-key",
                "server.key.der",
                "-tls1_3",
                "-serverpref",
                "-groups",
                groups,
                "-naccept",
                connections,
                "-www",
            ])
            .stdout(Stdio::piped()),
    );
    let stdout = peer.stdout.take().unwrap();
    let (ready, wait) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut pipe = BufReader::new(stdout);
        let address = (&mut pipe)
            .take(4096)
            .lines()
            .map_while(Result::ok)
            .find_map(|line| line.strip_prefix("ACCEPT ")?.parse::<SocketAddr>().ok());
        drop(ready.send((address, pipe.into_inner())));
    });
    let (address, stdout) = wait
        .recv_timeout(PATIENCE)
        .expect("OpenSSL must report its listening address");
    reader.join().unwrap();
    peer.stdout = Some(stdout);
    (peer, address.expect("an OpenSSL ACCEPT line"))
}

async fn connect(
    address: SocketAddr,
    profile: KeyExchangeProfile,
) -> Result<(Group, Option<ClassicalSelection>, Handshake), Error> {
    let memory = support::budget();
    let config = support::client_with(&[b"http/1.1"], profile);
    let core = tls::Stream::connect(&config, "server.test", LIMITS, Clock.domain(), &memory)?;
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut stream = Stream::new(core, tcp, support::pool(&memory)).unwrap();
    let facts = stream.handshake().await?;
    assert_eq!(facts.peer.unwrap().authentication, Authentication::EcdsaP256);
    let result = (facts.group, facts.classical_selection, facts.handshake);
    stream.close().await?;
    Ok(result)
}

#[test]
#[ignore = "run separately on the Ubuntu 26.04 OpenSSL interop host"]
fn openssl_selects_classical_from_a_hybrid_offer_and_retries_for_the_missing_hybrid_share() {
    use KeyExchangeProfile::{Classical, Default, Strict};
    let version = openssl("version").output().unwrap();
    assert!(version.status.success());
    println!("{}", core::str::from_utf8(&version.stdout).unwrap().trim_end());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Each slash starts a lower preference group in OpenSSL. Both groups stay enabled.
            let (mut peer, address) = server("X25519/X25519MLKEM768", "3");
            for (profile, group, selection) in [
                (Strict, Group::X25519_MLKEM768, None),
                (Default, Group::X25519, Some(ClassicalSelection::PeerSelected)),
                (Classical, Group::X25519, Some(ClassicalSelection::ExplicitProfile)),
            ] {
                assert_eq!(
                    connect(address, profile).await.unwrap(),
                    (group, selection, Handshake::Full)
                );
            }
            finished(&mut peer);

            let (mut peer, address) = server("X25519", "1");
            assert_eq!(connect(address, Strict).await.unwrap_err().kind(), Kind::Unsupported);
            finished(&mut peer);

            let (listener, address) = support::listener().await;
            // OpenSSL offers both groups and sends an initial key share only for the starred group.
            let mut peer = start(
                openssl("s_client")
                    .args([
                        "-connect",
                        &address.to_string(),
                        "-tls1_3",
                        "-groups",
                        "X25519MLKEM768:*X25519",
                        "-servername",
                        "server.test",
                        "-verify_hostname",
                        "server.test",
                        "-verify_return_error",
                        "-CAstore",
                        "ca.der",
                        "-no-CAfile",
                        "-no-CApath",
                        "-attime",
                        "1798761600",
                        "-brief",
                    ])
                    .stdout(Stdio::null()),
            );
            let (tcp, _) = tokio::time::timeout(PATIENCE, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let memory = support::budget();
            let core = tls::Stream::accept(&support::server_config(), LIMITS, Clock.domain(), &memory).unwrap();
            let mut stream = Stream::new(core, tcp, support::pool(&memory)).unwrap();
            let facts = stream.handshake().await.unwrap();
            assert_eq!(
                (facts.group, facts.classical_selection, facts.handshake),
                (Group::X25519_MLKEM768, None, Handshake::Retried)
            );
            stream.close().await.unwrap();
            finished(&mut peer);
        });
}
