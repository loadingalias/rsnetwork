//! Exchange one MiB in each direction with an independent QUIC peer on loopback.
//! Run `cargo run --locked --example quic_interop -- server 127.0.0.1:0` to accept one connection.
//! For the client, pass `client` and the listening address of the peer.
//! The client opens stream zero. Each end sends 262,144 little-endian words and a FIN.
//! Each word is its zero-based index XOR `0x43524551` in the request or `0x53524553` in the response.
//! The independent peer closes with application code `0x321` as client or `0x322` as server.

use core::error::Error;
use core::net::{Ipv4Addr, SocketAddr};
use core::num::NonZeroU64;
use std::io::{self, Write as _};
use std::net::UdpSocket;
use std::sync::Arc;

use rsnetwork::buffer::{Buffer as _, Lease};
use rsnetwork::capacity::Budget;
use rsnetwork::quic::frame::Direction;
use rsnetwork::quic::packet::Side;
use rsnetwork::quic::{Connection, Event, Limits, PeerClose, StreamId};
use rsnetwork::tls::{
    CertificateDer, ClientConfig, ClientOptions, DefaultTimeProvider, Entropy, Group, Identity, PrivateKeyDer,
    Resumption, ServerConfig, ServerOptions,
};

mod udp;

type Result<T> = core::result::Result<T, Box<dyn Error>>;
const BYTES: usize = 1 << 20;
const ALPN: &[u8] = b"rsnetwork-interop";
const REQUEST: u32 = 0x4352_4551;
const RESPONSE: u32 = 0x5352_4553;

/// Each four-byte little-endian word carries its index and a direction-specific mask.
fn payload(mask: u32) -> Vec<u8> {
    (0..u32::try_from(BYTES / 4).expect("the word count fits"))
        .flat_map(|index| (index ^ mask).to_le_bytes())
        .collect()
}

struct Exchange {
    side: Side,
    stream: Option<StreamId>,
    expected: Vec<u8>,
    received: usize,
    finished: bool,
}

impl Exchange {
    fn event(&mut self, conn: &mut Connection, event: Option<Event>) -> Result<()> {
        if self.side == Side::Client && self.stream.is_none() && conn.is_confirmed() {
            let id = conn
                .open(Direction::Bidirectional)?
                .ok_or("the peer refused the bidirectional stream")?;
            conn.send(id, Lease::from(payload(REQUEST)), true)?;
            self.stream = Some(id);
        }
        match event {
            Some(Event::Stream { stream, data, end }) => {
                if stream.get() != 0 || *self.stream.get_or_insert(stream) != stream || self.finished {
                    return Err("data arrived outside the one bidirectional stream".into());
                }
                let after = self.received + data.initialized();
                if self.expected.get(self.received..after) != Some(data.bytes()) {
                    return Err(format!("incorrect stream data at offset {}", self.received).into());
                }
                self.received = after;
                conn.release(stream, u64::try_from(data.initialized())?)?;
                if end {
                    if after != BYTES {
                        return Err(format!("stream ended at {after} bytes").into());
                    }
                    self.finished = true;
                    if self.side == Side::Server {
                        conn.send(stream, Lease::from(payload(RESPONSE)), true)?;
                    }
                }
            }
            Some(Event::Reset { .. } | Event::Stopped { .. } | Event::Unreliable(_)) => {
                return Err("the peer reset the stream, stopped it, or sent unreliable data".into());
            }
            _ => {}
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [role, address] = args.as_slice() else {
        return Err("expected client|server and a loopback address".into());
    };
    let address: SocketAddr = address.parse()?;
    if !address.is_ipv4() || !address.ip().is_loopback() {
        return Err("expected an IPv4 loopback address".into());
    }
    let budget = Budget::new(NonZeroU64::new(64 << 20).expect("positive connection budget"));
    let (client, server);
    let (socket, endpoint, side, expected, close) = match role.as_str() {
        "client" => {
            client = ClientConfig::new(ClientOptions {
                roots: &[CertificateDer::from(&include_bytes!("../tls/ca.der")[..])],
                identity: None,
                protocols: &[ALPN],
                resumption: Resumption::Off,
                budget: &budget,
                clock: Arc::new(DefaultTimeProvider),
                entropy: Entropy::System,
            })?;
            (
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?,
                udp::Endpoint::Client(&client, "server.test", address),
                Side::Client,
                RESPONSE,
                0x322,
            )
        }
        "server" => {
            server = ServerConfig::new(ServerOptions {
                identity: Identity {
                    chain: vec![CertificateDer::from(&include_bytes!("../tls/server.der")[..])],
                    key: PrivateKeyDer::try_from(&include_bytes!("../tls/server.key.der")[..])?,
                },
                client_roots: None,
                protocols: &[ALPN],
                resumption: Resumption::Off,
                budget: &budget,
                clock: Arc::new(DefaultTimeProvider),
                entropy: Entropy::System,
            })?;
            let socket = UdpSocket::bind(address)?;
            writeln!(io::stdout(), "LISTEN {}", socket.local_addr()?)?;
            io::stdout().flush()?;
            (socket, udp::Endpoint::Server(&server), Side::Server, REQUEST, 0x321)
        }
        _ => return Err("expected client or server".into()),
    };
    let mut exchange = Exchange {
        side,
        stream: None,
        expected: payload(expected),
        received: 0,
        finished: false,
    };
    let connection = udp::run(&socket, endpoint, Limits::DEFAULT, &budget, |conn, event| {
        exchange.event(conn, event)
    })?;
    let facts = connection.negotiated().ok_or("missing negotiated handshake")?;
    if !connection.is_confirmed() || facts.group != Group::X25519_MLKEM768 || facts.protocol != Some(ALPN) {
        return Err(format!("unexpected handshake parameters, group {:?}", facts.group).into());
    }
    if !exchange.finished || connection.peer_close() != Some(PeerClose::Application(close)) {
        return Err(format!(
            "received {} bytes, FIN {}, peer close {:?}",
            exchange.received,
            exchange.finished,
            connection.peer_close()
        )
        .into());
    }
    writeln!(
        io::stdout(),
        "rsnetwork {role} verified {BYTES} received bytes, sent {BYTES}, X25519MLKEM768, close {close:#x}"
    )?;
    Ok(())
}
