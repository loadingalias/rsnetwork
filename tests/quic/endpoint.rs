//! The server listener processes real packets from the client engine, also when the client moves
//! to a new local address.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroUsize;
use std::assert_matches;
use std::sync::Arc;

use super::{CA, CLIENT_PORT, Pair, SERVER, SERVER_PORT, at, budget, client_config, path, server_config};
use rsnetwork::buffer::Backing;
use rsnetwork::drive::{Kind, Progress};
use rsnetwork::quic::frame::Frame;
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Outgoing, Side};
use rsnetwork::quic::params::{Parameters, PreferredAddress};
use rsnetwork::quic::{
    Connection, ConnectionId, Endpoint, EndpointKeys, EndpointLimits, Handle, Limits, Path, PeerClose,
    REDEEMED_BYTES_DEFAULT, Route, ServerAddress,
};
use rsnetwork::time::Instant;
use rsnetwork::tls::{ClientConfig, Resumption, ServerConfig};

/// The path of the listener for a client at the port `port` of the loopback address.
fn address(port: u16) -> Path {
    path(SERVER_PORT, port)
}

fn configs() -> (ClientConfig, ServerConfig, Arc<EndpointKeys>) {
    let config = server_config(SERVER, &[], Resumption::Off);
    let keys = Arc::new(EndpointKeys::generate(&config, 2, REDEEMED_BYTES_DEFAULT).unwrap());
    (client_config(CA, Resumption::Off), config, keys)
}

fn listener(config: &ServerConfig, keys: &Arc<EndpointKeys>, retry_at: u16) -> Endpoint {
    let limits = EndpointLimits {
        connections_max: 4,
        handshakes_max: 2,
        retry_at,
        ..EndpointLimits::default()
    };
    Endpoint::new(config, keys.clone(), 37, limits, Limits::DEFAULT, &budget()).unwrap()
}

fn client(config: &ClientConfig) -> Connection {
    let route = path(CLIENT_PORT, SERVER_PORT);
    Connection::client(config, "server.test", route, Limits::DEFAULT, &budget(), at(0)).unwrap()
}

struct Admission {
    handle: Handle,
    validated: bool,
    retries: usize,
    /// The datagram of the client that the listener accepted.
    accepted: Vec<u8>,
}

fn handshake(endpoint: &mut Endpoint, client: &mut Connection, addr: Path) -> Admission {
    let mut admission = None;
    let mut retries = 0;
    let mut reply = [0; 1200];
    for _ in 0..64 {
        let to_server = Pair::send(client, at(0));
        let moved = !to_server.is_empty();
        for packet in to_server {
            let handle = match endpoint.route(addr, &packet, &mut reply, at(0)).unwrap() {
                Route::Accepted(h) => {
                    assert!(admission.is_none());
                    let validated = endpoint.with_connection(h, |c| c.address_validated()).unwrap();
                    admission = Some((h, validated, packet.clone()));
                    h
                }
                Route::Existing(h) => h,
                Route::Reply(n) => {
                    assert!(matches!(Header::parse(&reply[..n], 0), Ok(Header::Retry { .. })));
                    retries += 1;
                    Pair::give(client, reply[..n].to_vec(), at(0));
                    continue;
                }
                other => panic!("unexpected handshake route {other:?}"),
            };
            endpoint
                .with_connection(handle, |c| Pair::give(c, packet, at(0)))
                .unwrap();
        }
        if let Some((handle, validated, accepted)) = &admission {
            let flight = endpoint.with_connection(*handle, |c| Pair::send(c, at(0))).unwrap();
            if !moved && flight.is_empty() {
                assert!(client.is_confirmed());
                return Admission {
                    handle: *handle,
                    validated: *validated,
                    retries,
                    accepted: accepted.clone(),
                };
            }
            for packet in flight {
                Pair::give(client, packet, at(0));
            }
        }
    }
    panic!("the in-memory handshake did not finish")
}

#[test]
fn retry_validates_the_first_address_and_new_token_validates_a_repeat_connection_on_a_new_port() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 0);
    let mut first = client(&config);
    let first_admission = handshake(&mut endpoint, &mut first, address(4301));
    assert!(first_admission.validated && first_admission.retries > 0);
    let parameters = first.peer_parameters().unwrap();
    assert!(parameters.retry_source_cid.is_some());
    assert_ne!(parameters.original_destination_cid, parameters.retry_source_cid);
    let token = first.take_address_token().expect("the server issued a repeat token");
    let mut second = client(&config);
    second.use_address_token(token).unwrap();
    let second_admission = handshake(&mut endpoint, &mut second, address(4302));
    assert!(second_admission.validated);
    assert_eq!(second_admission.retries, 0);
    assert!(second.peer_parameters().unwrap().retry_source_cid.is_none());
    assert_eq!(
        endpoint.with_connection(second_admission.handle, |c| c
            .recovery()
            .amplification_blocked_round_trips),
        Some(0)
    );
    let token = second.take_address_token().unwrap();
    let mut third = client(&config);
    third.use_address_token(token).unwrap();
    let other_ip = Path {
        peer: (Ipv4Addr::new(127, 0, 0, 2), 4302).into(),
        ..address(4302)
    };
    assert!(handshake(&mut endpoint, &mut third, other_ip).retries > 0);
    let route = path(CLIENT_PORT, SERVER_PORT);
    let mut other = Connection::client(&config, "other.test", route, Limits::DEFAULT, &budget(), at(0)).unwrap();
    assert_eq!(
        other
            .use_address_token(third.take_address_token().unwrap())
            .unwrap_err()
            .kind(),
        rsnetwork::drive::Kind::Misuse
    );
}

#[test]
fn each_address_token_validates_one_handshake_and_a_copy_gets_normal_validation() {
    // Each listener asks each client for an address proof. The second listener is another worker
    // of the same service.
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 0);
    let mut first = client(&config);
    let retried = handshake(&mut endpoint, &mut first, address(4301));
    assert!(retried.validated && retried.retries > 0);
    let mut second = client(&config);
    second.use_address_token(first.take_address_token().unwrap()).unwrap();
    let repeated = handshake(&mut endpoint, &mut second, address(4302));
    assert!(repeated.validated && repeated.retries == 0);
    // A copy of the Initial with the Retry token, after its handshake: an invalid Retry token
    // drops (RFC 9000, section 8.1.3).
    let mut reply = [0; 1200];
    assert_eq!(
        endpoint
            .route(address(4301), &retried.accepted, &mut reply, at(0))
            .unwrap(),
        Route::Dropped
    );
    // A copy of the Initial with the NEW_TOKEN token, from another port, at the other worker:
    // that worker asks for a proof again.
    let limits = EndpointLimits {
        retry_at: 0,
        ..EndpointLimits::default()
    };
    let mut other = Endpoint::new(&server, keys, 38, limits, Limits::DEFAULT, &budget()).unwrap();
    let route = other
        .route(address(4303), &repeated.accepted, &mut reply, at(0))
        .unwrap();
    let Route::Reply(len) = route else {
        panic!("a copy of a token gets a Retry, not {route:?}");
    };
    assert_matches!(Header::parse(&reply[..len], 0), Ok(Header::Retry { .. }));
}

#[test]
fn the_retry_threshold_keeps_the_last_handshake_slot_for_a_validated_address() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 1);
    let packet = Pair::send(&mut client(&config), at(0)).remove(0);
    let mut reply = [0; 1200];
    let Header::Protected { dcid, scid, .. } = Header::parse(&packet, 0).unwrap() else {
        panic!("client Initial")
    };
    let mut short = [0; 1199];
    let hdr = Outgoing::Initial {
        dcid: &dcid,
        scid: &scid,
        token: &[],
    };
    let mut builder = Builder::new(&mut short, hdr, 0, 2).unwrap();
    builder.frame(&Frame::Ping).unwrap();
    builder.pad_to(1199).unwrap();
    let n = builder.seal(&packet::initial_keys(&dcid, Side::Client).local).unwrap();
    assert_eq!(
        endpoint.route(address(4301), &short[..n], &mut reply, at(0)).unwrap(),
        Route::Dropped
    );
    assert!(matches!(
        endpoint.route(address(4301), &packet, &mut reply, at(0)).unwrap(),
        Route::Accepted(_)
    ));
    let next = handshake(&mut endpoint, &mut client(&config), address(4302));
    assert!(next.validated && next.retries > 0);
}

#[test]
fn packet_and_parameter_diagnostics_keep_address_and_reset_tokens_private() {
    let secret = [191u8; 16];
    let id = rsnetwork::quic::ConnectionId::new(&[4; 8]).unwrap();
    let preferred = PreferredAddress {
        ipv4: ([0; 4], 0),
        ipv6: ([0; 16], 0),
        connection_id: id,
        reset_token: secret,
    };
    let params = Parameters {
        stateless_reset_token: Some(secret),
        preferred_address: Some(preferred),
        ..Parameters::default()
    };
    let outgoing = Outgoing::Initial {
        dcid: &id,
        scid: &id,
        token: &secret,
    };
    let mut buffer = [0; 1200];
    let mut builder = Builder::new(&mut buffer, outgoing, 0, 2).unwrap();
    builder.frame(&Frame::NewToken { token: &secret }).unwrap();
    let marker = format!("{secret:?}");
    assert!(marker.contains("191"));
    for diagnostic in [
        format!("{preferred:?}"),
        format!("{params:?}"),
        format!("{outgoing:?}"),
        format!("{builder:?}"),
    ] {
        assert!(!diagnostic.contains("191"), "the diagnostic exposed a credential");
    }
}

#[test]
fn full_handshake_admission_still_routes_an_established_connection_and_releases_removed_slots() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let mut established = client(&config);
    let admitted = handshake(&mut endpoint, &mut established, address(4301));
    assert!(!admitted.validated);
    assert_eq!(admitted.retries, 0);
    let mut reply = [0; 1200];
    let mut pending = Vec::new();
    for port in [4302, 4303] {
        let packet = Pair::send(&mut client(&config), at(0)).remove(0);
        let Route::Accepted(h) = endpoint.route(address(port), &packet, &mut reply, at(0)).unwrap() else {
            panic!("one handshake slot was available")
        };
        assert_eq!(
            endpoint.route(address(port), &packet, &mut reply, at(0)).unwrap(),
            Route::Existing(h)
        );
        pending.push(h);
    }
    let waiting = Pair::send(&mut client(&config), at(0)).remove(0);
    assert_eq!(
        endpoint.route(address(4304), &waiting, &mut reply, at(0)).unwrap(),
        Route::Refused
    );
    established.ping();
    let ping = Pair::send(&mut established, at(0)).remove(0);
    assert_eq!(
        endpoint.route(address(4301), &ping, &mut reply, at(0)).unwrap(),
        Route::Existing(admitted.handle)
    );
    let ack = endpoint
        .with_connection(admitted.handle, |c| {
            Pair::give(c, ping, at(0));
            Pair::send(c, at(0))
        })
        .unwrap();
    assert!(!ack.is_empty());
    for packet in ack {
        Pair::give(&mut established, packet, at(0));
    }
    assert_eq!(established.recovery().bytes_in_flight, 0);
    assert!(endpoint.remove(pending[0]));
    assert!(matches!(
        endpoint.route(address(4304), &waiting, &mut reply, at(0)).unwrap(),
        Route::Accepted(_)
    ));
    assert!(!endpoint.remove(pending[0]));
}

#[test]
fn initials_from_one_peer_address_to_two_local_addresses_start_two_connections() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    // A second address of the listener gets the same Initial: the same peer and connection ID.
    let first = address(4301);
    let second = Path {
        local: (Ipv4Addr::new(127, 0, 0, 2), SERVER_PORT).into(),
        ..first
    };
    let packet = Pair::send(&mut client(&config), at(0)).remove(0);
    let mut reply = [0; 1200];
    let mut handles = Vec::new();
    for path in [first, second] {
        let Route::Accepted(h) = endpoint.route(path, &packet, &mut reply, at(0)).unwrap() else {
            panic!("each local address starts its own connection")
        };
        handles.push(h);
    }
    assert_ne!(handles[0], handles[1]);
    for (path, h) in [first, second].into_iter().zip(handles) {
        assert_eq!(
            endpoint.route(path, &packet, &mut reply, at(0)).unwrap(),
            Route::Existing(h)
        );
    }
}

#[test]
fn retired_connection_ids_leave_the_route_and_a_stateless_reset_drains_the_peer() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let mut client = client(&config);
    let addr = address(4301);
    let h = handshake(&mut endpoint, &mut client, addr).handle;
    let old = client.peer_parameters().unwrap().initial_source_cid.unwrap();
    let old_ids = endpoint.with_connection(h, |c| c.local_ids()).unwrap();
    assert!(old_ids.into_iter().flatten().all(|id| keys.worker(&id) == Some(37)));
    let mut reply = [0; 1200];
    client.ping();
    let delayed = Pair::send(&mut client, at(0)).remove(0);
    assert_eq!(
        endpoint.route(addr, &delayed, &mut reply, at(0)).unwrap(),
        Route::Existing(h)
    );
    assert!(client.rotate_peer_id().unwrap());
    for packet in Pair::send(&mut client, at(0)) {
        assert_eq!(
            endpoint.route(addr, &packet, &mut reply, at(0)).unwrap(),
            Route::Existing(h)
        );
        endpoint.with_connection(h, |c| Pair::give(c, packet, at(0))).unwrap();
    }
    let new_ids = endpoint.with_connection(h, |c| c.local_ids()).unwrap();
    assert!(!new_ids.contains(&Some(old)));
    assert_eq!(new_ids.into_iter().flatten().count(), 2);
    assert!(new_ids.into_iter().flatten().all(|id| keys.worker(&id) == Some(37)));
    assert!(matches!(
        endpoint.route(addr, &delayed, &mut reply, at(0)).unwrap(),
        Route::Reply(_)
    ));
    // The listener loses its state, and a replacement takes its worker number.
    drop(endpoint);
    let mut replacement = listener(&server, &keys, 2);
    client.ping();
    let packet = Pair::send(&mut client, at(0)).remove(0);
    let Route::Reply(n) = replacement.route(addr, &packet, &mut reply, at(0)).unwrap() else {
        panic!("a listener that lost state sends a reset")
    };
    assert!((21..packet.len()).contains(&n));
    let mut other = reply[..n].to_vec();
    other[n - 1] ^= 1;
    Pair::give(&mut client, other, at(0));
    assert_eq!(client.peer_close(), None);
    // The token is valid only from the address that the client sent to (RFC 9000, section 10.3.1).
    let elsewhere = Path {
        peer: (Ipv4Addr::new(127, 0, 0, 2), SERVER_PORT).into(),
        ..client.path()
    };
    arrive(&mut client, elsewhere, reply[..n].to_vec(), at(0));
    assert_eq!(client.peer_close(), None);
    Pair::give(&mut client, reply[..n].to_vec(), at(0));
    assert_eq!(client.peer_close(), Some(PeerClose::StatelessReset));
    assert!(Pair::send(&mut client, at(0)).is_empty());
    let end = client.drive(at(0)).1.deadline.unwrap().instant();
    assert!(matches!(client.drive(end).1.progress, Progress::Terminal(Err(_))));
}

#[test]
fn one_live_listener_holds_each_worker_and_a_listener_of_another_worker_resets_no_live_connection() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let mut client = client(&config);
    let addr = address(4301);
    handshake(&mut endpoint, &mut client, addr);
    // A second listener of the same worker would reset each connection of the first one.
    let limits = EndpointLimits::default();
    let second = Endpoint::new(&server, keys.clone(), 37, limits, Limits::DEFAULT, &budget());
    assert_matches!(second, Err(error) if error.kind() == Kind::Misuse);
    // A listener of another worker takes over while the first one drains: a packet of the live
    // connection that reaches it gets no reset.
    let mut next = Endpoint::new(&server, keys.clone(), 38, limits, Limits::DEFAULT, &budget()).unwrap();
    client.ping();
    let packet = Pair::send(&mut client, at(0)).remove(0);
    let mut reply = [0; 1200];
    assert_eq!(next.route(addr, &packet, &mut reply, at(0)).unwrap(), Route::Dropped);
    // The first listener ends, and its worker number is free again.
    drop(endpoint);
    Endpoint::new(&server, keys, 37, limits, Limits::DEFAULT, &budget()).unwrap();
}

#[test]
fn a_stateless_reset_stops_the_copies_of_the_close_of_a_closing_end() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let mut client = client(&config);
    let addr = address(4301);
    let h = handshake(&mut endpoint, &mut client, addr).handle;
    // A datagram of the server that arrives late, and the reset of a listener that lost its state.
    client.ping();
    let ping = Pair::send(&mut client, at(0)).remove(0);
    let late = endpoint
        .with_connection(h, |c| {
            Pair::give(c, ping.clone(), at(0));
            Pair::send(c, at(0))
        })
        .unwrap();
    assert!(!late.is_empty());
    drop(endpoint);
    let mut reply = [0; 1200];
    let Route::Reply(n) = listener(&server, &keys, 2)
        .route(addr, &ping, &mut reply, at(0))
        .unwrap()
    else {
        panic!("a listener that lost state sends a reset")
    };
    client.close(7, at(0)).unwrap();
    assert_eq!(Pair::send(&mut client, at(0)).len(), 1);
    // The reset ends the copies of the frame: the client sends nothing more (RFC 9000, section
    // 10.3.1). It keeps the outcome of its own close.
    Pair::give(&mut client, reply[..n].to_vec(), at(0));
    for datagram in late {
        Pair::give(&mut client, datagram, at(0));
    }
    assert!(Pair::send(&mut client, at(0)).is_empty());
    let end = client.drive(at(0)).1.deadline.unwrap().instant();
    assert_eq!(client.drive(end).1.progress, Progress::Terminal(Ok(())));
}

/// The same path, as the other end names it.
fn mirror(route: Path) -> Path {
    Path {
        local: route.peer,
        peer: route.local,
    }
}

/// Each datagram that `connection` sends at `now`, with its path, after its timers at `now`.
fn routed(connection: &mut Connection, now: Instant) -> Vec<(Path, Vec<u8>)> {
    for _ in 0..64 {
        let (event, turn) = connection.drive(now);
        if event.is_none() && turn.progress != Progress::Pending {
            break;
        }
    }
    let mut datagrams = Vec::new();
    let mut out = vec![0; 1500];
    for _ in 0..64 {
        match connection.transmit(&mut out, NonZeroUsize::MIN, now).unwrap() {
            Some(sent) => datagrams.push((sent.path, out[..sent.len].to_vec())),
            None => return datagrams,
        }
    }
    panic!("a connection sends at most 64 datagrams at once");
}

/// Gives `datagram` to `connection` as a datagram that arrived on `route` at `now`.
fn arrive(connection: &mut Connection, route: Path, datagram: Vec<u8>, now: Instant) {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram), None, len);
    for _ in 0..64 {
        let (event, turn) = connection.receive(&mut datagrams, route, now);
        if event.is_none() && turn.progress != Progress::Pending {
            return;
        }
    }
    panic!("a datagram gives at most 64 events");
}

/// The path of each 1-RTT datagram of one direction, as its sender names it, with the destination
/// connection ID of the datagram.
type Sent = Vec<(Path, ConnectionId)>;

/// Moves the datagrams between `client` and its connection in `endpoint` until none moves, each
/// on the path that its sender names. Gives the datagrams of the client, and of the server.
fn shuttle(endpoint: &mut Endpoint, handle: Handle, client: &mut Connection) -> (Sent, Sent) {
    exchange(endpoint, handle, client, at(0), None)
}

/// The destination connection ID of a 1-RTT datagram whose IDs have `len` bytes.
fn destination(datagram: &[u8], len: usize) -> ConnectionId {
    match Header::parse(datagram, len) {
        Ok(Header::Protected { dcid, .. }) => dcid,
        _ => panic!("a 1-RTT packet"),
    }
}

/// Moves the datagrams as [`shuttle`] does, at `now`. Each datagram of the client to the address
/// `lost` drops on its way.
fn exchange(
    endpoint: &mut Endpoint,
    handle: Handle,
    client: &mut Connection,
    now: Instant,
    lost: Option<SocketAddr>,
) -> (Sent, Sent) {
    let (mut up, mut down) = (Vec::new(), Vec::new());
    let mut reply = [0; 1200];
    for _ in 0..64 {
        let to_server = routed(client, now);
        let moved = !to_server.is_empty();
        for (route, datagram) in to_server {
            // The connection IDs of the listener have 17 bytes.
            up.push((route, destination(&datagram, 17)));
            if Some(route.peer) == lost {
                continue;
            }
            let listener = endpoint.route(mirror(route), &datagram, &mut reply, now).unwrap();
            assert_eq!(listener, Route::Existing(handle));
            endpoint
                .with_connection(handle, |c| arrive(c, mirror(route), datagram, now))
                .unwrap();
        }
        let to_client = endpoint.with_connection(handle, |c| routed(c, now)).unwrap();
        if !moved && to_client.is_empty() {
            return (up, down);
        }
        for (route, datagram) in to_client {
            down.push((route, destination(&datagram, client.local_cid().as_bytes().len())));
            arrive(client, mirror(route), datagram, now);
        }
    }
    panic!("the connection is not quiet after 64 rounds");
}

/// The port of the preferred address of the listener, on the loopback address.
const PREFERRED_PORT: u16 = 8443;

/// A listener that gives the preferred address at [`PREFERRED_PORT`], and a client at
/// [`CLIENT_PORT`] with `limits` after its handshake.
fn preferred(limits: Limits) -> (Endpoint, Handle, Connection) {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let preferred = SocketAddrV4::new(Ipv4Addr::LOCALHOST, PREFERRED_PORT);
    endpoint.prefer(Some(preferred), None).unwrap();
    let route = path(CLIENT_PORT, SERVER_PORT);
    let mut client = Connection::client(&config, "server.test", route, limits, &budget(), at(0)).unwrap();
    // Each datagram goes on the path that its sender names, and the handshake ends when the
    // client is confirmed, before its next datagram.
    let mut reply = [0; 1200];
    let mut accepted = None;
    for _ in 0..64 {
        for (route, datagram) in routed(&mut client, at(0)) {
            let handle = match endpoint.route(mirror(route), &datagram, &mut reply, at(0)).unwrap() {
                Route::Accepted(handle) | Route::Existing(handle) => handle,
                other => panic!("unexpected handshake route {other:?}"),
            };
            accepted = Some(handle);
            endpoint
                .with_connection(handle, |c| arrive(c, mirror(route), datagram, at(0)))
                .unwrap();
        }
        let handle = accepted.unwrap();
        for (route, datagram) in endpoint.with_connection(handle, |c| routed(c, at(0))).unwrap() {
            arrive(&mut client, mirror(route), datagram, at(0));
        }
        if client.is_confirmed() {
            return (endpoint, handle, client);
        }
    }
    panic!("the in-memory handshake did not finish")
}

/// Gives each datagram of `datagrams` to the connection of `endpoint` on the path that `sent`, the
/// path of its sender, mirrors.
fn give_server(endpoint: &mut Endpoint, handle: Handle, datagrams: Vec<(Path, Vec<u8>)>, sent: Path) {
    let mut reply = [0; 1200];
    for (_, datagram) in datagrams {
        let listener = endpoint.route(mirror(sent), &datagram, &mut reply, at(0)).unwrap();
        assert_eq!(listener, Route::Existing(handle));
        endpoint
            .with_connection(handle, |c| arrive(c, mirror(sent), datagram, at(0)))
            .unwrap();
    }
}

#[test]
fn a_client_validates_the_preferred_address_moves_there_and_the_server_follows_after_its_own_validation() {
    let (mut endpoint, handle, mut client) = preferred(Limits::DEFAULT);
    let (home, there) = (path(CLIENT_PORT, SERVER_PORT), path(CLIENT_PORT, PREFERRED_PORT));
    let server_path = |endpoint: &mut Endpoint| endpoint.with_connection(handle, |c| c.path()).unwrap();
    // After the handshake, the client sends one PATH_CHALLENGE to the preferred address, and it
    // stays on its path until the answer (RFC 9000, section 9.6.1).
    let (probe, acks): (Vec<_>, Vec<_>) = routed(&mut client, at(0))
        .into_iter()
        .partition(|(route, _)| *route == there);
    assert!(acks.iter().all(|(route, _)| *route == home));
    give_server(&mut endpoint, handle, acks, home);
    assert_eq!((probe.len(), probe[0].1.len(), client.path()), (1, 1200, home));
    let (old_up, probe_up) = (
        endpoint.with_connection(handle, |c| *c.local_cid()).unwrap(),
        destination(&probe[0].1, 17),
    );
    assert_ne!(
        old_up, probe_up,
        "the probe takes the connection ID of the preferred address"
    );
    // The server answers from the address that the challenge arrived at, in a datagram of 1,200
    // bytes, and acknowledges on its path, where it stays.
    give_server(&mut endpoint, handle, probe, there);
    let answer = endpoint.with_connection(handle, |c| routed(c, at(0))).unwrap();
    let from = |datagrams: &[(Path, Vec<u8>)], route| {
        let sent = datagrams.iter().filter(|(sent, _)| *sent == route);
        sent.map(|(_, datagram)| datagram.len()).collect::<Vec<_>>()
    };
    assert_eq!(from(&answer, mirror(there)), [1200]);
    assert_eq!(from(&answer, mirror(home)).len() + 1, answer.len());
    assert_eq!(server_path(&mut endpoint), mirror(home));
    for (route, datagram) in answer {
        arrive(&mut client, mirror(route), datagram, at(0));
    }
    assert_eq!(client.path(), there);
    // The first packet of the client that is not a probe arrives there. The server then
    // validates the path from its preferred address, and sends from its first address until the
    // answer (RFC 9000, section 9.6.2).
    let moved = routed(&mut client, at(0));
    assert!(!moved.is_empty() && moved.iter().all(|(route, _)| *route == there));
    give_server(&mut endpoint, handle, moved, there);
    assert_eq!(server_path(&mut endpoint), mirror(home));
    exchange(&mut endpoint, handle, &mut client, at(0), None);
    assert_eq!((client.path(), server_path(&mut endpoint)), (there, mirror(there)));
    // The connection goes on there. The client retired the connection ID of the handshake, and
    // the listener routes it no more.
    client.ping();
    let (up, down) = exchange(&mut endpoint, handle, &mut client, at(0), None);
    assert!(!up.is_empty() && up.iter().all(|(route, id)| *route == there && *id != old_up));
    assert!(!down.is_empty() && down.iter().all(|(route, _)| *route == mirror(there)));
    let ids = endpoint.with_connection(handle, |c| c.local_ids()).unwrap();
    assert!(!ids.contains(&Some(old_up)));
}

#[test]
fn a_client_that_gets_no_answer_from_the_preferred_address_stays_on_the_handshake_address() {
    let (mut endpoint, handle, mut client) = preferred(Limits::DEFAULT);
    let (home, there) = (path(CLIENT_PORT, SERVER_PORT), path(CLIENT_PORT, PREFERRED_PORT));
    let mut probes = 0;
    for ms in (0..=4000).step_by(100) {
        client.ping();
        let (up, down) = exchange(&mut endpoint, handle, &mut client, at(ms), Some(there.peer));
        probes += up.iter().filter(|(route, _)| *route == there).count();
        // Each packet that is not a probe goes on the path of the handshake, and its answer comes
        // back there (RFC 9000, section 9.6.1).
        assert_eq!(client.path(), home, "at {ms} ms");
        assert!(up.iter().any(|(route, _)| *route == home) && down.iter().all(|(route, _)| *route == mirror(home)));
        if ms == 500 {
            // The two connection IDs of the server are on the path of the handshake and on the
            // probe, so no third path has an ID (RFC 9000, section 9.5).
            assert_eq!(client.migrate(path(4400, SERVER_PORT), at(ms)), Ok(false));
        }
    }
    // One challenge for each probe timeout of at least 999 ms, until three timeouts end.
    assert!((2..=4).contains(&probes), "{probes} probes");
    // The client retired the ID of the probe. The new ID of the server lets the client move.
    assert_eq!(client.migrate(path(4400, SERVER_PORT), at(4000)), Ok(true));
}

#[test]
fn a_server_on_its_preferred_address_drops_newer_packets_that_arrive_at_its_first_address() {
    let (mut endpoint, handle, mut client) = preferred(Limits::DEFAULT);
    let (home, there) = (path(CLIENT_PORT, SERVER_PORT), path(CLIENT_PORT, PREFERRED_PORT));
    exchange(&mut endpoint, handle, &mut client, at(0), None);
    let server_path = |endpoint: &mut Endpoint| endpoint.with_connection(handle, |c| c.path()).unwrap();
    assert_eq!(server_path(&mut endpoint), mirror(there));
    // A copy of a newer packet arrives at the first address: the server drops it, stays, and
    // answers nothing there (RFC 9000, section 9.6.2).
    client.ping();
    let newer = routed(&mut client, at(0));
    give_server(&mut endpoint, handle, newer.clone(), home);
    assert_eq!(server_path(&mut endpoint), mirror(there));
    let after = endpoint.with_connection(handle, |c| routed(c, at(0))).unwrap();
    assert!(after.is_empty(), "{} datagrams", after.len());
    // The same packet still counts at the preferred address.
    give_server(&mut endpoint, handle, newer, there);
    let answer = endpoint.with_connection(handle, |c| routed(c, at(0))).unwrap();
    assert!(!answer.is_empty() && answer.iter().all(|(route, _)| *route == mirror(there)));
}

#[test]
fn a_client_that_keeps_the_handshake_address_sends_nothing_to_the_preferred_address() {
    let limits = Limits {
        server_address: ServerAddress::Handshake,
        ..Limits::DEFAULT
    };
    let (mut endpoint, handle, mut client) = preferred(limits);
    client.ping();
    let (up, _) = exchange(&mut endpoint, handle, &mut client, at(0), None);
    let home = path(CLIENT_PORT, SERVER_PORT);
    assert!(!up.is_empty() && up.iter().all(|(route, _)| *route == home));
    assert_eq!(client.path(), home);
}

#[test]
fn a_client_moves_to_a_new_local_address_with_new_connection_ids_and_the_listener_follows() {
    let (config, server, keys) = configs();
    let mut endpoint = listener(&server, &keys, 2);
    let mut client = client(&config);
    let handle = handshake(&mut endpoint, &mut client, address(CLIENT_PORT)).handle;
    let home = path(CLIENT_PORT, SERVER_PORT);
    // The connection ID of each direction on the first path.
    client.ping();
    let (up, down) = shuttle(&mut endpoint, handle, &mut client);
    let (old_up, old_down) = (up[0].1, down[0].1);
    assert!(up.iter().all(|sent| *sent == (home, old_up)));
    assert!(down.iter().all(|sent| *sent == (mirror(home), old_down)));

    // The client moves to a new local port. The listener keeps the route of the connection.
    let moved = path(4400, SERVER_PORT);
    assert_eq!(client.migrate(moved, at(0)), Ok(true));
    let (up, down) = shuttle(&mut endpoint, handle, &mut client);
    assert_eq!(client.path(), moved);
    let followed = endpoint.with_connection(handle, |c| (c.path(), c.address_validated()));
    assert_eq!(followed, Some((mirror(moved), true)));
    // Each end uses a connection ID on the new path that the old path did not show, and the old
    // one only on the old path (RFC 9000, section 9.5).
    assert!(up.iter().any(|(route, _)| *route == moved));
    assert!(up.iter().all(|(route, id)| (*route == home) == (*id == old_up)));
    assert!(
        down.iter()
            .all(|(route, id)| (*route == mirror(home)) == (*id == old_down))
    );
    // The server asked the path that the client left, one time. The validation of the new path
    // came with it, and the client retired the connection ID of the old path. Thus the client
    // has no connection ID for an answer there (RFC 9000, section 9.5).
    assert_eq!(down.iter().filter(|(route, _)| *route == mirror(home)).count(), 1);
    assert_eq!(up.iter().filter(|(route, _)| *route == home).count(), 0);
    // After its validation, the client retired the connection ID of the old path, and the
    // listener routes that ID no more.
    let ids = endpoint.with_connection(handle, |c| c.local_ids()).unwrap();
    assert!(!ids.contains(&Some(old_up)));
    assert_eq!(ids.into_iter().flatten().count(), 2);

    // The connection goes on, on the new path only.
    client.ping();
    let (up, down) = shuttle(&mut endpoint, handle, &mut client);
    assert!(!up.is_empty() && up.iter().all(|(route, id)| *route == moved && *id != old_up));
    assert!(
        !down.is_empty()
            && down
                .iter()
                .all(|(route, id)| *route == mirror(moved) && *id != old_down)
    );
}
