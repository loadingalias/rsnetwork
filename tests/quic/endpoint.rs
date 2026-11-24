//! The server listener processes real packets from the client engine, also when the client moves
//! to a new local address.

use core::net::Ipv4Addr;
use std::sync::Arc;

use super::{CA, CLIENT_PORT, Pair, SERVER, SERVER_PORT, at, budget, client_config, path, server_config};
use rsnetwork::buffer::Backing;
use rsnetwork::drive::Progress;
use rsnetwork::quic::frame::Frame;
use rsnetwork::quic::packet::{self, Builder, Datagrams, Header, Outgoing, Side};
use rsnetwork::quic::params::{Parameters, PreferredAddress};
use rsnetwork::quic::{
    Connection, ConnectionId, Endpoint, EndpointKeys, EndpointLimits, Handle, Limits, Path, PeerClose, Route,
};
use rsnetwork::tls::{ClientConfig, Resumption, ServerConfig};

/// The path of the listener for a client at the port `port` of the loopback address.
fn address(port: u16) -> Path {
    path(SERVER_PORT, port)
}

fn configs() -> (ClientConfig, ServerConfig, Arc<EndpointKeys>) {
    let config = server_config(SERVER, &[], Resumption::Off);
    let keys = Arc::new(EndpointKeys::generate(&config, 2).unwrap());
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
                    admission = Some((h, endpoint.with_connection(h, |c| c.address_validated()).unwrap()));
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
        if let Some((handle, validated)) = admission {
            let flight = endpoint.with_connection(handle, |c| Pair::send(c, at(0))).unwrap();
            if !moved && flight.is_empty() {
                assert!(client.is_confirmed());
                return Admission {
                    handle,
                    validated,
                    retries,
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
    arrive(&mut client, elsewhere, reply[..n].to_vec());
    assert_eq!(client.peer_close(), None);
    Pair::give(&mut client, reply[..n].to_vec(), at(0));
    assert_eq!(client.peer_close(), Some(PeerClose::StatelessReset));
    assert!(Pair::send(&mut client, at(0)).is_empty());
    let end = client.drive(at(0)).1.deadline.unwrap().instant();
    assert!(matches!(client.drive(end).1.progress, Progress::Terminal(Err(_))));
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
    let mut reply = [0; 1200];
    let Route::Reply(n) = listener(&server, &keys, 2)
        .route(addr, &ping, &mut reply, at(0))
        .unwrap()
    else {
        panic!("a listener that lost state sends a reset")
    };
    let late = endpoint
        .with_connection(h, |c| {
            Pair::give(c, ping, at(0));
            Pair::send(c, at(0))
        })
        .unwrap();
    assert!(!late.is_empty());
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

/// Each datagram that `connection` sends now, with its path.
fn routed(connection: &mut Connection) -> Vec<(Path, Vec<u8>)> {
    let mut datagrams = Vec::new();
    let mut out = vec![0; 1500];
    for _ in 0..64 {
        match connection.transmit(&mut out, at(0)).unwrap() {
            Some(sent) => datagrams.push((sent.path, out[..sent.len].to_vec())),
            None => return datagrams,
        }
    }
    panic!("a connection sends at most 64 datagrams at once");
}

/// Gives `datagram` to `connection` as a datagram that arrived on `route`.
fn arrive(connection: &mut Connection, route: Path, datagram: Vec<u8>) {
    let len = connection.local_cid().as_bytes().len();
    let mut datagrams = Datagrams::new(Backing::from(datagram), None, len);
    for _ in 0..64 {
        let (event, turn) = connection.receive(&mut datagrams, route, at(0));
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
    let destination = |datagram: &[u8], len| match Header::parse(datagram, len) {
        Ok(Header::Protected { dcid, .. }) => dcid,
        _ => panic!("a 1-RTT packet"),
    };
    let (mut up, mut down) = (Vec::new(), Vec::new());
    let mut reply = [0; 1200];
    for _ in 0..64 {
        let to_server = routed(client);
        let moved = !to_server.is_empty();
        for (route, datagram) in to_server {
            let listener = endpoint.route(mirror(route), &datagram, &mut reply, at(0)).unwrap();
            assert_eq!(listener, Route::Existing(handle));
            // The connection IDs of the listener have 17 bytes.
            up.push((route, destination(&datagram, 17)));
            endpoint
                .with_connection(handle, |c| arrive(c, mirror(route), datagram))
                .unwrap();
        }
        let to_client = endpoint.with_connection(handle, routed).unwrap();
        if !moved && to_client.is_empty() {
            return (up, down);
        }
        for (route, datagram) in to_client {
            down.push((route, destination(&datagram, client.local_cid().as_bytes().len())));
            arrive(client, mirror(route), datagram);
        }
    }
    panic!("the connection is not quiet after 64 rounds");
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
