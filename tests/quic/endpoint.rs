//! The server listener processes real packets from the client engine.

use core::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use super::{CA, Pair, SERVER, at, budget, client_config, server_config};
use rsnetwork::drive::Progress;
use rsnetwork::quic::frame::Frame;
use rsnetwork::quic::packet::{self, Builder, Header, Outgoing, Side};
use rsnetwork::quic::params::{Parameters, PreferredAddress};
use rsnetwork::quic::{Connection, Endpoint, EndpointKeys, EndpointLimits, Handle, Limits, PeerClose, Route};
use rsnetwork::tls::{ClientConfig, Resumption, ServerConfig};

fn address(port: u16) -> SocketAddr {
    (Ipv4Addr::LOCALHOST, port).into()
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
    Connection::client(config, "server.test", Limits::DEFAULT, &budget(), at(0)).unwrap()
}

struct Admission {
    handle: Handle,
    validated: bool,
    retries: usize,
}

fn handshake(endpoint: &mut Endpoint, client: &mut Connection, addr: SocketAddr) -> Admission {
    let admission = exchange(endpoint, client, addr, super::Order::Sent);
    assert!(client.is_confirmed());
    admission
}

pub(super) fn validated_reversed_flight(
    config: &ClientConfig,
    server: &ServerConfig,
    limits: Limits,
) -> (Progress, Progress) {
    let keys = Arc::new(EndpointKeys::generate(server, 0).unwrap());
    let admission = EndpointLimits {
        retry_at: 0,
        connections_max: 1,
        handshakes_max: 1,
        ..EndpointLimits::default()
    };
    let mut endpoint = Endpoint::new(server, keys, 0, admission, limits, &budget()).unwrap();
    let mut client = client(config);
    let admitted = exchange(
        &mut endpoint,
        &mut client,
        address(443),
        super::Order::HandshakeReversed,
    );
    assert!(admitted.validated);
    (
        client.drive(at(0)).1.progress,
        endpoint
            .with_connection(admitted.handle, |c| c.drive(at(0)).1.progress)
            .unwrap(),
    )
}

fn exchange(endpoint: &mut Endpoint, client: &mut Connection, addr: SocketAddr, order: super::Order) -> Admission {
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
                return Admission {
                    handle,
                    validated,
                    retries,
                };
            }
            for packet in order.flight(flight) {
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
    let other_ip = (Ipv4Addr::new(127, 0, 0, 2), 4302).into();
    assert!(handshake(&mut endpoint, &mut third, other_ip).retries > 0);
    let mut other = Connection::client(&config, "other.test", Limits::DEFAULT, &budget(), at(0)).unwrap();
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
    Pair::give(&mut client, reply[..n].to_vec(), at(0));
    assert_eq!(client.peer_close(), Some(PeerClose::StatelessReset));
    assert!(Pair::send(&mut client, at(0)).is_empty());
    let end = client.drive(at(0)).1.deadline.unwrap().instant();
    assert!(matches!(client.drive(end).1.progress, Progress::Terminal(Err(_))));
}
