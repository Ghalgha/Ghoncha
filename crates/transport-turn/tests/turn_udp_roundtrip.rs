use core::net::SocketAddr;
use std::time::Duration;

use ghoncha_transport_api::MonotonicTime;
use ghoncha_transport_turn::TurnUdpEngine;
use turn_client_proto::udp::{TurnEvent, TurnPollRet, TurnRecvRet};
use turn_client_proto::types::Instant;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_server_proto::server::TurnServer;
use turn_server_proto::stun::agent::Transmit;
use turn_server_proto::types::{AddressFamily, TransportType};

fn instant(now: MonotonicTime) -> Instant {
    Instant::from_nanos(i64::try_from(now.0).unwrap())
}

fn advance_client(engine: &mut TurnUdpEngine, now: MonotonicTime) -> MonotonicTime {
    match engine.poll(now).unwrap() {
        TurnPollRet::WaitUntil(next) => MonotonicTime(next.as_nanos() as u64),
        _ => panic!("unexpected TURN client poll result"),
    }
}

fn exchange_client_request(
    engine: &mut TurnUdpEngine,
    server: &mut TurnServer,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    relay_v4: SocketAddr,
    relay_v6: SocketAddr,
    now: MonotonicTime,
) -> Vec<Transmit<Vec<u8>>> {
    let outgoing = engine
        .poll_transmit(now)
        .unwrap()
        .expect("client should have a TURN request ready");
    let incoming = Transmit::new(
        outgoing.data.as_ref(),
        TransportType::Udp,
        server_addr,
        client_addr,
    );

    let mut responses = Vec::new();
    if let Some(response) = server.recv(incoming, instant(now)) {
        responses.push(response.build());
    }

    loop {
        match server.poll(instant(now)) {
            TurnServerPollRet::AllocateSocket {
                transport,
                listen_addr,
                client_addr,
                allocation_transport,
                family,
            } => {
                let relay_addr = match family {
                    AddressFamily::IPV4 => relay_v4,
                    AddressFamily::IPV6 => relay_v6,
                };
                server.allocated_socket(
                    transport,
                    listen_addr,
                    client_addr,
                    allocation_transport,
                    family,
                    Ok(relay_addr),
                    instant(now),
                );
            }
            TurnServerPollRet::WaitUntil(_) => break,
            _ => panic!("unexpected TURN server poll result"),
        }
    }

    while let Some(response) = server.poll_transmit(instant(now)) {
        responses.push(response);
    }

    responses
}

fn deliver_responses(
    engine: &mut TurnUdpEngine,
    server_addr: SocketAddr,
    responses: Vec<Transmit<Vec<u8>>>,
    now: MonotonicTime,
) {
    for response in responses {
        assert!(matches!(
            engine
                .receive_from(server_addr, &response.data, now)
                .unwrap(),
            TurnRecvRet::Handled
        ));
    }
}

#[test]
fn turn_udp_allocation_permission_channel_and_peer_data_roundtrip() {
    let client_addr: SocketAddr = "192.0.2.10:40000".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.10:3478".parse().unwrap();
    let relay_v4: SocketAddr = "203.0.113.10:50000".parse().unwrap();
    let relay_v6: SocketAddr = "[2001:db8::10]:50001".parse().unwrap();
    let peer_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();

    let mut server = TurnServer::new(
        TransportType::Udp,
        server_addr,
        String::from("ghoncha-test-realm"),
    );
    server.add_user(
        String::from("ghoncha-test-user"),
        String::from("ghoncha-test-pass"),
    );
    server.set_nonce_expiry_duration(Duration::from_secs(30));

    let mut client = TurnUdpEngine::new(
        client_addr,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    let mut now = MonotonicTime(0);

    // Unauthenticated Allocate obtains the long-term credential challenge.
    let challenge = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_v4,
        relay_v6,
        now,
    );
    assert_eq!(challenge.len(), 1);
    deliver_responses(&mut client, server_addr, challenge, now);

    // Authenticated Allocate creates both requested address-family allocations.
    now = advance_client(&mut client, now);
    let allocation = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_v4,
        relay_v6,
        now,
    );
    assert!(!allocation.is_empty());
    deliver_responses(&mut client, server_addr, allocation, now);

    assert!(
        client
            .relayed_addresses()
            .any(|(transport, addr)| transport == TransportType::Udp && addr == relay_v4)
    );
    assert!(
        client
            .relayed_addresses()
            .any(|(transport, addr)| transport == TransportType::Udp && addr == relay_v6)
    );

    let mut saw_allocation = false;
    while let Some(event) = client.poll_event() {
        if matches!(event, TurnEvent::AllocationCreated(TransportType::Udp, _)) {
            saw_allocation = true;
        }
    }
    assert!(saw_allocation);

    // CreatePermission is scoped to the gateway peer IP.
    client.create_permission(peer_addr.ip(), now).unwrap();
    now = advance_client(&mut client, now);
    let permission = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_v4,
        relay_v6,
        now,
    );
    deliver_responses(&mut client, server_addr, permission, now);
    assert!(client.have_permission(peer_addr.ip()));

    // ChannelBind switches peer data from Send Indications to ChannelData.
    client.bind_channel(peer_addr, now).unwrap();
    now = advance_client(&mut client, now);
    let channel = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_v4,
        relay_v6,
        now,
    );
    deliver_responses(&mut client, server_addr, channel, now);

    let mut saw_channel = false;
    while let Some(event) = client.poll_event() {
        if matches!(event, TurnEvent::ChannelCreated(TransportType::Udp, addr) if addr == peer_addr)
        {
            saw_channel = true;
        }
    }
    assert!(saw_channel);

    // Client -> peer: the wrapper writes TURN framing into caller-owned memory.
    let payload = b"ghoncha-ping";
    let mut outbound_buffer = [0u8; 1500];
    let outbound = client
        .send_to_into(peer_addr, payload, now, &mut outbound_buffer)
        .unwrap();
    assert_eq!(outbound.destination, server_addr);

    let forwarded = server
        .recv(
            Transmit::new(
                &outbound_buffer[..outbound.len],
                TransportType::Udp,
                server_addr,
                client_addr,
            ),
            instant(now),
        )
        .expect("TURN server should forward client peer data")
        .build();
    assert_eq!(forwarded.from, relay_v4);
    assert_eq!(forwarded.to, peer_addr);
    assert_eq!(forwarded.data, payload);

    // Peer -> client: the TURN client returns a borrowed peer payload.
    let peer_payload = b"ghoncha-pong";
    let returned = server
        .recv(
            Transmit::new(
                peer_payload.as_slice(),
                TransportType::Udp,
                relay_v4,
                peer_addr,
            ),
            instant(now),
        )
        .expect("TURN server should forward peer data to the client")
        .build();

    match client
        .receive_from(server_addr, &returned.data, now)
        .unwrap()
    {
        TurnRecvRet::PeerData(peer_data) => {
            assert_eq!(peer_data.peer, peer_addr);
            assert_eq!(peer_data.data(), peer_payload);
        }
        _ => panic!("expected TURN peer data"),
    }
}
