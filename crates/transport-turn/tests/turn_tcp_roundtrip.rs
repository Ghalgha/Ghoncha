use core::net::SocketAddr;
use std::time::Duration;

use ghoncha_transport_api::MonotonicTime;
use ghoncha_transport_turn::{TurnReceiveResult, TurnRelayFamilies, TurnTcpEngine};
use turn_client_proto::tcp::TurnPollRet;
use turn_client_proto::types::Instant;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_server_proto::server::TurnServer;
use turn_server_proto::stun::agent::Transmit;
use turn_server_proto::types::TransportType;

fn instant(now: MonotonicTime) -> Instant {
    Instant::from_nanos(i64::try_from(now.0).unwrap())
}

fn advance_client(engine: &mut TurnTcpEngine, now: MonotonicTime) -> MonotonicTime {
    match engine.poll(now).unwrap() {
        TurnPollRet::WaitUntil(next) => MonotonicTime(next.as_nanos() as u64),
        _ => panic!("unexpected TURN TCP client poll result"),
    }
}

fn exchange_client_request(
    engine: &mut TurnTcpEngine,
    server: &mut TurnServer,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    relay_addr: SocketAddr,
    now: MonotonicTime,
) -> Vec<Transmit<Vec<u8>>> {
    let _ = engine.poll(now).unwrap();
    let outgoing = engine
        .poll_transmit(now)
        .unwrap()
        .expect("client should have a TURN request ready");
    assert_eq!(outgoing.transport, TransportType::Tcp);

    let incoming = Transmit::new(
        outgoing.data.as_ref(),
        TransportType::Tcp,
        client_addr,
        server_addr,
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
                assert_eq!(transport, TransportType::Tcp);
                assert_eq!(allocation_transport, TransportType::Udp);
                assert_eq!(family, turn_server_proto::types::AddressFamily::IPV4);
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

fn deliver_stream(
    engine: &mut TurnTcpEngine,
    responses: Vec<Transmit<Vec<u8>>>,
    now: MonotonicTime,
    chunk_size: usize,
) {
    // Concatenate TURN messages exactly as a TCP stream may coalesce them.
    let mut stream = Vec::new();
    for response in responses {
        assert_eq!(response.transport, TransportType::Tcp);
        stream.extend_from_slice(&response.data);
    }

    // Then split the same stream at arbitrary byte boundaries, including
    // inside STUN headers and attributes.
    for chunk in stream.chunks(chunk_size) {
        assert!(matches!(
            engine.receive_stream_bytes(chunk, now).unwrap(),
            TurnReceiveResult::Handled
        ));
        while engine.poll_peer_data(now).unwrap().is_some() {}
    }
}

#[test]
fn turn_tcp_stream_allocation_permission_and_peer_data_roundtrip() {
    let client_addr: SocketAddr = "192.0.2.10:40000".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.10:3478".parse().unwrap();
    let relay_addr: SocketAddr = "203.0.113.10:50000".parse().unwrap();
    let peer_addr: SocketAddr = "203.0.113.20:51820".parse().unwrap();

    let mut server = TurnServer::new(
        TransportType::Tcp,
        server_addr,
        String::from("ghoncha-test-realm"),
    );
    server.add_user(
        String::from("ghoncha-test-user"),
        String::from("ghoncha-test-pass"),
    );
    server.set_nonce_expiry_duration(Duration::from_secs(30));

    let mut client = TurnTcpEngine::new_with_relay_families(
        client_addr,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
        TurnRelayFamilies::Ipv4Only,
    )
    .unwrap();

    let mut now = MonotonicTime(0);

    // Unauthenticated Allocate obtains the long-term credential challenge.
    let challenge = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_addr,
        now,
    );
    assert_eq!(challenge.len(), 1);
    deliver_stream(&mut client, challenge, now, 3);

    // Authenticated Allocate creates a UDP relay over a TCP control stream.
    now = advance_client(&mut client, now);
    let allocation = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_addr,
        now,
    );
    assert!(!allocation.is_empty());
    deliver_stream(&mut client, allocation, now, 7);

    assert!(client.relayed_addresses().any(|(transport, addr)| {
        transport == TransportType::Udp && addr == relay_addr
    }));

    // Permissions apply to the UDP peer even though the client/server hop is TCP.
    client.create_permission(peer_addr.ip(), now).unwrap();
    now = advance_client(&mut client, now);
    let permission = exchange_client_request(
        &mut client,
        &mut server,
        client_addr,
        server_addr,
        relay_addr,
        now,
    );
    assert!(!permission.is_empty());
    deliver_stream(&mut client, permission, now, 5);
    assert!(client.have_permission(peer_addr.ip()));

    // Client -> peer: TURN sends an indication over the established TCP stream.
    let payload = b"ghoncha-tcp-ping";
    let mut outbound_buffer = [0u8; 1500];
    let outbound = client
        .send_to_into(peer_addr, payload, now, &mut outbound_buffer)
        .unwrap();
    assert_eq!(outbound.destination, server_addr);

    let forwarded = server
        .recv(
            Transmit::new(
                &outbound_buffer[..outbound.len],
                TransportType::Tcp,
                client_addr,
                server_addr,
            ),
            instant(now),
        )
        .expect("TURN server should forward client peer data")
        .build();
    assert_eq!(forwarded.from, relay_addr);
    assert_eq!(forwarded.to, peer_addr);
    assert_eq!(forwarded.data.as_slice(), payload.as_slice());

    // Peer -> client: the server returns a TURN message on the TCP stream.
    let peer_payload = b"ghoncha-tcp-pong";
    let returned = server
        .recv(
            Transmit::new(
                peer_payload.as_slice(),
                TransportType::Udp,
                peer_addr,
                relay_addr,
            ),
            instant(now),
        )
        .expect("TURN server should forward peer data to the client")
        .build();

    assert_eq!(returned.transport, TransportType::Tcp);
    match client
        .receive_stream_bytes(&returned.data, now)
        .unwrap()
    {
        TurnReceiveResult::PeerData(peer_data) => {
            assert_eq!(peer_data.peer, peer_addr);
            assert_eq!(peer_data.data(), peer_payload.as_slice());
        }
        _ => panic!("expected TURN peer data"),
    }
    assert!(client.poll_peer_data(now).unwrap().is_none());
}
