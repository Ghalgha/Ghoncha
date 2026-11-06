use core::net::SocketAddr;
use std::collections::VecDeque;
use std::time::Duration;

use ghoncha_transport_api::MonotonicTime;
use ghoncha_transport_turn::{
    DatagramFlushResult, DatagramReceive, DatagramSocketError, TurnDatagramSocket,
    TurnRelayFamilies, TurnUdpDriver, TurnUdpEngine,
};
use turn_client_proto::types::Instant;
use turn_client_proto::udp::{TurnEvent, TurnPollRet, TurnRecvRet};
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
    let _ = engine.poll(now).unwrap();
    let outgoing = engine
        .poll_transmit(now)
        .unwrap()
        .expect("client should have a TURN request ready");
    let incoming = Transmit::new(
        outgoing.data.as_ref(),
        TransportType::Udp,
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

    let mut client = TurnUdpEngine::new_with_relay_families(
        client_addr,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
        TurnRelayFamilies::DualStack,
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
    let mut saw_permission = false;
    while let Some(event) = client.poll_event() {
        if matches!(
            event,
            TurnEvent::PermissionCreated(TransportType::Udp, ip) if ip == peer_addr.ip()
        ) {
            saw_permission = true;
        }
    }
    assert!(saw_permission);

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
                client_addr,
                server_addr,
            ),
            instant(now),
        )
        .expect("TURN server should forward client peer data")
        .build();
    assert_eq!(forwarded.from, relay_v4);
    assert_eq!(forwarded.to, peer_addr);
    assert_eq!(forwarded.data.as_slice(), payload.as_slice());

    // Peer -> client: the TURN client returns a borrowed peer payload.
    let peer_payload = b"ghoncha-pong";
    let returned = server
        .recv(
            Transmit::new(
                peer_payload.as_slice(),
                TransportType::Udp,
                peer_addr,
                relay_v4,
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
            assert_eq!(peer_data.data(), peer_payload.as_slice());
        }
        _ => panic!("expected TURN peer data"),
    }
}

struct MockDatagramSocket {
    local: SocketAddr,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    block_next_send: bool,
    fail_next_send: bool,
    fail_next_receive: bool,
    truncate_next_receive: bool,
}

impl TurnDatagramSocket for MockDatagramSocket {
    fn local_addr(&self) -> SocketAddr {
        self.local
    }

    fn send_to(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<usize, DatagramSocketError> {
        if self.block_next_send {
            self.block_next_send = false;
            return Err(DatagramSocketError::WouldBlock);
        }
        if self.fail_next_send {
            self.fail_next_send = false;
            return Err(DatagramSocketError::Failed);
        }
        self.sent.push((destination, datagram.to_vec()));
        Ok(datagram.len())
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<DatagramReceive, DatagramSocketError> {
        if self.fail_next_receive {
            self.fail_next_receive = false;
            return Err(DatagramSocketError::Failed);
        }
        let Some((from, datagram)) = self.inbound.pop_front() else {
            return Err(DatagramSocketError::WouldBlock);
        };
        if self.truncate_next_receive {
            self.truncate_next_receive = false;
            return Ok(DatagramReceive {
                len: buffer.len(),
                from,
                truncated: true,
            });
        }
        if datagram.len() > buffer.len() {
            return Err(DatagramSocketError::Failed);
        }
        buffer[..datagram.len()].copy_from_slice(&datagram);
        Ok(DatagramReceive {
            len: datagram.len(),
            from,
            truncated: false,
        })
    }
}

#[test]
fn socket_owning_driver_retains_control_datagram_across_would_block() {
    let client_addr: SocketAddr = "192.0.2.10:40000".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.10:3478".parse().unwrap();
    let socket = MockDatagramSocket {
        local: client_addr,
        sent: Vec::new(),
        inbound: VecDeque::new(),
        block_next_send: true,
        fail_next_send: false,
        fail_next_receive: false,
        truncate_next_receive: false,
    };

    let mut driver = TurnUdpDriver::<_, 32, 32, 1500, 8192, 65536>::new(
        socket,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    assert!(driver.poll_control(MonotonicTime(0)).unwrap());
    assert_eq!(driver.queued_control(), 1);

    assert!(matches!(
        driver.flush_one().unwrap(),
        DatagramFlushResult::WouldBlock {
            class: ghoncha_transport_turn::DatagramClass::Control
        }
    ));
    assert_eq!(driver.queued_control(), 1);

    let sent = driver.flush_one().unwrap();
    assert!(matches!(
        sent,
        DatagramFlushResult::Sent {
            class: ghoncha_transport_turn::DatagramClass::Control,
            bytes
        } if bytes > 0
    ));
    assert_eq!(driver.queued_control(), 0);

    let (socket, _engine, queues) = driver.into_parts();
    assert_eq!(queues.control_len(), 0);
    assert_eq!(queues.peer_data_len(), 0);
    assert_eq!(socket.sent.len(), 1);
    assert_eq!(socket.sent[0].0, server_addr);
    assert!(!socket.sent[0].1.is_empty());
}

#[test]
fn socket_driver_parts_preserve_pending_control_datagram() {
    let client_addr: SocketAddr = "192.0.2.11:40001".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.11:3478".parse().unwrap();
    let socket = MockDatagramSocket {
        local: client_addr,
        sent: Vec::new(),
        inbound: VecDeque::new(),
        block_next_send: false,
        fail_next_send: false,
        fail_next_receive: false,
        truncate_next_receive: false,
    };

    let mut driver = TurnUdpDriver::<_, 32, 32, 1500, 8192, 65536>::new(
        socket,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    assert!(driver.poll_control(MonotonicTime(0)).unwrap());
    let (_socket, _engine, queues) = driver.into_parts();
    assert_eq!(queues.control_len(), 1);
    assert_eq!(queues.peer_data_len(), 0);
}

#[test]
fn socket_driver_retires_after_fatal_send_error() {
    let client_addr: SocketAddr = "192.0.2.12:40002".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.12:3478".parse().unwrap();
    let socket = MockDatagramSocket {
        local: client_addr,
        sent: Vec::new(),
        inbound: VecDeque::new(),
        block_next_send: false,
        fail_next_send: true,
        fail_next_receive: false,
        truncate_next_receive: false,
    };

    let mut driver = TurnUdpDriver::<_, 32, 32, 1500, 8192, 65536>::new(
        socket,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    assert!(driver.poll_control(MonotonicTime(0)).unwrap());
    assert!(matches!(
        driver.flush_one(),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Socket(
            DatagramSocketError::Failed
        ))
    ));
    assert!(matches!(
        driver.poll_control(MonotonicTime(1)),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Retired)
    ));
    let mut receive_buffer = [0u8; 128];
    assert!(matches!(
        driver.receive_one(&mut receive_buffer, MonotonicTime(1)),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Retired)
    ));
    let mut encoded_buffer = [0u8; 1500];
    assert!(matches!(
        driver.queue_peer_data(
            "203.0.113.20:51820".parse().unwrap(),
            &[1, 2, 3],
            MonotonicTime(1),
            &mut encoded_buffer,
        ),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Retired)
    ));
}

#[test]
fn socket_driver_discards_truncated_datagram_without_retiring_allocation() {
    let client_addr: SocketAddr = "192.0.2.13:40003".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.13:3478".parse().unwrap();
    let socket = MockDatagramSocket {
        local: client_addr,
        sent: Vec::new(),
        inbound: VecDeque::from([(server_addr, vec![0u8; 64])]),
        block_next_send: false,
        fail_next_send: false,
        fail_next_receive: false,
        truncate_next_receive: true,
    };

    let mut driver = TurnUdpDriver::<_, 32, 32, 1500, 8192, 65536>::new(
        socket,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    let mut receive_buffer = [0u8; 32];
    assert!(matches!(
        driver.receive_one(&mut receive_buffer, MonotonicTime(0)),
        Ok(ghoncha_transport_turn::TurnUdpDriverReceive::Truncated { from })
            if from == server_addr
    ));
    assert!(driver.poll_control(MonotonicTime(1)).is_ok());
}

#[test]
fn socket_driver_retires_after_fatal_receive_error() {
    let client_addr: SocketAddr = "192.0.2.14:40004".parse().unwrap();
    let server_addr: SocketAddr = "198.51.100.14:3478".parse().unwrap();
    let socket = MockDatagramSocket {
        local: client_addr,
        sent: Vec::new(),
        inbound: VecDeque::new(),
        block_next_send: false,
        fail_next_send: false,
        fail_next_receive: true,
        truncate_next_receive: false,
    };

    let mut driver = TurnUdpDriver::<_, 32, 32, 1500, 8192, 65536>::new(
        socket,
        server_addr,
        "ghoncha-test-user",
        "ghoncha-test-pass",
    )
    .unwrap();

    let mut receive_buffer = [0u8; 128];
    assert!(matches!(
        driver.receive_one(&mut receive_buffer, MonotonicTime(0)),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Socket(
            DatagramSocketError::Failed
        ))
    ));
    assert!(matches!(
        driver.poll_control(MonotonicTime(1)),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Retired)
    ));
    assert!(matches!(
        driver.flush_one(),
        Err(ghoncha_transport_turn::TurnUdpDriverError::Retired)
    ));
}
