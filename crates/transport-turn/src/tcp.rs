//! TURN over TCP client adapter.
//!
//! This is TURN client-to-server TCP with a UDP relay allocation (RFC 8656),
//! not the separate TCP relay allocation extension (RFC 6062). The caller
//! owns a connected TCP socket and drives its readiness. This module owns only
//! the TURN protocol state machine; it does not implement TLS or create sockets.

use core::net::{IpAddr, SocketAddr};

use turn_client_proto::api::{Data, Transmit, TurnClientApi, TurnConfig};
use turn_client_proto::prelude::DelayedTransmitBuild;
use turn_client_proto::tcp::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnClientTcp, TurnEvent,
    TurnPollRet, TurnRecvRet,
};
use turn_client_proto::types::{AddressFamily, Instant, TransportType, TurnCredentials};

use crate::{MonotonicTime, OutboundDatagram, TurnReceiveResult, TurnRelayFamilies};

/// Errors returned by the TURN-over-TCP protocol adapter.
#[derive(Debug)]
pub enum TurnTcpError {
    InvalidLocalPort,
    InvalidServerAddress,
    AddressFamilyMismatch,
    TimeOutOfRange,
    CreatePermission(CreatePermissionError),
    BindChannel(BindChannelError),
    Delete(DeleteError),
    Send(SendError),
    NoTransmit,
    BufferTooSmall { required: usize },
}

/// Sans-I/O TURN-over-TCP client using a UDP relay allocation.
///
/// The supplied local address must belong to a TCP socket already connected
/// to the TURN server. For Android, the platform must bind the socket to the
/// selected Network and call VpnService.protect() before connecting.
///
/// The client-to-server transport is TCP. The requested relayed peer transport
/// remains UDP, so permissions and ChannelBind operations use UDP peer
/// addresses. This is not an RFC 6062 TCP relay allocation.
pub struct TurnTcpEngine {
    client: TurnClientTcp,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
}

impl TurnTcpEngine {
    /// Creates a TURN-over-TCP client with IPv4 relay allocation.
    pub fn new(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> Result<Self, TurnTcpError> {
        Self::new_with_relay_families(
            local_addr,
            server_addr,
            username,
            password,
            TurnRelayFamilies::Ipv4Only,
        )
    }

    /// Creates a TURN-over-TCP client with an explicit relay address-family policy.
    pub fn new_with_relay_families(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
        relay_families: TurnRelayFamilies,
    ) -> Result<Self, TurnTcpError> {
        if local_addr.port() == 0 {
            return Err(TurnTcpError::InvalidLocalPort);
        }
        if server_addr.port() == 0 || server_addr.ip().is_unspecified() {
            return Err(TurnTcpError::InvalidServerAddress);
        }
        if local_addr.is_ipv4() != server_addr.is_ipv4() {
            return Err(TurnTcpError::AddressFamilyMismatch);
        }

        let credentials = TurnCredentials::new(username, password);
        let mut config = TurnConfig::new(credentials);
        // TCP is the client-to-server connection. The relayed peer transport
        // remains UDP; do not accidentally request an RFC 6062 TCP allocation.
        config.set_allocation_transport(TransportType::Udp);
        match relay_families {
            TurnRelayFamilies::Ipv4Only => {
                config.set_address_family(AddressFamily::IPV4);
            }
            TurnRelayFamilies::Ipv6Only => {
                config.set_address_family(AddressFamily::IPV6);
            }
            TurnRelayFamilies::DualStack => {
                config.set_address_family(AddressFamily::IPV4);
                config.add_address_family(AddressFamily::IPV6);
            }
        }
        config.add_supported_integrity(
            turn_client_proto::stun::types::message::IntegrityAlgorithm::Sha256,
        );

        let client = TurnClientTcp::allocate(local_addr, server_addr, config);
        Ok(Self {
            client,
            local_addr,
            server_addr,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub const fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Advances TURN timers and protocol state.
    pub fn poll(&mut self, now: MonotonicTime) -> Result<TurnPollRet, TurnTcpError> {
        let now = to_instant(now)?;
        Ok(self.client.poll(now))
    }

    /// Returns one already encoded TURN control message to write to the TCP stream.
    ///
    /// The bytes are TURN/STUN wire data. Do not add the generic four-byte
    /// GHONCHA stream-record prefix to these protocol bytes.
    pub fn poll_transmit(
        &mut self,
        now: MonotonicTime,
    ) -> Result<Option<Transmit<Data<'static>>>, TurnTcpError> {
        let now = to_instant(now)?;
        Ok(self.client.poll_transmit(now))
    }

    /// Drains one TURN lifecycle event.
    pub fn poll_event(&mut self) -> Option<TurnEvent> {
        self.client.poll_event()
    }

    /// Feeds bytes read from the connected TURN TCP stream into the protocol.
    ///
    /// The TURN library incrementally buffers split STUN/ChannelData messages
    /// and handles TCP ChannelData padding. Peer payloads may borrow bytes;
    /// consume them before the caller reuses its receive buffer.
    pub fn receive_stream_bytes<'a>(
        &mut self,
        bytes: &'a [u8],
        now: MonotonicTime,
    ) -> Result<TurnReceiveResult<'a>, TurnTcpError> {
        let now = to_instant(now)?;
        let transmit = Transmit::new(bytes, TransportType::Tcp, self.server_addr, self.local_addr);
        Ok(match self.client.recv(transmit, now) {
            TurnRecvRet::Handled => TurnReceiveResult::Handled,
            TurnRecvRet::Ignored(transmit) => TurnReceiveResult::Ignored {
                from: transmit.from,
            },
            TurnRecvRet::PeerData(peer_data) => TurnReceiveResult::PeerData(peer_data),
            TurnRecvRet::PeerIcmp {
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
                ..
            } => TurnReceiveResult::PeerIcmp {
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            },
        })
    }

    /// Drains one additional complete peer payload buffered by the TURN parser.
    ///
    /// A TCP read may contain multiple TURN messages. The protocol library can
    /// retain subsequent complete messages after returning the first payload.
    pub fn poll_peer_data(
        &mut self,
        now: MonotonicTime,
    ) -> Result<Option<turn_client_proto::api::TurnPeerData<alloc::vec::Vec<u8>>>, TurnTcpError>
    {
        let now = to_instant(now)?;
        Ok(self.client.poll_recv(now))
    }

    /// Creates a permission for a UDP peer address.
    pub fn create_permission(
        &mut self,
        peer: IpAddr,
        now: MonotonicTime,
    ) -> Result<(), TurnTcpError> {
        let now = to_instant(now)?;
        self.client
            .create_permission(TransportType::Udp, peer, now)
            .map_err(TurnTcpError::CreatePermission)
    }

    /// Binds a ChannelData channel for a UDP peer endpoint.
    pub fn bind_channel(
        &mut self,
        peer: SocketAddr,
        now: MonotonicTime,
    ) -> Result<(), TurnTcpError> {
        let now = to_instant(now)?;
        self.client
            .bind_channel(TransportType::Udp, peer, now)
            .map_err(TurnTcpError::BindChannel)
    }

    pub fn have_permission(&self, peer: IpAddr) -> bool {
        self.client.have_permission(TransportType::Udp, peer)
    }

    pub fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.client.relayed_addresses()
    }

    /// Encodes one peer payload as TURN stream bytes into caller-owned storage.
    ///
    /// When a channel is bound, the TURN library emits TCP-padded ChannelData
    /// as required by RFC 8656. The returned bytes must be written to the
    /// connected TCP stream in order; the caller must retain the unwritten
    /// suffix after partial writes.
    pub fn send_to_into(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
        now: MonotonicTime,
        output: &mut [u8],
    ) -> Result<OutboundDatagram, TurnTcpError> {
        let now = to_instant(now)?;
        let build = self
            .client
            .send_to(TransportType::Udp, peer, payload, now)
            .map_err(TurnTcpError::Send)?
            .ok_or(TurnTcpError::NoTransmit)?;

        let required = build.data.len();
        if output.len() < required {
            self.client.protocol_error();
            return Err(TurnTcpError::BufferTooSmall { required });
        }

        let transmit = build.write_into(&mut output[..required]);
        Ok(OutboundDatagram {
            destination: self.server_addr,
            len: transmit,
        })
    }

    /// Deletes the TURN allocation. Flush resulting control bytes before closing.
    pub fn delete(&mut self, now: MonotonicTime) -> Result<(), TurnTcpError> {
        let now = to_instant(now)?;
        self.client.delete(now).map_err(TurnTcpError::Delete)
    }

    /// Marks the protocol unusable after a fatal stream or framing error.
    pub fn protocol_error(&mut self) {
        self.client.protocol_error();
    }
}

fn to_instant(now: MonotonicTime) -> Result<Instant, TurnTcpError> {
    let nanos = i64::try_from(now.0).map_err(|_| TurnTcpError::TimeOutOfRange)?;
    Ok(Instant::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> SocketAddr {
        "192.0.2.10:40000".parse().unwrap()
    }

    fn server() -> SocketAddr {
        "198.51.100.1:3478".parse().unwrap()
    }

    #[test]
    fn creates_tcp_control_connection_with_udp_relay_transport() {
        let mut engine =
            TurnTcpEngine::new(local(), server(), "test-user", "test-password").unwrap();
        assert_eq!(engine.local_addr(), local());
        assert_eq!(engine.server_addr(), server());

        // Initial TURN Allocate is emitted on the TCP control stream.
        let _ = engine.poll(MonotonicTime(1)).unwrap();
        assert!(engine.poll_transmit(MonotonicTime(1)).unwrap().is_some());
    }

    #[test]
    fn rejects_invalid_socket_tuple() {
        assert!(matches!(
            TurnTcpEngine::new(
                "192.0.2.10:0".parse().unwrap(),
                server(),
                "user",
                "password"
            ),
            Err(TurnTcpError::InvalidLocalPort)
        ));
        assert!(matches!(
            TurnTcpEngine::new(local(), "0.0.0.0:3478".parse().unwrap(), "user", "password"),
            Err(TurnTcpError::InvalidServerAddress)
        ));
        assert!(matches!(
            TurnTcpEngine::new(
                "[2001:db8::1]:40000".parse().unwrap(),
                server(),
                "user",
                "password"
            ),
            Err(TurnTcpError::AddressFamilyMismatch)
        ));
    }

    #[test]
    fn accepts_incremental_stream_input_without_inventing_datagram_boundaries() {
        let mut engine = TurnTcpEngine::new(local(), server(), "test-user", "test-password")
            .unwrap();

        // A deliberately incomplete STUN header is buffered by TurnClientTcp.
        assert!(matches!(
            engine
                .receive_stream_bytes(&[0x00, 0x01], MonotonicTime(1))
                .unwrap(),
            TurnReceiveResult::Handled
        ));
    }

    #[test]
    fn monotonic_time_conversion_is_checked() {
        assert!(matches!(
            to_instant(MonotonicTime(u64::MAX)),
            Err(TurnTcpError::TimeOutOfRange)
        ));
    }
}
