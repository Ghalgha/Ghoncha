#![no_std]

//! Sans-I/O UDP TURN client adapter.
//!
//! This crate owns TURN protocol state only. The caller owns and drives the UDP
//! socket, including Android network binding and VpnService.protect().
//! Packet buffers are supplied by the caller; no socket or async runtime is
//! created here.

mod manager;
pub use manager::*;

use core::convert::TryFrom;
use core::net::{IpAddr, SocketAddr};

use ghoncha_transport_api::MonotonicTime;
use turn_client_proto::api::{TurnClientApi, TurnConfig};
use turn_client_proto::prelude::DelayedTransmitBuild;
use turn_client_proto::stun::agent::Transmit;
use turn_client_proto::stun::types::data::Data;
use turn_client_proto::stun::types::message::IntegrityAlgorithm;
use turn_client_proto::types::{AddressFamily, Instant, TransportType, TurnCredentials};
use turn_client_proto::udp::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnClientUdp, TurnEvent,
    TurnPollRet, TurnRecvRet,
};

/// Errors returned by the UDP TURN adapter.
#[derive(Debug)]
pub enum TurnError {
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

/// Address families requested for a TURN relay allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnRelayFamilies {
    Ipv4Only,
    Ipv6Only,
    DualStack,
}

/// A datagram that the caller must send to the TURN server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundDatagram {
    pub destination: SocketAddr,
    pub len: usize,
}

/// Sans-I/O TURN-over-UDP protocol state.
///
/// The TURN credentials are copied into the upstream client state. Never log
/// this object or upstream TURN config/client values: their Debug
/// implementations may expose credential material.
pub struct TurnUdpEngine {
    client: TurnClientUdp,
    local_addr: SocketAddr,
    server_addr: SocketAddr,
}

impl TurnUdpEngine {
    /// Creates a TURN UDP client state machine using IPv4 relay allocation.
    ///
    /// IPv4-only is the conservative default to avoid an unnecessary second
    /// relay allocation. Use new_with_relay_families when the selected peer
    /// requires IPv6 or dual-stack relay addresses.
    pub fn new(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> Result<Self, TurnError> {
        Self::new_with_relay_families(
            local_addr,
            server_addr,
            username,
            password,
            TurnRelayFamilies::Ipv4Only,
        )
    }

    /// Creates a TURN UDP client with an explicit relay address-family policy.
    ///
    /// The socket must already be bound to the selected network. On Android,
    /// bind it to the active Network and call VpnService.protect() before
    /// sending the first datagram. SHA-1 remains preferred for compatibility
    /// with deployed TURN servers; SHA-256 is retained as an alternative.
    pub fn new_with_relay_families(
        local_addr: SocketAddr,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
        relay_families: TurnRelayFamilies,
    ) -> Result<Self, TurnError> {
        if local_addr.port() == 0 {
            return Err(TurnError::InvalidLocalPort);
        }
        if server_addr.port() == 0 || server_addr.ip().is_unspecified() {
            return Err(TurnError::InvalidServerAddress);
        }
        if local_addr.is_ipv4() != server_addr.is_ipv4() {
            return Err(TurnError::AddressFamilyMismatch);
        }

        let credentials = TurnCredentials::new(username, password);
        let mut config = TurnConfig::new(credentials);
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
        config.add_supported_integrity(IntegrityAlgorithm::Sha256);

        let client = TurnClientUdp::allocate(local_addr, server_addr, config);

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
    pub fn poll(&mut self, now: MonotonicTime) -> Result<TurnPollRet, TurnError> {
        let now = to_instant(now)?;
        Ok(self.client.poll(now))
    }

    /// Returns the next TURN control datagram to send, if one is pending.
    ///
    /// The returned data is already encoded by the TURN library. The caller
    /// sends it directly to the returned destination without copying it.
    pub fn poll_transmit(
        &mut self,
        now: MonotonicTime,
    ) -> Result<Option<Transmit<Data<'static>>>, TurnError> {
        let now = to_instant(now)?;
        Ok(self.client.poll_transmit(now))
    }

    /// Drains one TURN lifecycle event.
    pub fn poll_event(&mut self) -> Option<TurnEvent> {
        self.client.poll_event()
    }

    /// Provides one received UDP datagram to the TURN state machine.
    ///
    /// The input remains borrowed. Peer data returned by the library may
    /// reference this same input buffer; process it before reusing the buffer.
    pub fn receive_from<'a>(
        &mut self,
        from: SocketAddr,
        datagram: &'a [u8],
        now: MonotonicTime,
    ) -> Result<TurnRecvRet<&'a [u8]>, TurnError> {
        let now = to_instant(now)?;
        let transmit = Transmit::new(datagram, TransportType::Udp, from, self.local_addr);
        Ok(self.client.recv(transmit, now))
    }

    /// Creates a TURN permission for a peer IP address.
    pub fn create_permission(&mut self, peer: IpAddr, now: MonotonicTime) -> Result<(), TurnError> {
        let now = to_instant(now)?;
        self.client
            .create_permission(TransportType::Udp, peer, now)
            .map_err(TurnError::CreatePermission)
    }

    /// Binds a TURN channel for a peer endpoint.
    ///
    /// Until the ChannelBind transaction succeeds, send_to_into may use a
    /// Send Indication instead of ChannelData.
    pub fn bind_channel(&mut self, peer: SocketAddr, now: MonotonicTime) -> Result<(), TurnError> {
        let now = to_instant(now)?;
        self.client
            .bind_channel(TransportType::Udp, peer, now)
            .map_err(TurnError::BindChannel)
    }

    /// Returns whether a TURN permission currently exists for the peer IP.
    pub fn have_permission(&self, peer: IpAddr) -> bool {
        self.client.have_permission(TransportType::Udp, peer)
    }

    /// Returns the relayed addresses currently known to the TURN client.
    pub fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.client.relayed_addresses()
    }

    /// Builds a TURN peer-data datagram into caller-owned storage.
    ///
    /// The payload is borrowed until it has been written into output. The
    /// returned destination is the TURN server, not the remote peer.
    pub fn send_to_into(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
        now: MonotonicTime,
        output: &mut [u8],
    ) -> Result<OutboundDatagram, TurnError> {
        let now = to_instant(now)?;
        let build = self
            .client
            .send_to(TransportType::Udp, peer, payload, now)
            .map_err(TurnError::Send)?
            .ok_or(TurnError::NoTransmit)?;

        let required = build.data.len();
        if output.len() < required {
            return Err(TurnError::BufferTooSmall { required });
        }

        let transmit = build.write_into(output);
        Ok(OutboundDatagram {
            destination: transmit.to,
            len: transmit.data.len(),
        })
    }

    /// Deletes the TURN allocation. The caller must send the resulting
    /// control datagram, if any, before closing its socket.
    pub fn delete(&mut self, now: MonotonicTime) -> Result<(), TurnError> {
        let now = to_instant(now)?;
        self.client.delete(now).map_err(TurnError::Delete)
    }

    /// Informs the TURN state machine that the caller encountered a fatal
    /// protocol or I/O error and the client must no longer be used.
    pub fn protocol_error(&mut self) {
        self.client.protocol_error();
    }
}

fn to_instant(now: MonotonicTime) -> Result<Instant, TurnError> {
    let nanos = i64::try_from(now.0).map_err(|_| TurnError::TimeOutOfRange)?;
    Ok(Instant::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unbound_local_port() {
        let result = TurnUdpEngine::new(
            "192.0.2.1:0".parse().unwrap(),
            "198.51.100.1:3478".parse().unwrap(),
            "temporary-user",
            "temporary-password",
        );
        assert!(matches!(result, Err(TurnError::InvalidLocalPort)));
    }

    #[test]
    fn rejects_mismatched_socket_address_families() {
        let result = TurnUdpEngine::new(
            "[2001:db8::1]:40000".parse().unwrap(),
            "198.51.100.1:3478".parse().unwrap(),
            "temporary-user",
            "temporary-password",
        );
        assert!(matches!(result, Err(TurnError::AddressFamilyMismatch)));
    }

    #[test]
    fn accepts_a_bound_udp_socket_tuple() {
        let engine = TurnUdpEngine::new(
            "192.0.2.1:40000".parse().unwrap(),
            "198.51.100.1:3478".parse().unwrap(),
            "temporary-user",
            "temporary-password",
        )
        .unwrap();

        assert_eq!(engine.local_addr(), "192.0.2.1:40000".parse().unwrap());
        assert_eq!(engine.server_addr(), "198.51.100.1:3478".parse().unwrap());
    }

    #[test]
    fn converts_monotonic_nanoseconds_without_losing_precision() {
        let instant = to_instant(MonotonicTime(1_234_567_890)).unwrap();
        assert_eq!(instant.as_nanos(), 1_234_567_890);
        assert!(matches!(
            to_instant(MonotonicTime(u64::MAX)),
            Err(TurnError::TimeOutOfRange)
        ));
    }
}
