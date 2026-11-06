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
pub use turn_client_proto::api::TurnPeerData;
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

/// Result of processing one datagram received from the TURN server.
///
/// Peer payloads borrow the caller's receive buffer and must be consumed before
/// that buffer is reused. Non-peer TURN messages are handled by the protocol
/// state machine and must not be forwarded into the VPN data plane.
#[derive(Debug)]
pub enum TurnReceiveResult<'a> {
    Handled,
    Ignored {
        from: SocketAddr,
    },
    PeerData(TurnPeerData<&'a [u8]>),
    PeerIcmp {
        peer: SocketAddr,
        icmp_type: u8,
        icmp_code: u8,
        icmp_data: u32,
    },
}

/// A bounded datagram retained until the socket confirms a complete UDP send.
struct QueuedDatagram<const MAX_DATAGRAM: usize> {
    destination: SocketAddr,
    len: usize,
    bytes: [u8; MAX_DATAGRAM],
}

/// Borrowed view of the next datagram waiting for socket transmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingDatagram<'a> {
    pub destination: SocketAddr,
    pub bytes: &'a [u8],
}

/// Why a datagram could not be added to a bounded send queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramQueueError {
    DatagramTooLarge {
        maximum: usize,
        actual: usize,
    },
    RecordCapacityReached,
    ByteCapacityReached {
        maximum: usize,
        queued: usize,
        incoming: usize,
    },
    EncodedLengthExceedsBuffer {
        declared: usize,
        available: usize,
    },
}

/// Fixed-capacity UDP send queue.
///
/// The front item remains unchanged until `pop_sent` is called after the OS
/// reports a complete datagram send. A WouldBlock result must leave the item
/// in place. Both record count and aggregate bytes are bounded at compile time.
pub struct DatagramSendQueue<
    const CAPACITY: usize,
    const MAX_DATAGRAM: usize,
    const MAX_QUEUED_BYTES: usize,
> {
    entries: [Option<QueuedDatagram<MAX_DATAGRAM>>; CAPACITY],
    head: usize,
    len: usize,
    queued_bytes: usize,
}

impl<const CAPACITY: usize, const MAX_DATAGRAM: usize, const MAX_QUEUED_BYTES: usize>
    DatagramSendQueue<CAPACITY, MAX_DATAGRAM, MAX_QUEUED_BYTES>
{
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
            queued_bytes: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    fn check_capacity(&self, incoming: usize) -> Result<(), DatagramQueueError> {
        if incoming > MAX_DATAGRAM {
            return Err(DatagramQueueError::DatagramTooLarge {
                maximum: MAX_DATAGRAM,
                actual: incoming,
            });
        }
        if self.len == CAPACITY {
            return Err(DatagramQueueError::RecordCapacityReached);
        }
        let next_bytes = self.queued_bytes.saturating_add(incoming);
        if next_bytes > MAX_QUEUED_BYTES {
            return Err(DatagramQueueError::ByteCapacityReached {
                maximum: MAX_QUEUED_BYTES,
                queued: self.queued_bytes,
                incoming,
            });
        }
        Ok(())
    }

    /// Copies one already-encoded UDP datagram into bounded queue storage.
    pub fn push(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<(), DatagramQueueError> {
        self.check_capacity(datagram.len())?;

        // len == CAPACITY was rejected above, so CAPACITY is nonzero here.
        let tail = (self.head + self.len) % CAPACITY;
        let mut bytes = [0; MAX_DATAGRAM];
        bytes[..datagram.len()].copy_from_slice(datagram);
        self.entries[tail] = Some(QueuedDatagram {
            destination,
            len: datagram.len(),
            bytes,
        });
        self.len += 1;
        self.queued_bytes = self.queued_bytes.saturating_add(datagram.len());
        Ok(())
    }

    /// Returns the next datagram without removing or modifying it.
    ///
    /// Call repeatedly after WouldBlock; the returned bytes and destination
    /// remain identical until `pop_sent` succeeds.
    pub fn front(&self) -> Option<PendingDatagram<'_>> {
        let entry = self.entries.get(self.head)?.as_ref()?;
        Some(PendingDatagram {
            destination: entry.destination,
            bytes: &entry.bytes[..entry.len],
        })
    }

    /// Removes the front datagram after a complete successful UDP send.
    pub fn pop_sent(&mut self) -> Option<usize> {
        let entry = self.entries.get_mut(self.head)?.take()?;
        self.queued_bytes -= entry.len;
        self.len -= 1;
        self.head = if self.head + 1 == CAPACITY {
            0
        } else {
            self.head + 1
        };
        Some(entry.len)
    }
}

impl<const CAPACITY: usize, const MAX_DATAGRAM: usize, const MAX_QUEUED_BYTES: usize> Default
    for DatagramSendQueue<CAPACITY, MAX_DATAGRAM, MAX_QUEUED_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Class of a datagram selected from the TURN send queues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramClass {
    /// TURN control traffic: Allocate, authentication, Refresh, Permission,
    /// ChannelBind, and Delete transactions.
    Control,
    /// Encapsulated peer payload carried by Send Indication or ChannelData.
    PeerData,
}

/// Result reported by a caller-owned UDP socket send operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramSendAttempt {
    /// The socket reports the number of bytes accepted as one UDP datagram.
    Sent(usize),
    /// The socket is not currently writable; retain the datagram unchanged.
    WouldBlock,
    /// A fatal or otherwise unrecoverable send error occurred.
    Failed,
}

/// Outcome of attempting to send the next queued datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramFlushResult {
    Empty,
    Sent {
        class: DatagramClass,
        bytes: usize,
    },
    WouldBlock {
        class: DatagramClass,
    },
    Failed {
        class: DatagramClass,
    },
    /// UDP sends are atomic. A partial result is an I/O contract violation;
    /// the queue retains the record and the caller must retire the socket.
    PartialDatagram {
        class: DatagramClass,
        expected: usize,
        actual: usize,
    },
}

/// Independent bounded queues for TURN control and peer payload datagrams.
///
/// Control traffic is selected first so sustained user-data traffic cannot
/// leave allocation refreshes or permission/channel transactions waiting
/// behind a bulk FIFO. Each class has its own record and byte budget.
const CONTROL_BURST_LIMIT: u8 = 8;

pub struct TurnUdpSendQueues<
    const CONTROL_CAPACITY: usize,
    const PEER_CAPACITY: usize,
    const MAX_DATAGRAM: usize,
    const CONTROL_MAX_BYTES: usize,
    const PEER_MAX_BYTES: usize,
> {
    control: DatagramSendQueue<CONTROL_CAPACITY, MAX_DATAGRAM, CONTROL_MAX_BYTES>,
    peer_data: DatagramSendQueue<PEER_CAPACITY, MAX_DATAGRAM, PEER_MAX_BYTES>,
    consecutive_control_sends: u8,
}

impl<
    const CONTROL_CAPACITY: usize,
    const PEER_CAPACITY: usize,
    const MAX_DATAGRAM: usize,
    const CONTROL_MAX_BYTES: usize,
    const PEER_MAX_BYTES: usize,
>
    TurnUdpSendQueues<
        CONTROL_CAPACITY,
        PEER_CAPACITY,
        MAX_DATAGRAM,
        CONTROL_MAX_BYTES,
        PEER_MAX_BYTES,
    >
{
    pub fn new() -> Self {
        Self {
            control: DatagramSendQueue::new(),
            peer_data: DatagramSendQueue::new(),
            consecutive_control_sends: 0,
        }
    }

    fn ensure_control_capacity(&self, maximum_datagram: usize) -> Result<(), DatagramQueueError> {
        self.control.check_capacity(maximum_datagram)
    }

    fn ensure_peer_capacity(&self, maximum_datagram: usize) -> Result<(), DatagramQueueError> {
        self.peer_data.check_capacity(maximum_datagram)
    }

    pub fn push_control(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<(), DatagramQueueError> {
        self.control.push(destination, datagram)
    }

    /// Queues an already encoded TURN control transmit without rebuilding it.
    pub fn push_control_transmit<T: AsRef<[u8]>>(
        &mut self,
        transmit: &Transmit<T>,
    ) -> Result<(), DatagramQueueError> {
        self.control.push(transmit.to, transmit.data.as_ref())
    }

    pub fn push_peer_data(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<(), DatagramQueueError> {
        self.peer_data.push(destination, datagram)
    }

    /// Queues the exact encoded prefix returned by `TurnUdpEngine::send_to_into`.
    ///
    /// The output buffer may be larger than the encoded datagram. A mismatched
    /// reported length is rejected rather than truncating or reading past it.
    pub fn push_peer_output(
        &mut self,
        outbound: OutboundDatagram,
        encoded_buffer: &[u8],
    ) -> Result<(), DatagramQueueError> {
        if outbound.len > encoded_buffer.len() {
            return Err(DatagramQueueError::EncodedLengthExceedsBuffer {
                declared: outbound.len,
                available: encoded_buffer.len(),
            });
        }
        self.peer_data
            .push(outbound.destination, &encoded_buffer[..outbound.len])
    }

    /// Attempts one datagram send using the caller-owned socket.
    ///
    /// The closure must perform exactly one atomic UDP send. The queue removes
    /// the record only when the closure reports the full datagram length.
    /// WouldBlock and Failed preserve the record; the caller owns retry,
    /// socket retirement, and error reporting policy.
    pub fn flush_one<F>(&mut self, send: F) -> DatagramFlushResult
    where
        F: FnOnce(SocketAddr, &[u8]) -> DatagramSendAttempt,
    {
        let Some((class, pending)) = self.next() else {
            return DatagramFlushResult::Empty;
        };
        let destination = pending.destination;
        let expected = pending.bytes.len();

        match send(destination, pending.bytes) {
            DatagramSendAttempt::Sent(actual) if actual == expected => {
                let _ = self.pop_sent(class);
                DatagramFlushResult::Sent {
                    class,
                    bytes: actual,
                }
            }
            DatagramSendAttempt::Sent(actual) => DatagramFlushResult::PartialDatagram {
                class,
                expected,
                actual,
            },
            DatagramSendAttempt::WouldBlock => DatagramFlushResult::WouldBlock { class },
            DatagramSendAttempt::Failed => DatagramFlushResult::Failed { class },
        }
    }

    /// Selects control traffic first, but serves peer data after a bounded
    /// burst of successful control sends. FIFO order is preserved per class.
    pub fn next(&self) -> Option<(DatagramClass, PendingDatagram<'_>)> {
        if self.consecutive_control_sends >= CONTROL_BURST_LIMIT
            && let Some(datagram) = self.peer_data.front()
        {
            return Some((DatagramClass::PeerData, datagram));
        }
        if let Some(datagram) = self.control.front() {
            return Some((DatagramClass::Control, datagram));
        }
        self.peer_data
            .front()
            .map(|datagram| (DatagramClass::PeerData, datagram))
    }

    /// Removes the selected class's front item after a complete socket send
    /// and updates the bounded control-burst scheduler.
    pub fn pop_sent(&mut self, class: DatagramClass) -> Option<usize> {
        let removed = match class {
            DatagramClass::Control => self.control.pop_sent(),
            DatagramClass::PeerData => self.peer_data.pop_sent(),
        };
        if removed.is_some() {
            match class {
                DatagramClass::Control => {
                    self.consecutive_control_sends = self
                        .consecutive_control_sends
                        .saturating_add(1)
                        .min(CONTROL_BURST_LIMIT);
                }
                DatagramClass::PeerData => self.consecutive_control_sends = 0,
            }
        }
        removed
    }

    pub const fn control_len(&self) -> usize {
        self.control.len()
    }

    pub const fn peer_data_len(&self) -> usize {
        self.peer_data.len()
    }

    pub const fn control_queued_bytes(&self) -> usize {
        self.control.queued_bytes()
    }

    pub const fn peer_data_queued_bytes(&self) -> usize {
        self.peer_data.queued_bytes()
    }
}

impl<
    const CONTROL_CAPACITY: usize,
    const PEER_CAPACITY: usize,
    const MAX_DATAGRAM: usize,
    const CONTROL_MAX_BYTES: usize,
    const PEER_MAX_BYTES: usize,
> Default
    for TurnUdpSendQueues<
        CONTROL_CAPACITY,
        PEER_CAPACITY,
        MAX_DATAGRAM,
        CONTROL_MAX_BYTES,
        PEER_MAX_BYTES,
    >
{
    fn default() -> Self {
        Self::new()
    }
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

    /// Processes a received TURN datagram and exposes peer payload explicitly.
    ///
    /// This is the preferred receive API for a transport driver: it separates
    /// relayed peer data from TURN control traffic and unrelated datagrams.
    /// The payload borrows the input buffer and must be consumed before reuse.
    pub fn receive_datagram<'a>(
        &mut self,
        from: SocketAddr,
        datagram: &'a [u8],
        now: MonotonicTime,
    ) -> Result<TurnReceiveResult<'a>, TurnError> {
        match self.receive_from(from, datagram, now)? {
            TurnRecvRet::Handled => Ok(TurnReceiveResult::Handled),
            TurnRecvRet::Ignored(transmit) => Ok(TurnReceiveResult::Ignored {
                from: transmit.from,
            }),
            TurnRecvRet::PeerData(peer_data) => Ok(TurnReceiveResult::PeerData(peer_data)),
            TurnRecvRet::PeerIcmp {
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
                ..
            } => Ok(TurnReceiveResult::PeerIcmp {
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            }),
        }
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

        // DelayedTransmitBuild implementations may require an exact-size
        // destination. Pass only the encoded prefix, not the caller's full
        // reusable buffer, which may intentionally be larger.
        let transmit = build.write_into(&mut output[..required]);
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

/// Non-blocking UDP socket operations required by the TURN driver.
///
/// Implementations must bind the socket to the intended underlay network and,
/// on Android, protect it from the VPN before the first send. One driver owns
/// one socket for one TURN Allocation.
pub trait TurnDatagramSocket {
    fn local_addr(&self) -> SocketAddr;
    fn send_to(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<usize, DatagramSocketError>;
    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), DatagramSocketError>;
}

/// Portable socket error categories. Platform adapters should preserve their
/// native error details in their own diagnostics while mapping them here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramSocketError {
    WouldBlock,
    Failed,
}

/// Errors surfaced by the socket-owning TURN driver.
#[derive(Debug)]
pub enum TurnUdpDriverError {
    Turn(TurnError),
    Queue(DatagramQueueError),
    Socket(DatagramSocketError),
    PartialDatagram {
        expected: usize,
        actual: usize,
    },
    /// The socket or protocol failed; this Allocation driver is no longer usable.
    Retired,
}

/// Result of one bounded receive attempt.
#[derive(Debug)]
pub enum TurnUdpDriverReceive<'a> {
    WouldBlock,
    Datagram(TurnReceiveResult<'a>),
}

/// Owns one UDP socket, one TURN Allocation state machine, and bounded queues.
///
/// This driver deliberately does not create or bind sockets. The platform
/// supplies a socket that is already bound to the selected network and
/// protected from the VPN. No packet is forwarded through FFI.
pub struct TurnUdpDriver<
    S,
    const CONTROL_CAPACITY: usize = 32,
    const PEER_CAPACITY: usize = 256,
    const MAX_DATAGRAM: usize = 2048,
    const CONTROL_MAX_BYTES: usize = 16_384,
    const PEER_MAX_BYTES: usize = 262_144,
> {
    socket: S,
    engine: TurnUdpEngine,
    queues: TurnUdpSendQueues<
        CONTROL_CAPACITY,
        PEER_CAPACITY,
        MAX_DATAGRAM,
        CONTROL_MAX_BYTES,
        PEER_MAX_BYTES,
    >,
    retired: bool,
}

impl<
    S: TurnDatagramSocket,
    const CONTROL_CAPACITY: usize,
    const PEER_CAPACITY: usize,
    const MAX_DATAGRAM: usize,
    const CONTROL_MAX_BYTES: usize,
    const PEER_MAX_BYTES: usize,
>
    TurnUdpDriver<
        S,
        CONTROL_CAPACITY,
        PEER_CAPACITY,
        MAX_DATAGRAM,
        CONTROL_MAX_BYTES,
        PEER_MAX_BYTES,
    >
{
    /// Takes ownership of a pre-bound socket and creates its TURN state.
    pub fn new(
        socket: S,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> Result<Self, TurnError> {
        let engine = TurnUdpEngine::new(socket.local_addr(), server_addr, username, password)?;
        Ok(Self {
            socket,
            engine,
            queues: TurnUdpSendQueues::new(),
            retired: false,
        })
    }

    fn ensure_active(&self) -> Result<(), TurnUdpDriverError> {
        if self.retired {
            Err(TurnUdpDriverError::Retired)
        } else {
            Ok(())
        }
    }

    /// Advances TURN timers and queues at most one pending control datagram.
    ///
    /// Call this from the shared event loop when the driver's deadline expires
    /// or after relevant socket activity; do not create a task per packet.
    pub fn poll_control(&mut self, now: MonotonicTime) -> Result<bool, TurnUdpDriverError> {
        self.ensure_active()?;
        // Reserve worst-case queue capacity before advancing protocol state:
        // poll_transmit may consume a pending control transaction.
        self.queues
            .ensure_control_capacity(MAX_DATAGRAM)
            .map_err(TurnUdpDriverError::Queue)?;
        self.engine.poll(now).map_err(TurnUdpDriverError::Turn)?;
        let Some(transmit) = self
            .engine
            .poll_transmit(now)
            .map_err(TurnUdpDriverError::Turn)?
        else {
            return Ok(false);
        };
        self.queues
            .push_control_transmit(&transmit)
            .map_err(TurnUdpDriverError::Queue)?;
        Ok(true)
    }

    /// Encodes and queues one peer payload in caller-owned scratch storage.
    pub fn queue_peer_data(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
        now: MonotonicTime,
        encoded_buffer: &mut [u8],
    ) -> Result<usize, TurnUdpDriverError> {
        self.ensure_active()?;
        // Ensure both scratch storage and queue budgets can hold the largest
        // datagram before asking the TURN engine to build/consume this send.
        if encoded_buffer.len() < MAX_DATAGRAM {
            return Err(TurnUdpDriverError::Turn(TurnError::BufferTooSmall {
                required: MAX_DATAGRAM,
            }));
        }
        self.queues
            .ensure_peer_capacity(MAX_DATAGRAM)
            .map_err(TurnUdpDriverError::Queue)?;
        let outbound = self
            .engine
            .send_to_into(peer, payload, now, &mut encoded_buffer[..MAX_DATAGRAM])
            .map_err(TurnUdpDriverError::Turn)?;
        self.queues
            .push_peer_output(outbound, encoded_buffer)
            .map_err(TurnUdpDriverError::Queue)?;
        Ok(outbound.len)
    }

    /// Attempts one non-blocking UDP send. WouldBlock retains the queue item.
    ///
    /// A fatal socket error or a partial UDP send invalidates this driver;
    /// callers should drop it and establish a fresh Allocation/socket pair.
    pub fn flush_one(&mut self) -> Result<DatagramFlushResult, TurnUdpDriverError> {
        self.ensure_active()?;
        let socket = &mut self.socket;
        let mut socket_error = None;
        let result =
            self.queues.flush_one(
                |destination, bytes| match socket.send_to(destination, bytes) {
                    Ok(sent) => DatagramSendAttempt::Sent(sent),
                    Err(DatagramSocketError::WouldBlock) => DatagramSendAttempt::WouldBlock,
                    Err(error) => {
                        socket_error = Some(error);
                        DatagramSendAttempt::Failed
                    }
                },
            );

        if let Some(error) = socket_error {
            self.retired = true;
            self.engine.protocol_error();
            return Err(TurnUdpDriverError::Socket(error));
        }
        if let DatagramFlushResult::PartialDatagram {
            expected, actual, ..
        } = result
        {
            self.retired = true;
            self.engine.protocol_error();
            return Err(TurnUdpDriverError::PartialDatagram { expected, actual });
        }
        Ok(result)
    }

    /// Receives and processes at most one datagram into caller-owned storage.
    ///
    /// Peer payloads borrow the buffer; consume them before reusing it. TURN
    /// control messages are handled internally and are never exposed as VPN
    /// payloads. WouldBlock is not an error.
    pub fn receive_one<'a>(
        &mut self,
        buffer: &'a mut [u8],
        now: MonotonicTime,
    ) -> Result<TurnUdpDriverReceive<'a>, TurnUdpDriverError> {
        self.ensure_active()?;
        let (len, from) = match self.socket.recv_from(buffer) {
            Ok(received) => received,
            Err(DatagramSocketError::WouldBlock) => {
                return Ok(TurnUdpDriverReceive::WouldBlock);
            }
            Err(error) => {
                self.retired = true;
                self.engine.protocol_error();
                return Err(TurnUdpDriverError::Socket(error));
            }
        };
        if len > buffer.len() {
            self.retired = true;
            self.engine.protocol_error();
            return Err(TurnUdpDriverError::Turn(TurnError::BufferTooSmall {
                required: len,
            }));
        }
        self.engine
            .receive_datagram(from, &buffer[..len], now)
            .map(TurnUdpDriverReceive::Datagram)
            .map_err(TurnUdpDriverError::Turn)
    }

    pub const fn engine(&self) -> &TurnUdpEngine {
        &self.engine
    }

    pub const fn queued_control(&self) -> usize {
        self.queues.control_len()
    }

    pub const fn queued_peer_data(&self) -> usize {
        self.queues.peer_data_len()
    }

    /// Returns the socket, protocol state, and queues without discarding work.
    ///
    /// Pending control and peer datagrams remain available to the caller in the
    /// returned queues and must be flushed or explicitly abandoned.
    pub fn into_parts(
        self,
    ) -> (
        S,
        TurnUdpEngine,
        TurnUdpSendQueues<
            CONTROL_CAPACITY,
            PEER_CAPACITY,
            MAX_DATAGRAM,
            CONTROL_MAX_BYTES,
            PEER_MAX_BYTES,
        >,
    ) {
        (self.socket, self.engine, self.queues)
    }

    /// Explicitly abandons queued datagrams and returns only socket and engine.
    ///
    /// Use only during teardown after deciding that pending control and peer
    /// traffic must be discarded.
    pub fn into_parts_discarding_pending(self) -> (S, TurnUdpEngine) {
        (self.socket, self.engine)
    }
}

#[cfg(feature = "std")]
impl TurnDatagramSocket for std::net::UdpSocket {
    fn local_addr(&self) -> SocketAddr {
        std::net::UdpSocket::local_addr(self)
            .expect("bound UDP socket must expose its local address")
    }

    fn send_to(
        &mut self,
        destination: SocketAddr,
        datagram: &[u8],
    ) -> Result<usize, DatagramSocketError> {
        std::net::UdpSocket::send_to(self, datagram, destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                DatagramSocketError::WouldBlock
            } else {
                DatagramSocketError::Failed
            }
        })
    }

    fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), DatagramSocketError> {
        std::net::UdpSocket::recv_from(self, buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                DatagramSocketError::WouldBlock
            } else {
                DatagramSocketError::Failed
            }
        })
    }
}

fn to_instant(now: MonotonicTime) -> Result<Instant, TurnError> {
    let nanos = i64::try_from(now.0).map_err(|_| TurnError::TimeOutOfRange)?;
    Ok(Instant::from_nanos(nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination() -> SocketAddr {
        "198.51.100.1:3478".parse().unwrap()
    }

    #[test]
    fn receive_datagram_rejects_packets_from_unconfigured_server() {
        let mut engine = TurnUdpEngine::new(
            "192.0.2.10:40000".parse().unwrap(),
            "198.51.100.1:3478".parse().unwrap(),
            "test-user",
            "test-password",
        )
        .unwrap();
        let result = engine
            .receive_datagram(
                "203.0.113.9:3478".parse().unwrap(),
                &[0, 1, 2, 3],
                MonotonicTime(1),
            )
            .unwrap();
        assert!(matches!(
            result,
            TurnReceiveResult::Ignored { from }
                if from == "203.0.113.9:3478".parse().unwrap()
        ));
    }

    #[test]
    fn send_queue_retains_exact_datagram_across_would_block() {
        let mut queue = DatagramSendQueue::<3, 64, 128>::new();
        let first = [1, 2, 3, 4, 5];
        let second = [9, 8, 7];
        queue.push(destination(), &first).unwrap();
        queue
            .push("198.51.100.2:3478".parse().unwrap(), &second)
            .unwrap();

        // Re-reading front models a WouldBlock result: no state is consumed.
        for _ in 0..3 {
            let pending = queue.front().unwrap();
            assert_eq!(pending.destination, destination());
            assert_eq!(pending.bytes, first);
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.queued_bytes(), 8);
        }

        assert_eq!(queue.pop_sent(), Some(first.len()));
        let pending = queue.front().unwrap();
        assert_eq!(pending.destination, "198.51.100.2:3478".parse().unwrap());
        assert_eq!(pending.bytes, second);
        assert_eq!(queue.pop_sent(), Some(second.len()));
        assert!(queue.is_empty());
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[test]
    fn send_queue_enforces_record_byte_and_datagram_limits() {
        let mut queue = DatagramSendQueue::<1, 4, 3>::new();
        assert_eq!(
            queue.push(destination(), &[1, 2, 3, 4, 5]),
            Err(DatagramQueueError::DatagramTooLarge {
                maximum: 4,
                actual: 5
            })
        );
        queue.push(destination(), &[1, 2, 3]).unwrap();
        assert_eq!(
            queue.push(destination(), &[4]),
            Err(DatagramQueueError::RecordCapacityReached)
        );
        assert_eq!(
            queue.push(destination(), &[]),
            Err(DatagramQueueError::RecordCapacityReached)
        );
        assert_eq!(queue.queued_bytes(), 3);
        assert_eq!(queue.pop_sent(), Some(3));
        assert_eq!(queue.queued_bytes(), 0);
    }

    #[test]
    fn send_queue_enforces_aggregate_byte_limit() {
        let mut queue = DatagramSendQueue::<2, 4, 3>::new();
        queue.push(destination(), &[1, 2, 3]).unwrap();
        assert_eq!(
            queue.push(destination(), &[4]),
            Err(DatagramQueueError::ByteCapacityReached {
                maximum: 3,
                queued: 3,
                incoming: 1
            })
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.queued_bytes(), 3);
    }

    #[test]
    fn zero_capacity_queue_fails_closed_without_panicking() {
        let mut queue = DatagramSendQueue::<0, 4, 4>::new();
        assert_eq!(
            queue.push(destination(), &[1]),
            Err(DatagramQueueError::RecordCapacityReached)
        );
        assert!(queue.front().is_none());
        assert!(queue.pop_sent().is_none());
    }

    #[test]
    fn send_queue_reuses_ring_slots_without_reordering() {
        let mut queue = DatagramSendQueue::<2, 8, 16>::new();
        queue.push(destination(), &[1]).unwrap();
        queue.push(destination(), &[2]).unwrap();
        assert_eq!(queue.pop_sent(), Some(1));
        queue.push(destination(), &[3]).unwrap();
        assert_eq!(queue.front().unwrap().bytes, &[2]);
        assert_eq!(queue.pop_sent(), Some(1));
        assert_eq!(queue.front().unwrap().bytes, &[3]);
        assert_eq!(queue.pop_sent(), Some(1));
        assert!(queue.is_empty());
    }

    #[test]
    fn control_datagrams_are_selected_before_peer_data() {
        let mut queues = TurnUdpSendQueues::<2, 2, 32, 64, 64>::new();
        queues.push_peer_data(destination(), &[1, 2, 3]).unwrap();
        queues.push_peer_data(destination(), &[4, 5]).unwrap();
        queues.push_control(destination(), &[9, 8]).unwrap();

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::Control);
        assert_eq!(pending.bytes, &[9, 8]);
        assert_eq!(queues.pop_sent(class), Some(2));

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::PeerData);
        assert_eq!(pending.bytes, &[1, 2, 3]);
        assert_eq!(queues.pop_sent(class), Some(3));

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::PeerData);
        assert_eq!(pending.bytes, &[4, 5]);
        assert_eq!(queues.pop_sent(class), Some(2));
        assert!(queues.next().is_none());
    }

    #[test]
    fn control_transmit_queues_exact_encoded_bytes_and_destination() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 8, 8>::new();
        let transmit = Transmit::new(
            &[7, 8, 9][..],
            TransportType::Udp,
            destination(),
            destination(),
        );

        queues.push_control_transmit(&transmit).unwrap();

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::Control);
        assert_eq!(pending.destination, destination());
        assert_eq!(pending.bytes, &[7, 8, 9]);
    }

    #[test]
    fn peer_output_queues_only_the_encoded_prefix() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 8, 8>::new();
        let outbound = OutboundDatagram {
            destination: destination(),
            len: 3,
        };
        queues
            .push_peer_output(outbound, &[1, 2, 3, 99, 99])
            .unwrap();

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::PeerData);
        assert_eq!(pending.bytes, &[1, 2, 3]);
    }

    #[test]
    fn peer_output_rejects_length_beyond_buffer() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 8, 8>::new();
        let outbound = OutboundDatagram {
            destination: destination(),
            len: 4,
        };

        assert_eq!(
            queues.push_peer_output(outbound, &[1, 2, 3]),
            Err(DatagramQueueError::EncodedLengthExceedsBuffer {
                declared: 4,
                available: 3,
            })
        );
        assert_eq!(queues.peer_data_len(), 0);
    }

    #[test]
    fn peer_data_gets_service_after_bounded_control_burst() {
        let mut queues = TurnUdpSendQueues::<10, 1, 8, 80, 8>::new();
        for value in 0..10 {
            queues.push_control(destination(), &[value]).unwrap();
        }
        queues.push_peer_data(destination(), &[99]).unwrap();

        for _ in 0..CONTROL_BURST_LIMIT {
            let (class, _) = queues.next().unwrap();
            assert_eq!(class, DatagramClass::Control);
            assert_eq!(queues.pop_sent(class), Some(1));
        }

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::PeerData);
        assert_eq!(pending.bytes, &[99]);
        assert_eq!(queues.pop_sent(class), Some(1));

        let (class, pending) = queues.next().unwrap();
        assert_eq!(class, DatagramClass::Control);
        assert_eq!(pending.bytes, &[8]);
    }

    #[test]
    fn flush_one_removes_only_a_fully_sent_datagram() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 8, 8>::new();
        queues.push_control(destination(), &[1, 2, 3]).unwrap();

        assert_eq!(
            queues.flush_one(|to, bytes| {
                assert_eq!(to, destination());
                assert_eq!(bytes, &[1, 2, 3]);
                DatagramSendAttempt::WouldBlock
            }),
            DatagramFlushResult::WouldBlock {
                class: DatagramClass::Control
            }
        );
        assert_eq!(queues.control_len(), 1);

        assert_eq!(
            queues.flush_one(|_, _| DatagramSendAttempt::Failed),
            DatagramFlushResult::Failed {
                class: DatagramClass::Control
            }
        );
        assert_eq!(queues.control_len(), 1);

        assert_eq!(
            queues.flush_one(|_, bytes| DatagramSendAttempt::Sent(bytes.len())),
            DatagramFlushResult::Sent {
                class: DatagramClass::Control,
                bytes: 3
            }
        );
        assert_eq!(queues.control_len(), 0);
        assert_eq!(
            queues.flush_one(|_, _| unreachable!()),
            DatagramFlushResult::Empty
        );
    }

    #[test]
    fn flush_one_rejects_partial_udp_send_without_consuming_record() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 8, 8>::new();
        queues.push_peer_data(destination(), &[1, 2, 3, 4]).unwrap();

        assert_eq!(
            queues.flush_one(|_, _| DatagramSendAttempt::Sent(2)),
            DatagramFlushResult::PartialDatagram {
                class: DatagramClass::PeerData,
                expected: 4,
                actual: 2,
            }
        );
        assert_eq!(queues.peer_data_len(), 1);
        assert_eq!(queues.peer_data_queued_bytes(), 4);
    }

    #[test]
    fn control_and_peer_data_have_independent_capacity_budgets() {
        let mut queues = TurnUdpSendQueues::<1, 1, 8, 4, 4>::new();
        queues.push_peer_data(destination(), &[1, 2, 3, 4]).unwrap();
        queues.push_control(destination(), &[5, 6, 7, 8]).unwrap();

        assert_eq!(queues.control_len(), 1);
        assert_eq!(queues.peer_data_len(), 1);
        assert_eq!(queues.control_queued_bytes(), 4);
        assert_eq!(queues.peer_data_queued_bytes(), 4);
        assert_eq!(
            queues.push_control(destination(), &[9]),
            Err(DatagramQueueError::RecordCapacityReached)
        );
        assert_eq!(
            queues.push_peer_data(destination(), &[9]),
            Err(DatagramQueueError::RecordCapacityReached)
        );
    }

    #[test]
    fn would_block_does_not_remove_prioritized_control_datagram() {
        let mut queues = TurnUdpSendQueues::<2, 2, 16, 32, 32>::new();
        queues.push_peer_data(destination(), &[1]).unwrap();
        queues.push_control(destination(), &[2, 3]).unwrap();

        for _ in 0..3 {
            let (class, pending) = queues.next().unwrap();
            assert_eq!(class, DatagramClass::Control);
            assert_eq!(pending.bytes, &[2, 3]);
            assert_eq!(queues.control_len(), 1);
            assert_eq!(queues.peer_data_len(), 1);
        }
    }

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
