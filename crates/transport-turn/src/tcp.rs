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
            len: transmit.data.len(),
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
        let mut engine =
            TurnTcpEngine::new(local(), server(), "test-user", "test-password").unwrap();

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


/// Non-blocking byte-stream operations required by the TURN TCP driver.
///
/// The socket must already be connected to the configured TURN server, bound
/// to the selected underlay Network, and protected from the VPN on Android.
pub trait TurnStreamSocket {
    fn local_addr(&self) -> SocketAddr;
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TurnStreamIoError>;
    fn write(&mut self, bytes: &[u8]) -> Result<usize, TurnStreamIoError>;
}

/// Portable non-blocking stream I/O error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnStreamIoError {
    WouldBlock,
    Failed,
}

/// Errors from the bounded raw TURN stream send queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnTcpQueueError {
    EmptyFrame,
    FrameTooLarge { maximum: usize, actual: usize },
    QueueFull,
    ByteLimitReached {
        maximum: usize,
        queued: usize,
        incoming: usize,
    },
    NoPendingFrame,
    NoProgress,
    WriteExceedsPending { remaining: usize, attempted: usize },
}

/// One encoded TURN wire frame retained across partial TCP writes.
struct QueuedTurnFrame<const MAX_FRAME: usize> {
    bytes: [u8; MAX_FRAME],
    len: usize,
    offset: usize,
}

/// Borrowed unwritten suffix of the current TURN stream frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingTurnFrame<'a> {
    pub bytes: &'a [u8],
}

/// Fixed-capacity FIFO for raw TURN stream bytes.
///
/// This queue deliberately adds no framing prefix. STUN messages and
/// ChannelData already have TURN-defined framing; adding a generic record
/// prefix here would corrupt the TURN/TCP wire protocol.
pub struct TurnTcpSendQueue<
    const CAPACITY: usize,
    const MAX_FRAME: usize,
    const MAX_QUEUED_BYTES: usize,
> {
    entries: [Option<QueuedTurnFrame<MAX_FRAME>>; CAPACITY],
    head: usize,
    len: usize,
    queued_bytes: usize,
}

impl<const CAPACITY: usize, const MAX_FRAME: usize, const MAX_QUEUED_BYTES: usize>
    TurnTcpSendQueue<CAPACITY, MAX_FRAME, MAX_QUEUED_BYTES>
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

    pub fn ensure_capacity(&self, maximum_incoming: usize) -> Result<(), TurnTcpQueueError> {
        if self.len == CAPACITY {
            return Err(TurnTcpQueueError::QueueFull);
        }
        let next = self.queued_bytes.checked_add(maximum_incoming).ok_or(
            TurnTcpQueueError::ByteLimitReached {
                maximum: MAX_QUEUED_BYTES,
                queued: self.queued_bytes,
                incoming: maximum_incoming,
            },
        )?;
        if next > MAX_QUEUED_BYTES {
            return Err(TurnTcpQueueError::ByteLimitReached {
                maximum: MAX_QUEUED_BYTES,
                queued: self.queued_bytes,
                incoming: maximum_incoming,
            });
        }
        Ok(())
    }

    pub fn push(&mut self, frame: &[u8]) -> Result<(), TurnTcpQueueError> {
        if frame.is_empty() {
            return Err(TurnTcpQueueError::EmptyFrame);
        }
        if frame.len() > MAX_FRAME {
            return Err(TurnTcpQueueError::FrameTooLarge {
                maximum: MAX_FRAME,
                actual: frame.len(),
            });
        }
        self.ensure_capacity(frame.len())?;

        let tail = (self.head + self.len) % CAPACITY;
        let mut bytes = [0; MAX_FRAME];
        bytes[..frame.len()].copy_from_slice(frame);
        self.entries[tail] = Some(QueuedTurnFrame {
            bytes,
            len: frame.len(),
            offset: 0,
        });
        self.len += 1;
        self.queued_bytes += frame.len();
        Ok(())
    }

    pub fn front(&self) -> Option<PendingTurnFrame<'_>> {
        let entry = self.entries.get(self.head)?.as_ref()?;
        Some(PendingTurnFrame {
            bytes: &entry.bytes[entry.offset..entry.len],
        })
    }

    /// Accounts for bytes accepted by the socket. Returns true when the
    /// current logical TURN frame has been fully written.
    pub fn advance_written(&mut self, written: usize) -> Result<bool, TurnTcpQueueError> {
        if self.len == 0 {
            return Err(TurnTcpQueueError::NoPendingFrame);
        }
        if written == 0 {
            return Err(TurnTcpQueueError::NoProgress);
        }

        let complete = {
            let entry = self.entries[self.head]
                .as_mut()
                .expect("occupied queue head must contain a frame");
            let remaining = entry.len - entry.offset;
            if written > remaining {
                return Err(TurnTcpQueueError::WriteExceedsPending {
                    remaining,
                    attempted: written,
                });
            }
            entry.offset += written;
            entry.offset == entry.len
        };

        self.queued_bytes -= written;
        if complete {
            self.entries[self.head] = None;
            self.len -= 1;
            self.head = if self.head + 1 == CAPACITY {
                0
            } else {
                self.head + 1
            };
        }
        Ok(complete)
    }
}

impl<const CAPACITY: usize, const MAX_FRAME: usize, const MAX_QUEUED_BYTES: usize> Default
    for TurnTcpSendQueue<CAPACITY, MAX_FRAME, MAX_QUEUED_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Result of advancing TURN timers and queueing one control frame.
#[derive(Debug)]
pub struct TurnTcpControlPoll {
    pub protocol: TurnPollRet,
    pub queued_control: bool,
    pub queue_blocked: bool,
}

/// Outcome of one non-blocking TCP stream write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnTcpFlushResult {
    Empty,
    Written { bytes: usize, frame_complete: bool },
    WouldBlock,
    Closed,
    Failed,
    InvalidWriteCount { offered: usize, reported: usize },
}

/// Outcome of one non-blocking TCP stream read.
#[derive(Debug)]
pub enum TurnTcpDriverReceive<'a> {
    WouldBlock,
    Closed,
    Data(TurnReceiveResult<'a>),
}

/// Errors surfaced by the socket-owning TURN TCP driver.
#[derive(Debug)]
pub enum TurnTcpDriverError {
    Turn(TurnTcpError),
    Queue(TurnTcpQueueError),
    Socket(TurnStreamIoError),
    Retired,
}

/// Owns one connected TCP stream, one TURN client state machine, and a bounded
/// FIFO of raw TURN wire frames.
///
/// Partial writes retain the exact unwritten suffix. The next frame is never
/// interleaved with the current one. No generic length prefix is added because
/// TURN/STUN and ChannelData have their own framing.
pub struct TurnTcpDriver<
    S,
    const CAPACITY: usize = 16,
    const MAX_FRAME: usize = 4096,
    const MAX_QUEUED_BYTES: usize = 65_536,
> {
    socket: S,
    engine: TurnTcpEngine,
    queue: TurnTcpSendQueue<CAPACITY, MAX_FRAME, MAX_QUEUED_BYTES>,
    retired: bool,
}

impl<
        S: TurnStreamSocket,
        const CAPACITY: usize,
        const MAX_FRAME: usize,
        const MAX_QUEUED_BYTES: usize,
    > TurnTcpDriver<S, CAPACITY, MAX_FRAME, MAX_QUEUED_BYTES>
{
    /// Takes ownership of a connected stream and creates its TURN state.
    pub fn new(
        socket: S,
        server_addr: SocketAddr,
        username: &str,
        password: &str,
    ) -> Result<Self, TurnTcpError> {
        let engine = TurnTcpEngine::new(socket.local_addr(), server_addr, username, password)?;
        Ok(Self {
            socket,
            engine,
            queue: TurnTcpSendQueue::new(),
            retired: false,
        })
    }

    fn ensure_active(&self) -> Result<(), TurnTcpDriverError> {
        if self.retired {
            Err(TurnTcpDriverError::Retired)
        } else {
            Ok(())
        }
    }

    /// Advances TURN timers and queues at most one control frame.
    ///
    /// The caller schedules the next timer from the returned WaitUntil value.
    /// A full queue leaves the pending protocol transmit untouched.
    pub fn poll_control_with_deadline(
        &mut self,
        now: MonotonicTime,
    ) -> Result<TurnTcpControlPoll, TurnTcpDriverError> {
        self.ensure_active()?;
        let protocol = self.engine.poll(now).map_err(TurnTcpDriverError::Turn)?;
        if self.queue.ensure_capacity(MAX_FRAME).is_err() {
            return Ok(TurnTcpControlPoll {
                protocol,
                queued_control: false,
                queue_blocked: true,
            });
        }

        let Some(transmit) = self
            .engine
            .poll_transmit(now)
            .map_err(TurnTcpDriverError::Turn)?
        else {
            return Ok(TurnTcpControlPoll {
                protocol,
                queued_control: false,
                queue_blocked: false,
            });
        };

        let bytes = transmit.data.as_ref();
        if bytes.len() > MAX_FRAME {
            self.retire();
            return Err(TurnTcpDriverError::Queue(
                TurnTcpQueueError::FrameTooLarge {
                    maximum: MAX_FRAME,
                    actual: bytes.len(),
                },
            ));
        }
        if let Err(error) = self.queue.push(bytes) {
            self.retire();
            return Err(TurnTcpDriverError::Queue(error));
        }

        Ok(TurnTcpControlPoll {
            protocol,
            queued_control: true,
            queue_blocked: false,
        })
    }

    /// Encodes and queues one peer payload. The scratch buffer must be at
    /// least MAX_FRAME bytes so the TURN build cannot be consumed then lost.
    pub fn queue_peer_data(
        &mut self,
        peer: SocketAddr,
        payload: &[u8],
        now: MonotonicTime,
        encoded_buffer: &mut [u8],
    ) -> Result<usize, TurnTcpDriverError> {
        self.ensure_active()?;
        if encoded_buffer.len() < MAX_FRAME {
            return Err(TurnTcpDriverError::Queue(
                TurnTcpQueueError::FrameTooLarge {
                    maximum: MAX_FRAME,
                    actual: encoded_buffer.len(),
                },
            ));
        }
        self.queue
            .ensure_capacity(MAX_FRAME)
            .map_err(TurnTcpDriverError::Queue)?;

        let outbound = match self.engine.send_to_into(
            peer,
            payload,
            now,
            &mut encoded_buffer[..MAX_FRAME],
        ) {
            Ok(outbound) => outbound,
            Err(error @ TurnTcpError::BufferTooSmall { .. }) => {
                self.retire();
                return Err(TurnTcpDriverError::Turn(error));
            }
            Err(error) => return Err(TurnTcpDriverError::Turn(error)),
        };

        if let Err(error) = self.queue.push(&encoded_buffer[..outbound.len]) {
            self.retire();
            return Err(TurnTcpDriverError::Queue(error));
        }
        Ok(outbound.len)
    }

    /// Attempts one non-blocking write. WouldBlock preserves the queue.
    pub fn flush_one(&mut self) -> Result<TurnTcpFlushResult, TurnTcpDriverError> {
        self.ensure_active()?;
        let Some(pending) = self.queue.front() else {
            return Ok(TurnTcpFlushResult::Empty);
        };
        let offered = pending.bytes.len();

        match self.socket.write(pending.bytes) {
            Ok(0) => {
                self.retire();
                Ok(TurnTcpFlushResult::Closed)
            }
            Ok(reported) if reported > offered => {
                self.retire();
                Ok(TurnTcpFlushResult::InvalidWriteCount { offered, reported })
            }
            Ok(reported) => {
                let frame_complete = self
                    .queue
                    .advance_written(reported)
                    .map_err(TurnTcpDriverError::Queue)?;
                Ok(TurnTcpFlushResult::Written {
                    bytes: reported,
                    frame_complete,
                })
            }
            Err(TurnStreamIoError::WouldBlock) => Ok(TurnTcpFlushResult::WouldBlock),
            Err(TurnStreamIoError::Failed) => {
                self.retire();
                Ok(TurnTcpFlushResult::Failed)
            }
        }
    }

    /// Reads one bounded chunk from the stream and feeds the TURN parser.
    /// A zero-byte read is EOF and permanently retires this driver.
    pub fn receive_one<'a>(
        &mut self,
        buffer: &'a mut [u8],
        now: MonotonicTime,
    ) -> Result<TurnTcpDriverReceive<'a>, TurnTcpDriverError> {
        self.ensure_active()?;
        if buffer.is_empty() {
            return Ok(TurnTcpDriverReceive::WouldBlock);
        }

        match self.socket.read(buffer) {
            Ok(0) => {
                self.retire();
                Ok(TurnTcpDriverReceive::Closed)
            }
            Ok(read) if read > buffer.len() => {
                self.retire();
                Err(TurnTcpDriverError::Socket(TurnStreamIoError::Failed))
            }
            Ok(read) => self
                .engine
                .receive_stream_bytes(&buffer[..read], now)
                .map(TurnTcpDriverReceive::Data)
                .map_err(TurnTcpDriverError::Turn),
            Err(TurnStreamIoError::WouldBlock) => Ok(TurnTcpDriverReceive::WouldBlock),
            Err(TurnStreamIoError::Failed) => {
                self.retire();
                Ok(TurnTcpDriverReceive::Closed)
            }
        }
    }

    /// Drains one additional peer payload already buffered by the TURN parser.
    pub fn poll_peer_data(
        &mut self,
        now: MonotonicTime,
    ) -> Result<
        Option<turn_client_proto::api::TurnPeerData<alloc::vec::Vec<u8>>>,
        TurnTcpDriverError,
    > {
        self.ensure_active()?;
        self.engine
            .poll_peer_data(now)
            .map_err(TurnTcpDriverError::Turn)
    }

    pub fn poll_event(&mut self) -> Option<TurnEvent> {
        self.engine.poll_event()
    }

    pub fn socket(&self) -> &S {
        &self.socket
    }

    pub const fn queued_frames(&self) -> usize {
        self.queue.len()
    }

    pub const fn queued_bytes(&self) -> usize {
        self.queue.queued_bytes()
    }

    fn retire(&mut self) {
        if !self.retired {
            self.retired = true;
            self.engine.protocol_error();
        }
    }

    /// Returns all owned state without discarding queued bytes.
    pub fn into_parts(
        self,
    ) -> (
        S,
        TurnTcpEngine,
        TurnTcpSendQueue<CAPACITY, MAX_FRAME, MAX_QUEUED_BYTES>,
    ) {
        (self.socket, self.engine, self.queue)
    }

    /// Explicitly abandons queued bytes during teardown.
    pub fn into_parts_discarding_pending(self) -> (S, TurnTcpEngine) {
        (self.socket, self.engine)
    }
}

#[cfg(feature = "std")]
impl TurnStreamSocket for std::net::TcpStream {
    fn local_addr(&self) -> SocketAddr {
        std::net::TcpStream::local_addr(self)
            .expect("connected TCP stream must expose its local address")
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TurnStreamIoError> {
        use std::io::Read;
        std::io::Read::read(self, buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                TurnStreamIoError::WouldBlock
            } else {
                TurnStreamIoError::Failed
            }
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, TurnStreamIoError> {
        use std::io::Write;
        std::io::Write::write(self, bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                TurnStreamIoError::WouldBlock
            } else {
                TurnStreamIoError::Failed
            }
        })
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;
    use alloc::vec::Vec;

    #[derive(Debug)]
    struct MockStream {
        local: SocketAddr,
        writes: Vec<u8>,
        write_limit: usize,
        would_block: bool,
    }

    impl TurnStreamSocket for MockStream {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }

        fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, TurnStreamIoError> {
            Err(TurnStreamIoError::WouldBlock)
        }

        fn write(&mut self, bytes: &[u8]) -> Result<usize, TurnStreamIoError> {
            if self.would_block {
                return Err(TurnStreamIoError::WouldBlock);
            }
            let written = bytes.len().min(self.write_limit);
            self.writes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }
    }

    fn mock_stream() -> MockStream {
        MockStream {
            local: "192.0.2.10:40000".parse().unwrap(),
            writes: Vec::new(),
            write_limit: 2,
            would_block: false,
        }
    }

    #[test]
    fn raw_turn_queue_preserves_frame_boundaries_across_partial_writes() {
        let mut queue = TurnTcpSendQueue::<2, 16, 32>::new();
        queue.push(&[1, 2, 3, 4, 5]).unwrap();
        queue.push(&[6, 7, 8]).unwrap();

        assert_eq!(queue.front().unwrap().bytes, &[1, 2, 3, 4, 5]);
        assert!(!queue.advance_written(2).unwrap());
        assert_eq!(queue.front().unwrap().bytes, &[3, 4, 5]);
        assert!(queue.advance_written(3).unwrap());
        assert_eq!(queue.front().unwrap().bytes, &[6, 7, 8]);
        assert!(queue.advance_written(3).unwrap());
        assert!(queue.is_empty());
    }

    #[test]
    fn raw_turn_queue_enforces_record_and_byte_budgets() {
        let mut queue = TurnTcpSendQueue::<2, 8, 8>::new();
        assert_eq!(queue.push(&[]), Err(TurnTcpQueueError::EmptyFrame));
        assert_eq!(
            queue.push(&[0; 9]),
            Err(TurnTcpQueueError::FrameTooLarge {
                maximum: 8,
                actual: 9
            })
        );
        queue.push(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(
            queue.push(&[6, 7, 8, 9]),
            Err(TurnTcpQueueError::ByteLimitReached {
                maximum: 8,
                queued: 5,
                incoming: 4
            })
        );
    }

    #[test]
    fn driver_retains_unwritten_suffix_after_would_block_and_partial_write() {
        let mut driver = TurnTcpDriver::<MockStream, 2, 16, 32>::new(
            mock_stream(),
            "198.51.100.1:3478".parse().unwrap(),
            "test-user",
            "test-password",
        )
        .unwrap();
        driver.queue.push(&[1, 2, 3, 4, 5]).unwrap();
        driver.socket.would_block = true;

        assert_eq!(driver.flush_one().unwrap(), TurnTcpFlushResult::WouldBlock);
        assert_eq!(driver.queued_bytes(), 5);
        driver.socket.would_block = false;

        assert_eq!(
            driver.flush_one().unwrap(),
            TurnTcpFlushResult::Written {
                bytes: 2,
                frame_complete: false
            }
        );
        assert_eq!(driver.queued_bytes(), 3);
        assert_eq!(driver.socket.writes, &[1, 2]);

        assert_eq!(
            driver.flush_one().unwrap(),
            TurnTcpFlushResult::Written {
                bytes: 2,
                frame_complete: false
            }
        );
        assert_eq!(
            driver.flush_one().unwrap(),
            TurnTcpFlushResult::Written {
                bytes: 1,
                frame_complete: true
            }
        );
        assert_eq!(driver.socket.writes, &[1, 2, 3, 4, 5]);
        assert_eq!(driver.queued_frames(), 0);
    }

    #[test]
    fn zero_capacity_queue_fails_without_modulo_or_panic() {
        let mut queue = TurnTcpSendQueue::<0, 8, 8>::new();
        assert_eq!(queue.push(&[1]), Err(TurnTcpQueueError::QueueFull));
        assert!(queue.front().is_none());
    }
}
