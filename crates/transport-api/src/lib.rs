#![no_std]

//! Runtime-neutral interfaces shared by GHONCHA transport adapters.
//!
//! This crate deliberately contains no sockets, async runtime, VK integration,
//! TURN implementation, cryptographic implementation, or packet parser.
//! Adapters exchange opaque authenticated tunnel records with the caller.

mod credentials;
pub use credentials::*;

mod rtp;
pub use rtp::*;

/// Stable, implementation-defined transport identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportId(pub &'static str);

/// How a transport preserves record boundaries on its underlying network path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordFraming {
    /// The underlying path preserves datagram boundaries.
    Datagram,
    /// The adapter frames records over a byte stream.
    LengthPrefixedStream,
}

/// Delivery behavior visible to the tunnel layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliverySemantics {
    /// Records may be lost, duplicated, or reordered.
    BestEffort,
    /// Records are delivered reliably and in order by the adapter.
    ReliableOrdered,
    /// Delivery behavior is specific to the adapter and must be documented.
    AdapterDefined,
}

/// Network protocol used by an adapter to reach its next hop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkProtocol {
    Udp,
    Tcp,
    Tls,
    Dtls,
    Quic,
    Other,
}

/// Address-family support advertised by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressFamilies(u8);

impl AddressFamilies {
    pub const NONE: Self = Self(0);
    pub const IPV4: Self = Self(1);
    pub const IPV6: Self = Self(2);
    pub const IPV4_AND_IPV6: Self = Self(3);

    pub const fn supports_ipv4(self) -> bool {
        self.0 & Self::IPV4.0 != 0
    }

    pub const fn supports_ipv6(self) -> bool {
        self.0 & Self::IPV6.0 != 0
    }
}

/// Immutable capabilities used by transport selection and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCapabilities {
    pub framing: RecordFraming,
    pub delivery: DeliverySemantics,
    pub max_record_size: u32,
    pub address_families: AddressFamilies,
    pub network_protocol: NetworkProtocol,
    pub supports_network_migration: bool,
    pub requires_keepalive: bool,
    pub requires_external_credentials: bool,
}

impl TransportCapabilities {
    /// Returns whether this adapter can carry a record of the given size.
    pub const fn supports_record_size(self, size: usize) -> bool {
        size <= self.max_record_size as usize
    }
}

/// Monotonic time in nanoseconds from an implementation-defined origin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime(pub u64);

/// Per-iteration limits. Adapters must not exceed either budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBudget {
    pub max_events: u16,
    pub max_bytes: u32,
}

/// Lifecycle of one adapter instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportState {
    Idle,
    Preparing,
    Establishing,
    Ready,
    Degraded,
    Recovering,
    Closing,
    Closed,
    Failed,
}

/// Parameters common to all transport adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    /// Monotonically increasing Android/Rust network generation.
    pub network_generation: u64,
    /// Maximum accepted GHONCHA record size for this session.
    pub max_record_size: u32,
}

/// Result of advancing timers, socket readiness and protocol state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollOutcome {
    pub work_done: u16,
    pub state: TransportState,
    /// Earliest time at which the adapter needs another timer-driven poll.
    pub next_deadline: Option<MonotonicTime>,
}

/// Non-secret reasons why a transport path has degraded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportDegradation {
    RelayUnavailable,
    Congestion,
    HighLatency,
    HighLoss,
    PathMtuReduced,
    NetworkChanged,
    Other,
}

/// Events emitted by an adapter and drained by the Rust client core.
///
/// Events are advisory observations, not proof that the VPN tunnel is
/// authenticated or that application traffic is flowing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportEventKind {
    StateChanged(TransportState),
    Degraded(TransportDegradation),
    PathMtuChanged { mtu: u16 },
    CredentialsExpiring,
    RemoteClosed,
}

/// A transport event tagged with its originating network generation.
///
/// The consumer must discard events whose generation is not the currently
/// active network generation. Timestamps use the same monotonic clock supplied
/// to the adapter's poll method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportEvent {
    pub at: MonotonicTime,
    pub network_generation: u64,
    pub kind: TransportEventKind,
}

/// Result of attempting to enqueue one complete record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    Accepted,
    Backpressure,
}

/// Result of receiving one complete record into caller-owned memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Record {
        len: usize,
    },
    WouldBlock,
    /// The next record remains queued; retry with a buffer of at least this size.
    BufferTooSmall {
        required: usize,
    },
}

/// Reasons for an explicit, idempotent adapter shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    UserRequest,
    NetworkChanged,
    CredentialsExpired,
    ProviderRevoked,
    PeerRejected,
    RetryBudgetExhausted,
    InternalFailure,
}

/// Errors with stable, non-secret diagnostic categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidConfiguration,
    NotStarted,
    AlreadyStarted,
    RecordTooLarge,
    InvalidState,
    NetworkGenerationMismatch,
    AuthenticationFailed,
    PeerIdentityMismatch,
    ProtocolViolation,
    ResourceLimit,
    IoFailure,
}

/// Stop condition for a bounded batch send.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchSendStop {
    Complete,
    Backpressure,
    Failed(TransportError),
}

/// Outcome of sending a prefix of a record batch.
///
/// `accepted` is valid even when `stop` is Backpressure or Failed; callers
/// must not retry records in the accepted prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchSendOutcome {
    pub accepted: usize,
    pub stop: BatchSendStop,
}

/// Caller-owned storage for one received record in a batch.
pub struct RecordBuffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl<'a> RecordBuffer<'a> {
    pub const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub const fn capacity(&self) -> usize {
        self.bytes.len()
    }
}

/// Stop condition for a bounded batch receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchReceiveStop {
    Complete,
    WouldBlock,
    BufferTooSmall { required: usize },
    Failed(TransportError),
}

/// Outcome of receiving a prefix of records into caller-owned buffers.
///
/// The first `received` buffers contain complete records. On BufferTooSmall,
/// the next record remains queued and its required size is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchReceiveOutcome {
    pub received: usize,
    pub stop: BatchReceiveStop,
}

/// Runtime-neutral contract for an adapter that transports opaque GHONCHA records.
///
/// Implementations must preserve record boundaries, enforce configured size
/// limits, bound all internal queues, and associate asynchronous work with the
/// active network generation. send_record and receive_record are called from
/// the Rust data plane; they must never be bridged to Kotlin per record.
pub trait RecordTransport {
    fn id(&self) -> TransportId;

    fn capabilities(&self) -> TransportCapabilities;

    fn state(&self) -> TransportState;

    /// Starts asynchronous setup. Progress is observed through poll.
    fn start(&mut self, config: TransportConfig) -> Result<(), TransportError>;

    /// Advances protocol timers and I/O readiness by at most budget.
    fn poll(&mut self, now: MonotonicTime, budget: IoBudget)
    -> Result<PollOutcome, TransportError>;

    /// Drains up to output.len() pending events into caller-owned storage.
    ///
    /// Events must be returned in emission order. Implementations must not
    /// consume an event that does not fit in output. A zero-length output slice
    /// must return zero without changing adapter state.
    fn poll_events(&mut self, output: &mut [TransportEvent]) -> usize {
        let _ = output;
        0
    }

    /// Enqueues one complete record or reports backpressure.
    fn send_record(&mut self, record: &[u8]) -> Result<SendOutcome, TransportError>;

    /// Enqueues as many complete records as possible without blocking.
    ///
    /// The default implementation preserves partial-acceptance information.
    /// Adapters may override it to batch framing, queue operations, or syscalls.
    fn send_records(&mut self, records: &[&[u8]]) -> BatchSendOutcome {
        let mut accepted = 0;
        for record in records {
            match self.send_record(record) {
                Ok(SendOutcome::Accepted) => accepted += 1,
                Ok(SendOutcome::Backpressure) => {
                    return BatchSendOutcome {
                        accepted,
                        stop: BatchSendStop::Backpressure,
                    };
                }
                Err(error) => {
                    return BatchSendOutcome {
                        accepted,
                        stop: BatchSendStop::Failed(error),
                    };
                }
            }
        }
        BatchSendOutcome {
            accepted,
            stop: BatchSendStop::Complete,
        }
    }

    /// Receives one complete record without allocating.
    ///
    /// BufferTooSmall must not consume or truncate the queued record.
    fn receive_record(&mut self, output: &mut [u8]) -> Result<ReceiveOutcome, TransportError>;

    /// Receives a bounded batch into caller-owned buffers without allocating.
    ///
    /// Each completed record is written to the corresponding buffer and its
    /// length is available through RecordBuffer::len/as_slice. On any stop
    /// condition, already received records remain valid and the next record
    /// is not consumed unless it fits in its destination buffer.
    fn receive_records(&mut self, output: &mut [RecordBuffer<'_>]) -> BatchReceiveOutcome {
        let mut received = 0;
        for slot in output.iter_mut() {
            slot.len = 0;
            match self.receive_record(slot.bytes) {
                Ok(ReceiveOutcome::Record { len }) if len <= slot.bytes.len() => {
                    slot.len = len;
                    received += 1;
                }
                Ok(ReceiveOutcome::Record { .. }) => {
                    return BatchReceiveOutcome {
                        received,
                        stop: BatchReceiveStop::Failed(TransportError::ProtocolViolation),
                    };
                }
                Ok(ReceiveOutcome::WouldBlock) => {
                    return BatchReceiveOutcome {
                        received,
                        stop: BatchReceiveStop::WouldBlock,
                    };
                }
                Ok(ReceiveOutcome::BufferTooSmall { required }) => {
                    return BatchReceiveOutcome {
                        received,
                        stop: BatchReceiveStop::BufferTooSmall { required },
                    };
                }
                Err(error) => {
                    return BatchReceiveOutcome {
                        received,
                        stop: BatchReceiveStop::Failed(error),
                    };
                }
            }
        }
        BatchReceiveOutcome {
            received,
            stop: BatchReceiveStop::Complete,
        }
    }

    /// Stops the adapter and releases sockets/allocations. Must be idempotent.
    fn close(&mut self, reason: CloseReason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_family_flags_are_independent() {
        assert!(AddressFamilies::IPV4_AND_IPV6.supports_ipv4());
        assert!(AddressFamilies::IPV4_AND_IPV6.supports_ipv6());
        assert!(AddressFamilies::IPV4.supports_ipv4());
        assert!(!AddressFamilies::IPV4.supports_ipv6());
        assert!(!AddressFamilies::NONE.supports_ipv4());
        assert!(!AddressFamilies::NONE.supports_ipv6());
    }

    #[test]
    fn record_size_limit_is_inclusive() {
        let capabilities = TransportCapabilities {
            framing: RecordFraming::Datagram,
            delivery: DeliverySemantics::BestEffort,
            max_record_size: 1200,
            address_families: AddressFamilies::IPV4_AND_IPV6,
            network_protocol: NetworkProtocol::Udp,
            supports_network_migration: false,
            requires_keepalive: true,
            requires_external_credentials: true,
        };

        assert!(capabilities.supports_record_size(0));
        assert!(capabilities.supports_record_size(1200));
        assert!(!capabilities.supports_record_size(1201));
    }

    #[test]
    fn stream_framing_is_distinct_from_reliable_delivery() {
        let framing = RecordFraming::LengthPrefixedStream;
        let delivery = DeliverySemantics::ReliableOrdered;

        assert_eq!(framing, RecordFraming::LengthPrefixedStream);
        assert_eq!(delivery, DeliverySemantics::ReliableOrdered);
    }

    #[test]
    fn events_are_scoped_to_a_network_generation() {
        let event = TransportEvent {
            at: MonotonicTime(42),
            network_generation: 9,
            kind: TransportEventKind::Degraded(TransportDegradation::HighLoss),
        };

        assert_eq!(event.at, MonotonicTime(42));
        assert_eq!(event.network_generation, 9);
        assert_eq!(
            event.kind,
            TransportEventKind::Degraded(TransportDegradation::HighLoss)
        );
    }

    struct MockTransport {
        state: TransportState,
        max_record_size: usize,
        pending: [u8; 1200],
        pending_len: Option<usize>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                state: TransportState::Idle,
                max_record_size: 1200,
                pending: [0; 1200],
                pending_len: None,
            }
        }
    }

    impl RecordTransport for MockTransport {
        fn id(&self) -> TransportId {
            TransportId("test")
        }

        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities {
                framing: RecordFraming::Datagram,
                delivery: DeliverySemantics::BestEffort,
                max_record_size: self.max_record_size as u32,
                address_families: AddressFamilies::IPV4_AND_IPV6,
                network_protocol: NetworkProtocol::Udp,
                supports_network_migration: false,
                requires_keepalive: false,
                requires_external_credentials: false,
            }
        }

        fn state(&self) -> TransportState {
            self.state
        }

        fn start(&mut self, config: TransportConfig) -> Result<(), TransportError> {
            if self.state != TransportState::Idle {
                return Err(TransportError::AlreadyStarted);
            }
            if config.max_record_size == 0 || config.max_record_size as usize > self.max_record_size
            {
                return Err(TransportError::InvalidConfiguration);
            }
            self.max_record_size = config.max_record_size as usize;
            self.state = TransportState::Ready;
            Ok(())
        }

        fn poll(
            &mut self,
            _now: MonotonicTime,
            _budget: IoBudget,
        ) -> Result<PollOutcome, TransportError> {
            Ok(PollOutcome {
                work_done: 0,
                state: self.state,
                next_deadline: None,
            })
        }

        fn send_record(&mut self, record: &[u8]) -> Result<SendOutcome, TransportError> {
            if self.state != TransportState::Ready {
                return Err(TransportError::NotStarted);
            }
            if record.len() > self.max_record_size {
                return Err(TransportError::RecordTooLarge);
            }
            if self.pending_len.is_some() {
                return Ok(SendOutcome::Backpressure);
            }
            self.pending[..record.len()].copy_from_slice(record);
            self.pending_len = Some(record.len());
            Ok(SendOutcome::Accepted)
        }

        fn receive_record(&mut self, output: &mut [u8]) -> Result<ReceiveOutcome, TransportError> {
            let Some(len) = self.pending_len else {
                return Ok(ReceiveOutcome::WouldBlock);
            };
            if output.len() < len {
                return Ok(ReceiveOutcome::BufferTooSmall { required: len });
            }
            output[..len].copy_from_slice(&self.pending[..len]);
            self.pending_len = None;
            Ok(ReceiveOutcome::Record { len })
        }

        fn close(&mut self, _reason: CloseReason) {
            self.pending_len = None;
            self.state = TransportState::Closed;
        }
    }

    #[test]
    fn bounded_transport_preserves_records_and_reports_backpressure() {
        let mut transport = MockTransport::new();
        transport
            .start(TransportConfig {
                network_generation: 7,
                max_record_size: 1200,
            })
            .unwrap();

        assert_eq!(
            transport.send_record(b"test").unwrap(),
            SendOutcome::Accepted
        );
        assert_eq!(
            transport.send_record(b"next").unwrap(),
            SendOutcome::Backpressure
        );

        let mut short = [0u8; 2];
        assert_eq!(
            transport.receive_record(&mut short).unwrap(),
            ReceiveOutcome::BufferTooSmall { required: 4 }
        );

        let mut output = [0u8; 4];
        assert_eq!(
            transport.receive_record(&mut output).unwrap(),
            ReceiveOutcome::Record { len: 4 }
        );
        assert_eq!(&output, b"test");
        assert_eq!(
            transport.receive_record(&mut output).unwrap(),
            ReceiveOutcome::WouldBlock
        );

        transport.close(CloseReason::UserRequest);
        transport.close(CloseReason::InternalFailure);
        assert_eq!(transport.state(), TransportState::Closed);
    }

    #[test]
    fn batch_send_reports_partial_acceptance_and_backpressure() {
        let mut transport = MockTransport::new();
        transport
            .start(TransportConfig {
                network_generation: 1,
                max_record_size: 1200,
            })
            .unwrap();

        let records: [&[u8]; 2] = [b"first", b"second"];
        let outcome = transport.send_records(&records);

        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.stop, BatchSendStop::Backpressure);
    }

    #[test]
    fn batch_receive_preserves_lengths_and_stops_when_drained() {
        let mut transport = MockTransport::new();
        transport
            .start(TransportConfig {
                network_generation: 1,
                max_record_size: 1200,
            })
            .unwrap();
        assert_eq!(
            transport.send_record(b"batch").unwrap(),
            SendOutcome::Accepted
        );

        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        let mut output = [
            RecordBuffer::new(&mut first),
            RecordBuffer::new(&mut second),
        ];
        let outcome = transport.receive_records(&mut output);

        assert_eq!(outcome.received, 1);
        assert_eq!(outcome.stop, BatchReceiveStop::WouldBlock);
        assert_eq!(output[0].as_slice(), b"batch");
        assert_eq!(output[1].len(), 0);
    }

    #[test]
    fn bounded_transport_rejects_oversized_records() {
        let mut transport = MockTransport::new();
        transport
            .start(TransportConfig {
                network_generation: 1,
                max_record_size: 8,
            })
            .unwrap();

        assert_eq!(
            transport.send_record(b"123456789"),
            Err(TransportError::RecordTooLarge)
        );
    }
}
