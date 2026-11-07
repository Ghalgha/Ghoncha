//! Heap-owned, bounded multi-allocation TURN UDP runtime core.
//!
//! This runtime owns one boxed driver per allocation and provides bounded
//! timer/readiness dispatch. The platform remains responsible for registering
//! each socket with its OS poller and must unregister a token before removing
//! or dropping its driver. No thread, socket, or async executor is created here.

extern crate alloc;

use alloc::alloc::{Layout, alloc};
use alloc::boxed::Box;
use core::net::SocketAddr;
use core::ptr;

use ghoncha_transport_api::MonotonicTime;

use crate::{
    TurnReceiveResult, TurnUdpControlPoll, TurnUdpDriver, TurnUdpDriverError, TurnUdpIoProgress,
    TurnUdpIoReady,
};

/// Errors while adding or locating a runtime allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnUdpRuntimeError {
    CapacityReached,
    DuplicateAllocationId,
    DuplicateRegistrationToken,
    UnknownAllocation,
    AllocationFailed,
}

/// Failure while dispatching an event or payload through the runtime.
#[derive(Debug)]
pub enum TurnUdpRuntimeServiceError {
    Runtime(TurnUdpRuntimeError),
    Driver(TurnUdpDriverError),
}

/// One heap-owned driver and its OS-poller registration identity.
struct RuntimeAllocation<S> {
    id: u16,
    token: u64,
    driver: Box<TurnUdpDriver<S>>,
    deadline: Option<MonotonicTime>,
}

/// Bounded owner for multiple independent TURN UDP allocation drivers.
///
/// Driver state and its large bounded datagram queues live behind one Box per
/// allocation. The fixed slot table remains inline and contains only small
/// ownership handles. The runtime never moves an existing flow between
/// allocations; flow affinity is handled by the allocation manager.
pub struct TurnUdpRuntime<S, const CAPACITY: usize> {
    slots: [Option<RuntimeAllocation<S>>; CAPACITY],
    len: usize,
    scan_cursor: usize,
}

impl<S: crate::TurnDatagramSocket, const CAPACITY: usize> TurnUdpRuntime<S, CAPACITY> {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
            scan_cursor: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn capacity(&self) -> usize {
        CAPACITY
    }

    /// Inserts a driver and schedules its first protocol poll immediately.
    ///
    /// The driver is boxed with a fallible allocation so a large per-driver
    /// object is never placed in a long-lived stack slot. Its queue backing
    /// stores were already allocated fallibly by TurnUdpDriver::new().
    pub fn insert(
        &mut self,
        id: u16,
        token: u64,
        driver: TurnUdpDriver<S>,
        now: MonotonicTime,
    ) -> Result<(), TurnUdpRuntimeError> {
        if self.len == CAPACITY {
            return Err(TurnUdpRuntimeError::CapacityReached);
        }
        if self.slots.iter().flatten().any(|slot| slot.id == id) {
            return Err(TurnUdpRuntimeError::DuplicateAllocationId);
        }
        if token == 0 || self.slots.iter().flatten().any(|slot| slot.token == token) {
            return Err(TurnUdpRuntimeError::DuplicateRegistrationToken);
        }
        let boxed = try_box(driver)?;
        let vacant = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("runtime length and slot occupancy must agree");
        *vacant = Some(RuntimeAllocation {
            id,
            token,
            driver: boxed,
            deadline: Some(now),
        });
        self.len += 1;
        Ok(())
    }

    pub fn token_for_id(&self, id: u16) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.id == id)
            .map(|slot| slot.token)
    }

    pub fn id_for_token(&self, token: u64) -> Option<u16> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.token == token)
            .map(|slot| slot.id)
    }

    pub fn driver(&self, id: u16) -> Option<&TurnUdpDriver<S>> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.id == id)
            .map(|slot| slot.driver.as_ref())
    }

    pub fn driver_mut(&mut self, id: u16) -> Option<&mut TurnUdpDriver<S>> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.id == id)
            .map(|slot| slot.driver.as_mut())
    }

    /// Earliest protocol timer across all active drivers.
    pub fn next_deadline(&self) -> Option<MonotonicTime> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|slot| slot.deadline)
            .min()
    }

    /// Whether a token currently has queued output and should request POLLOUT.
    pub fn has_pending_output(&self, token: u64) -> Option<bool> {
        self.slots
            .iter()
            .flatten()
            .find(|slot| slot.token == token)
            .map(|slot| slot.driver.queued_control() != 0 || slot.driver.queued_peer_data() != 0)
    }

    /// Advances due allocation timers, with a persistent scan cursor and an
    /// explicit maximum number of drivers per call.
    ///
    /// Errors are returned to the callback for platform policy. A failed driver
    /// is not silently removed: the caller must unregister its poller token,
    /// drain/retire it, and then call remove().
    pub fn poll_due<F>(&mut self, now: MonotonicTime, max_drivers: usize, mut on_result: F) -> usize
    where
        F: FnMut(u16, u64, Result<TurnUdpControlPoll, TurnUdpDriverError>),
    {
        if CAPACITY == 0 || max_drivers == 0 {
            return 0;
        }
        let mut serviced = 0;
        let scan_budget = core::cmp::min(max_drivers, CAPACITY);
        let mut scanned = 0;
        while scanned < CAPACITY && serviced < scan_budget {
            let index = self.scan_cursor;
            self.scan_cursor = (self.scan_cursor + 1) % CAPACITY;
            scanned += 1;

            let Some(slot) = self.slots[index].as_mut() else {
                continue;
            };
            if !slot.deadline.is_some_and(|deadline| now >= deadline) {
                continue;
            }

            let result = slot.driver.poll_control_with_deadline(now);
            slot.deadline = match &result {
                Ok(progress) => progress.next_deadline,
                Err(_) => None,
            };
            let id = slot.id;
            let token = slot.token;
            serviced += 1;
            on_result(id, token, result);
        }
        serviced
    }

    /// Services one poller event identified by its opaque registration token.
    /// The callback must consume borrowed peer payloads before it returns.
    pub fn service_ready<F>(
        &mut self,
        token: u64,
        ready: TurnUdpIoReady,
        now: MonotonicTime,
        receive_buffer: &mut [u8],
        on_datagram: F,
    ) -> Result<TurnUdpIoProgress, TurnUdpRuntimeServiceError>
    where
        F: for<'a> FnMut(TurnReceiveResult<'a>),
    {
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.token == token)
            .ok_or(TurnUdpRuntimeServiceError::Runtime(
                TurnUdpRuntimeError::UnknownAllocation,
            ))?;
        slot.driver
            .service_ready(ready, now, receive_buffer, on_datagram)
            .map_err(TurnUdpRuntimeServiceError::Driver)
    }

    /// Queues one peer payload on an allocation selected by flow affinity.
    pub fn queue_peer_data(
        &mut self,
        id: u16,
        peer: SocketAddr,
        payload: &[u8],
        now: MonotonicTime,
        encoded_buffer: &mut [u8],
    ) -> Result<usize, TurnUdpRuntimeQueueError> {
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.id == id)
            .ok_or(TurnUdpRuntimeQueueError::Runtime(
                TurnUdpRuntimeError::UnknownAllocation,
            ))?;
        slot.driver
            .queue_peer_data(peer, payload, now, encoded_buffer)
            .map_err(TurnUdpRuntimeQueueError::Driver)
    }

    /// Removes a driver after its poller registration has already been
    /// unregistered. The caller owns the returned Box and decides whether its
    /// pending protocol work is flushed or explicitly abandoned.
    pub fn remove(&mut self, id: u16) -> Result<Box<TurnUdpDriver<S>>, TurnUdpRuntimeError> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.id == id))
            .ok_or(TurnUdpRuntimeError::UnknownAllocation)?;
        let slot = self.slots[index]
            .take()
            .expect("located runtime slot must remain occupied");
        self.len -= 1;
        Ok(slot.driver)
    }
}

impl<S: crate::TurnDatagramSocket, const CAPACITY: usize> Default for TurnUdpRuntime<S, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

/// Failure to enqueue through a runtime-owned allocation.
#[derive(Debug)]
pub enum TurnUdpRuntimeQueueError {
    Runtime(TurnUdpRuntimeError),
    Driver(TurnUdpDriverError),
}

/// Allocates a Box without invoking the infallible Box::new allocation path.
fn try_box<T>(value: T) -> Result<Box<T>, TurnUdpRuntimeError> {
    let layout = Layout::new::<T>();
    // SAFETY: layout is the exact layout of T and the returned allocation is
    // initialized below before it is converted into Box<T>.
    let raw = unsafe { alloc(layout) }.cast::<T>();
    if raw.is_null() {
        return Err(TurnUdpRuntimeError::AllocationFailed);
    }
    // SAFETY: raw points to a suitably aligned allocation for one T.
    unsafe {
        ptr::write(raw, value);
        Ok(Box::from_raw(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatagramReceive, DatagramSocketError, TurnDatagramSocket};
    use core::net::SocketAddr;

    struct MockSocket {
        local: SocketAddr,
        sent: usize,
    }

    impl TurnDatagramSocket for MockSocket {
        fn local_addr(&self) -> SocketAddr {
            self.local
        }

        fn send_to(
            &mut self,
            _destination: SocketAddr,
            datagram: &[u8],
        ) -> Result<usize, DatagramSocketError> {
            self.sent += 1;
            Ok(datagram.len())
        }

        fn recv_from(
            &mut self,
            _buffer: &mut [u8],
        ) -> Result<DatagramReceive, DatagramSocketError> {
            Err(DatagramSocketError::WouldBlock)
        }
    }

    fn driver(port: u16) -> TurnUdpDriver<MockSocket> {
        let socket = MockSocket {
            local: SocketAddr::from(([192, 0, 2, 1], port)),
            sent: 0,
        };
        TurnUdpDriver::new(
            socket,
            SocketAddr::from(([198, 51, 100, 1], 3478)),
            "runtime-test-user",
            "runtime-test-password",
        )
        .unwrap()
    }

    #[test]
    fn owns_boxed_drivers_and_rejects_duplicate_identity() {
        let mut runtime = TurnUdpRuntime::<MockSocket, 2>::new();
        runtime
            .insert(7, 101, driver(40001), MonotonicTime(10))
            .unwrap();
        assert_eq!(runtime.len(), 1);
        assert_eq!(runtime.token_for_id(7), Some(101));
        assert_eq!(runtime.id_for_token(101), Some(7));
        assert_eq!(
            runtime
                .insert(7, 102, driver(40002), MonotonicTime(10))
                .unwrap_err(),
            TurnUdpRuntimeError::DuplicateAllocationId
        );
        assert_eq!(
            runtime
                .insert(8, 101, driver(40002), MonotonicTime(10))
                .unwrap_err(),
            TurnUdpRuntimeError::DuplicateRegistrationToken
        );
    }

    #[test]
    fn due_poll_queues_initial_allocate_and_exposes_timer() {
        let mut runtime = TurnUdpRuntime::<MockSocket, 2>::new();
        runtime
            .insert(7, 101, driver(40001), MonotonicTime(10))
            .unwrap();
        let mut called = false;
        let serviced = runtime.poll_due(MonotonicTime(10), 1, |id, token, result| {
            assert_eq!(id, 7);
            assert_eq!(token, 101);
            let progress = result.unwrap();
            assert!(progress.queued_control);
            called = true;
        });
        assert_eq!(serviced, 1);
        assert!(called);
        assert_eq!(runtime.has_pending_output(101), Some(true));
        assert!(runtime.next_deadline().is_some());
    }

    #[test]
    fn readiness_dispatch_uses_registration_token_and_flushes_control() {
        let mut runtime = TurnUdpRuntime::<MockSocket, 1>::new();
        runtime
            .insert(7, 101, driver(40001), MonotonicTime(10))
            .unwrap();
        runtime.poll_due(MonotonicTime(10), 1, |_, _, result| {
            assert!(result.unwrap().queued_control);
        });
        let mut receive = [0_u8; 2048];
        let progress = runtime
            .service_ready(
                101,
                TurnUdpIoReady {
                    readable: false,
                    writable: true,
                    max_receive_datagrams: 0,
                    max_send_datagrams: 4,
                },
                MonotonicTime(11),
                &mut receive,
                |_| {},
            )
            .unwrap();
        assert_eq!(progress.sent_datagrams, 1);
        assert_eq!(runtime.has_pending_output(101), Some(false));
    }

    #[test]
    fn removal_returns_driver_only_after_explicit_token_lookup() {
        let mut runtime = TurnUdpRuntime::<MockSocket, 1>::new();
        runtime
            .insert(7, 101, driver(40001), MonotonicTime(10))
            .unwrap();
        let removed = runtime.remove(7).unwrap();
        assert_eq!(removed.socket().local_addr().port(), 40001);
        assert!(runtime.is_empty());
    }

    #[test]
    fn timer_polling_respects_work_budget_and_rotates_scan_cursor() {
        let mut runtime = TurnUdpRuntime::<MockSocket, 3>::new();
        runtime
            .insert(1, 11, driver(40001), MonotonicTime(0))
            .unwrap();
        runtime
            .insert(2, 12, driver(40002), MonotonicTime(0))
            .unwrap();
        runtime
            .insert(3, 13, driver(40003), MonotonicTime(0))
            .unwrap();
        let mut seen = [false; 4];
        assert_eq!(
            runtime.poll_due(MonotonicTime(0), 2, |id, _, _| {
                seen[usize::from(id)] = true;
            }),
            2
        );
        assert!(seen[1]);
        assert!(seen[2]);
        assert!(!seen[3]);
        assert_eq!(
            runtime.poll_due(MonotonicTime(0), 2, |id, _, _| {
                assert_eq!(id, 3);
            }),
            1
        );
    }
}
