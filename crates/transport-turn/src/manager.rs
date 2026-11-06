//! Bounded ownership and admission control for independent TURN Allocations.
//!
//! The caller binds one distinct UDP socket per Allocation, constructs its
//! `TurnUdpEngine`, and transfers engine ownership into this manager. The
//! manager never creates sockets or an async runtime. On Android, the caller
//! must bind each socket to the selected Network and protect it with
//! `VpnService.protect()` before the first send.

use core::net::SocketAddr;

use crate::TurnUdpEngine;

/// Initial admission threshold. This is a tunable starting point, not a
/// transport guarantee; production tuning must use measured queueing and RTT.
pub const DEFAULT_SATURATION_THRESHOLD_PPM: u32 = 800_000;
const PPM_SCALE: u32 = 1_000_000;

/// Lifecycle of a managed independent TURN Allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationState {
    Active,
    Draining,
    Unhealthy,
}

/// Load observations supplied by the I/O runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationLoad {
    /// Normalized load from 0 to 1,000,000 parts per million.
    pub pressure_ppm: u32,
    /// Bytes waiting in this Allocation's bounded transmit queue.
    pub queued_bytes: u32,
    /// Packets accepted for this Allocation but not yet completed.
    pub in_flight_packets: u32,
}

impl AllocationLoad {
    pub const IDLE: Self = Self {
        pressure_ppm: 0,
        queued_bytes: 0,
        in_flight_packets: 0,
    };
}

/// Result of choosing an Allocation for a new flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    Use { allocation_id: u16 },
    OpenAllocation,
    Backpressure,
    NoActiveAllocations,
}

/// Errors when adding or managing an Allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationManagerError {
    CapacityReached,
    DuplicateId,
    DuplicateLocalSocket,
    UnknownAllocation,
    NotDraining,
    InFlightWorkRemains,
}

/// Owns a single TURN engine and its scheduling observations.
pub struct ManagedAllocation {
    id: u16,
    engine: TurnUdpEngine,
    state: AllocationState,
    load: AllocationLoad,
}

impl ManagedAllocation {
    pub const fn id(&self) -> u16 {
        self.id
    }

    pub const fn state(&self) -> AllocationState {
        self.state
    }

    pub const fn load(&self) -> AllocationLoad {
        self.load
    }

    pub fn engine(&self) -> &TurnUdpEngine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut TurnUdpEngine {
        &mut self.engine
    }
}

/// Fixed-capacity manager for independent TURN Allocation sessions.
///
/// Capacity is supplied by the adapter/runtime, not hard-coded as a product
/// limit. Each slot owns a distinct engine, whose local socket address must be
/// unique within this manager.
pub struct TurnAllocationManager<const CAPACITY: usize> {
    slots: [Option<ManagedAllocation>; CAPACITY],
    len: usize,
    saturation_threshold_ppm: u32,
}

impl<const CAPACITY: usize> TurnAllocationManager<CAPACITY> {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
            saturation_threshold_ppm: DEFAULT_SATURATION_THRESHOLD_PPM,
        }
    }

    /// Sets the admission threshold. Values are clamped to the PPM scale.
    pub fn set_saturation_threshold_ppm(&mut self, threshold_ppm: u32) {
        self.saturation_threshold_ppm = threshold_ppm.min(PPM_SCALE);
    }

    pub const fn saturation_threshold_ppm(&self) -> u32 {
        self.saturation_threshold_ppm
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

    /// Transfers ownership of a separately initialized TURN engine.
    ///
    /// Distinct local socket addresses enforce independent UDP 5-tuples. A
    /// TURN Channel does not count as another Allocation.
    pub fn insert(
        &mut self,
        id: u16,
        engine: TurnUdpEngine,
    ) -> Result<(), AllocationManagerError> {
        if self.len == CAPACITY {
            return Err(AllocationManagerError::CapacityReached);
        }
        if self.slots.iter().flatten().any(|slot| slot.id == id) {
            return Err(AllocationManagerError::DuplicateId);
        }
        let local_addr = engine.local_addr();
        if self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.engine.local_addr() == local_addr)
        {
            return Err(AllocationManagerError::DuplicateLocalSocket);
        }

        let vacant = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("length and slot occupancy must agree");
        *vacant = Some(ManagedAllocation {
            id,
            engine,
            state: AllocationState::Active,
            load: AllocationLoad::IDLE,
        });
        self.len += 1;
        Ok(())
    }

    pub fn get(&self, id: u16) -> Option<&ManagedAllocation> {
        self.slots.iter().flatten().find(|slot| slot.id == id)
    }

    pub fn get_mut(&mut self, id: u16) -> Option<&mut ManagedAllocation> {
        self.slots.iter_mut().flatten().find(|slot| slot.id == id)
    }

    /// Refreshes load metrics from the runtime; pressure is normalized/clamped.
    pub fn update_load(
        &mut self,
        id: u16,
        mut load: AllocationLoad,
    ) -> Result<(), AllocationManagerError> {
        load.pressure_ppm = load.pressure_ppm.min(PPM_SCALE);
        let slot = self
            .get_mut(id)
            .ok_or(AllocationManagerError::UnknownAllocation)?;
        slot.load = load;
        Ok(())
    }

    /// Selects the least-loaded healthy Allocation, or requests another one
    /// before saturation when demand is waiting.
    pub fn admit_new_flow(
        &self,
        pending_demand: bool,
        effective_maximum: usize,
    ) -> AdmissionDecision {
        let mut best: Option<(u16, u32)> = None;
        for slot in self.slots.iter().flatten() {
            if slot.state != AllocationState::Active {
                continue;
            }
            let pressure = slot.load.pressure_ppm;
            if pressure < self.saturation_threshold_ppm
                && best.is_none_or(|(_, best_pressure)| pressure < best_pressure)
            {
                best = Some((slot.id, pressure));
            }
        }

        if let Some((allocation_id, _)) = best {
            return AdmissionDecision::Use { allocation_id };
        }
        if !pending_demand {
            return if self.len == 0 {
                AdmissionDecision::NoActiveAllocations
            } else {
                AdmissionDecision::Backpressure
            };
        }
        if self.len < effective_maximum.min(CAPACITY) {
            return AdmissionDecision::OpenAllocation;
        }
        if self.len == 0 {
            AdmissionDecision::NoActiveAllocations
        } else {
            AdmissionDecision::Backpressure
        }
    }

    /// Stops assigning new flows to this Allocation.
    pub fn begin_drain(&mut self, id: u16) -> Result<(), AllocationManagerError> {
        let slot = self
            .get_mut(id)
            .ok_or(AllocationManagerError::UnknownAllocation)?;
        slot.state = AllocationState::Draining;
        Ok(())
    }

    /// Removes a drained engine only after all accepted packets have completed.
    ///
    /// The caller receives ownership and must send TURN Refresh(0)/Delete
    /// control traffic before closing the corresponding socket.
    pub fn take_drained(
        &mut self,
        id: u16,
    ) -> Result<TurnUdpEngine, AllocationManagerError> {
        let index = self
            .slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slot| slot.id == id))
            .ok_or(AllocationManagerError::UnknownAllocation)?;
        let slot = self.slots[index]
            .as_ref()
            .expect("located slot must be occupied");
        if slot.state != AllocationState::Draining {
            return Err(AllocationManagerError::NotDraining);
        }
        if slot.load.in_flight_packets != 0 {
            return Err(AllocationManagerError::InFlightWorkRemains);
        }
        let allocation = self.slots[index]
            .take()
            .expect("located slot must remain occupied");
        self.len -= 1;
        Ok(allocation.engine)
    }

    /// Marks an Allocation unavailable for new flows without affecting others.
    pub fn mark_unhealthy(&mut self, id: u16) -> Result<(), AllocationManagerError> {
        let slot = self
            .get_mut(id)
            .ok_or(AllocationManagerError::UnknownAllocation)?;
        slot.state = AllocationState::Unhealthy;
        Ok(())
    }

    /// Returns the local socket tuples currently owned by this manager.
    pub fn local_socket_in_use(&self, address: SocketAddr) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|slot| slot.engine.local_addr() == address)
    }
}

impl<const CAPACITY: usize> Default for TurnAllocationManager<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(local_port: u16) -> TurnUdpEngine {
        TurnUdpEngine::new(
            SocketAddr::from(([192, 0, 2, 1], local_port)),
            SocketAddr::from(([198, 51, 100, 1], 3478)),
            "test-user",
            "test-password",
        )
        .unwrap()
    }

    #[test]
    fn owns_multiple_independent_allocation_engines() {
        let mut manager = TurnAllocationManager::<3>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager.insert(2, engine(40002)).unwrap();
        assert_eq!(manager.len(), 2);
        assert_ne!(
            manager.get(1).unwrap().engine().local_addr(),
            manager.get(2).unwrap().engine().local_addr()
        );
    }

    #[test]
    fn rejects_duplicate_ids_and_local_socket_tuples() {
        let mut manager = TurnAllocationManager::<3>::new();
        manager.insert(1, engine(40001)).unwrap();
        assert_eq!(
            manager.insert(1, engine(40002)).unwrap_err(),
            AllocationManagerError::DuplicateId
        );
        assert_eq!(
            manager.insert(2, engine(40001)).unwrap_err(),
            AllocationManagerError::DuplicateLocalSocket
        );
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn admits_on_least_loaded_allocation_below_eighty_percent() {
        let mut manager = TurnAllocationManager::<3>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager.insert(2, engine(40002)).unwrap();
        manager
            .update_load(
                1,
                AllocationLoad {
                    pressure_ppm: 700_000,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        manager
            .update_load(
                2,
                AllocationLoad {
                    pressure_ppm: 300_000,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 3),
            AdmissionDecision::Use { allocation_id: 2 }
        );
    }

    #[test]
    fn requests_new_allocation_at_threshold_when_demand_is_waiting() {
        let mut manager = TurnAllocationManager::<3>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager
            .update_load(
                1,
                AllocationLoad {
                    pressure_ppm: 800_000,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 3),
            AdmissionDecision::OpenAllocation
        );
        assert_eq!(
            manager.admit_new_flow(false, 3),
            AdmissionDecision::Backpressure
        );
    }

    #[test]
    fn effective_capacity_causes_backpressure() {
        let mut manager = TurnAllocationManager::<2>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager
            .update_load(
                1,
                AllocationLoad {
                    pressure_ppm: 900_000,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 1),
            AdmissionDecision::Backpressure
        );
    }

    #[test]
    fn draining_waits_for_in_flight_packets_and_then_returns_engine() {
        let mut manager = TurnAllocationManager::<2>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager
            .update_load(
                1,
                AllocationLoad {
                    in_flight_packets: 2,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        manager.begin_drain(1).unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 2),
            AdmissionDecision::OpenAllocation
        );
        assert!(matches!(
            manager.take_drained(1),
            Err(AllocationManagerError::InFlightWorkRemains)
        ));
        manager
            .update_load(1, AllocationLoad::IDLE)
            .unwrap();
        let returned = manager.take_drained(1).unwrap();
        assert_eq!(returned.local_addr().port(), 40001);
        assert!(manager.is_empty());
    }

    #[test]
    fn unhealthy_allocation_is_not_selected() {
        let mut manager = TurnAllocationManager::<2>::new();
        manager.insert(1, engine(40001)).unwrap();
        manager.mark_unhealthy(1).unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 2),
            AdmissionDecision::OpenAllocation
        );
    }

    #[test]
    fn clamps_pressure_and_threshold() {
        let mut manager = TurnAllocationManager::<1>::new();
        manager.set_saturation_threshold_ppm(u32::MAX);
        assert_eq!(manager.saturation_threshold_ppm(), PPM_SCALE);
        manager.insert(1, engine(40001)).unwrap();
        manager
            .update_load(
                1,
                AllocationLoad {
                    pressure_ppm: u32::MAX,
                    ..AllocationLoad::IDLE
                },
            )
            .unwrap();
        assert_eq!(
            manager.admit_new_flow(true, 1),
            AdmissionDecision::Backpressure
        );
    }
}
