//! Pre-saturation placement policy for independent TURN allocations.
//!
//! This policy selects a healthy allocation with headroom for a new flow. It
//! requests another allocation before every active allocation is saturated;
//! it never waits for a queue or transport limit to be completely exhausted.
//! The runtime supplies normalized pressure from measured queue, service-rate,
//! latency, and loss observations. Thresholds are configuration, not universal
//! constants: they must be tuned from the actual path and server limits.

/// One independently established TURN Allocation and its current pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationLoad {
    pub id: u16,
    pub healthy: bool,
    /// Composite pressure in parts per million, where 1_000_000 is saturation.
    pub pressure_ppm: u32,
}

/// Runtime-tuned thresholds for allocation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationPolicyConfig {
    /// Open another allocation once all healthy allocations reach this pressure.
    pub saturation_threshold_ppm: u32,
}

/// The action to take for a newly observed flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationAction {
    /// Keep the new flow on an existing allocation with the most headroom.
    AssignTo(u16),
    /// Start another independent Allocation before existing ones are exhausted.
    OpenAllocation,
    /// No allocation is healthy and no new allocation capacity is available.
    NoHealthyAllocation,
    /// All allocations are saturated and the transport/server limit is reached.
    Backpressure,
}

/// Selects a destination for a new flow without moving existing flows.
///
/// pending_demand must indicate queued work that cannot be served immediately.
/// active_allocations is the number of established allocations, while
/// maximum_allocations is the effective limit after transport, server quota,
/// and device constraints. Existing flows remain sticky.
pub fn choose_allocation(
    loads: &[AllocationLoad],
    config: AllocationPolicyConfig,
    pending_demand: bool,
    active_allocations: usize,
    maximum_allocations: usize,
) -> AllocationAction {
    let threshold = config.saturation_threshold_ppm.min(1_000_000);
    let mut best: Option<(u32, u16)> = None;

    for load in loads.iter().filter(|load| load.healthy) {
        if load.pressure_ppm < threshold
            && best.is_none_or(|(pressure, id)| {
                load.pressure_ppm < pressure || (load.pressure_ppm == pressure && load.id < id)
            }) {
            best = Some((load.pressure_ppm, load.id));
        }
        }
    }

    if let Some((_, id)) = best {
        return AllocationAction::AssignTo(id);
    }

    if !pending_demand {
        return if loads.iter().any(|load| load.healthy) {
            AllocationAction::Backpressure
        } else {
            AllocationAction::NoHealthyAllocation
        };
    }

    if active_allocations < maximum_allocations {
        return AllocationAction::OpenAllocation;
    }

    if loads.iter().any(|load| load.healthy) {
        AllocationAction::Backpressure
    } else {
        AllocationAction::NoHealthyAllocation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: AllocationPolicyConfig = AllocationPolicyConfig {
        saturation_threshold_ppm: 750_000,
    };

    #[test]
    fn chooses_least_loaded_allocation_before_saturation() {
        let loads = [
            AllocationLoad {
                id: 8,
                healthy: true,
                pressure_ppm: 620_000,
            },
            AllocationLoad {
                id: 3,
                healthy: true,
                pressure_ppm: 410_000,
            },
        ];
        assert_eq!(
            choose_allocation(&loads, CONFIG, true, 2, 8),
            AllocationAction::AssignTo(3)
        );
    }

    #[test]
    fn opens_another_allocation_before_existing_queues_are_full() {
        let loads = [
            AllocationLoad {
                id: 1,
                healthy: true,
                pressure_ppm: 820_000,
            },
            AllocationLoad {
                id: 2,
                healthy: true,
                pressure_ppm: 910_000,
            },
        ];
        assert_eq!(
            choose_allocation(&loads, CONFIG, true, 2, 8),
            AllocationAction::OpenAllocation
        );
    }

    #[test]
    fn does_not_open_allocation_without_pending_demand() {
        let loads = [AllocationLoad {
            id: 1,
            healthy: true,
            pressure_ppm: 990_000,
        }];
        assert_eq!(
            choose_allocation(&loads, CONFIG, false, 1, 8),
            AllocationAction::Backpressure
        );
    }

    #[test]
    fn respects_effective_server_or_transport_limit() {
        let loads = [AllocationLoad {
            id: 1,
            healthy: true,
            pressure_ppm: 900_000,
        }];
        assert_eq!(
            choose_allocation(&loads, CONFIG, true, 1, 1),
            AllocationAction::Backpressure
        );
    }

    #[test]
    fn ignores_unhealthy_allocations_and_reports_no_capacity() {
        let loads = [AllocationLoad {
            id: 1,
            healthy: false,
            pressure_ppm: 0,
        }];
        assert_eq!(
            choose_allocation(&loads, CONFIG, true, 1, 1),
            AllocationAction::NoHealthyAllocation
        );
    }

    #[test]
    fn threshold_is_clamped_to_one_million() {
        let loads = [AllocationLoad {
            id: 1,
            healthy: true,
            pressure_ppm: 900_000,
        }];
        let config = AllocationPolicyConfig {
            saturation_threshold_ppm: u32::MAX,
        };
        assert_eq!(
            choose_allocation(&loads, config, true, 1, 4),
            AllocationAction::OpenAllocation
        );
    }
}
