//! User-selectable connection profiles and independent-flow targets.
//!
//! These policies describe independent transport flows (for example, separate
//! TURN data flows). They do not describe OS threads, SCTP streams, TURN
//! Channels, or TURN allocations. A runtime controller must ramp toward a
//! desired count using measured goodput, demand, and transport health; this
//! module performs no I/O and starts no timers.

/// A user-selected connection profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionProfile {
    /// No product-imposed concurrency cap; maximize useful measured goodput.
    Unlimited,
    /// Aim for 30–40 independent flows, with 35 as the steady-state target.
    Standard,
    /// Begin with one flow and add capacity only when measured demand requires it.
    EnergySaving,
}

/// Strategy used by the runtime to choose a flow count within the plan's bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowScalingPolicy {
    /// Increase concurrency while additional flows produce useful goodput.
    MaximizeUsefulGoodput,
    /// Maintain the configured standard range around the preferred target.
    StandardRange,
    /// Keep the minimum flow count unless demand or queue pressure requires more.
    DemandDriven,
}

/// Independent-flow capabilities advertised by a transport adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowCapabilities {
    /// Maximum independent data flows supported by this adapter and endpoint.
    pub max_independent_flows: u16,
    /// Whether flow count can be changed without replacing the VPN tunnel.
    pub supports_live_resize: bool,
}

/// Measurements used by the profile flow-scaling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowObservation {
    /// Estimated application demand in bits per second.
    pub requested_goodput_bps: u64,
    /// Measured aggregate application goodput in bits per second.
    pub aggregate_goodput_bps: u64,
    /// Bytes waiting in the bounded packet/transport queues.
    pub queued_bytes: u32,
    /// Queue level considered sustained pressure. Zero disables this signal.
    pub queue_high_watermark_bytes: u32,
    /// Measured incremental goodput from the most recently added flow.
    pub last_flow_marginal_goodput_bps: Option<u64>,
    /// Minimum useful marginal goodput required to justify another flow.
    pub minimum_useful_marginal_gain_bps: u64,
    /// Time without application traffic, in nanoseconds.
    pub idle_for_ns: u64,
    /// Minimum idle duration before EnergySaving may retire an excess flow.
    pub shrink_after_idle_ns: u64,
}

/// A resolved plan for a profile on one specific transport path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowPlan {
    /// Number of flows to establish initially. The runtime should ramp gradually.
    pub initial_flows: u16,
    /// Do not scale below this number while this profile is selected.
    pub minimum_flows: u16,
    /// Initial desired count; the runtime may adjust it according to scaling policy.
    pub initial_target_flows: u16,
    /// Hard adapter-provided upper bound; never exceed this value.
    pub maximum_flows: u16,
    /// Strategy used to select a desired count between minimum and maximum.
    pub scaling_policy: FlowScalingPolicy,
    /// True when the adapter cannot reach the profile's nominal standard target.
    pub limited_by_transport: bool,
    /// Whether the plan can be applied live without replacing the VPN tunnel.
    pub supports_live_resize: bool,
}

/// The currently selected profile and its monotonic command revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileSelection {
    profile: ConnectionProfile,
    revision: u64,
}

/// A successfully accepted profile selection change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileSelectionChange {
    pub previous: ConnectionProfile,
    pub selected: ConnectionProfile,
    pub revision: u64,
}

/// A stale or repeated profile command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileSelectionError {
    StaleRevision,
}

impl ProfileSelection {
    /// Creates the initial selection before the VPN session starts.
    pub const fn new(profile: ConnectionProfile) -> Self {
        Self {
            profile,
            revision: 0,
        }
    }

    pub const fn profile(self) -> ConnectionProfile {
        self.profile
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Accepts only a strictly newer user command.
    ///
    /// Revisions let the control plane discard late asynchronous work from an
    /// earlier selection when the user changes profiles repeatedly.
    pub fn select(
        &mut self,
        revision: u64,
        profile: ConnectionProfile,
    ) -> Result<ProfileSelectionChange, ProfileSelectionError> {
        if revision <= self.revision {
            return Err(ProfileSelectionError::StaleRevision);
        }

        let change = ProfileSelectionChange {
            previous: self.profile,
            selected: profile,
            revision,
        };
        self.profile = profile;
        self.revision = revision;
        Ok(change)
    }

    /// Returns whether an asynchronous result still belongs to the latest command.
    pub const fn is_current(self, revision: u64) -> bool {
        self.revision == revision
    }
}

/// Errors produced when resolving a profile against transport capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowPlanError {
    /// The adapter cannot establish any independent data flow.
    NoIndependentFlows,
}

/// A bounded live adjustment required to reach a desired flow count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowReconfiguration {
    /// The active flow count already equals the requested target.
    Unchanged,
    /// Add this many flows, creating them gradually while the tunnel stays up.
    Add { count: u16 },
    /// Drain this many flows after their in-flight records are handled.
    Drain { count: u16 },
    /// The requested count is outside the resolved profile bounds.
    InvalidTarget { target_flows: u16 },
    /// The adapter cannot resize flows without replacing its transport session.
    LiveResizeUnsupported { target_flows: u16 },
}

impl ConnectionProfile {
    /// Resolves a profile without exceeding the adapter's advertised limit.
    ///
    /// All profiles start with one flow to avoid a synchronized connection
    /// burst. Standard ramps toward 35 flows (30–40 range). Unlimited starts
    /// at one and lets the measured-goodput controller scale up to the adapter
    /// maximum. EnergySaving starts and idles at one, scaling only on demand.
    pub const fn resolve(self, capabilities: FlowCapabilities) -> Result<FlowPlan, FlowPlanError> {
        let maximum = capabilities.max_independent_flows;
        if maximum == 0 {
            return Err(FlowPlanError::NoIndependentFlows);
        }

        match self {
            Self::Unlimited => Ok(FlowPlan {
                initial_flows: 1,
                minimum_flows: 1,
                initial_target_flows: 1,
                maximum_flows: maximum,
                scaling_policy: FlowScalingPolicy::MaximizeUsefulGoodput,
                limited_by_transport: false,
                supports_live_resize: capabilities.supports_live_resize,
            }),
            Self::Standard => {
                let minimum = if maximum < 30 { maximum } else { 30 };
                let target = if maximum < 35 { maximum } else { 35 };
                let upper = if maximum < 40 { maximum } else { 40 };

                Ok(FlowPlan {
                    initial_flows: 1,
                    minimum_flows: minimum,
                    initial_target_flows: target,
                    maximum_flows: upper,
                    scaling_policy: FlowScalingPolicy::StandardRange,
                    limited_by_transport: maximum < 35,
                    supports_live_resize: capabilities.supports_live_resize,
                })
            }
            Self::EnergySaving => Ok(FlowPlan {
                initial_flows: 1,
                minimum_flows: 1,
                initial_target_flows: 1,
                maximum_flows: maximum,
                scaling_policy: FlowScalingPolicy::DemandDriven,
                limited_by_transport: false,
                supports_live_resize: capabilities.supports_live_resize,
            }),
        }
    }
}

impl FlowPlan {
    /// Chooses at most one flow-count step from current measurements.
    ///
    /// The caller remains responsible for applying the change asynchronously,
    /// observing the result, and preserving in-flight records. This policy does
    /// not assume a fixed per-flow throughput; it uses measured marginal gain.
    pub const fn recommend_next_count(
        self,
        current_flows: u16,
        observation: FlowObservation,
    ) -> Option<u16> {
        if current_flows == 0 {
            return Some(1);
        }
        if current_flows > self.maximum_flows {
            return Some(current_flows - 1);
        }

        match self.scaling_policy {
            FlowScalingPolicy::StandardRange => {
                if current_flows < self.initial_target_flows {
                    self.next_increase(current_flows)
                } else if current_flows > self.initial_target_flows {
                    self.next_decrease(current_flows)
                } else {
                    None
                }
            }
            FlowScalingPolicy::MaximizeUsefulGoodput => {
                if current_flows >= self.maximum_flows {
                    return None;
                }
                match observation.last_flow_marginal_goodput_bps {
                    Some(gain) if gain >= observation.minimum_useful_marginal_gain_bps => {
                        self.next_increase(current_flows)
                    }
                    Some(_) if current_flows > self.minimum_flows => {
                        self.next_decrease(current_flows)
                    }
                    None if current_flows == 1 => self.next_increase(current_flows),
                    _ => None,
                }
            }
            FlowScalingPolicy::DemandDriven => {
                let queue_pressure = observation.queue_high_watermark_bytes > 0
                    && observation.queued_bytes >= observation.queue_high_watermark_bytes;
                let capacity_pressure =
                    observation.requested_goodput_bps > observation.aggregate_goodput_bps;

                if (queue_pressure || capacity_pressure) && current_flows < self.maximum_flows {
                    self.next_increase(current_flows)
                } else if !queue_pressure
                    && !capacity_pressure
                    && current_flows > self.minimum_flows
                    && observation.shrink_after_idle_ns > 0
                    && observation.idle_for_ns >= observation.shrink_after_idle_ns
                {
                    self.next_decrease(current_flows)
                } else {
                    None
                }
            }
        }
    }

    /// Plans a live transition to this profile's initial target.
    pub const fn reconfiguration(self, current_flows: u16) -> FlowReconfiguration {
        self.reconfiguration_to(current_flows, self.initial_target_flows)
    }

    /// Plans a live transition to a measured/controller-selected flow count.
    ///
    /// The desired count must remain within the profile's bounds. This lets
    /// Unlimited scale to the measured useful-goodput ceiling and EnergySaving
    /// temporarily add capacity under load without changing the selected profile.
    pub const fn reconfiguration_to(
        self,
        current_flows: u16,
        desired_flows: u16,
    ) -> FlowReconfiguration {
        if desired_flows < self.minimum_flows || desired_flows > self.maximum_flows {
            return FlowReconfiguration::InvalidTarget {
                target_flows: desired_flows,
            };
        }
        if current_flows == desired_flows {
            return FlowReconfiguration::Unchanged;
        }
        if !self.supports_live_resize {
            return FlowReconfiguration::LiveResizeUnsupported {
                target_flows: desired_flows,
            };
        }
        if current_flows < desired_flows {
            FlowReconfiguration::Add {
                count: desired_flows - current_flows,
            }
        } else {
            FlowReconfiguration::Drain {
                count: current_flows - desired_flows,
            }
        }
    }

    /// Returns the next one-flow increase, bounded by the resolved plan.
    pub const fn next_increase(self, current_flows: u16) -> Option<u16> {
        if current_flows == 0 || current_flows >= self.maximum_flows {
            return None;
        }
        Some(current_flows + 1)
    }

    /// Returns the next one-flow decrease, bounded by the resolved plan.
    pub const fn next_decrease(self, current_flows: u16) -> Option<u16> {
        if current_flows <= self.minimum_flows {
            return None;
        }
        Some(current_flows - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: FlowCapabilities = FlowCapabilities {
        max_independent_flows: 100,
        supports_live_resize: true,
    };

    const OBSERVATION: FlowObservation = FlowObservation {
        requested_goodput_bps: 1_000_000,
        aggregate_goodput_bps: 2_000_000,
        queued_bytes: 0,
        queue_high_watermark_bytes: 64 * 1024,
        last_flow_marginal_goodput_bps: None,
        minimum_useful_marginal_gain_bps: 100_000,
        idle_for_ns: 0,
        shrink_after_idle_ns: 5_000_000_000,
    };

    #[test]
    fn profile_selection_rejects_stale_commands() {
        let mut selection = ProfileSelection::new(ConnectionProfile::EnergySaving);
        let change = selection.select(1, ConnectionProfile::Standard).unwrap();

        assert_eq!(change.previous, ConnectionProfile::EnergySaving);
        assert_eq!(change.selected, ConnectionProfile::Standard);
        assert_eq!(selection.profile(), ConnectionProfile::Standard);
        assert_eq!(selection.revision(), 1);
        assert!(selection.is_current(1));
        assert_eq!(
            selection.select(1, ConnectionProfile::Unlimited),
            Err(ProfileSelectionError::StaleRevision)
        );
        assert_eq!(
            selection.select(0, ConnectionProfile::Unlimited),
            Err(ProfileSelectionError::StaleRevision)
        );
    }

    #[test]
    fn unlimited_starts_small_and_scales_on_measured_marginal_gain() {
        let plan = ConnectionProfile::Unlimited.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.initial_target_flows, 1);
        assert_eq!(plan.maximum_flows, 100);
        assert_eq!(
            plan.scaling_policy,
            FlowScalingPolicy::MaximizeUsefulGoodput
        );
        assert_eq!(plan.recommend_next_count(1, OBSERVATION), Some(2));

        let useful_gain = FlowObservation {
            last_flow_marginal_goodput_bps: Some(1_500_000),
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(2, useful_gain), Some(3));

        let poor_gain = FlowObservation {
            last_flow_marginal_goodput_bps: Some(10_000),
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(2, poor_gain), Some(1));
    }

    #[test]
    fn standard_ramps_to_thirty_five_within_thirty_to_forty() {
        let plan = ConnectionProfile::Standard.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 30);
        assert_eq!(plan.initial_target_flows, 35);
        assert_eq!(plan.maximum_flows, 40);
        assert_eq!(plan.scaling_policy, FlowScalingPolicy::StandardRange);
        assert_eq!(plan.recommend_next_count(34, OBSERVATION), Some(35));
        assert_eq!(plan.recommend_next_count(36, OBSERVATION), Some(35));
        assert!(!plan.limited_by_transport);
    }

    #[test]
    fn standard_reports_transport_limit_below_nominal_target() {
        let capabilities = FlowCapabilities {
            max_independent_flows: 24,
            supports_live_resize: false,
        };
        let plan = ConnectionProfile::Standard.resolve(capabilities).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 24);
        assert_eq!(plan.initial_target_flows, 24);
        assert_eq!(plan.maximum_flows, 24);
        assert!(plan.limited_by_transport);
        assert!(!plan.supports_live_resize);
    }

    #[test]
    fn energy_saving_adds_capacity_under_demand_or_queue_pressure() {
        let plan = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.initial_target_flows, 1);
        assert_eq!(plan.maximum_flows, 100);
        assert_eq!(plan.scaling_policy, FlowScalingPolicy::DemandDriven);

        let demand = FlowObservation {
            requested_goodput_bps: 5_000_000,
            aggregate_goodput_bps: 2_000_000,
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(1, demand), Some(2));

        let queue = FlowObservation {
            queued_bytes: 64 * 1024,
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(1, queue), Some(2));
    }

    #[test]
    fn energy_saving_retires_excess_flows_only_after_idle_threshold() {
        let plan = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();

        let idle = FlowObservation {
            idle_for_ns: 10_000_000_000,
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(4, idle), Some(3));

        let recent = FlowObservation {
            idle_for_ns: 1_000_000_000,
            ..OBSERVATION
        };
        assert_eq!(plan.recommend_next_count(4, recent), None);
    }

    #[test]
    fn zero_flow_capacity_is_rejected() {
        let capabilities = FlowCapabilities {
            max_independent_flows: 0,
            supports_live_resize: true,
        };
        assert_eq!(
            ConnectionProfile::Unlimited.resolve(capabilities),
            Err(FlowPlanError::NoIndependentFlows)
        );
    }

    #[test]
    fn flow_adjustments_are_bounded_and_incremental() {
        let plan = ConnectionProfile::Standard.resolve(LIVE).unwrap();

        assert_eq!(plan.next_increase(1), Some(2));
        assert_eq!(plan.next_increase(34), Some(35));
        assert_eq!(plan.next_increase(40), None);
        assert_eq!(plan.next_decrease(41), Some(40));
        assert_eq!(plan.next_decrease(31), Some(30));
        assert_eq!(plan.next_decrease(30), None);
    }

    #[test]
    fn standard_clamps_range_when_transport_supports_fewer_than_thirty() {
        let capabilities = FlowCapabilities {
            max_independent_flows: 8,
            supports_live_resize: true,
        };
        let plan = ConnectionProfile::Standard.resolve(capabilities).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 8);
        assert_eq!(plan.initial_target_flows, 8);
        assert_eq!(plan.maximum_flows, 8);
        assert!(plan.limited_by_transport);
    }

    #[test]
    fn live_profile_switch_adds_or_drains_without_restarting_tunnel() {
        let standard = ConnectionProfile::Standard.resolve(LIVE).unwrap();
        let saving = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();

        assert_eq!(
            standard.reconfiguration(1),
            FlowReconfiguration::Add { count: 34 }
        );
        assert_eq!(
            saving.reconfiguration(35),
            FlowReconfiguration::Drain { count: 34 }
        );
        assert_eq!(saving.reconfiguration(1), FlowReconfiguration::Unchanged);
    }

    #[test]
    fn profile_target_must_respect_bounds_and_live_resize_capability() {
        let plan = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();
        assert_eq!(
            plan.reconfiguration_to(1, 101),
            FlowReconfiguration::InvalidTarget { target_flows: 101 }
        );

        let fixed = ConnectionProfile::EnergySaving
            .resolve(FlowCapabilities {
                max_independent_flows: 40,
                supports_live_resize: false,
            })
            .unwrap();
        assert_eq!(
            fixed.reconfiguration_to(35, 1),
            FlowReconfiguration::LiveResizeUnsupported { target_flows: 1 }
        );
    }
}
