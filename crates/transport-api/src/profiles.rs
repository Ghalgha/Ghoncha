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
    pub const fn resolve(
        self,
        capabilities: FlowCapabilities,
    ) -> Result<FlowPlan, FlowPlanError> {
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
                let minimum = maximum.min(30);
                let target = maximum.min(35);
                let upper = maximum.min(40);

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
    ///
    /// The caller must first establish that more capacity is needed and that
    /// adding a flow is beneficial. This method deliberately makes no network
    /// or performance assumptions.
    pub const fn next_increase(self, current_flows: u16) -> Option<u16> {
        if current_flows == 0 || current_flows >= self.maximum_flows {
            return None;
        }
        Some(current_flows + 1)
    }

    /// Returns the next one-flow decrease, bounded by the resolved plan.
    ///
    /// The caller must ensure that draining the flow will not interrupt
    /// in-flight records or violate transport lifecycle requirements.
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

    #[test]
    fn unlimited_starts_small_and_can_scale_to_measured_limit() {
        let plan = ConnectionProfile::Unlimited.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.initial_target_flows, 1);
        assert_eq!(plan.maximum_flows, 100);
        assert_eq!(plan.scaling_policy, FlowScalingPolicy::MaximizeUsefulGoodput);
        assert_eq!(
            plan.reconfiguration_to(1, 24),
            FlowReconfiguration::Add { count: 23 }
        );
        assert!(!plan.limited_by_transport);
        assert!(plan.supports_live_resize);
    }

    #[test]
    fn standard_ramps_to_thirty_five_within_thirty_to_forty() {
        let plan = ConnectionProfile::Standard.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 30);
        assert_eq!(plan.initial_target_flows, 35);
        assert_eq!(plan.maximum_flows, 40);
        assert_eq!(plan.scaling_policy, FlowScalingPolicy::StandardRange);
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
    fn energy_saving_starts_at_one_and_can_scale_on_demand() {
        let plan = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.initial_target_flows, 1);
        assert_eq!(plan.maximum_flows, 100);
        assert_eq!(plan.scaling_policy, FlowScalingPolicy::DemandDriven);
        assert_eq!(plan.next_increase(1), Some(2));
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
        assert_eq!(
            saving.reconfiguration(1),
            FlowReconfiguration::Unchanged
        );
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
