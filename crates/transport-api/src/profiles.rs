//! User-selectable connection profiles and independent-flow targets.
//!
//! These policies describe independent transport flows (for example, separate
//! TURN data flows). They do not describe OS threads, SCTP streams, TURN
//! Channels, or TURN allocations. A runtime controller must ramp toward the
//! target using measured goodput and transport health; this module performs no
//! I/O and starts no timers.

/// A user-selected connection profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionProfile {
    /// No product-imposed concurrency cap; stop scaling when added flows stop
    /// producing useful goodput or a transport/resource limit is reached.
    Unlimited,
    /// Aim for 30–40 independent flows, with 35 as the initial target.
    Standard,
    /// Begin with one flow and add capacity only when measured demand requires it.
    EnergySaving,
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
    /// Desired steady-state count before considering measured demand/goodput.
    pub target_flows: u16,
    /// Hard adapter-provided upper bound; never exceed this value.
    pub maximum_flows: u16,
    /// True when the adapter cannot reach the profile's nominal target.
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

impl ConnectionProfile {
    /// Resolves a profile without exceeding the adapter's advertised limit.
    ///
    /// Unlimited starts with one flow and may ramp to the adapter's maximum.
    /// Standard targets 35 flows (with a 30–40 operating range). EnergySaving
    /// starts and normally idles at one flow, but may scale up to the adapter
    /// maximum when the runtime observes insufficient capacity.
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
                target_flows: maximum,
                maximum_flows: maximum,
                limited_by_transport: false,
                supports_live_resize: capabilities.supports_live_resize,
            }),
            Self::Standard => {
                let minimum = if maximum < 30 { maximum } else { 30 };
                let target = if maximum < 35 { maximum } else { 35 };
                let upper = if maximum < 40 { maximum } else { 40 };

                Ok(FlowPlan {
                    initial_flows: minimum,
                    minimum_flows: minimum,
                    target_flows: target,
                    maximum_flows: upper,
                    limited_by_transport: maximum < 35,
                    supports_live_resize: capabilities.supports_live_resize,
                })
            }
            Self::EnergySaving => Ok(FlowPlan {
                initial_flows: 1,
                minimum_flows: 1,
                target_flows: 1,
                maximum_flows: maximum,
                limited_by_transport: false,
                supports_live_resize: capabilities.supports_live_resize,
            }),
        }
    }
}

impl FlowPlan {
    /// Returns the next one-flow increase, bounded by the resolved plan.
    ///
    /// The caller must first establish that more capacity is needed and that
    /// adding a flow is beneficial. This method deliberately makes no network
    /// or performance assumptions.
    pub const fn next_increase(self, current_flows: u16) -> Option<u16> {
        if current_flows < self.minimum_flows || current_flows >= self.maximum_flows {
            return None;
        }
        Some(current_flows + 1)
    }

    /// Returns the next one-flow decrease, bounded by the resolved plan.
    ///
    /// The caller must ensure that draining the flow will not interrupt
    /// in-flight records or violate transport lifecycle requirements.
    pub const fn next_decrease(self, current_flows: u16) -> Option<u16> {
        if current_flows <= self.minimum_flows || current_flows > self.maximum_flows {
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
    fn unlimited_starts_small_and_has_no_product_cap() {
        let plan = ConnectionProfile::Unlimited.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.target_flows, 100);
        assert_eq!(plan.maximum_flows, 100);
        assert!(!plan.limited_by_transport);
        assert!(plan.supports_live_resize);
    }

    #[test]
    fn standard_targets_thirty_five_within_thirty_to_forty() {
        let plan = ConnectionProfile::Standard.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 30);
        assert_eq!(plan.minimum_flows, 30);
        assert_eq!(plan.target_flows, 35);
        assert_eq!(plan.maximum_flows, 40);
        assert!(!plan.limited_by_transport);
    }

    #[test]
    fn standard_reports_transport_limit_below_nominal_target() {
        let capabilities = FlowCapabilities {
            max_independent_flows: 24,
            supports_live_resize: false,
        };
        let plan = ConnectionProfile::Standard.resolve(capabilities).unwrap();

        assert_eq!(plan.initial_flows, 24);
        assert_eq!(plan.target_flows, 24);
        assert_eq!(plan.maximum_flows, 24);
        assert!(plan.limited_by_transport);
        assert!(!plan.supports_live_resize);
    }

    #[test]
    fn energy_saving_starts_and_idles_at_one_but_can_scale_on_demand() {
        let plan = ConnectionProfile::EnergySaving.resolve(LIVE).unwrap();

        assert_eq!(plan.initial_flows, 1);
        assert_eq!(plan.minimum_flows, 1);
        assert_eq!(plan.target_flows, 1);
        assert_eq!(plan.maximum_flows, 100);
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

        assert_eq!(plan.next_increase(34), Some(35));
        assert_eq!(plan.next_increase(40), None);
        assert_eq!(plan.next_decrease(31), Some(30));
        assert_eq!(plan.next_decrease(30), None);
        assert_eq!(plan.next_decrease(41), None);
    }

    #[test]
    fn standard_clamps_range_when_transport_supports_fewer_than_thirty() {
        let capabilities = FlowCapabilities {
            max_independent_flows: 8,
            supports_live_resize: true,
        };
        let plan = ConnectionProfile::Standard.resolve(capabilities).unwrap();

        assert_eq!(plan.initial_flows, 8);
        assert_eq!(plan.minimum_flows, 8);
        assert_eq!(plan.target_flows, 8);
        assert_eq!(plan.maximum_flows, 8);
        assert!(plan.limited_by_transport);
    }
}
