//! Sequential three-profile speed-test result collection.
//!
//! This module coordinates result ordering and validation only. It does not
//! generate traffic, choose a test endpoint, or perform socket I/O. The caller
//! must run each profile sequentially against a controlled GHONCHA endpoint.

use crate::ConnectionProfile;

/// Goodput and path-quality measurements for one profile test.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpeedTestMetrics {
    /// Application payload download rate in bits per second.
    pub download_bps: u64,
    /// Application payload upload rate in bits per second.
    pub upload_bps: u64,
    /// Median round-trip time in microseconds.
    pub median_rtt_us: u64,
    /// 95th-percentile round-trip time in microseconds.
    pub p95_rtt_us: u64,
    /// Measured round-trip-time jitter in microseconds.
    pub jitter_us: u64,
    /// Packet loss in parts per million; 10_000 is one percent.
    pub packet_loss_ppm: u32,
    /// Actual independent TURN data flows used during the measurement.
    pub actual_flow_count: u16,
    /// Measurement duration in milliseconds.
    pub duration_ms: u32,
}

/// Result associated with one connection profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpeedTestResult {
    pub profile: ConnectionProfile,
    pub metrics: SpeedTestMetrics,
}

/// Lifecycle state of a three-profile speed-test sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpeedTestState {
    Running,
    Complete,
    Cancelled,
}

/// Errors returned by the speed-test sequence coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpeedTestError {
    /// Do not compete with active user traffic or silently interrupt it.
    UserTrafficActive,
    /// The requested order must contain each supported profile exactly once.
    InvalidProfileOrder,
    /// The caller attempted to record a result after completion.
    AlreadyComplete,
    /// The caller attempted to record a result after cancellation.
    Cancelled,
    /// The result belongs to a different Android network generation.
    StaleNetworkGeneration,
    /// The measurement is incomplete or contains invalid values.
    InvalidMetrics,
}

/// Sequential result collector for Unlimited, Standard, and EnergySaving.
///
/// The caller supplies a rotated order to reduce test-order bias between runs.
/// Only one profile is active at a time. A network-generation change invalidates
/// the run; callers should cancel it rather than combine results from different
/// network paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpeedTestSequence {
    network_generation: u64,
    profiles: [ConnectionProfile; 3],
    next_index: u8,
    results: [Option<SpeedTestResult>; 3],
    state: SpeedTestState,
}

impl SpeedTestSequence {
    /// Starts a sequence if there is no active user traffic.
    ///
    /// The profile order must contain all three profiles exactly once. The
    /// caller can rotate the order between tests without requiring randomness
    /// or allocation inside this no_std crate.
    pub const fn new(
        network_generation: u64,
        profiles: [ConnectionProfile; 3],
        user_traffic_active: bool,
    ) -> Result<Self, SpeedTestError> {
        if user_traffic_active {
            return Err(SpeedTestError::UserTrafficActive);
        }

        if !Self::is_valid_order(profiles) {
            return Err(SpeedTestError::InvalidProfileOrder);
        }

        Ok(Self {
            network_generation,
            profiles,
            next_index: 0,
            results: [None; 3],
            state: SpeedTestState::Running,
        })
    }

    /// Returns the profile that must be tested next, if the run is active.
    pub const fn current_profile(self) -> Option<ConnectionProfile> {
        if matches!(self.state, SpeedTestState::Running) {
            Some(self.profiles[self.next_index as usize])
        } else {
            None
        }
    }

    /// Records the current profile's result and returns the next profile.
    ///
    /// A None return means all three profile measurements are complete.
    /// The caller must not run profile tests concurrently.
    pub fn record_result(
        &mut self,
        network_generation: u64,
        metrics: SpeedTestMetrics,
    ) -> Result<Option<ConnectionProfile>, SpeedTestError> {
        match self.state {
            SpeedTestState::Complete => return Err(SpeedTestError::AlreadyComplete),
            SpeedTestState::Cancelled => return Err(SpeedTestError::Cancelled),
            SpeedTestState::Running => {}
        }

        if network_generation != self.network_generation {
            return Err(SpeedTestError::StaleNetworkGeneration);
        }
        if !Self::valid_metrics(metrics) {
            return Err(SpeedTestError::InvalidMetrics);
        }

        let index = self.next_index as usize;
        self.results[index] = Some(SpeedTestResult {
            profile: self.profiles[index],
            metrics,
        });
        self.next_index += 1;

        if self.next_index as usize == self.profiles.len() {
            self.state = SpeedTestState::Complete;
            Ok(None)
        } else {
            Ok(self.current_profile())
        }
    }

    /// Cancels the sequence. Previously recorded results remain available.
    pub fn cancel(&mut self) {
        if self.state == SpeedTestState::Running {
            self.state = SpeedTestState::Cancelled;
        }
    }

    pub const fn state(self) -> SpeedTestState {
        self.state
    }

    pub const fn results(self) -> [Option<SpeedTestResult>; 3] {
        self.results
    }

    const fn is_valid_order(profiles: [ConnectionProfile; 3]) -> bool {
        let mut index = 0;
        while index < profiles.len() {
            let mut other = index + 1;
            while other < profiles.len() {
                if profiles[index] as u8 == profiles[other] as u8 {
                    return false;
                }
                other += 1;
            }
            index += 1;
        }
        true
    }

    const fn valid_metrics(metrics: SpeedTestMetrics) -> bool {
        metrics.actual_flow_count > 0
            && metrics.duration_ms > 0
            && metrics.packet_loss_ppm <= 1_000_000
            && metrics.p95_rtt_us >= metrics.median_rtt_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER: [ConnectionProfile; 3] = [
        ConnectionProfile::Standard,
        ConnectionProfile::EnergySaving,
        ConnectionProfile::Unlimited,
    ];

    const METRICS: SpeedTestMetrics = SpeedTestMetrics {
        download_bps: 20_000_000,
        upload_bps: 10_000_000,
        median_rtt_us: 30_000,
        p95_rtt_us: 55_000,
        jitter_us: 4_000,
        packet_loss_ppm: 1_000,
        actual_flow_count: 12,
        duration_ms: 5_000,
    };

    #[test]
    fn runs_profiles_sequentially_in_supplied_order() {
        let mut run = SpeedTestSequence::new(7, ORDER, false).unwrap();

        assert_eq!(run.current_profile(), Some(ConnectionProfile::Standard));
        assert_eq!(
            run.record_result(7, METRICS).unwrap(),
            Some(ConnectionProfile::EnergySaving)
        );
        assert_eq!(
            run.record_result(7, METRICS).unwrap(),
            Some(ConnectionProfile::Unlimited)
        );
        assert_eq!(run.record_result(7, METRICS).unwrap(), None);
        assert_eq!(run.state(), SpeedTestState::Complete);
        assert_eq!(run.current_profile(), None);
        assert!(run.results().iter().all(Option::is_some));
    }

    #[test]
    fn rejects_start_when_user_traffic_is_active() {
        assert_eq!(
            SpeedTestSequence::new(1, ORDER, true),
            Err(SpeedTestError::UserTrafficActive)
        );
    }

    #[test]
    fn rejects_duplicate_or_missing_profiles() {
        let invalid = [
            ConnectionProfile::Standard,
            ConnectionProfile::Standard,
            ConnectionProfile::Unlimited,
        ];
        assert_eq!(
            SpeedTestSequence::new(1, invalid, false),
            Err(SpeedTestError::InvalidProfileOrder)
        );
    }

    #[test]
    fn rejects_stale_network_generation() {
        let mut run = SpeedTestSequence::new(7, ORDER, false).unwrap();

        assert_eq!(
            run.record_result(8, METRICS),
            Err(SpeedTestError::StaleNetworkGeneration)
        );
        assert_eq!(run.current_profile(), Some(ConnectionProfile::Standard));
    }

    #[test]
    fn rejects_invalid_measurements() {
        let mut run = SpeedTestSequence::new(7, ORDER, false).unwrap();
        let invalid = SpeedTestMetrics {
            actual_flow_count: 0,
            ..METRICS
        };

        assert_eq!(
            run.record_result(7, invalid),
            Err(SpeedTestError::InvalidMetrics)
        );
        assert_eq!(run.current_profile(), Some(ConnectionProfile::Standard));
    }

    #[test]
    fn cancellation_stops_the_sequence_without_erasing_results() {
        let mut run = SpeedTestSequence::new(7, ORDER, false).unwrap();
        run.record_result(7, METRICS).unwrap();
        run.cancel();

        assert_eq!(run.state(), SpeedTestState::Cancelled);
        assert_eq!(
            run.record_result(7, METRICS),
            Err(SpeedTestError::Cancelled)
        );
        assert!(run.results()[0].is_some());
        assert!(run.results()[1].is_none());
    }

    #[test]
    fn rejects_results_after_completion() {
        let mut run = SpeedTestSequence::new(7, ORDER, false).unwrap();
        for _ in 0..3 {
            run.record_result(7, METRICS).unwrap();
        }

        assert_eq!(
            run.record_result(7, METRICS),
            Err(SpeedTestError::AlreadyComplete)
        );
    }
}
