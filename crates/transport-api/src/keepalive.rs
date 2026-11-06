//! Adaptive idle keepalive scheduling shared by transport adapters.
//!
//! The policy is intentionally timer-driven: callers arm one deadline after
//! outbound activity and do not poll periodically. Successful application data
//! transmission resets the activity timestamp, suppressing redundant probes.
//! Measurements must be scoped to the active network generation and discarded
//! after a network change.

/// Configuration errors for an idle keepalive policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeepaliveConfigError {
    ZeroMinimumInterval,
    MaximumBelowMinimum,
    InvalidSafetyMargin,
}

/// Adaptive policy derived from an observed NAT or relay idle timeout.
///
/// A keepalive is scheduled only when a usable timeout has been measured.
/// This avoids guessing a short interval that wastes radio energy, or a long
/// interval that silently exceeds the path's actual idle lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdleKeepalivePolicy {
    observed_idle_timeout_ns: Option<u64>,
    minimum_interval_ns: u64,
    maximum_interval_ns: u64,
    safety_margin_basis_points: u16,
}

impl IdleKeepalivePolicy {
    /// Creates a policy. safety_margin_basis_points is in the range 1..10000.
    ///
    /// The effective interval is the measured idle timeout minus the configured
    /// safety margin, bounded by the minimum and maximum intervals. If the
    /// measured path cannot safely support the minimum interval, keepalives are
    /// disabled rather than scheduled too late.
    pub const fn new(
        observed_idle_timeout_ns: Option<u64>,
        minimum_interval_ns: u64,
        maximum_interval_ns: u64,
        safety_margin_basis_points: u16,
    ) -> Result<Self, KeepaliveConfigError> {
        if minimum_interval_ns == 0 {
            return Err(KeepaliveConfigError::ZeroMinimumInterval);
        }
        if maximum_interval_ns < minimum_interval_ns {
            return Err(KeepaliveConfigError::MaximumBelowMinimum);
        }
        if safety_margin_basis_points == 0 || safety_margin_basis_points >= 10_000 {
            return Err(KeepaliveConfigError::InvalidSafetyMargin);
        }

        Ok(Self {
            observed_idle_timeout_ns,
            minimum_interval_ns,
            maximum_interval_ns,
            safety_margin_basis_points,
        })
    }

    /// Returns the effective interval, or None until a path timeout is known.
    pub fn interval_ns(self) -> Option<u64> {
        let timeout = self.observed_idle_timeout_ns?;
        let usable = (u128::from(timeout)
            * u128::from(10_000 - self.safety_margin_basis_points)
            / 10_000) as u64;

        if usable < self.minimum_interval_ns {
            return None;
        }

        Some(usable.min(self.maximum_interval_ns))
    }

    /// Returns the one-shot deadline after the last successful outbound packet.
    ///
    /// Callers should reset this deadline whenever any outbound application
    /// data is sent. Keepalive packets themselves must be authenticated by the
    /// active transport session and must not carry arbitrary unauthenticated
    /// payloads.
    pub fn deadline_after_activity(self, last_outbound_at_ns: u64) -> Option<u64> {
        last_outbound_at_ns.checked_add(self.interval_ns()?)
    }

    /// Returns whether the one-shot keepalive deadline has elapsed.
    pub fn is_due(self, now_ns: u64, last_outbound_at_ns: u64) -> bool {
        self.deadline_after_activity(last_outbound_at_ns)
            .is_some_and(|deadline| now_ns >= deadline)
    }

    /// Replaces the timeout measurement after a validated observation.
    ///
    /// The caller must discard measurements when the underlying network
    /// generation changes. No probing or background timer is started here.
    pub const fn with_observed_idle_timeout(self, timeout_ns: Option<u64>) -> Self {
        Self {
            observed_idle_timeout_ns: timeout_ns,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn does_not_schedule_until_timeout_is_measured() {
        let policy = IdleKeepalivePolicy::new(None, 5 * SECOND, 60 * SECOND, 2_000).unwrap();
        assert_eq!(policy.interval_ns(), None);
        assert_eq!(policy.deadline_after_activity(10), None);
        assert!(!policy.is_due(u64::MAX, 10));
    }

    #[test]
    fn applies_safety_margin_and_interval_bounds() {
        let policy =
            IdleKeepalivePolicy::new(Some(30 * SECOND), 5 * SECOND, 60 * SECOND, 2_000)
                .unwrap();
        assert_eq!(policy.interval_ns(), Some(24 * SECOND));

        let capped =
            IdleKeepalivePolicy::new(Some(120 * SECOND), 5 * SECOND, 45 * SECOND, 1_000)
                .unwrap();
        assert_eq!(capped.interval_ns(), Some(45 * SECOND));
    }

    #[test]
    fn disables_keepalive_when_minimum_cannot_fit_safely() {
        let policy =
            IdleKeepalivePolicy::new(Some(5 * SECOND), 5 * SECOND, 60 * SECOND, 2_000)
                .unwrap();
        assert_eq!(policy.interval_ns(), None);
    }

    #[test]
    fn uses_one_shot_deadline_and_respects_new_activity() {
        let policy =
            IdleKeepalivePolicy::new(Some(20 * SECOND), 1 * SECOND, 60 * SECOND, 2_000)
                .unwrap();
        assert_eq!(
            policy.deadline_after_activity(10 * SECOND),
            Some(26 * SECOND)
        );
        assert!(!policy.is_due(25 * SECOND, 10 * SECOND));
        assert!(policy.is_due(26 * SECOND, 10 * SECOND));
        assert!(!policy.is_due(26 * SECOND, 21 * SECOND));
    }

    #[test]
    fn overflow_does_not_create_an_immediate_deadline() {
        let policy =
            IdleKeepalivePolicy::new(Some(20 * SECOND), 1 * SECOND, 60 * SECOND, 2_000)
                .unwrap();
        assert_eq!(policy.deadline_after_activity(u64::MAX - 1), None);
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert_eq!(
            IdleKeepalivePolicy::new(Some(10), 0, 10, 2_000),
            Err(KeepaliveConfigError::ZeroMinimumInterval)
        );
        assert_eq!(
            IdleKeepalivePolicy::new(Some(10), 5, 4, 2_000),
            Err(KeepaliveConfigError::MaximumBelowMinimum)
        );
        assert_eq!(
            IdleKeepalivePolicy::new(Some(10), 1, 10, 0),
            Err(KeepaliveConfigError::InvalidSafetyMargin)
        );
        assert_eq!(
            IdleKeepalivePolicy::new(Some(10), 1, 10, 10_000),
            Err(KeepaliveConfigError::InvalidSafetyMargin)
        );
    }

    #[test]
    fn accepts_new_measurement_without_mutating_other_limits() {
        let policy = IdleKeepalivePolicy::new(None, 2 * SECOND, 40 * SECOND, 1_500)
            .unwrap()
            .with_observed_idle_timeout(Some(20 * SECOND));
        assert_eq!(policy.interval_ns(), Some(17 * SECOND));
    }
}
