//! Bounded challenge lifecycle primitives for credential providers.
//!
//! This module does not implement a provider-specific CAPTCHA solver. It
//! supplies explicit states and an attempt budget so a VK adapter can run
//! supported challenge handlers without unbounded retries or confusing a
//! locally produced answer with server acceptance.

/// Challenge family selected by the provider's response parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeKind {
    Checkbox,
    ProofOfWork,
    Slider,
    Other,
}

impl ChallengeKind {
    const fn index(self) -> usize {
        match self {
            Self::Checkbox => 0,
            Self::ProofOfWork => 1,
            Self::Slider => 2,
            Self::Other => 3,
        }
    }
}

/// Observable phase of one challenge instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengePhase {
    Idle,
    Detected,
    Solving,
    AwaitingUser,
    Submitted,
    Accepted,
    Rejected,
    Expired,
    RateLimited,
    Failed,
}

impl ChallengePhase {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Expired | Self::RateLimited | Self::Failed
        )
    }
}

/// Errors from challenge state transitions and attempt accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    InvalidTransition {
        from: ChallengePhase,
        to: ChallengePhase,
    },
    AttemptLimitReached,
}

/// Attempt limits scoped to one credential-acquisition or refresh cycle.
///
/// Keep this budget alive across repeated challenge instances in the same
/// provider cycle. Constructing a new budget resets the counters, so callers
/// must not create one merely because VK returned another challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeAttemptBudget {
    max_total: u8,
    max_per_kind: [u8; 4],
    total_used: u8,
    per_kind_used: [u8; 4],
}

impl ChallengeAttemptBudget {
    pub const fn new(max_total: u8, max_per_kind: [u8; 4]) -> Self {
        Self {
            max_total,
            max_per_kind,
            total_used: 0,
            per_kind_used: [0; 4],
        }
    }

    /// Reserves an attempt before invoking a solver or submitting an answer.
    pub fn reserve(&mut self, kind: ChallengeKind) -> Result<u8, ChallengeError> {
        let index = kind.index();
        if self.total_used >= self.max_total
            || self.per_kind_used[index] >= self.max_per_kind[index]
        {
            return Err(ChallengeError::AttemptLimitReached);
        }

        self.total_used = self.total_used.saturating_add(1);
        self.per_kind_used[index] = self.per_kind_used[index].saturating_add(1);
        Ok(self.total_used)
    }

    pub const fn total_used(&self) -> u8 {
        self.total_used
    }

    pub const fn used_for(&self, kind: ChallengeKind) -> u8 {
        self.per_kind_used[kind.index()]
    }

    pub const fn remaining_total(&self) -> u8 {
        self.max_total.saturating_sub(self.total_used)
    }
}

/// State and retry accounting for one provider credential cycle.
///
/// A solver result must transition through Submitted and then Accepted only
/// after the provider confirms acceptance. A locally generated token or answer
/// is not evidence that the remote service accepted the challenge.
pub struct ChallengeSession {
    phase: ChallengePhase,
    attempts: ChallengeAttemptBudget,
}

impl ChallengeSession {
    pub const fn new(attempts: ChallengeAttemptBudget) -> Self {
        Self {
            phase: ChallengePhase::Idle,
            attempts,
        }
    }

    pub const fn phase(&self) -> ChallengePhase {
        self.phase
    }

    pub const fn attempts(&self) -> &ChallengeAttemptBudget {
        &self.attempts
    }

    pub fn detect(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Detected)
    }

    /// Starts a subsequent challenge in the same credential cycle after VK
    /// accepted the previous one. The shared attempt budget is not reset.
    pub fn next_challenge(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Detected)
    }

    /// Reserves budget and enters Solving. Rejected challenges may be retried
    /// while the shared cycle budget still permits it.
    pub fn begin_attempt(&mut self, kind: ChallengeKind) -> Result<u8, ChallengeError> {
        if !matches!(
            self.phase,
            ChallengePhase::Detected | ChallengePhase::Rejected
        ) {
            return Err(ChallengeError::InvalidTransition {
                from: self.phase,
                to: ChallengePhase::Solving,
            });
        }
        let attempt = self.attempts.reserve(kind)?;
        self.phase = ChallengePhase::Solving;
        Ok(attempt)
    }

    pub fn await_user(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::AwaitingUser)
    }

    pub fn submitted(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Submitted)
    }

    pub fn accepted(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Accepted)
    }

    pub fn rejected(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Rejected)
    }

    pub fn expired(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Expired)
    }

    pub fn rate_limited(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::RateLimited)
    }

    pub fn failed(&mut self) -> Result<(), ChallengeError> {
        self.transition(ChallengePhase::Failed)
    }

    fn transition(&mut self, next: ChallengePhase) -> Result<(), ChallengeError> {
        let allowed = matches!(
            (self.phase, next),
            (ChallengePhase::Idle, ChallengePhase::Detected)
                | (ChallengePhase::Accepted, ChallengePhase::Detected)
                | (ChallengePhase::Detected, ChallengePhase::AwaitingUser)
                | (ChallengePhase::Solving, ChallengePhase::AwaitingUser)
                | (ChallengePhase::Solving, ChallengePhase::Submitted)
                | (ChallengePhase::AwaitingUser, ChallengePhase::Submitted)
                | (ChallengePhase::Rejected, ChallengePhase::AwaitingUser)
                | (ChallengePhase::Submitted, ChallengePhase::Accepted)
                | (ChallengePhase::Submitted, ChallengePhase::Rejected)
                | (ChallengePhase::Detected, ChallengePhase::Expired)
                | (ChallengePhase::Solving, ChallengePhase::Expired)
                | (ChallengePhase::AwaitingUser, ChallengePhase::Expired)
                | (ChallengePhase::Submitted, ChallengePhase::Expired)
                | (ChallengePhase::Rejected, ChallengePhase::Expired)
                | (ChallengePhase::Detected, ChallengePhase::RateLimited)
                | (ChallengePhase::Solving, ChallengePhase::RateLimited)
                | (ChallengePhase::AwaitingUser, ChallengePhase::RateLimited)
                | (ChallengePhase::Submitted, ChallengePhase::RateLimited)
                | (ChallengePhase::Rejected, ChallengePhase::RateLimited)
                | (ChallengePhase::Detected, ChallengePhase::Failed)
                | (ChallengePhase::Solving, ChallengePhase::Failed)
                | (ChallengePhase::AwaitingUser, ChallengePhase::Failed)
                | (ChallengePhase::Submitted, ChallengePhase::Failed)
                | (ChallengePhase::Rejected, ChallengePhase::Failed)
        );

        if !allowed {
            return Err(ChallengeError::InvalidTransition {
                from: self.phase,
                to: next,
            });
        }
        self.phase = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn budget() -> ChallengeAttemptBudget {
        ChallengeAttemptBudget::new(5, [2, 2, 2, 1])
    }

    #[test]
    fn requires_remote_acceptance_after_submission() {
        let mut session = ChallengeSession::new(budget());
        session.detect().unwrap();
        session.begin_attempt(ChallengeKind::Checkbox).unwrap();
        session.submitted().unwrap();

        assert_eq!(session.phase(), ChallengePhase::Submitted);
        assert!(session.accepted().is_ok());
        assert_eq!(session.phase(), ChallengePhase::Accepted);
    }

    #[test]
    fn enforces_total_and_per_kind_attempt_limits() {
        let mut attempts = budget();
        attempts.reserve(ChallengeKind::Checkbox).unwrap();
        attempts.reserve(ChallengeKind::Checkbox).unwrap();
        assert_eq!(
            attempts.reserve(ChallengeKind::Checkbox),
            Err(ChallengeError::AttemptLimitReached)
        );

        attempts.reserve(ChallengeKind::ProofOfWork).unwrap();
        attempts.reserve(ChallengeKind::Slider).unwrap();
        attempts.reserve(ChallengeKind::Other).unwrap();
        assert_eq!(
            attempts.reserve(ChallengeKind::Other),
            Err(ChallengeError::AttemptLimitReached)
        );
        assert_eq!(attempts.total_used(), 5);
        assert_eq!(attempts.remaining_total(), 0);
    }

    #[test]
    fn rejected_challenge_can_retry_within_same_budget() {
        let mut session = ChallengeSession::new(budget());
        session.detect().unwrap();
        session.begin_attempt(ChallengeKind::Slider).unwrap();
        session.submitted().unwrap();
        session.rejected().unwrap();
        assert_eq!(session.begin_attempt(ChallengeKind::Slider), Ok(2));
    }

    #[test]
    fn cannot_accept_an_answer_that_was_not_submitted() {
        let mut session = ChallengeSession::new(budget());
        session.detect().unwrap();
        assert_eq!(
            session.accepted(),
            Err(ChallengeError::InvalidTransition {
                from: ChallengePhase::Detected,
                to: ChallengePhase::Accepted,
            })
        );
    }

    #[test]
    fn accepted_challenge_can_be_followed_by_another_without_resetting_budget() {
        let mut session = ChallengeSession::new(budget());
        session.detect().unwrap();
        assert_eq!(session.begin_attempt(ChallengeKind::Checkbox), Ok(1));
        session.submitted().unwrap();
        session.accepted().unwrap();

        session.next_challenge().unwrap();
        assert_eq!(session.begin_attempt(ChallengeKind::Slider), Ok(2));
        assert_eq!(session.attempts().total_used(), 2);
    }

    #[test]
    fn rate_limit_is_terminal_and_does_not_allow_retry() {
        let mut session = ChallengeSession::new(budget());
        session.detect().unwrap();
        session.rate_limited().unwrap();
        assert!(session.phase().is_terminal());
        assert!(matches!(
            session.begin_attempt(ChallengeKind::Checkbox),
            Err(ChallengeError::InvalidTransition { .. })
        ));
    }
}
