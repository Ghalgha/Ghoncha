//! Short-lived TURN credentials and their independent provider lifecycle.
//!
//! Credential providers run only during session setup and refresh. The TURN
//! data path receives borrowed credentials and never handles VK account tokens,
//! cookies, call links, or provider-specific secrets.

use crate::{IoBudget, MonotonicTime};

/// Transport requested between the TURN client and the TURN server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnServerTransport {
    Udp,
    Tcp,
    Tls,
    Dtls,
}

/// One server URI returned by a credential provider.
///
/// The URI may contain sensitive or short-lived provider information. Do not
/// derive Debug or include it in logs.
pub struct TurnEndpoint<'a> {
    pub uri: &'a str,
    pub transport: TurnServerTransport,
}

/// Short-lived TURN credentials borrowed from the provider.
///
/// This type intentionally does not implement Debug or Clone. Callers must not
/// persist or log the username, credential, realm, or endpoint URIs. The
/// provider owns the backing storage and is responsible for zeroizing secret
/// material when credentials are invalidated or the provider is dropped.
pub struct TurnCredentials<'a> {
    /// Network generation for which these credentials were acquired.
    pub network_generation: u64,
    pub username: &'a str,
    pub credential: &'a [u8],
    pub realm: Option<&'a str>,
    pub endpoints: &'a [TurnEndpoint<'a>],
    pub expires_at: Option<MonotonicTime>,
    pub refresh_at: Option<MonotonicTime>,
}

/// Provider lifecycle, independent from TURN allocation and tunnel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProviderState {
    Idle,
    AwaitingUserAuthorization,
    Bootstrapping,
    ChallengeRequired,
    ChallengeInProgress,
    InteractiveVerificationRequired,
    Ready,
    CallUnavailable,
    RateLimited,
    Expired,
    Revoked,
    Failed,
}

/// Stable, redacted provider error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProviderError {
    NotConfigured,
    AuthorizationRequired,
    ChallengeRequired,
    ChallengeRejected,
    ChallengeExpired,
    InteractiveVerificationRequired,
    RateLimited,
    CallUnavailable,
    NetworkUnavailable,
    InvalidResponse,
    CredentialsExpired,
    CredentialsRevoked,
    ProviderFailure,
    InvalidState,
}

/// Why a credential acquisition or refresh operation is being stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialCancelReason {
    UserRequest,
    Logout,
    CallEnded,
    PermissionRevoked,
    NetworkChanged,
    SessionReplaced,
    Shutdown,
}

/// Result of advancing provider work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialPollOutcome {
    pub state: CredentialProviderState,
    pub next_deadline: Option<MonotonicTime>,
}

/// Asynchronous, runtime-neutral source of short-lived TURN credentials.
///
/// A concrete VK provider is configured separately with a user-authorized call
/// link or account-session reference. Those secrets are not passed through this
/// generic interface. Supported challenge handlers may run through a bounded
/// challenge session. The provider must expose ChallengeRequired and
/// ChallengeInProgress while handling a challenge, and must not report success
/// until the remote service confirms acceptance. If user interaction is needed,
/// expose InteractiveVerificationRequired without discarding the challenge
/// session. Rate limits and expired challenges are terminal for the current
/// provider cycle; callers must not reset retry budgets by recreating it.
pub trait TurnCredentialProvider {
    fn state(&self) -> CredentialProviderState;

    /// Begins credential acquisition for the supplied network generation.
    fn begin(&mut self, network_generation: u64) -> Result<(), CredentialProviderError>;

    /// Advances credential acquisition or refresh within the supplied budget.
    fn poll(
        &mut self,
        now: MonotonicTime,
        budget: IoBudget,
    ) -> Result<CredentialPollOutcome, CredentialProviderError>;

    /// Returns credentials only while the provider is in Ready state.
    fn credentials(&self) -> Option<TurnCredentials<'_>>;

    /// Cancels acquisition and invalidates credentials when required.
    /// Implementations must make repeated calls safe.
    fn cancel(&mut self, reason: CredentialCancelReason);
}
