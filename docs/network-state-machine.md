# GHONCHA network state machine and adapter contracts

Status: interface contract for implementation. This document complements `docs/network-availability.md` and `docs/architecture.md`. It defines ownership and observable behavior, not a selected async runtime or transport implementation.

## 1. Design rules

- Android is authoritative for platform network observations and VPN lifecycle.
- Rust Core is authoritative for endpoint probes, transport health, retry scheduling, transport policy, and the consolidated connection state.
- All packet processing and transport packet I/O remain inside Rust. FFI is control-plane only; never cross FFI once per IP packet or tunnel datagram.
- Network availability, endpoint reachability, tunnel establishment, and useful data flow are separate dimensions. Do not collapse them into one boolean.
- State transitions are driven by timestamped events and a monotonically increasing network generation. Stale events from an old network generation must not revive old sockets or overwrite newer state.
- Side effects (socket creation, probes, connect, close, refresh) are emitted by the state machine and executed by adapters. The reducer itself must be deterministic and testable.
- No state or retry policy may claim that a network is censored, allowlisted, or unrestricted based only on a timeout or one successful probe.

## 2. Ownership boundaries

### Android platform adapter

Owns:
- `VpnService`, TUN creation/closure, foreground-service lifecycle, and user consent.
- `ConnectivityManager` / `NetworkCallback` registration and unregistration.
- Immutable snapshots of the active network: ephemeral network token, generation, transport type, metered status, internet/validated/captive-portal capabilities, addresses, routes, and DNS server addresses.
- Android-specific socket operations required for an outer transport socket: protect it from the VPN route with `VpnService.protect()`, and bind it to the intended Android `Network` when applicable.
- Delivery of lifecycle and network events to Rust Core.

It must not implement transport selection, retry loops, TURN allocation state, or packet processing.

### Rust Core

Owns:
- Canonical network snapshot and generation checks.
- Probe scheduling and result interpretation.
- Endpoint health, adapter selection policy, retry budget, backoff, and state reduction.
- Tunnel lifecycle coordination and user-visible diagnostics.
- All packet queues, transport packet I/O, and tunnel-engine integration.

It must not call Android framework APIs directly or retain Android `Network` objects.

### Rust transport adapter

Each adapter owns its protocol-specific resources and state, for example TURN allocation, permissions, channel bindings, HTTP session, congestion/flow-control state, socket handles, and protocol timers. It exposes a common lifecycle and datagram contract to Rust Core. Adapter code must not make policy decisions about whether a network is generally available.

### Gateway/control plane

The control plane provisions authenticated endpoint configuration and peer identity. The gateway owns tunnel termination and packet forwarding. A relay remains an opaque relay and must not gain VPN session keys.

## 3. FFI control contract

The FFI boundary carries bounded, versioned control messages only. The exact Kotlin/Rust binding mechanism remains subject to JNI/JNA/UniFFI benchmarking.

### Android to Rust events

- `CoreStart(config, tun_fd, initial_network_snapshot)`
- `NetworkChanged(snapshot)`
- `NetworkLost(generation)`
- `SocketPrepared(request_id, result)`
- `VpnPermissionRevoked`
- `AppForegroundChanged(is_foreground)`
- `UserConnect`
- `UserDisconnect`
- `UserRetry`
- `CoreStop`

The TUN descriptor transfer must use one explicit ownership rule: after successful handoff Rust owns the descriptor; on failed handoff Android retains it and closes it according to the caller contract. Never allow both sides to close or neither side to close the same descriptor.

A network snapshot includes a monotonically increasing `generation`, an opaque process-local network token, capability flags, transport type, metered status, and bounded lists of addresses/routes/DNS servers. Do not persist the token or treat it as a stable network identity across process restarts.

### Rust to Android requests and events

- `PrepareSocket(request_id, network_token, raw_fd)`: Android protects the socket using `VpnService.protect()` and binds it to the requested `Network` if that network is still current. Return success/failure with the same request ID. If the token is stale, fail explicitly; do not silently bind to the default network.
- `CoreStateChanged(snapshot)`
- `DiagnosticEvent(category, severity, timestamp, redacted_detail)`
- `Statistics(snapshot)`
- `CoreStopped(reason)`

Socket preparation is a bounded control operation, not a packet callback. Rust must not send application packets through FFI. A socket must not transmit until protection and required network binding have succeeded.

All messages include a schema version. Reject unsupported versions and malformed lengths. Bound strings and collection sizes. Do not pass private keys, credentials, or packet payloads in diagnostic events.

## 4. State model

Maintain three orthogonal state dimensions rather than a single large enum.

### Platform network state

- `NoNetwork`: no usable Android network is currently available.
- `Unvalidated`: a network exists but Android has not validated general internet access.
- `Validated`: Android reports validated general internet access.
- `CaptivePortal`: Android reports a captive portal.
- `Unknown`: the snapshot is unavailable or internally inconsistent.

The `Validated` state is not evidence that a GHONCHA endpoint is reachable.

### Endpoint and transport state

For each configured endpoint and adapter:
- `Unknown`
- `Probing`
- `Reachable`
- `Unreachable`
- `Unsupported`
- `AuthenticationFailed`
- `CoolingDown)

Record the observation time, network generation, failure category, and confidence/evidence. A result is usable only for the generation on which it was measured and within its configured freshness window.

### Tunnel state

- `Stopped`
- `WaitingForNetwork`
- `CheckingEndpoint`
- `Connecting`
- `Connected`
- `Degraded` (tunnel established but data health or path quality is below policy)
- `Recovering`
- `Failed`

The public diagnostic state is derived from these dimensions. For example, `Validated + Endpoint Unreachable + Stopped` maps to “Internet available; GHONCHA server unreachable”; it does not prove filtering.

## 5. Event and transition contract

Every event has a monotonic timestamp and, where relevant, a network generation. Wall-clock time is for diagnostics only; use monotonic time for deadlines and backoff.

On a new network generation:
1. Replace the stored platform snapshot atomically.
2. Mark endpoint observations from prior generations stale.
3. Cancel pending probes and connection attempts for the old generation.
4. Close or retire sockets bound to the old network; do not reuse them on the new network.
5. Re-resolve configured endpoint names using the selected network's DNS path.
6. Schedule a bounded probe set, then evaluate adapter candidates.
7. Attempt connection only if user intent is connected and configuration is valid.

On network loss:
1. Invalidate the active generation and sockets.
2. Stop active probes and connection attempts.
3. Move the tunnel to `WaitingForNetwork` or `Recovering` according to whether a tunnel had been active.
4. Do not run periodic retry work while no usable network exists.

On endpoint probe success:
- Record only the exact endpoint, protocol, and network generation tested.
- Permit adapter selection if authentication and policy checks pass.
- Do not infer that other ports, protocols, destinations, or the general internet are reachable.

On endpoint probe failure:
- Record the observed layer and failure category.
- Do not label a timeout as censorship or DPI.
- Apply per-endpoint backoff and continue only with other explicitly configured candidates within the retry budget.

On tunnel handshake success:
- Enter `Connected` only after peer authentication succeeds.
- Continue low-frequency data-health monitoring; handshake success alone does not prove useful routing.

On data-health failure:
- Enter `Degraded`, then attempt bounded recovery if the failure persists.
- Preserve the last known-good adapter until a replacement is authenticated and ready, where protocol semantics allow.
- Never report `Connected` solely because a socket is open.

On user disconnect or permission revocation:
- Stop retries, close tunnel and transport resources, and release owned descriptors.
- A later network callback must not reconnect unless user intent and permission state allow it.

## 6. Transport adapter contract

The core-facing adapter contract is conceptually:

- `capabilities() -> AdapterCapabilities`: supported network families, datagram semantics, proxy requirements, and required platform features.
- `prepare(config, network_generation) -> Result`: validate configuration and allocate bounded resources.
- `probe(deadline) -> ProbeResult`: protocol-specific reachability/authentication check to a configured endpoint only.
- `connect(deadline) -> Result`: establish the transport session.
- `send_datagram(bytes) -> Result`: accept one complete tunnel datagram or return an explicit backpressure/error result.
- `receive_datagrams(budget) -> bounded batch`: deliver complete datagrams to the tunnel engine without FFI.
- `poll_events(budget) -> bounded events`: report allocation expiry, permission/channel refresh, path changes, and transport errors.
- `close(reason)`: idempotently release all resources.

This is a semantic contract, not a mandate for a particular Rust trait syntax, async runtime, or polling library. Implementations must preserve datagram boundaries, bound all queues and batches, expose backpressure, and avoid per-datagram task spawning. A stream transport must add explicit framing and must not pretend that TCP preserves datagram loss/congestion semantics.

Adapter errors use stable categories: `DNS_FAILURE`, `SOCKET_PROTECTION_FAILED`, `NETWORK_BIND_FAILED`, `CONNECT_TIMEOUT`, `PROTOCOL_UNSUPPORTED`, `AUTHENTICATION_FAILED`, `REMOTE_UNAVAILABLE`, `RESOURCE_EXHAUSTED`, `MTU_EXCEEDED`, `CLOSED`, and `INTERNAL`. Preserve the underlying layer and retryability separately; never turn all errors into a generic timeout.

## 7. Transport selection and fallback policy

- Selection is policy-driven and based on measured reachability plus configured operator policy, not on a hardcoded country/operator allowlist.
- Prefer the lowest-overhead authenticated datagram path when it is reachable and healthy.
- Consider TURN UDP, TURN TCP/TLS, MASQUE CONNECT-UDP, or CONNECT-IP only when the corresponding endpoint is explicitly provisioned and the adapter is supported.
- Do not probe every adapter on every reconnect. Use last-known-good preference with bounded freshness, then test a small candidate set.
- Switch away from a working path only for a material failure or a measured policy threshold; avoid oscillation with hysteresis and a minimum dwell interval.
- A fallback is successful only after authentication and tunnel data-health confirmation.
- TCP/TLS fallback may improve reachability but can worsen latency and jitter. Expose the selected adapter and degraded quality.
- If all configured endpoints fail, stop at the retry budget and report the observed failure layer. Never invent an alternate endpoint or silently use an unapproved third-party relay.

## 8. Retry, timers, and energy

- Use one central scheduler for deadlines and retry work; avoid one timer/task per endpoint or packet.
- Apply bounded exponential backoff with jitter per endpoint/adapter. Set a maximum attempt count or elapsed retry budget.
- Reset backoff only after authenticated connection and useful data flow, or after a material network-generation change.
- Coalesce repeated network/capability changes into the newest snapshot.
- Suspend probes and retries when no usable network exists, the user disconnected, permission is revoked, or the service is stopping.
- On metered or low-power networks, reduce optional diagnostics and health-probe frequency; do not reduce correctness-critical protocol refreshes below their required deadlines.
- Do not hold a wake lock for background retry loops. Keep the active tunnel's scheduling separate from deferrable configuration refresh.
- Every timer must be cancellable on generation change and shutdown.

## 9. Observability and privacy

Expose a compact diagnostic snapshot:
- derived user-visible state;
- platform network type and metered/validated/captive-portal flags;
- network generation (diagnostic counter only);
- selected adapter and configured endpoint identifier (not secret URL parameters);
- last successful handshake/data-flow timestamps;
- last failure category and retry deadline;
- bounded counters for bytes, packets, drops, reconnects, and probe outcomes.

Do not log packet contents, keys, TURN credentials, raw DNS query history, or full user traffic metadata. Diagnostic export must be opt-in, redacted, and bounded. Counters and timestamps should use monotonic sources internally.

## 10. Required tests before implementation

1. Deterministic reducer tests for every state/event pair, including stale generations and out-of-order events.
2. Network transition tests: Wi-Fi to cellular, cellular to Wi-Fi, network loss, captive portal, unvalidated network, and rapid repeated callbacks.
3. Socket tests proving protection and network binding complete before first send; stale network tokens must fail closed.
4. Adapter contract tests for datagram boundary preservation, backpressure, queue limits, close idempotence, deadline expiry, and malformed peer responses.
5. Retry tests for jitter bounds, retry budgets, cancellation, no-network suspension, and no retry after user disconnect.
6. Tunnel tests proving that only authenticated handshake plus useful data flow yields `Connected`.
7. Energy tests measuring wakeups and probe frequency under idle, metered, low-power, and repeated network-change conditions.
8. End-to-end tests for TURN UDP/TCP/TLS and MASQUE only after each adapter is independently selected and implemented.

No transport, crypto engine, async runtime, or FFI generator is selected by this document.
