# GHONCHA transport abstraction

Status: design contract for implementation. VK Calls TURN is the primary transport. The abstraction exists to make additional transports possible without changing the packet engine, tunnel cryptography, Android VPN lifecycle, or server gateway.

## 1. Architectural rule

The transport layer carries **opaque, already-authenticated GHONCHA tunnel records** between the client and the GHONCHA gateway. It does not parse inner IPv4/IPv6 packets, decide routes, own VPN keys, or implement gateway policy.

The logical client path is:

```text
Android VpnService / TUN
  -> Rust IP packet engine
  -> GHONCHA tunnel protocol (peer authentication, AEAD, replay protection)
  -> Transport API (opaque records)
       -> VK Calls adapter (primary)
            -> VK credential provider
            -> TURN client / ChannelData
            -> DTLS carrier to GHONCHA gateway
       -> Direct UDP adapter (future)
       -> TURN provider adapter (future)
       -> MASQUE adapter (future)
       -> other approved adapters
  -> GHONCHA gateway
  -> tunnel protocol verification / decapsulation
  -> IP forwarding and NAT
```

The exact placement of DTLS versus the GHONCHA tunnel protocol must remain explicit. The reference VK projects use DTLS as the client-to-server protected carrier. GHONCHA must not accidentally double-encrypt every packet without a measured and documented reason. The initial prototype should choose one authenticated record layer and prove its peer identity, replay handling, key lifecycle and wire compatibility before production integration.

## 2. Two separate interfaces

Do not merge credential acquisition and packet transport into one VK-specific interface.

### 2.1 CredentialProvider

A provider obtains short-lived access material for a transport. It runs on session setup and refresh boundaries, not for every packet.

Conceptual result:

- opaque provider/session identifier;
- transport endpoint list and supported modes;
- short-lived username/credential or equivalent access material;
- expiry and refresh metadata when available;
- redacted provider diagnostics;
- explicit cancellation/invalidation.

VK Calls implements this provider first. A future provider may supply ordinary TURN credentials, a MASQUE endpoint configuration, or another transport's access token. The packet engine never sees VK access tokens, cookies, call secrets, or raw credentials.

Credential providers must not expose secrets through Debug, Display, metrics, crash reports, or logs. Credentials remain in memory for the shortest practical lifetime and are invalidated on logout, call termination, permission revocation, or session replacement.

### 2.2 RecordTransport

A transport adapter moves bounded opaque records in both directions. It owns all framing and protocol details needed to preserve record boundaries over its underlying network path.

Required semantics:

- one successful send accepts one complete record or returns an explicit backpressure result;
- receive yields complete records, never partial records;
- ordering/reliability behavior is declared by capabilities, not assumed;
- no silent truncation, coalescing ambiguity, or unbounded buffering;
- cancellation and close are idempotent;
- all asynchronous events are associated with a network/session generation;
- the adapter reports transport health separately from tunnel authentication and useful IP data flow.

The API must support batch receive/send to amortize event-loop and FFI overhead. Packet processing remains inside Rust; no per-record FFI calls.

## 3. Transport capability model

Each adapter declares immutable capabilities before selection:

- record semantics: datagram-preserving or framed-stream;
- reliability: best-effort, reliable ordered, or adapter-defined;
- maximum record size and effective payload budget;
- supported address families;
- supported network transports: UDP, TCP, TLS, or other explicitly named modes;
- whether network migration/rebinding is supported;
- whether keepalive/refresh is required;
- whether an external credential provider is required;
- whether the adapter can expose path MTU and congestion/backpressure signals.

The selector must not assume that reliable ordered transports are interchangeable with datagrams. TCP/TLS fallback can preserve record boundaries through explicit length framing, but introduces head-of-line blocking and different loss/congestion behavior. MTU and effective payload limits must include every outer protocol header.

Capabilities are data, not a pile of VK-specific conditionals in the packet engine.

## 4. Initial transport adapters

### 4.1 VK Calls TURN — primary

- CredentialProvider: VK Calls user-authorized call/session bootstrap.
- Carrier: TURN allocation, peer permission, channel binding, ChannelData or Send/Data indications.
- Client-to-gateway protected carrier: DTLS as established by the interoperability prototype.
- Default mode: TURN over UDP where reachable.
- Fallbacks: only modes actually returned/supported by the provider and verified against the peer, such as TURN over TCP/TLS.
- The VK relay is a relay, not the GHONCHA gateway.
- VK account/call signalling, TURN allocation, DTLS association, GHONCHA peer authentication, and VPN tunnel state remain separate state machines.

### 4.2 Direct UDP — future

Direct UDP carries the same authenticated GHONCHA records without a TURN allocation. It must use the same peer authentication, replay protection, key lifecycle and record limits. It is a separate adapter, not a special case inside the VK adapter.

### 4.3 Generic TURN — future

A generic TURN adapter can reuse a standards-compliant TURN engine but must obtain credentials from its own provider. It must not depend on VK call lifecycle or VK-specific response schemas.

### 4.4 MASQUE — future

MASQUE CONNECT-UDP and CONNECT-IP are separate candidates. CONNECT-UDP can carry UDP datagrams; CONNECT-IP carries IP packets and therefore needs a deliberately defined boundary relative to GHONCHA's own tunnel protocol. Do not pretend they are the same adapter mode. Both require a reachable, authorized proxy and actual interoperability/performance tests.

### 4.5 Other transports

New adapters may be added behind the same RecordTransport contract when their security, framing, resource bounds and operational semantics are documented. A new transport must not require changes to the IP parser, routing engine, Android TUN ownership, or gateway forwarding core.

## 5. Lifecycle and selection

Transport lifecycle is independent from VPN tunnel lifecycle:

- Unconfigured
- CredentialsPending
- Preparing
- Establishing
- Ready
- Degraded
- Recovering
- Closing
- Closed
- Failed

A transport may be Ready while the GHONCHA tunnel is unauthenticated. A tunnel may be authenticated while useful application traffic is not flowing. Expose these as distinct facts.

Selection policy:
1. Respect explicit user choice and provider authorization.
2. Check endpoint and network generation.
3. Establish the candidate adapter and verify peer identity.
4. Run a bounded authenticated health probe.
5. Promote it only after the GHONCHA tunnel confirms readiness.
6. Keep the previous path alive only during a bounded handover window where resource and provider limits permit.
7. Close stale adapters and release allocations after successful migration.
8. Apply bounded exponential backoff with jitter and a retry budget.

Never create VK calls or TURN allocations in an infinite background retry loop. Never use a transport solely because its port or hostname is presumed allowlisted.

## 6. Performance and resource rules

- Bounded queues and packet pools; no unbounded channel growth.
- Batch I/O and event processing.
- No packet-per-task or packet-per-thread design.
- Reuse buffers where ownership permits; avoid copying the complete packet unnecessarily.
- Explicit backpressure; never silently drop control messages.
- Keepalive and TURN refresh intervals derived from protocol lifetime and measured path behavior.
- No periodic polling where event-driven readiness is available.
- Avoid holding Android wake locks during retry delays.
- Track per-adapter CPU, allocations, queue depth, goodput, RTT, jitter, loss, reordering, reconnect time, radio activity, thermal state and battery cost.
- Do not increase worker/allocation count unless controlled tests show a repeatable end-to-end improvement.

## 7. Rust implementation boundary

The first Rust interface crate should contain only stable shared types and traits. It must not depend on Android, VK SDKs, a specific async runtime, a TURN implementation, or a crypto provider.

Keep the implementation Sans-I/O or runtime-neutral at the contract boundary. A concrete adapter may use an event loop or async runtime internally, but the core should not be forced to adopt that runtime.

Recommended workspace split when implementation begins:

- `crates/packet`: validated zero-copy IPv4/IPv6 packet views.
- `crates/transport-api`: transport capabilities, opaque record I/O contract, lifecycle and error types.
- `crates/tunnel`: authenticated GHONCHA record protocol and peer lifecycle.
- `crates/transport-vk-turn`: VK credential provider integration and TURN/DTLS adapter.
- `crates/client-core`: network state machine, transport selection and TUN data path.
- `crates/gateway`: server-side tunnel termination and IP forwarding.

Do not add all crates at once. Add and test one crate at a time. Do not pin TURN/DTLS dependencies until their Android NDK build, licence, maintenance, security posture and interoperability have been checked.

## 8. Candidate library assessment (2026-11-06)

### TURN

`turn-client-proto 0.7.3` from `ystreet/turn-proto` is the leading candidate for an interoperability spike:
- Sans-I/O design separates protocol state from sockets and runtime.
- Version 0.7.3 documentation lists RFC 8656, IPv6, UDP and TCP client support.
- For the reference VK proxy topology, start with the UDP TURN client: TURN/UDP is the outer hop to the VK relay. The GHONCHA client-to-gateway DTLS association is application data sent to the gateway peer through TURN; it is not DTLS between the client and the VK TURN server.
- The crate also documents separate TLS-over-TCP and DTLS-over-UDP client extension crates. Those secure the client-to-TURN-server hop and are not interchangeable with the end-to-end DTLS carrier used by the reference projects.
- It uses `turn-types` / `stun-proto` and has a documented API.
- It is not yet selected for production. Verify its exact RFC 8656 coverage, VK server interoperability, credential/nonce behavior, Android cross-compilation, dependency graph, allocation behavior and license.

The CSQTT TURN engine remains an important comparison implementation. Compare wire behavior and tests rather than assuming a newer crate is automatically more correct.

### DTLS

`dimpl 0.9.0` (released 2026-10-25) is a Sans-I/O DTLS 1.2/1.3 candidate with explicit version constructors and an event-loop-oriented design. It is a candidate for the **client-to-GHONCHA-gateway application DTLS association**, not a TURN client and not the TURN-to-relay security wrapper.
- prove DTLS 1.2 interoperability with the reference CSQTT/WDTT client and server wire behavior;
- verify certificate or PSK peer authentication and reject insecure verification shortcuts;
- the library exposes the peer certificate but explicitly leaves PKI/fingerprint/name validation to the application; GHONCHA must implement and test strict pin/identity validation;
- test retransmission, fragmentation, replay handling, key lifecycle and malformed records;
- verify Android NDK targets and crypto dependency portability;
- review the project's security history and license.

Do not use `rtc-dtls` solely because it is mature within WebRTC: its feature set and handshake expectations must be checked against this non-WebRTC client/server use case.

### Standards

TURN behavior follows RFC 8656 and STUN behavior follows RFC 8489. TURN-over-TCP/TLS framing, UDP retransmission, allocation lifetime, permissions, ChannelBind, nonce challenges, IPv6 and MTU handling require dedicated conformance tests.

## 9. Decision gates

Before the first production adapter:
1. Define the exact record-layer choice and authenticated peer identity.
2. Build a client/server interoperability harness independent of Android and VK.
3. Compare `turn-client-proto` with the CSQTT reference on identical test vectors and TURN servers.
4. Compare `dimpl` with the reference DTLS behavior; no insecure certificate bypass.
5. Cross-compile the selected dependencies for Android ABIs using the current supported NDK.
6. Fuzz STUN/TURN parsing, DTLS record handling, and transport framing.
7. Verify licensing and transitive dependencies.
8. Benchmark UDP first, then TCP/TLS fallback and controlled worker-count changes.
9. Integrate TUN only after the standalone client/server path is authenticated, stable and measured.

A transport is not production-ready merely because it connects once. It must survive credential expiry, call termination, network handover, packet loss, server restart, Doze, and malformed peer input.
