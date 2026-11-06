# GHONCHA transport abstraction

Status: design contract for implementation. VK Calls TURN is the primary transport. The abstraction exists to make additional transports possible without changing the packet engine, tunnel cryptography, Android VPN lifecycle, or server gateway.

## 1. Architectural rule

The transport layer carries **opaque, already-authenticated GHONCHA tunnel records** between the client and the GHONCHA gateway. It does not parse inner IPv4/IPv6 packets, decide routes, own VPN keys, or implement gateway policy.

The logical client path is:

```text
Android VpnService / TUN
  -> Rust IP packet engine
  -> WireGuard tunnel (inner VPN authentication and AEAD)
  -> Transport API (opaque WireGuard datagrams)
       -> VK Calls adapter (primary)
            -> VK credential provider (setup/refresh only)
            -> Transport API (opaque WireGuard datagrams)
       -> VK Calls TURN adapter (primary)
            -> VK credential provider (setup/refresh only)
            -> DTLS-SRTP handshake and gateway identity validation
            -> RTP packetization + SRTP protection
            -> TURN client / ChannelData
            -> VK TURN relay
       -> Direct UDP adapter (future)
       -> Generic TURN adapter (future)
       -> MASQUE adapter (future)
       -> other approved adapters
  -> GHONCHA gateway UDP peer socket
  -> SRTP authentication/deprotection + RTP payload extraction (VK path)
  -> WireGuard peer authentication/decapsulation
  -> IP forwarding and NAT
```

For the VK adapter, the transport API accepts complete WireGuard datagrams and the adapter internally packetizes each record into RTP, protects it with SRTP using keys exported by a DTLS-SRTP handshake, then sends it through TURN. The gateway performs the inverse operation before passing the datagram to WireGuard. This is distinct from sending DTLS record-layer application data: after negotiating DTLS-SRTP, use SRTP for RTP/RTCP data as specified by RFC 5764. Authenticate the configured DTLS gateway identity independently from TURN credentials and WireGuard peer identity. Other adapters may carry WireGuard datagrams directly when their threat model and network path permit it.

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

The core must process I/O in bounded batches and keep packet movement inside Rust; no per-record FFI calls. The trait now exposes caller-owned batch send/receive buffers and explicit partial-acceptance/backpressure results. Its default batch methods preserve correctness by iterating single-record methods; adapters should override them when they can batch queue operations, packetization, or syscalls without changing record ordering or error semantics.

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
- Client-to-gateway carrier: DTLS-SRTP handshake with authenticated gateway identity, followed by RTP packets carrying complete WireGuard datagrams and SRTP protection. Do not send DTLS application-data records on an association that negotiated `use_srtp`.
- Default mode: TURN over UDP where reachable.
- Fallbacks: only modes actually returned/supported by the provider and verified against the peer, such as TURN over TCP/TLS.
- The VK relay is a relay, not the GHONCHA gateway.
- VK account/call signalling, TURN allocation, DTLS-SRTP handshake, SRTP context/replay state, GHONCHA peer authentication, and VPN tunnel state remain separate state machines.

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
- `crates/transport-vk-turn`: VK credential provider integration, TURN, DTLS-SRTP, and SRTP/RTP adapter.
- `crates/client-core`: network state machine, transport selection and TUN data path.
- `crates/gateway`: server-side tunnel termination and IP forwarding.

Do not add all crates at once. Add and test one crate at a time. Do not pin TURN/DTLS dependencies until their Android NDK build, licence, maintenance, security posture and interoperability have been checked.

## 8. Candidate library assessment (2026-11-06)

### TURN

`turn-client-proto 0.7.3` from `ystreet/turn-proto` is the leading candidate for an interoperability spike:
- The published 0.7.3 workspace declares Rust 1.80.0 MSRV and the crate manifest declares MIT OR Apache-2.0. The library is `no_std`/Sans-I/O and implements RFC 8656 with IPv4/IPv6 and UDP/TCP client state.
- `TurnClientUdp::allocate(local_addr, remote_addr, config)` creates protocol state only; the application owns the socket. This fits Android's requirement to bind the socket to the selected `Network` and call `VpnService.protect()` before sending.
- For the VK proxy topology, start with the UDP TURN client: TURN/UDP is the outer hop to the VK relay. The client-to-gateway DTLS-SRTP association is carried through TURN; this is not DTLS between the client and the VK TURN server.
- The crate also documents separate TLS-over-TCP and DTLS-over-UDP client extension crates. Those secure the client-to-TURN-server hop and are not interchangeable with the end-to-end DTLS-SRTP association used by the reference projects.
- The generic `recv(Transmit<T>) -> TurnRecvRet<T>` path can retain caller-owned receive-buffer storage and returns peer data as a borrowed range where possible. Avoid the convenience `poll_recv()` path in the hot loop because it returns `Vec<u8>`.
- `send_to()` returns a `TransmitBuild`; `write_into()` serializes ChannelData or Send Indications into caller-owned output storage. Prefer it over `build()`, which allocates a new `Vec<u8>`. `poll_transmit()` provides control messages for the socket driver.
- `TurnClientApi` is not dyn-compatible because it has return-position `impl Iterator` methods. Use static dispatch with `TurnClientUdp` or the crate's `impl_client!` macro-generated enum; do not force it behind `dyn TurnClientApi`.
- `TurnConfig::new()` defaults to IPv4 only and SHA-1 integrity. GHONCHA must explicitly configure IPv6 and a deliberate integrity preference (SHA-256 first where supported, SHA-1 fallback only when required by the server); do not mistake the defaults for complete IPv4/IPv6 coverage.
- The UDP constructor panics if the configured allocation transport is not UDP. Validate the URI/transport before construction and keep this invariant inside the VK adapter.
- Some packet-data types require `Debug`; never enable payload-bearing debug logs or format transport objects containing user traffic.
- **Implemented baseline:** `crates/transport-turn` wraps `TurnClientUdp` as a `no_std`, caller-driven protocol engine. It owns no socket or runtime; the caller supplies the already-bound socket addresses, drives timers and I/O, and protects/binds the socket on Android. Control datagrams are returned directly, peer sends serialize into caller-owned output buffers, and receive parsing borrows the input buffer. The wrapper explicitly enables IPv4+IPv6 and prefers SHA-256 integrity with SHA-1 fallback.
- The generic TURN engine is a lower layer; it does not yet implement `RecordTransport`, obtain VK credentials, perform DTLS-SRTP, or connect a VPN gateway. Linux CI format/lint/tests pass; Android NDK compilation and live VK relay interoperability remain unverified.
- **Credential hardening blocker:** upstream `TurnCredentials` in `turn-types 0.7.3` stores username/password in ordinary `String` fields and derives `Debug` and `Clone`; it does not zeroize them. The GHONCHA wrapper deliberately does not implement `Debug` and must never log upstream client/config values, but secure erasure still requires an upstream fix or a reviewed maintained patch before production.
- **Receive-buffer limitation:** the upstream `TurnPeerData` API exposes peer payload as an immutable slice and has no mutable-range accessor. The TURN parser can avoid an allocation, but the SRTP layer will initially need one copy into a bounded reusable buffer before in-place unprotection. Evaluate an upstream mutable-buffer API; do not use the allocating `poll_recv()` convenience path.
- Verify nonce/authentication behavior with real VK relay credentials, IPv4/IPv6 allocations, channel-binding expiry, network handover, Android cross-compilation, dependency graph and packet-level interoperability before production selection.

The CSQTT TURN engine remains an important comparison implementation. Compare wire behavior and tests rather than assuming a newer crate is automatically more correct.

### DTLS-SRTP

`dimpl 0.9.0` is a Sans-I/O DTLS 1.2/1.3 candidate with explicit version constructors and DTLS-SRTP key export. It is a candidate for the **client-to-GHONCHA-gateway DTLS-SRTP handshake**, not a TURN client and not the TURN-to-relay security wrapper.
- prove DTLS 1.2 interoperability with the reference CSQTT/WDTT client and server wire behavior;
- verify mutual certificate or PSK peer authentication and reject insecure verification shortcuts;
- the library exposes the peer certificate but explicitly leaves PKI/fingerprint/name validation to the application; GHONCHA must validate the certificate fingerprint against authenticated provisioning before accepting exported SRTP keying material or sending tunnel data;
- **security blocker:** in v0.9.0, `Output::KeyingMaterial` wraps a heap `Vec<u8>` and `KeyingMaterial` does not implement zeroization. The exporter copies the material into that Vec. Do not treat dropping the value as secure erasure; require an upstream fix or a reviewed maintained patch before production use;
- **performance/configuration blocker:** the built-in DTLS-SRTP profile preference is fixed as AEAD-AES-256-GCM, AEAD-AES-128-GCM, then AES128-CM-SHA1-80. The public configuration does not expose an allow-list/preference setter. Measure AES-256 versus AES-128 on target ARM devices and require configurable profile policy if AES-128 is the chosen performance baseline;
- the default feature set enables `aws-lc-rs` and `rcgen`; enabling `rcgen` also enables AWS-LC. Compare `rust-crypto` and AWS-LC-RS Android builds, binary size, CPU, and battery rather than accepting defaults;
- defaults include bounded DTLS queues, a 40-second handshake timeout, and retransmission backoff; tune and test them for mobile network handovers and credential expiry;
- every fatal error from the public DTLS processing API requires discarding the DTLS instance and starting a new handshake; transient malformed/replayed datagrams are handled internally by the library;
- the release documents no session resumption or renegotiation, so measure full-handshake cost during network handover and call/credential refresh;
- test retransmission, fragmentation, profile negotiation, key lifecycle, certificate pinning and malformed records;
- verify Android NDK targets and crypto dependency portability;
- its 0.9.0 manifest declares edition 2024, MSRV 1.89.0, and MIT OR Apache-2.0;
- the default feature set enables aws-lc-rs and rcgen; a separate rust-crypto feature exists. Compare Android ABI build size, compile time, CPU performance, and cryptographic-provider portability before selecting a provider;
- review the project's security history and license.

### SRTP

`rtc-srtp 0.21.1` is a Sans-I/O SRTP/SRTCP candidate. Its documented context provides RTP/RTCP protection, replay protection, and rollover-counter tracking. It documents AEAD-AES-128-GCM and AES-128-CM-SHA1-80 profiles; GHONCHA should prioritize an AEAD profile and must verify that its negotiated profile and keying material match the selected DTLS implementation. The crate is not selected for production until interoperability, Android ABI builds, licensing, and performance are verified.

Do not assume that an RTP header with an Opus or VP8 payload type is a valid Opus/VP8 media packet when its payload actually contains opaque VPN data. Define a private, explicitly configured RTP payload format for GHONCHA. Any media-shaped camouflage experiment must be isolated, accurately described, and tested separately from protocol conformance.

### SRTP implementation trade-offs

Two implementations remain under evaluation; neither is approved for production.

- `rtc-srtp 0.21.1` is a maintained Sans-I/O Rust implementation. It supports AEAD-AES-128-GCM and provider selection through `rtc-crypto` (Ring or AWS-LC-RS). It maintains replay/rollover state and uses separate one-way contexts for send and receive. Source inspection shows `encrypt_rtp_with_header` currently creates and returns a new `BytesMut` per packet; this is a measurable allocation risk for GHONCHA's hot path. Keep it as the portable Rust baseline and benchmark it on Android.
- `srtp 0.7.0` wraps the mature C `libsrtp2` library and supports in-place packet protection through `VecLike`, including a caller-owned `Cursor<&mut [u8]>`. This may better satisfy the no-allocation packet-path goal. Its default policy is AES-CM-128/HMAC-SHA1-80. AES-GCM policy constructors are compiled only when the OpenSSL feature is enabled; the build then includes native libsrtp2, bindgen, a C toolchain, and potentially OpenSSL. `srtp2-sys 3.0.2` is BSD-3-Clause; the safe wrapper is MIT OR Apache-2.0. Android NDK cross-compilation and binary size are unresolved.
- The C implementation is not automatically faster or more energy-efficient on Android. Compare both implementations with identical RTP/SRTP vectors, profile, MTU, and traffic patterns. Measure allocations per packet, throughput, p50/p95 latency, CPU time, thermal behavior, and battery draw.
- The initial security target is AEAD-AES-128-GCM (SRTP profile 0x0007). If the native libsrtp2 build cannot enable GCM cleanly for Android, compare the pure-Rust AEAD implementation against the native AES-CM/HMAC-SHA1-80 path; do not downgrade silently. Any profile change must be explicit and authenticated.

The chosen library must expose reliable replay protection, rollover-counter handling, key-lifetime limits, explicit failure semantics, and a way to reuse packet buffers. If no candidate meets the requirements, evaluate a narrowly scoped upstream contribution or another maintained implementation rather than writing a custom SRTP cryptographic engine.

### Standards

TURN behavior follows RFC 8656 and STUN behavior follows RFC 8489. DTLS-SRTP follows RFC 5764; SRTP AES-GCM follows RFC 7714. TURN-over-TCP/TLS framing, UDP retransmission, allocation lifetime, permissions, ChannelBind, nonce challenges, IPv6 and MTU handling require dedicated conformance tests.

## 9. Decision gates

Before the first production adapter:
1. Define the exact record-layer choice and authenticated peer identity.
2. Build a client/server interoperability harness independent of Android and VK.
3. Compare `turn-client-proto` with the reference TURN engine on identical test vectors and TURN servers.
4. Verify `dimpl` DTLS-SRTP negotiation and both candidate SRTP protectors against an independent implementation; no insecure certificate bypass.
5. Cross-compile the selected dependencies for Android ABIs using the current supported NDK.
6. Fuzz STUN/TURN parsing, DTLS-SRTP handshake, RTP/SRTP framing, and transport record boundaries.
7. Verify licensing and transitive dependencies.
8. Benchmark UDP first, then TCP/TLS fallback and controlled worker-count changes.
9. Integrate TUN only after the standalone client/server path is authenticated, stable and measured.

A transport is not production-ready merely because it connects once. It must survive credential expiry, call termination, network handover, packet loss, server restart, Doze, and malformed peer input.
