# GHONCHA VK Calls TURN transport

Status: architecture baseline for an experimental, user-authorized transport. This document supersedes the earlier WebRTC DataChannel framing. The primary mechanism studied in the supplied reference projects is VK Calls TURN relay, not a generic VK Calls DataChannel.

## 1. Correct transport model

The reference implementations use VK Calls as a source of TURN relay service and short-lived TURN credentials. They do not generally tunnel IP packets through the public VK Calls JavaScript SDK's DataChannel API.

The conceptual path is:

```text
Android TUN
  -> GHONCHA Rust packet engine
  -> per-session GHONCHA authenticated encryption
  -> DTLS-protected datagrams
  -> TURN client (Allocate / Permission / ChannelBind / Refresh)
  -> VK Calls TURN relay
  -> GHONCHA server TURN client / relay listener
  -> DTLS termination and GHONCHA authentication
  -> VPN gateway / IP forwarding
```

The TURN relay forwards packets between the client's allocation and the configured GHONCHA server peer. The relay is not the VPN gateway and must not possess GHONCHA traffic keys. The VPN gateway is the only endpoint that decapsulates user IP traffic and routes/NATs it.

A separate TURN-over-TCP/TLS mode carries STUN/TURN framing over a stream. It requires explicit stream framing and bounded queues; TCP head-of-line blocking and retransmission behavior differ from UDP.

## 2. VK Calls credential and call lifecycle

The supplied projects demonstrate two broad bootstrap paths:

1. **User-provided call link/hash:** the user supplies a link/hash for a call they are authorized to use. The client derives or fetches temporary call/TURN access material using the implementation's VK Calls integration.
2. **User-authorized call creation:** some newer CSQTT branches use VK account authorization and call-management methods to create and later end their own calls. This requires an explicit user login/consent flow and must be kept separate from the data plane.

Observed code in the supplied repositories uses a mixture of:
- VK API host/methods and versioned request formats;
- Calls-specific anonymous bootstrap and preview/token methods;
- the Calls/OK CDN backend to create/join the call and retrieve `turn_server.username`, `turn_server.credential`, and `turn_server.urls`;
- call hashes/links and, in some variants, account access tokens.

Examples of observed method names in source include `auth.getAnonymToken`, `messages.getCallPreview`, `messages.getAnonymCallToken`, `auth.anonymLogin`, and `vchat.joinConversationByLink`. These are source-observed integration details, not a promise that every method is part of the stable public VK API. The public VK API's documented `calls.start` / `calls.forceFinish` management methods are a different layer from the Calls-specific TURN credential bootstrap.

**Documentation boundary:** official VK API documentation is authoritative only for methods it actually documents. Calls-specific endpoints, request signatures, browser/TLS fingerprints, undocumented payloads, and returned TURN fields must be treated as unstable and independently verified. Do not represent private Calls backend methods as a supported public API. Do not hardcode one API version, host, IP range, or client fingerprint as permanent.

If VK requires an interactive security challenge or account verification, pause and ask the user to complete the supported flow. Do not automate or bypass account security, CAPTCHA, rate limits, or anti-abuse controls.

## 3. TURN protocol lifecycle

The client-side TURN adapter must implement and test the actual TURN lifecycle, not just forward arbitrary UDP to a relay address:

- resolve and validate the returned TURN URI list and transport parameters;
- establish the outer UDP, TCP, or TLS socket on the selected Android Network;
- protect the socket with `VpnService.protect()` before the first send and bind it to the selected Android Network where required;
- perform STUN/TURN Allocate with the issued username, credential, and server-provided realm/nonce challenge;
- retain allocation lifetime and refresh before expiry;
- create/refresh peer Permission for the GHONCHA server address;
- ChannelBind and ChannelData where supported, otherwise use Send/Data indications as appropriate;
- handle 401/438 authentication challenge, nonce rotation, transaction timeout, server errors, allocation expiry, and deallocation;
- implement bounded retransmission, keepalive, cancellation, and cleanup;
- never reuse credentials or allocations across a different call/session unless the provider explicitly permits it.

The server side receives the DTLS transport from the configured peer and forwards authenticated tunnel datagrams to a loopback or otherwise tightly scoped VPN backend. It must not expose a generic unauthenticated UDP forwarder to the public internet.

TURN allocation, TURN permission, channel binding, DTLS session, GHONCHA peer authentication, and VPN data-plane health are separate states. A successful Allocate does not mean the VPN tunnel is connected.

## 4. DTLS and end-to-end security

The reference projects use DTLS 1.2 between client and server, with TURN carrying the DTLS records. This is distinct from the DTLS/SRTP association between ordinary WebRTC media endpoints.

GHONCHA requirements:
- use a maintained DTLS implementation and standard cipher suites; do not implement DTLS or cryptographic primitives from scratch;
- authenticate the GHONCHA server independently, e.g. by a pinned public key/fingerprint or an authenticated handshake bound to the provisioned peer identity;
- never set certificate verification to insecure/skip-verify in production;
- use a distinct GHONCHA session key schedule and replay protection; TURN credentials are not tunnel encryption keys;
- enforce packet and handshake size limits, retransmission/deadline bounds, replay windows, and key rotation;
- fail closed on peer identity mismatch, malformed records, authentication failure, or replay;
- fuzz the DTLS integration and all framing/decoding boundaries.

One reviewed Rust reference configuration sets `insecure_skip_verify = true` for a self-signed certificate. That is a research implementation detail and is **not** an acceptable production security policy for GHONCHA.

## 5. Transport modes and performance

Treat these as separate configured modes:
- TURN over UDP (preferred baseline when reachable);
- TURN over TCP;
- TURN over TLS;
- optional multiple independent TURN allocations/workers, only when measurements justify the extra overhead and provider limits permit it.

Do not assume more workers increase throughput. They can improve aggregate bandwidth on some paths, but can also increase handshake cost, CPU, radio activity, relay load, congestion, and account/call risk. Begin with one path and benchmark controlled increments.

Measure on the same device, gateway, network, payload mix, and call configuration:
- connection and credential acquisition success/time;
- per-allocation and aggregate goodput;
- median/p95/p99 RTT, jitter, loss, reordering, retransmits, and recovery;
- DTLS CPU, TURN maintenance CPU, allocations, memory, wakeups, radio-active time, temperature, and battery drain;
- UDP vs TCP vs TLS and worker-count scaling;
- behavior under call termination, credential expiry, nonce changes, Wi-Fi/cellular handover, Doze, and background restrictions.

Do not copy published throughput claims or assume a fixed worker count, TURN IP list, port, or MTU is universally optimal.

## 6. Rust and Android architecture

Recommended GHONCHA ownership:
- Kotlin Android layer: `VpnService`, user consent/auth UI, call-link/account input, interactive security challenges, `ConnectivityManager`, socket protection/binding, TUN FD creation/ownership.
- Rust client core: VK credential-provider abstraction, TURN protocol engine, DTLS session, GHONCHA peer authentication, bounded packet pools/queues, worker policy, reconnect state machine, statistics.
- Rust server: TURN-facing DTLS listener, peer authentication, decapsulation, gateway forwarding, rate/resource limits, observability.
- FFI: control plane only. No packet-per-call JNI/UniFFI/JNA crossings. Keep packet movement and TURN/DTLS processing inside Rust.

Credential provider contract:
- input: explicit user-selected call link/hash or an authorized account session reference;
- output: short-lived TURN username, credential, realm/nonce if supplied, URI list, expiry/refresh metadata, and redacted provider diagnostics;
- cancellation and explicit invalidation on logout, call end, or session change;
- no persistence of raw credentials in logs, crash reports, analytics, or ordinary preferences.

Transport adapter contract:
- `prepare(network_generation, credentials, peer)`
- `allocate(deadline)`
- `create_permission(peer, deadline)`
- `bind_channel(peer, deadline)`
- `send_datagram(packet)` with explicit backpressure
- `receive_datagrams(budget)` with bounded batches
- `refresh(deadline)`
- `poll_events(budget)`
- `close(reason)` idempotently

This is a semantic contract, not a commitment to a particular Rust crate, async runtime, or native FFI design.

## 7. Source projects reviewed

The reference audit is recorded in `docs/vk-turn-reference-audit.md`. The key starting points are:
- `cacggghp/vk-turn-proxy`: original Go TURN/DTLS proxy design and basic client/server split;
- `Urtyom-Alyanov/turn-proxy`: Rust TURN/DTLS implementation, client/server separation, UDP/TCP stream paths;
- `amurcanov/csqtt`: later Rust client/server implementation with explicit TURN/STUN engine, packet pools, bounded queues, stream transport, worker management, Android VPN integration, and VK credential/call lifecycle;
- `MYSOREZ/vk-turn-proxy-android`, `amurcanov/proxy-turn-vk-android`, and `SpaceNeuroX/proxy-turn-vk-android`: Android lifecycle/UI and integration examples.

These repositories are implementation references, not production security audits. Check the exact commit and license before considering any code reuse.

## 8. Decision gates

Before production integration:
1. Validate the current VK Calls credential bootstrap with a test account and user-authorized call. Record only non-secret request/response schemas and failure categories.
2. Separate documented public VK API methods from undocumented Calls backend methods in the provider implementation and documentation.
3. Implement a standalone TURN/DTLS interoperability test between GHONCHA client and server, without TUN.
4. Validate peer authentication and replay protection independently of TURN credentials.
5. Run TURN conformance tests for UDP, TCP, and TLS, including allocation refresh, permission, channel binding, nonce rotation, and cleanup.
6. Complete security review, fuzzing, Android lifecycle tests, and real-device performance/battery benchmarks.
7. Only then connect the adapter to the TUN packet engine.

No VK account credential, TURN endpoint, undocumented request signature, or production dependency is embedded by this document.
