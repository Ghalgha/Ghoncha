# GHONCHA VK Calls TURN transport

Status: architecture baseline for an experimental, user-authorized transport. The primary carrier is VK Calls TURN relay, not a generic VK Calls DataChannel.

## 1. Correct transport model

VK Calls is used as a source of TURN relay service and short-lived TURN credentials. Ghoncha does not tunnel IP packets through the public VK Calls JavaScript SDK DataChannel API.

The selected Ghoncha carrier is:

```text
Android TUN
  -> Ghoncha Rust packet engine
  -> WireGuard tunnel datagram (inner VPN authentication and AEAD)
  -> RTP packet carrying one opaque Ghoncha record
  -> SRTP protection using keys exported by DTLS-SRTP
  -> TURN client (Allocate / Permission / ChannelBind / Refresh)
  -> VK Calls TURN relay
  -> Ghoncha Gateway UDP peer socket
  -> SRTP authentication/deprotection and RTP payload extraction
  -> WireGuard peer authentication/decapsulation
  -> VPN gateway / IP forwarding
```

DTLS performs authenticated key agreement and peer authentication; SRTP protects RTP data packets after the handshake. TURN relays the resulting UDP datagrams to the configured Ghoncha Gateway peer. The relay is not the VPN gateway and must not possess SRTP or WireGuard keys. WireGuard remains the inner VPN protocol and authoritative identity for user IP traffic. The Gateway validates/decrypts the SRTP packet, extracts the complete WireGuard datagram, then passes it to the WireGuard endpoint.

Keep a plain DTLS application-data carrier as a separate experimental profile only; do not mix DTLS application data with a negotiated DTLS-SRTP association. RFC 5764 specifies that after `use_srtp` negotiation, RTP/RTCP data is protected by SRTP and application data is not sent in DTLS application-data records.

### Initial GHONCHA RTP payload profile

The first implementation uses a strict private RTPv2 profile, not an audio/video codec:
- dynamic payload type 127, negotiated by GHONCHA configuration;
- marker bit always zero;
- no CSRC entries, header extensions, or RTP padding;
- exactly one complete WireGuard datagram per RTP payload; no fragmentation or multi-record aggregation;
- one stable random SSRC per direction and a cryptographically random initial sequence number; SRTP owns rollover and replay state;
- timestamp is a monotonic 90 kHz session clock and is not used as a packet sequence number.

The profile has a fixed 12-byte RTP header and a zero-copy parser in `ghoncha-transport-api`. It rejects any unsupported RTP header feature instead of guessing. Payload type 127 is a private dynamic assignment, not a claim that the payload is Opus/VP8. If interoperability testing requires another payload type, change it through explicit authenticated configuration and keep the payload-format semantics documented.

A separate TURN-over-TCP/TLS mode carries STUN/TURN framing over a stream. It requires explicit stream framing and bounded queues; TCP head-of-line blocking and retransmission behavior differ from UDP.

## 2. VK Calls credential and call lifecycle

Ghoncha supports two user-authorized bootstrap paths:

1. **User-provided call link/hash:** the user supplies a link/hash for a call they are authorized to use. The client derives or fetches temporary call/TURN access material using the implementation's VK Calls integration.
2. **User-authorized call creation:** where the provider exposes a supported call-management flow, Ghoncha may create and later end its own calls. This requires an explicit user login/consent flow and must be kept separate from the data plane.

Depending on the currently supported provider flow, integration may involve:
- versioned VK API host/method request formats;
- Calls-specific anonymous bootstrap and preview/token methods;
- call/session creation or joining and retrieval of `turn_server.username`, `turn_server.credential`, and `turn_server.urls`;
- a user-provided call hash/link or an authorized account session.

Method names such as `auth.getAnonymToken`, `messages.getCallPreview`, `messages.getAnonymCallToken`, `auth.anonymLogin`, and `vchat.joinConversationByLink` are provider-integration details, not a promise that every method is part of the stable public VK API. The public VK API's documented `calls.start` / `calls.forceFinish` management methods are a different layer from Calls-specific TURN credential bootstrap.

**Documentation boundary:** official VK API documentation is authoritative only for methods it actually documents. Calls-specific endpoints, request signatures, browser/TLS fingerprints, undocumented payloads, and returned TURN fields must be treated as unstable and independently verified. Do not represent private Calls backend methods as a supported public API. Do not hardcode one API version, host, IP range, or client fingerprint as permanent.

If VK requires an interactive security challenge or account verification, pause and ask the user to complete the supported flow. Do not automate or bypass account security, CAPTCHA, rate limits, or anti-abuse controls.

## 3. VK API documentation map

Use these sources in this order when maintaining the credential provider:

- **Official VK API reference:** https://dev.vk.com/ru/reference — method contracts, authorization, access scopes, API versioning, errors, and rate limits.
- **Calls management methods:** https://dev.vk.com/method/calls.start and https://dev.vk.com/method/calls.forceFinish — verify current availability, parameters, permissions, and response schemas directly against the live official reference before implementation.
- **VK Android SDK:** https://github.com/VKCOM/vk-android-sdk — supported Android authorization and API client patterns; prefer the supported SDK for documented account API operations where practical.
- **VK Calls JavaScript SDK:** https://st.mycdn.me/static/callssdk/latest/doc/index.html — call/media integration SDK. It is not the TURN credential provider and does not define the TURN protocol used by the reference VPN projects.

Maintain a small provider compatibility record containing the date checked, API version, method, authorization type, required scopes, documented/undocumented status, response schema version, and last successful integration test. Do not infer that a Calls-specific backend endpoint is public just because it appears under a VK-owned domain or is called by a first-party client.

## 4. TURN protocol lifecycle

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

The GHONCHA server is the TURN peer: the VK relay forwards peer datagrams to a UDP socket on the configured GHONCHA gateway address. The gateway does not need a second TURN allocation for this topology. That socket feeds the DTLS-SRTP endpoint during handshake and the SRTP/RTP decoder after handshake. The gateway authenticates the DTLS peer, validates SRTP authentication/replay state, extracts the opaque WireGuard datagram, and passes it to the WireGuard endpoint. It must not expose a generic unauthenticated UDP forwarder to the public internet.

TURN allocation, TURN permission, channel binding, DTLS session, GHONCHA peer authentication, and VPN data-plane health are separate states. A successful Allocate does not mean the VPN tunnel is connected.

### Provider-specific TURN compatibility notes

- Use standard TURN attributes by default. Add a provider-specific extension only when live packet captures and repeatable interoperability tests demonstrate that it is required; keep it isolated behind an explicit compatibility option.
- The current GHONCHA TURN adapter uses standard TURN attributes and does not yet inject that custom attribute. It also relies on TURN allocation/permission/channel refresh; the upstream client has no explicit periodic ChannelData keepalive API. The upper DTLS layer must own an authenticated, adaptive heartbeat rather than sending arbitrary dummy payloads.
- Do not hardcode a keepalive interval from an unrelated deployment. Derive refresh and heartbeat deadlines from protocol lifetimes, observed NAT behavior, provider constraints, and measured mobile-radio energy.

## 5. DTLS-SRTP, SRTP, and inner VPN security

The outer carrier must use a standards-compliant DTLS-SRTP handshake and SRTP packet protection. Do not substitute a proprietary packet wrapper for SRTP or assume that negotiating `use_srtp` alone proves that subsequent packets conform to RFC 3711.
GHONCHA requirements:
- use standard WireGuard for inner VPN peer authentication, key establishment, replay protection, and IP-packet encryption; do not invent a GHONCHA-specific AEAD or key schedule;
- use a maintained DTLS implementation for the DTLS-SRTP handshake and a maintained SRTP implementation for packet protection; do not implement either protocol or cryptographic primitives from scratch;
- authenticate the DTLS gateway independently through a provisioned certificate/public-key fingerprint or another explicitly reviewed identity mechanism; TURN credentials and VK call links are not gateway identity;
- validate the peer certificate/fingerprint before accepting exported SRTP keying material or sending tunnel data;
- prefer an AEAD SRTP profile such as `SRTP_AEAD_AES_128_GCM` (profile 0x0007) when both peers support it; compare profile support and performance before selection. Do not silently fall back to unauthenticated or weak profiles;
- enforce RTP/SRTP packet-size limits, per-SSRC sequence/rollover handling, replay windows, key lifetime limits, handshake deadlines, and bounded retransmission;
- fail closed on peer identity mismatch, SRTP authentication failure, malformed RTP headers, replay, or key expiry;
- fuzz the DTLS handshake, RTP parser, SRTP context, and TURN framing boundaries.

Candidate Rust components as of 2026-11-06:
- `dimpl 0.9.0`: Sans-I/O DTLS 1.2/1.3 candidate with DTLS-SRTP key export. Its documentation states that the application must validate the peer certificate; the crate does not perform PKI/fingerprint validation itself.
- `rtc-srtp 0.21.1`: Sans-I/O SRTP/SRTCP candidate with RTP/RTCP protection, replay protection, and rollover-counter tracking. It supports AEAD-AES-128-GCM. Source inspection shows its current `encrypt_rtp_with_header` path creates a new `BytesMut` per packet, so allocation rate is a performance risk that must be measured.
- `srtp 0.7.0`: MIT/Apache Rust wrapper around `libsrtp2`; its `VecLike` interface can protect/unprotect in caller-owned buffers, including fixed-size `Cursor<&mut [u8]>`. This may better fit GHONCHA's bounded data plane. AES-GCM policy constructors require the OpenSSL feature; the native build uses `srtp2-sys 3.0.2` (BSD-3-Clause), bindgen and a C toolchain. Android NDK cross-compilation and binary size remain unresolved.
- These are interoperability-spike candidates, not approved production dependencies. Verify the exact `dimpl` `use_srtp` negotiation and key exporter with each SRTP implementation, then test against an independent implementation and the GHONCHA gateway. Benchmark allocation count, CPU, throughput, RTT and battery on real Android devices before selecting one.

A plain DTLS application-data tunnel is a separate possible carrier profile. If selected, it must use a normal DTLS association without negotiating `use_srtp`; never send application-data records after establishing a DTLS-SRTP association. Ghoncha must validate Gateway identity and fail closed rather than silently downgrade to a weaker or unauthenticated carrier.

## 6. Transport modes and performance

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

## 7. Rust and Android architecture

Recommended GHONCHA ownership:
- Kotlin Android layer: `VpnService`, user consent/auth UI, call-link/account input, interactive security challenges, `ConnectivityManager`, socket protection/binding, TUN FD creation/ownership.
- Rust client core: VK credential-provider abstraction, TURN protocol engine, DTLS-SRTP handshake, SRTP/RTP packet protection, WireGuard tunnel endpoint, bounded packet pools/queues, worker policy, reconnect state machine, statistics.
- Rust server: public UDP TURN-peer socket, DTLS-SRTP handshake endpoint, SRTP/RTP packet protection, WireGuard gateway endpoint, IP forwarding, rate/resource limits, observability.
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

## 9. Decision gates

Before production integration:
1. Validate the current VK Calls credential bootstrap with a test account and user-authorized call. Record only non-secret request/response schemas and failure categories.
2. Separate documented public VK API methods from undocumented Calls backend methods in the provider implementation and documentation.
3. Implement a standalone TURN + DTLS-SRTP + SRTP interoperability test between GHONCHA client and server, without TUN. Keep a separate DTLS application-data experiment only if a concrete deployment requirement justifies it.
4. Validate peer authentication and replay protection independently of TURN credentials.
5. Run TURN conformance tests for UDP, TCP, and TLS, including allocation refresh, permission, channel binding, nonce rotation, and cleanup.
6. Complete security review, fuzzing, Android lifecycle tests, and real-device performance/battery benchmarks.
7. Only then connect the adapter to the TUN packet engine.

No VK account credential, TURN endpoint, undocumented request signature, or production dependency is embedded by this document.
