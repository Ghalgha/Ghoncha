# VK TURN interoperability and security requirements

Status: internal Ghoncha engineering document. This document defines protocol requirements, validation gates, and implementation constraints. It does not compare products or prescribe reuse of external application code.

## 1. Transport model

Ghoncha obtains short-lived TURN access through a user-authorized VK Calls session. The client establishes a TURN allocation and relays authenticated datagrams to the configured Ghoncha Gateway peer. TURN is a relay service, not the VPN endpoint.

The intended data path is:

```text
Android TUN
  -> Ghoncha packet engine
  -> authenticated inner VPN datagram
  -> configured outer carrier protection
  -> TURN client
  -> VK Calls TURN relay
  -> Ghoncha Gateway peer socket
  -> outer carrier authentication/deprotection
  -> inner VPN endpoint
  -> IP forwarding
```

The exact outer media/security profile must be verified against the live VK Calls transport. Do not infer DTLS-SRTP, plain DTLS application data, ICE, or WebRTC DataChannel semantics solely from the availability of TURN credentials.

## 2. TURN lifecycle requirements

- Resolve and validate the returned TURN URI list and transport parameters.
- Establish the outer UDP, TCP, or TLS socket on the selected Android Network.
- Call `VpnService.protect()` before the first send and bind the socket to the selected Android Network where required.
- Perform STUN/TURN Allocate with the issued username, credential, and server-provided realm/nonce challenge.
- Retain allocation lifetime and refresh before expiry.
- Create and refresh peer Permission for the Ghoncha Gateway address.
- Use ChannelBind/ChannelData where supported, otherwise use Send/Data indications as appropriate.
- Handle 401/438 authentication challenge, nonce rotation, transaction timeout, server errors, allocation expiry, and deallocation.
- Implement bounded retransmission, keepalive, cancellation, and cleanup.
- Never reuse credentials or allocations across a different call/session unless the provider explicitly permits it.

A successful Allocate does not mean the VPN tunnel is connected. TURN allocation, permission, channel binding, outer cryptographic session, inner peer authentication, and useful VPN data flow are separate states.

## 3. Outer security and packet framing

- Use a maintained DTLS implementation for DTLS-SRTP and a maintained SRTP implementation for RTP packet protection. Do not implement protocol cryptography from scratch.
- Authenticate the DTLS Gateway independently through a provisioned certificate/public-key fingerprint or another explicitly reviewed identity mechanism. TURN credentials and VK call links are not Gateway identity.
- Validate peer identity before accepting exported SRTP keying material or sending tunnel data.
- Prefer an AEAD SRTP profile such as `SRTP_AEAD_AES_128_GCM` (profile 0x0007) when both peers support it; negotiate the profile explicitly.
- Enforce RTP/SRTP packet-size limits, per-SSRC sequence/rollover handling, replay windows, key lifetime limits, handshake deadlines, and bounded retransmission.
- Fail closed on peer identity mismatch, SRTP authentication failure, malformed RTP headers, replay, or key expiry.
- Fuzz the DTLS handshake, RTP parser, SRTP context, and TURN framing boundaries.
- Exactly one complete inner tunnel datagram is carried per RTP payload in the initial profile. Do not fragment or aggregate records without a separately specified and tested format.
- A plain DTLS application-data tunnel is a separate carrier profile and must not negotiate `use_srtp`. Never send application-data records after establishing a DTLS-SRTP association.

## 4. Provider compatibility

- Standard TURN attributes are the default.
- Do not add non-standard STUN attributes, proprietary keepalive payloads, or undocumented control messages unless live packet captures and repeatable interoperability tests prove they are required by the provider.
- Keep any provider-specific extension behind an explicit compatibility option and isolate it from the portable TURN core.
- Do not hardcode allocation, permission, channel, or heartbeat intervals from unrelated deployments. Follow RFC 8656 lifetimes and derive additional heartbeat deadlines from observed NAT behavior and measured radio energy.
- Record only non-secret request/response schemas, expiry metadata, and failure categories. Never log raw credentials, call secrets, cookies, keys, session salts, or user payload.

## 5. Credential and call lifecycle

Supported bootstrap inputs:
1. A user-provided call link/hash for a call the user is authorized to use.
2. A user-authorized account session, if the provider exposes a supported call creation and termination flow.

The provider adapter must isolate VK-specific authorization, call signalling, short-lived TURN credentials, and refresh behavior from the packet data plane. Treat undocumented provider endpoints and response fields as unstable. Do not automate or bypass interactive security challenges, account verification, CAPTCHA, rate limits, or anti-abuse controls.

Credential-provider output is limited to short-lived username/credential, realm/nonce when supplied, URI list, expiry/refresh metadata, and redacted diagnostics. Invalidate credentials on logout, call termination, permission revocation, or session replacement.

## 6. Implementation boundaries

- Kotlin owns Android VPN consent, VpnService lifecycle, ConnectivityManager callbacks, socket protection/binding, and TUN descriptor creation/ownership.
- Rust owns packet processing, TURN protocol state, outer cryptographic processing, inner VPN endpoint, bounded queues, worker policy, reconnect state machine, and statistics.
- FFI carries lifecycle/configuration/events/errors/counters and owned descriptor handoff only. Do not cross FFI for each packet.
- The Gateway authenticates the client and applies IP forwarding policy. It must not expose an unauthenticated public UDP forwarder.
- Keep control-plane work separate from packet processing. Bound parsing, queueing, retries, allocation, handshake, and cleanup work.

## 7. Transport and performance validation

Measure on the same device, Gateway, network, payload mix, and call configuration:
- credential acquisition success and latency;
- allocation and end-to-end tunnel establishment success;
- per-allocation and aggregate goodput;
- median/p95/p99 RTT, jitter, loss, reordering, and recovery;
- CPU, allocations, memory, wakeups, radio-active time, temperature, and battery drain;
- UDP vs TCP vs TLS behavior and worker-count scaling;
- behavior under call termination, credential expiry, nonce changes, Wi-Fi/cellular handover, Doze, and background restrictions.

Do not assume more workers increase throughput. Begin with one path and benchmark controlled increments. More parallelism can increase handshake cost, CPU, radio activity, relay load, congestion, and service limits.

## 8. Decision gates

Before production integration:
1. Validate the current VK Calls credential bootstrap with a test account and user-authorized call.
2. Confirm the actual outer wire profile using controlled packet captures and the live provider.
3. Complete client/Gateway interoperability for TURN, outer authentication, inner peer authentication, and bidirectional data.
4. Run TURN conformance tests for UDP, TCP, and TLS, including allocation refresh, permission, channel binding, nonce rotation, and cleanup.
5. Complete security review, fuzzing, Android lifecycle tests, and real-device performance/battery benchmarks.
6. Verify IPv4/IPv6, NAT rebinding, Wi-Fi/cellular handover, sleep/wake, credential expiry, and allocation expiry.
7. Connect the adapter to the TUN packet engine only after the standalone path is authenticated, stable, and measured.

A transport is not production-ready merely because it connects once. It must survive credential expiry, call termination, network handover, packet loss, server restart, Doze, and malformed peer input.
