# GHONCHA transport and security architecture

Status: design baseline; implementation choices remain subject to interoperability, security, and performance tests.

## Goals

- Keep the IP data path in native code and avoid per-packet FFI crossings.
- Preserve datagram semantics on the preferred path.
- Keep the VPN payload end-to-end encrypted between the client tunnel endpoint and the VPN gateway.
- Allow a TURN relay to forward traffic without possessing SRTP or WireGuard keys or interpreting inner IP packets.
- Make fallback behavior explicit rather than silently changing transport semantics.
- Keep VK Calls TURN as the primary transport while allowing additional transports through one runtime-neutral record interface.

## Roles

1. **Android client** owns the `VpnService`, TUN descriptor, network callbacks, and Android-specific routing/protection.
2. **Rust client core** owns tunnel state, packet processing, transport selection, TURN client state, and statistics.
3. **VK Calls credential provider** obtains short-lived TURN credentials through a user-authorized call/session. It is a control-plane component, not the packet transport.
4. **TURN relay** implements RFC 8656. It authenticates and allocates relay resources, applies peer permissions, and forwards opaque datagrams. It is not the VPN gateway.
5. **VPN gateway** receives VK-relayed UDP datagrams on its configured peer socket, terminates the DTLS-SRTP association, validates/decrypts SRTP records, extracts the inner WireGuard datagrams, passes them to the WireGuard endpoint, routes inner IPv4/IPv6 packets, and applies forwarding policy/NAT where configured.
6. **Rust server control plane** provisions peers, keys, addresses, routes, quotas, and gateway lifecycle. It must not handle every packet in a high-level request/task abstraction.
7. **Transport adapters** expose one runtime-neutral record interface. VK Calls TURN is the primary adapter; direct UDP, generic TURN, MASQUE, and other adapters can be added without changing the packet engine or VPN UI.

## Tunnel cryptography

Use the standard WireGuard protocol as the inner VPN protocol candidate; do not invent a GHONCHA-specific handshake, KDF, nonce format, replay window, or AEAD construction.

The primary VK path uses two distinct security layers for different purposes:

- **Inner WireGuard:** authoritative VPN peer identity, key establishment, replay protection, and IP-packet confidentiality/integrity.
- **Outer DTLS-SRTP:** authenticated client-to-gateway key agreement and RTP/SRTP packet protection for the VK TURN carrier. It provides the configured RTP/SRTP outer record format for the VK TURN carrier.

After the DTLS-SRTP handshake, a complete WireGuard datagram is carried as the payload of one RTP packet and protected by SRTP. The gateway authenticates/deprotects SRTP, extracts the WireGuard datagram, then passes it to the WireGuard endpoint. Do not send DTLS record-layer `application_data` after negotiating the DTLS-SRTP `use_srtp` extension; RFC 5764 defines RTP/RTCP data to be protected by SRTP after the handshake. A plain DTLS application-data tunnel, if ever needed, is a separate carrier profile and must not negotiate `use_srtp`.

The VK TURN relay sees TURN framing and opaque SRTP packets, not WireGuard keys or inner IP packets. TURN credentials, VK call links, DTLS certificate identity, SRTP traffic keys, and WireGuard peer keys are separate credentials with separate lifecycles.

The exact Rust WireGuard engine is **not selected yet**. Select an implementation only after reviewing its maintenance status, security history, licensing, Android target support, protocol conformance, interoperability, fuzzing results, and measured performance. Do not pin or integrate an implementation until these checks pass.

Initial gateway evaluation should include the mature Linux kernel WireGuard implementation, controlled by the Rust server plane, as a correctness and performance baseline. A Rust userspace gateway may replace it only after equivalent interoperability, security, and throughput evidence.

## Packet path

### Preferred: VK Calls TURN over UDP with DTLS-SRTP

1. The client obtains short-lived TURN credentials from the user-authorized VK Calls provider.
2. It establishes a TURN UDP allocation, authenticates using the supplied credentials and server challenge, creates a peer permission, and binds a channel when supported.
3. The client establishes a DTLS-SRTP association with the configured GHONCHA gateway through the TURN relay. The gateway identity must be validated against authenticated provisioning before any tunnel data is accepted.
4. DTLS negotiates an approved SRTP protection profile and exports the SRTP keying material.
5. The WireGuard engine produces a standard tunnel datagram.
6. The VK adapter places that complete datagram in the payload of one RTP packet and protects it with SRTP. SSRC and sequence-number allocation must be unique and correctly managed for each sending context.
7. The TURN client sends the resulting SRTP datagram to the configured gateway peer using TURN Send Indication or ChannelData.
8. The VK TURN relay forwards the opaque datagram to the gateway UDP peer socket without terminating DTLS-SRTP or seeing the inner WireGuard packet.
9. The gateway validates the RTP/SRTP framing, authenticates and decrypts SRTP, enforces replay protection, extracts the complete WireGuard datagram, and passes it to the WireGuard endpoint.
10. The gateway wraps response WireGuard datagrams in RTP/SRTP and returns them through the relay to the client's allocation.

The gateway must treat the relay address as the observed network endpoint, not as the client's identity. Peer identity comes from DTLS-SRTP gateway authentication and WireGuard cryptographic peer authentication, not from the source IP or TURN username.

### Fallback: TURN over TCP or TLS over TCP

RFC 8656 permits TCP or TLS over TCP between the client and TURN server while the TURN server relays UDP to the gateway peer. This changes only the client-to-relay carrier: TURN still delivers one datagram at a time to the gateway's UDP peer socket. It is a compatibility fallback for networks that block UDP, not a performance mode. TCP head-of-line blocking and retransmission latency can severely affect interactive traffic. The client should prefer TURN/UDP, detect path failure with bounded timeouts, and expose the active outer transport in diagnostics.

TURN ChannelData framing preserves datagram boundaries at the TURN layer. Do not concatenate raw WireGuard packets into an undocumented byte stream. Follow RFC 8656 framing, padding, channel lifetime, permission lifetime, and allocation refresh rules exactly.

Do not confuse the DTLS-SRTP association between GHONCHA client and gateway with TURN-over-DTLS (DTLS between the TURN client and TURN server), which RFC 8656 also defines as an optional client-to-relay transport. They are independent layers and require separate interoperability tests.

## Extensible transport model

The packet engine exchanges opaque, authenticated WireGuard datagrams with a transport adapter. It does not know about VK API calls, TURN credentials, RTP headers, SRTP sequence numbers, TLS proxies, or MASQUE framing.

The generic TURN-over-UDP protocol engine is implemented in `crates/transport-turn` as a `no_std`, Sans-I/O layer. It owns no socket or runtime, exposes caller-driven timers and events, and supports caller-owned transmit buffers. It is not yet the VK adapter: VK credential acquisition, DTLS-SRTP, SRTP protection, gateway integration, and Android socket binding/protection remain separate implementation steps. The upstream TURN credential type currently lacks memory zeroization, so this engine is not production-approved until that is addressed.

The VK adapter internally composes:
- a VK Calls credential provider;
- a TURN client;
- a DTLS-SRTP handshake and gateway identity verifier;
- an SRTP/RTP packetizer and depacketizer.

A direct UDP adapter may carry the same WireGuard datagrams without TURN or SRTP when the configured path and threat model permit it. A generic TURN adapter can use credentials from another provider. MASQUE CONNECT-UDP and CONNECT-IP are separate candidates; CONNECT-IP carries IP packets and therefore needs a deliberately defined boundary relative to the WireGuard tunnel.

New adapters must preserve complete record boundaries, expose capabilities and backpressure, use bounded buffers, and implement explicit lifecycle/error handling. Adding an adapter must not require changes to the IP parser, WireGuard endpoint, TUN ownership, or Android VPN UI.

## MTU and packet sizing

- Derive the effective TUN MTU from the actual path MTU and all outer encapsulation overheads.
- Account for IP, UDP, TURN ChannelData/Send Indication, RTP header/extensions, SRTP tag, and WireGuard overhead. TURN TCP/TLS fallback has different framing and congestion behavior.
- Avoid IP fragmentation. Prefer a conservative initial MTU and implement path-MTU tests before enabling larger values.
- Never silently truncate an inner packet. Reject oversize records with a measurable reason and use correct ICMP/PMTU behavior where supported.
- Test IPv4 and IPv6 independently, including cellular networks and transitions between networks.

## Data-plane constraints

- No per-packet Kotlin/JNI/UniFFI calls. FFI carries lifecycle commands, configuration, events, errors, counters, and owned descriptor handoff only.
- Keep packet buffers bounded and reusable. Avoid unbounded queues, per-packet task spawning, unnecessary copies, and locks on the hot path.
- Make descriptor ownership explicit. The Rust side receives an owned TUN descriptor only under a documented transfer contract; Android retains responsibility for protecting the outer transport sockets with `VpnService.protect()`.
- Separate control-plane work from packet processing. Control-plane updates must not stall the packet loop.
- Bound all parsing, queueing, retry, allocation, handshake, and reassembly work against resource exhaustion.

## Reliability and security requirements

- Authenticate the DTLS-SRTP gateway identity, SRTP packet integrity/replay state, WireGuard peer identity, and TURN service independently.
- Store long-term private keys using Android Keystore-backed protection where feasible; never log secrets or raw key material.
- Enforce key rotation, handshake rate limits, per-SSRC sequence/rollover limits, replay windows, peer authorization, and strict per-peer resource limits.
- Treat TURN responses, network changes, peer addresses, and all packet input as untrusted.
- Validate inner IP packets before routing; the existing packet parser is a minimal view/parser, not a complete security policy or full IPv6 extension-header validator.
- Make reconnect, allocation refresh, permission refresh, DTLS-SRTP restart, SRTP key replacement, and network migration state machines explicit and testable.
- Do not claim anonymity, censorship resistance, or leak-free behavior without threat-model-specific tests.

## Required verification before implementation is considered production-ready

1. WireGuard interoperability against the official implementation and independent peers.
2. Fuzzing and malformed-packet tests for packet, TURN, RTP, SRTP, and tunnel boundaries.
3. TURN UDP, TCP, and TLS interoperability against more than one server implementation, plus DTLS-SRTP handshake/profile negotiation, certificate pinning, SRTP replay, and bidirectional data tests.
4. NAT rebinding, Wi-Fi/cellular handover, IPv4/IPv6, DNS, sleep/wake, credential expiry, and allocation expiry tests.
5. Benchmarks on real Android devices: throughput, RTT, jitter, loss, CPU, thermal behavior, memory, and battery consumption.
6. Gateway load tests, abuse limits, failure recovery, and operational observability without sensitive payload logging.

## Relevant specifications and candidate references

- TURN: RFC 8656, https://www.rfc-editor.org/rfc/rfc8656
- DTLS-SRTP: RFC 5764, https://www.rfc-editor.org/rfc/rfc5764
- SRTP AES-GCM: RFC 7714, https://www.rfc-editor.org/rfc/rfc7714
- DTLS candidate: https://docs.rs/dimpl/0.9.0/dimpl/
- SRTP candidate: https://docs.rs/rtc-srtp/0.21.1/rtc_srtp/

No cryptographic or transport dependency is added by this document.
