# GHONCHA transport and security architecture

Status: design baseline; implementation choices remain subject to interoperability, security, and performance tests.

## Goals

- Keep the IP data path in native code and avoid per-packet FFI crossings.
- Preserve datagram semantics on the preferred path.
- Keep the VPN payload end-to-end encrypted between the client tunnel endpoint and the VPN gateway.
- Allow a TURN relay to forward traffic without possessing VPN keys or interpreting inner IP packets.
- Make fallback behavior explicit rather than silently changing transport semantics.

## Roles

1. **Android client** owns the `VpnService`, TUN descriptor, network callbacks, and Android-specific routing/protection.
2. **Rust client core** owns tunnel state, packet processing, transport selection, TURN client state, and statistics.
3. **TURN relay** implements RFC 8656. It authenticates and allocates relay resources, applies peer permissions, and forwards opaque datagrams. It is not the VPN gateway.
4. **VPN gateway** receives VK-relayed DTLS datagrams on its public UDP peer socket, terminates the application-level DTLS carrier, passes the inner WireGuard datagrams to the WireGuard endpoint for peer authentication and decryption, routes inner IPv4/IPv6 packets, applies forwarding policy and NAT where configured, and returns packets through the same layered path.
5. **Rust server control plane** provisions peers, keys, addresses, routes, quotas, and gateway lifecycle. It must not handle every packet in a high-level request/task abstraction.
6. **VK Calls TURN provider/transport (experimental)** obtains short-lived TURN credentials and relay URIs from a user-authorized VK Calls session, then carries GHONCHA's DTLS-protected tunnel traffic over TURN. The VK TURN relay forwards opaque traffic; it is not the VPN gateway or GHONCHA identity endpoint. Public VK API methods and Calls-specific undocumented bootstrap endpoints must remain clearly separated. Details and reference audit: `docs/vk-calls-transport.md` and `docs/vk-turn-reference-audit.md`.

## Tunnel cryptography

Use the standard WireGuard protocol as the initial protocol candidate; do not invent a GHONCHA-specific handshake, KDF, nonce format, replay window, or AEAD construction.

WireGuard is the inner VPN protocol and remains the authoritative identity and IP-packet protection layer. On the primary VK Calls path, the WireGuard datagram is carried as application data inside a separate client-to-gateway DTLS association; TURN transports the resulting DTLS datagrams to the gateway UDP peer socket. The VK relay sees DTLS records and TURN metadata, not the inner WireGuard packet. The gateway terminates DTLS, validates its configured peer identity, extracts the WireGuard datagram, and passes it to the WireGuard endpoint. DTLS credentials and TURN credentials are not WireGuard keys. TURN authentication only protects access to relay resources.

The exact Rust WireGuard engine is **not selected yet**. Cloudflare BoringTun is a candidate because it is a Rust userspace implementation with Android targets, but its 0.7.1 release has a reported open session regression and other protocol-conformance concerns that require investigation. Do not pin or integrate it until those reports are triaged and interoperability, fuzzing, and performance tests pass. The old `wireguard-rs` repository is not an acceptable production dependency: its own documentation says it is incomplete and should not be used.

Initial gateway evaluation should include the mature Linux kernel WireGuard implementation, controlled by the Rust server plane, as a correctness and performance baseline. A Rust userspace gateway may replace it only after equivalent interoperability, security, and throughput evidence.

## Packet path

### Preferred: TURN over UDP

1. The client establishes a TURN UDP allocation and authenticates using short-lived credentials obtained from the user-authorized VK Calls provider.
2. It creates a permission and, when beneficial, a channel binding for the GHONCHA gateway's public UDP peer address.
3. The WireGuard engine produces a standard WireGuard transport or handshake datagram.
4. The VK transport adapter places that datagram in the application-data channel of the authenticated GHONCHA DTLS association.
5. The TURN client sends the resulting DTLS datagram to the gateway peer using TURN Send Indication or ChannelData.
6. The VK TURN relay forwards the opaque DTLS datagram to the gateway's UDP peer socket without terminating DTLS or seeing the inner WireGuard packet.
7. The gateway validates/terminates DTLS, extracts the WireGuard datagram, and passes it to the WireGuard endpoint for peer authentication and IP decapsulation.
8. The gateway wraps the WireGuard response in DTLS application data and sends the resulting datagram to the client's relayed transport address; TURN forwards it to the client.

The gateway must treat the relay address as the observed network endpoint, not as the client's identity. Peer identity comes from WireGuard cryptographic authentication and server-side peer configuration.

### Fallback: TURN over TCP or TLS over TCP

RFC 8656 permits TCP or TLS over TCP between the client and TURN server while the TURN server relays UDP to the gateway peer. This changes only the client-to-relay carrier: TURN still delivers the DTLS application datagram to the gateway's UDP socket. It is a compatibility fallback for networks that block UDP, not a performance mode. TCP head-of-line blocking and retransmission latency can severely affect interactive traffic. The client should prefer TURN/UDP, detect path failure with bounded timeouts, and expose the active outer transport in diagnostics.

TURN ChannelData framing preserves datagram boundaries at the TURN layer. Do not concatenate raw WireGuard packets into an undocumented byte stream. Follow RFC 8656 framing, padding, channel lifetime, permission lifetime, and allocation refresh rules exactly.

Do not confuse the application-level DTLS association between GHONCHA client and gateway with TURN-over-DTLS (DTLS between the TURN client and the TURN server), which RFC 8656 also defines as an optional client-to-relay transport. The VK reference topology uses TURN/UDP to the relay and a separate DTLS association to the gateway. TURN-over-DTLS is a distinct optional mode and must be evaluated independently; neither DTLS mode replaces WireGuard peer authentication.

## MTU and packet sizing

- Derive the effective TUN MTU from the actual path MTU and all outer encapsulation overheads.
- Account for IP, UDP, TURN ChannelData/Send Indication, application-level DTLS, and WireGuard overhead. TURN TCP/TLS fallback has different framing and congestion behavior.
- Avoid IP fragmentation. Prefer a conservative initial MTU and implement path-MTU tests before enabling larger values.
- Never silently truncate an inner packet. Reject oversize packets with a measurable reason and use correct ICMP/PMTU behavior where supported.
- Test IPv4 and IPv6 independently, including cellular networks and transitions between networks.

## Data-plane constraints

- No per-packet Kotlin/JNI/UniFFI calls. FFI carries lifecycle commands, configuration, events, errors, counters, and owned descriptor handoff only.
- Keep packet buffers bounded and reusable. Avoid unbounded queues, per-packet task spawning, unnecessary copies, and locks on the hot path.
- Make descriptor ownership explicit. The Rust side receives an owned TUN descriptor only under a documented transfer contract; Android retains responsibility for protecting the outer transport sockets with `VpnService.protect()`.
- Separate control-plane work from packet processing. Control-plane updates must not stall the packet loop.
- Bound all parsing, queueing, retry, allocation, and handshake work against resource exhaustion.

## Reliability and security requirements

- Authenticate the GHONCHA DTLS peer identity, WireGuard peer identity, and TURN service independently.
- Store long-term private keys using Android Keystore-backed protection where feasible; never log secrets or raw key material.
- Enforce replay protection, key rotation, handshake rate limits, peer authorization, and strict per-peer resource limits using the selected WireGuard implementation.
- Treat TURN responses, network changes, peer addresses, and all packet input as untrusted.
- Validate inner IP packets before routing; the existing packet parser is a minimal view/parser, not a complete security policy or full IPv6 extension-header validator.
- Make reconnect, allocation refresh, permission refresh, and network migration state machines explicit and testable.
- Do not claim anonymity, censorship resistance, or leak-free behavior without threat-model-specific tests.

## Required verification before implementation is considered production-ready

1. WireGuard interoperability against the official implementation and independent peers.
2. Fuzzing and malformed-packet tests for packet, TURN, and tunnel boundaries.
3. TURN UDP, TCP, and TLS interoperability against more than one server implementation, plus separate application-level DTLS client/gateway interoperability and peer-pinning tests.
4. NAT rebinding, Wi-Fi/cellular handover, IPv4/IPv6, DNS, sleep/wake, and allocation expiry tests.
5. Benchmarks on real Android devices: throughput, RTT, jitter, loss, CPU, thermal behavior, memory, and battery consumption.
6. Gateway load tests, abuse limits, failure recovery, and operational observability without sensitive payload logging.

## Relevant specifications and candidate references

- TURN: RFC 8656, https://www.rfc-editor.org/rfc/rfc8656
- WireGuard protocol and implementation references: https://www.wireguard.com/
- BoringTun crate documentation: https://docs.rs/boringtun/
- BoringTun known issue tracker: https://github.com/cloudflare/boringtun/issues/495
- BoringTun protocol/padding issue: https://github.com/cloudflare/boringtun/issues/494

No cryptographic or transport dependency is added by this document.