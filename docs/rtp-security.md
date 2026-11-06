# RTP framing and tunnel record security

## Scope

RTP is a packet format and timing protocol. SRTP is a security profile for RTP/RTCP. An RTP header, sequence number, timestamp, or SSRC does not by itself provide confidentiality, integrity, peer authentication, or replay protection.

The GHONCHA RTP profile in `crates/transport-api/src/rtp.rs` is framing for one opaque tunnel record. It is not an SRTP implementation. Its 16-bit RTP sequence number is transport metadata and must never be treated as a cryptographic nonce or as the tunnel's replay counter. The tunnel payload may already be protected by an inner protocol; the security layer must document exactly which layer owns encryption and authentication to avoid accidental double encryption or unauthenticated paths.

## Design decision

Do not make SRTP a mandatory security layer for GHONCHA. SRTP is specifically defined around RTP/RTCP packet semantics. GHONCHA transports IP packets and must also work over non-RTP carriers, including TURN datagrams, TURN streams, and VK Calls.

Instead, define a transport-independent authenticated tunnel-record layer above every carrier:

1. The tunnel security layer accepts a complete inner IP packet and emits one authenticated opaque record.
2. Carrier adapters transport records and preserve record boundaries; they do not choose keys, construct nonces, or silently downgrade record protection.
3. On receive, the security layer authenticates a record before exposing its plaintext to the IP data plane.
4. The same record-security contract applies regardless of whether the carrier is RTP-shaped, UDP, TCP/TLS, or another future adapter.

If an authenticated inner tunnel protocol already provides the required end-to-end properties, reuse that protection and explicitly document it. Do not add another cryptographic wrapper solely because a carrier uses RTP.

## Required record protection properties

The eventual record protector must use a maintained, audited AEAD implementation rather than a custom AES-CTR/HMAC construction.

- **Confidentiality and integrity:** authenticate the complete record header as associated data and encrypt the IP payload.
- **Directional separation:** derive independent client-to-gateway and gateway-to-client keys.
- **Nonce uniqueness:** use a monotonic packet counter scoped to a key epoch and direction. Never derive a nonce from the 16-bit RTP sequence number alone.
- **Session binding:** derive traffic keys from an authenticated handshake and bind them to the peer identity, session, direction, and negotiated protocol version.
- **Replay protection:** maintain a bounded sliding replay window per receive key context. Authenticate before committing a packet to the replay window. Permit legitimate reordering within the configured window; reject duplicates and packets older than the window.
- **Rekeying:** rotate keys before algorithm-specific usage limits. A new key epoch is required before resetting any packet counter. Reject stale epochs and never resume an old key/counter pair after network migration.
- **Failure behavior:** authentication failure, nonce exhaustion, malformed headers, and unsupported key epochs must fail closed. Never pass unauthenticated plaintext to TUN.
- **Resource bounds:** bound replay-window state, pending key epochs, and any reordering buffers. Do not allocate memory based on unauthenticated lengths.
- **Key hygiene:** erase traffic keys and intermediate secrets when their session context is retired, where the platform and implementation permit reliable zeroization.

For multipath operation, packet counters and replay state must remain correct when records arrive out of order across different allocations. The simplest safe initial design is one logical directional counter and replay window per tunnel key epoch, shared by all carrier paths. If per-allocation subkeys are later introduced, derive them with distinct context labels and keep their replay state separate. Never let two workers encrypt under the same key and nonce.

## RTP-specific considerations

- Keep RTP sequence/timestamp/SSRC fields as carrier metadata only.
- RTP's 16-bit sequence number wraps. It is not a substitute for a 64-bit tunnel packet counter or key epoch.
- The RTP profile may remain fixed and minimal for interoperability, but its parser must reject unsupported fields and malformed lengths before exposing payload bytes.
- If a future adapter uses standards-compliant SRTP, it must implement the negotiated SRTP profile, packet-index rollover, key derivation, authentication, and replay rules from the applicable RFCs. Do not label a proprietary RTP wrapper as SRTP.
- SRTP's RTP-specific protection does not remove the need for GHONCHA peer authentication and tunnel-session binding.

## Performance and correctness

Measure security overhead independently from carrier overhead:

- bytes added per record, including framing, nonce/epoch metadata, and AEAD tag;
- encryption/decryption throughput, CPU time, allocations, and battery impact;
- p50/p95 latency and jitter under packet loss and reordering;
- replay-window acceptance under multipath reordering;
- behavior at key rotation and network handover;
- packet-size limits after all headers and tags are included.

Do not reduce the TUN MTU to compensate for record overhead. The tunnel packetization layer must segment and reassemble complete inner IP packets within bounded memory and time limits, as specified in [MTU and reassembly](mtu-and-reassembly.md).

## Security test requirements

Before enabling a record protector in a production data path, add deterministic test vectors and tests for:

- successful round-trip in both directions with distinct keys;
- modification of every authenticated header field and payload;
- wrong peer/session/key epoch;
- duplicate, stale, reordered, and out-of-window records;
- counter rollover and rekey boundaries;
- concurrent senders and multipath arrival ordering;
- truncated, oversized, and malformed records;
- key erasure on close and network-generation replacement;
- fuzzing of the record parser and replay-window state machine.

The transport API already models adapters as carriers of opaque authenticated records. Keep cryptographic implementation outside the transport adapters and do not route each packet through Kotlin/FFI.

## Standards

- [RFC 3711 — The Secure Real-time Transport Protocol (SRTP)](https://www.rfc-editor.org/rfc/rfc3711.html)
- [RFC 7714 — AES-GCM Authenticated Encryption in SRTP](https://www.rfc-editor.org/rfc/rfc7714.html)
- [RFC 9335 — Completely Encrypting RTP Header Extensions and Contributing Sources](https://www.rfc-editor.org/rfc/rfc9335.html)
