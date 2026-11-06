# RTP and SRTP security in GHONCHA

## Scope and architectural placement

RTP is a packet format and timing protocol. SRTP is the standardized security profile for RTP/RTCP. An RTP header, sequence number, timestamp, or SSRC alone does not provide confidentiality, integrity, peer authentication, or replay protection.

GHONCHA has two distinct security layers in its primary VK Calls path:

1. **Inner WireGuard:** the VPN protocol. It authenticates the VPN peer, establishes tunnel keys, protects IP packets, and provides its own replay protection. This is the authoritative VPN security boundary.
2. **Outer DTLS-SRTP:** the VK Calls carrier profile. DTLS authenticates the GHONCHA gateway according to the configured identity policy and exports SRTP keying material. SRTP protects RTP packets that carry complete WireGuard datagrams across the TURN relay.

The VK TURN relay forwards opaque SRTP datagrams. It does not terminate the client-to-gateway DTLS-SRTP association, possess WireGuard keys, or act as the VPN gateway.

SRTP is required by the selected RTP-based VK Calls adapter profile. It is **not** a mandatory security layer for every GHONCHA transport. A future direct UDP or other adapter may carry authenticated WireGuard datagrams without RTP/SRTP, provided its path and threat model are documented. Do not add a second custom tunnel AEAD layer on top of WireGuard without a specific, reviewed protocol requirement.

## What SRTP does and does not do

SRTP provides confidentiality, message authentication/integrity, and replay protection for RTP packets; SRTCP provides the corresponding protection for RTCP. The negotiated SRTP protection profile determines the cipher, authentication tag, key/salt lengths, and packet processing rules.

SRTP does not replace:
- DTLS peer authentication and certificate/fingerprint validation;
- WireGuard peer authentication and VPN packet protection;
- TURN authentication, permissions, allocation refresh, or relay lifecycle;
- the GHONCHA transport lifecycle and network-generation checks.

Keep these identities and credentials separate: VK account/call authorization, TURN username/password, DTLS gateway identity, SRTP traffic keys, and WireGuard peer keys.

## DTLS-SRTP integration requirements

- Negotiate the SRTP protection profile using the DTLS-SRTP mechanism (RFC 5764). Do not use a DTLS application-data tunnel after negotiating `use_srtp`; RTP/RTCP media packets are protected with SRTP after the handshake.
- Validate the DTLS peer identity against authenticated provisioning before accepting exported keying material or sending tunnel data. A successful DTLS handshake alone is not sufficient if certificate validation has been delegated to the application.
- Export keying material using the exact label, role, profile, key length, and salt length specified by the negotiated DTLS-SRTP profile. Do not hand-split or reinterpret exporter bytes based on assumptions from another profile.
- Create independent SRTP send and receive contexts with the correct client/server key and salt assignment. Never reuse a sending context's key/SSRC/packet-index state for another sender.
- Treat every fatal DTLS error as a failed association. Retire the DTLS and SRTP contexts together and establish a fresh authenticated association.
- Never silently downgrade from DTLS-SRTP to a proprietary wrapper or plaintext RTP. Any alternate profile must be explicit, separately provisioned, and independently reviewed.
- Keep DTLS-SRTP association state separate from TURN allocation state. A TURN allocation refresh or network handover does not automatically prove that the old DTLS peer path remains valid.

## SRTP implementation requirements

Use a maintained, interoperable SRTP implementation rather than implementing packet cryptography in GHONCHA.

- Prefer an AEAD SRTP profile such as AEAD-AES-128-GCM when supported by both endpoints and the selected implementation. Profile choice must be explicit and measured on target Android devices.
- Let the SRTP implementation own packet-index/rollover-counter calculation, authentication, and replay-window updates. Do not use the 16-bit RTP sequence number alone as a nonce or replay counter.
- Authenticate before exposing the RTP payload to the WireGuard transport path.
- Reject duplicate and stale packets according to the negotiated SRTP replay policy while permitting legitimate packet reordering.
- Keep SSRC allocation unique per sending context and handle sequence rollover according to SRTP rules.
- Keep key material out of Debug/Display, logs, crash reports, metrics, and diagnostic events. Require secure zeroization support or a reviewed upstream fix for keying material and context teardown.
- Bound all packet buffers and queues. Reject malformed or oversized RTP/SRTP packets before they can cause unbounded allocation.
- Do not interpret SRTP replay protection as a replacement for WireGuard replay protection. Both layers protect different packet domains.

For multipath or multiple TURN allocations, do not share one SRTP sending context across concurrent writers unless the SRTP library explicitly guarantees safe, unique packet-index allocation. The safer initial model is a distinct DTLS-SRTP/SRTP association per independently established media path, with explicit SSRC and key lifecycle. If one association is intentionally shared across paths, serialize its send context and verify replay-window behavior under cross-path reordering.

## RTP framing in GHONCHA

The RTP helper in `crates/transport-api/src/rtp.rs` is a framing/packetization primitive, not a complete SRTP implementation. It must not be described as providing cryptographic protection.

- Keep RTP sequence, timestamp, and SSRC as RTP metadata only.
- RTP's 16-bit sequence number wraps and is not the WireGuard packet counter or nonce.
- Validate RTP version, header length, CSRC count, extension and padding lengths, payload bounds, and the configured profile before passing payload to SRTP or the next protocol layer.
- Keep complete WireGuard datagram boundaries: one RTP payload carries one complete WireGuard datagram in the selected VK profile.
- Do not pass unauthenticated RTP payload bytes to the WireGuard engine.
- For non-RTP transports, bypass RTP/SRTP and carry the same WireGuard datagrams using that adapter's explicitly defined framing and security model.

## Performance and correctness testing

Measure DTLS, SRTP, TURN, and WireGuard costs separately where possible:

- DTLS handshake time, retransmissions, and CPU cost;
- SRTP bytes of overhead per packet, encrypt/decrypt throughput, CPU time, allocations, and battery impact;
- p50/p95 latency, jitter, loss, and reordering;
- replay-window behavior during cross-path reordering;
- sequence rollover and context rekey/re-establishment;
- certificate/fingerprint mismatch, invalid exporter output, and unsupported profile negotiation;
- packet-size limits after RTP, SRTP tag, TURN framing, and outer network headers;
- network handover and TURN allocation replacement without stale key/context reuse.

Do not reduce TUN MTU solely to compensate for RTP/SRTP overhead. The tunnel packetization layer must segment and reassemble complete inner IP packets within bounded memory and time limits, as specified in [MTU and reassembly](mtu-and-reassembly.md).

## Security test requirements

Before enabling the VK Calls adapter in a production data path, add deterministic tests for:

- DTLS-SRTP profile negotiation and exact exporter key/salt mapping;
- successful SRTP protect/unprotect in both directions;
- certificate/fingerprint mismatch and failed peer authentication;
- modification of RTP header, payload, and authentication tag;
- duplicate, stale, reordered, and out-of-window SRTP packets;
- SSRC collision handling and RTP sequence rollover;
- malformed/truncated/oversized RTP and SRTP packets;
- context retirement, key zeroization, and network-generation replacement;
- WireGuard authentication after successful SRTP unprotection;
- fuzzing of RTP parsing and the integration boundary.

## Standards

- [RFC 3711 — The Secure Real-time Transport Protocol (SRTP)](https://www.rfc-editor.org/rfc/rfc3711.html)
- [RFC 5764 — DTLS Extension to Establish Keys for SRTP](https://www.rfc-editor.org/rfc/rfc5764.html)
- [RFC 7714 — AES-GCM Authenticated Encryption in SRTP](https://www.rfc-editor.org/rfc/rfc7714.html)
