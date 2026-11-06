# MTU, packet sizing, and reassembly

## Requirements

GHONCHA must distinguish three different sizes:

1. **TUN interface MTU**: the maximum IP packet Android delivers to the VPN data plane. Android exposes this through `VpnService.Builder.setMtu()`; the value must be selected deliberately, not silently reduced to match an outer transport frame.
2. **Outer transport packet limit**: the maximum encoded/obfuscated datagram that a particular path and transport can carry without loss or lower-layer fragmentation.
3. **Tunnel payload MPS**: the maximum inner-packet bytes that fit after subtracting transport, framing, authentication, encryption, and obfuscation overhead.

These values are not interchangeable. A 1500-byte TUN MTU does not imply that a 1500-byte inner packet fits in one VK Calls or TURN datagram.

## Initial compatibility target

A 1500-byte TUN MTU is the compatibility target to test first, especially for interactive UDP applications and games. Do not lower it globally merely because one transport currently carries smaller outer datagrams.

The following values are implementation observations supplied for investigation, not protocol guarantees:

- approximately 1300 bytes for a reassembled/segmented packet unit;
- approximately 1350 bytes as a maximum encoded/obfuscated packet size;
- 1280 bytes as an earlier implementation value;
- a reported association with VK's OKMP framing.

The exact meaning of each size, whether it includes IP/UDP/OKMP headers, and whether it applies to a specific VK Calls path must be confirmed with packet captures and controlled tests. Do not hard-code these numbers as universal MTU constants.

## Packetization and reassembly

- Determine a per-path maximum packet size (MPS) from measured path capability.
- Subtract every layer's overhead exactly once: outer IP/UDP or TCP framing, TURN framing, VK framing, tunnel metadata, AEAD nonce/tag, and obfuscation padding.
- When an inner IP packet is larger than the current MPS, segment the encrypted tunnel payload into bounded transport fragments. Include a packet identifier, fragment offset/index, total length, and integrity/authentication protection.
- Reassemble the original inner IP packet before injecting it into the destination TUN interface. Do not expose partial fragments to applications.
- Bound reassembly memory, fragment count, packet lifetime, and concurrent incomplete packets. Reject overlaps, inconsistent lengths, duplicate abuse, and unauthenticated fragments; expire incomplete packets promptly.
- Preserve original packet boundaries and ordering. Do not merge unrelated IP packets into one semantic datagram.
- Prefer tunnel-layer segmentation over relying on outer IP fragmentation. IP fragmentation is fragile across NATs, firewalls, and paths that drop fragments.
- For TCP, consider MSS clamping only as a supplementary fallback. It does not solve oversized UDP datagrams or all IPv6 cases.
- Ensure IPv4 and IPv6 are both tested, including IPv6's minimum link MTU requirements and Packet Too Big handling.

## Path MTU discovery

Implement Datagram Packetization Layer PMTU Discovery (DPLPMTUD) or an equivalent authenticated probe mechanism per transport path. Start conservatively, probe larger packet sizes, confirm delivery end-to-end, and reduce the MPS after repeated black-hole evidence. Reset or revalidate the estimate when the underlying network or transport path changes.

Do not infer path MTU from a single successful send call. A UDP send succeeding locally does not prove end-to-end delivery. Avoid synchronized probing across all parallel allocations.

## Test matrix

Test at minimum:

- TUN MTU 1500 with outer transport MPS around 1280, 1300, and 1350, while recording whether those values include headers;
- IPv4 and IPv6, TCP and latency-sensitive UDP;
- large UDP datagrams, game-like small frequent UDP packets, DNS, QUIC, and bulk TCP;
- Wi-Fi, cellular, NAT rebinding, network handover, and paths that drop fragmented outer IP packets;
- loss, duplication, reordering, delayed fragments, missing fragments, malformed lengths, and reassembly timeout;
- CPU, allocations, queue pressure, throughput, RTT, jitter, packet loss, and battery impact.

A change is accepted only if it preserves application-visible packet contents and boundaries, avoids unbounded reassembly state, and demonstrates compatibility with interactive UDP traffic. Do not claim gaming compatibility based only on a bulk speed test.

## References

- Android `VpnService.Builder.setMtu()`: https://developer.android.com/reference/android/net/VpnService.Builder
- IETF RFC 8899, Datagram Packetization Layer Path MTU Discovery: https://www.rfc-editor.org/rfc/rfc8899.html
