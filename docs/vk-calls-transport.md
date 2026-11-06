# GHONCHA VK Calls transport

Status: experimental transport design. VK Calls is a first-class GHONCHA connectivity target, but the public VK API, the public Calls SDK, and any undocumented call-internal signalling are distinct interfaces with different support and compatibility guarantees.

## 1. Why this transport exists

Some access networks may permit VK Calls infrastructure while blocking GHONCHA's ordinary VPN endpoints. GHONCHA may therefore offer a user-authorized VK Calls path between:
- a GHONCHA client on the restricted network; and
- a GHONCHA peer/bridge with a usable route to the public internet.

This is an availability option, not a guarantee. A call may be blocked, rate-limited, unavailable to a particular account, or unusable for data transport. Never assume that VK is allowlisted merely because the app or website opens.

The VK path is a WebRTC media/data transport adapter. It is not TURN, and VK's SFU is not the GHONCHA VPN gateway. End-to-end GHONCHA encryption must terminate only at the GHONCHA peer/gateway, not at an intermediary bridge that should not read user traffic.

## 2. Public VK interfaces: documented scope

The current public VK Calls SDK documentation is published as `@vkontakte/calls-sdk` (the documentation observed for this design is v2.8.9):
- SDK overview and quick start: https://st.mycdn.me/static/callssdk/latest/doc/index.html
- Getting started and lifecycle: https://st.mycdn.me/static/callssdk/2-8-9/doc/guide/usage.html
- API reference: https://st.mycdn.me/static/callssdk/2-8-9/doc/api/

The public SDK documents initialization, authorization, call creation/joining, call lifecycle, participant state, device/media handling, local and remote media streams, screen sharing, and network-quality callbacks. It is a browser-oriented JavaScript SDK; the published quick start uses browser media streams.

The documented `customData(data, externalId)` method sends a JSON object to a participant (or all participants when no external ID is supplied). Treat it as a bounded signalling/control facility only. It is not a documented arbitrary binary stream, IP tunnel, or replacement for a WebRTC DataChannel.

The documented `publishStream(roomId)` method publishes a call stream. Its public reference does not define a generic byte-stream or raw packet interface.

The public VK API also provides call-management functionality. VK's public announcement describes creating call links, sharing invitations, scheduling/starting/ending conferences, and recording. These methods manage calls; they do not by themselves define a general-purpose packet tunnel.

**Important boundary:** the public documentation reviewed here does not expose a supported generic SCTP DataChannel API through `@vkontakte/calls-sdk`. Do not claim that the public SDK alone provides a stable arbitrary-data tunnel.

## 3. WebRTC transport modes to evaluate

Treat the following as separate experimental modes behind one VK adapter.

### Mode A: WebRTC DataChannel

A WebRTC peer connection negotiates an SCTP DataChannel through the call infrastructure. The DataChannel carries framed GHONCHA tunnel records; it must not carry raw TUN packets directly without bounded framing, authentication, and flow control.

Measure:
- whether the deployed VK call topology actually forwards the negotiated DataChannel between the intended participants;
- ordered/reliable and unordered/partially-reliable behavior, message-size limits, buffering, and backpressure;
- SCTP retransmission and head-of-line behavior under loss;
- DTLS/SCTP setup time, ICE candidate types, relay usage, and reconnection behavior;
- SFU policy, data-channel limits, and per-account/per-call rate limits.

The public Calls SDK reference does not document a generic DataChannel surface. Any integration that depends on call-internal signalling or undocumented peer-connection negotiation is experimental, version-sensitive, and must be isolated from the stable core. Do not scrape or imitate private app sessions as if they were a supported public API.

### Mode B: Media-track carrier

A second experimental mode may encode bounded tunnel records into a media track and recover them at the other end. A VP8 video-track carrier is one researched design; it is not equivalent to a DataChannel.

It must account for:
- lossy frame delivery, frame drops, reordering, decoder behavior, and bitrate adaptation;
- encoder CPU, thermal load, radio use, and end-to-end latency;
- strict pacing and congestion control so tunnel traffic does not overwhelm the call;
- payload framing, integrity, replay protection, and authenticated session establishment;
- visible call/media behavior, participant consent, and platform policy.

Do not assume that a video codec is a reliable byte channel. If reliable delivery is required, any retransmission layer must be bounded and congestion-aware. Compare its overhead and latency against DataChannel mode rather than enabling it automatically.

### Mode C: SDK customData

Use `customData` only for low-volume control signalling if its documented semantics, size limits, rate limits, and delivery behavior meet requirements. Examples include exchanging a session nonce, protocol version, or a user-approved pairing confirmation. Do not carry user IP packets, bulk data, credentials, or long-lived secrets in this API.

## 4. VK call setup and signalling boundary

Separate call lifecycle from tunnel lifecycle.

The call-control component is responsible for:
- obtaining user-authorized access through a supported VK authentication flow;
- creating or joining a call using documented VK interfaces where available;
- handling invitation/link lifecycle and participant admission;
- reporting call state and platform errors;
- explicitly ending the call and revoking local resources on disconnect.

The WebRTC component is responsible for:
- peer-connection construction;
- ICE configuration and candidate exchange;
- SDP negotiation;
- DataChannel or media-track setup;
- transport statistics and bounded recovery.

The GHONCHA tunnel component is responsible for:
- authenticated peer identity and end-to-end encryption;
- multiplexing and framing;
- bounded queues and backpressure;
- packet/datagram delivery to the Rust tunnel engine;
- MTU and loss handling.

Never treat a VK account, call link, participant ID, or SFU connection as GHONCHA cryptographic identity. Authenticate the GHONCHA peer independently.

## 5. Undocumented implementation observations

An external open-source project, `kulikov0/whitelist-bypass`, demonstrates a VK Calls WebRTC tunnel architecture and is useful as a research reference:
- Repository: https://github.com/kulikov0/whitelist-bypass
- README: https://github.com/kulikov0/whitelist-bypass#readme
- VK headless implementation: https://github.com/kulikov0/whitelist-bypass/tree/main/headless/vk

Its published description distinguishes DataChannel mode from VP8 media-track mode and describes a headless WebRTC/Pion path. Its current VK implementation uses a mixture of VK API calls and call-internal HTTP/WebSocket signalling. Some of those call-internal endpoints and message formats are not documented as public VK API contracts.

For architecture review only, the observed private/internal names include `calls.getSettings`, `messages.getCallToken`, `vchat.joinConversationByLink`, and call signalling messages such as `transmit-data`. Their presence in third-party source does not make them supported, stable, or authorized public interfaces. They may change without notice, require application-specific credentials, trigger anti-abuse controls, or stop working. GHONCHA must not hardcode these as a stable public API or make the entire client depend on them.

Do not copy implementation code or assets from the reference project without checking its license and notices. The repository currently declares MIT, but attribution and license obligations still apply to any code actually reused. Prefer independent implementations against documented interfaces and standards.

## 6. Security, account, and privacy requirements

- Require explicit user consent before joining, creating, or maintaining a call.
- Use supported authentication flows. Never ask users to paste passwords, session cookies, or long-lived access tokens into diagnostics or logs.
- Store any required credentials using platform-backed secure storage; redact them from crash reports and telemetry.
- Do not log call links, bearer tokens, cookies, SDP, ICE credentials, or participant identifiers unless a user explicitly enables a redacted diagnostic export.
- Apply independent GHONCHA peer authentication and authenticated encryption before any user traffic enters the VK transport.
- Enforce message size, queue, rate, retry, and memory limits. Treat all remote signalling and media as untrusted input.
- Do not use VK's infrastructure to attack, scan, or relay traffic for third parties without authorization. Respect account controls, call participant consent, platform terms, and applicable law.
- If VK rejects the session, requires an unsupported challenge, or changes its protocol, fail closed and show an accurate diagnostic. Do not bypass CAPTCHA, account security, or anti-abuse protections.

## 7. Integration with Network Availability Manager

Represent VK as an explicitly provisioned adapter candidate, not as a universal fallback.

Its endpoint state must include:
- `NotConfigured`
- `Configured`
- `CallControlUnavailable`
- `CallCreatedOrJoined`
- `PeerConnectionNegotiating`
- `DataChannelReady`
- `MediaCarrierReady`
- `TunnelAuthenticated`
- `Degraded`
- `Closed`
- `Failed`

A VK call being joined does not mean the GHONCHA tunnel is ready. `Connected` is permitted only after GHONCHA peer authentication and successful bidirectional tunnel data-health checks.

On network-generation change, invalidate ICE/network-bound resources and renegotiate under a bounded retry budget. Do not continuously recreate calls or rotate accounts. Keep user disconnect, call termination, and authentication revocation as hard stop conditions.

Expose the active mode (DataChannel or media carrier), call state, peer-authentication state, measured RTT/loss/throughput, last failure category, and retry deadline. Avoid displaying sensitive call identifiers.

## 8. Performance and interoperability test plan

Compare VK DataChannel, VK media-track carrier, direct WireGuard UDP, TURN, and any supported MASQUE adapter using the same gateway, device, payload mix, and network profile.

Measure:
- setup success rate and time-to-connected;
- sustained and burst upload/download throughput;
- median, p95, and p99 RTT, jitter, loss, reordering, and recovery time;
- CPU, memory, thermal throttling, wakeups, radio-active time, and battery drain on real Android devices;
- behavior under packet loss, bandwidth changes, background/foreground transitions, sleep/wake, ICE restart, and Wi-Fi/cellular handover;
- SFU-imposed message/bitrate limits and behavior across multiple accounts, call types, and regions where authorized test access exists.

Do not publish a speed ranking until repeated real-device measurements exist. Do not assume video mode is more reliable merely because media packets pass through an SFU.

## 9. Decision gates

Before production use:
1. Verify current VK public API and SDK documentation and supported authentication requirements.
2. Establish whether the desired DataChannel or media-track integration is available through a documented and permitted interface. If not, keep it explicitly experimental.
3. Verify platform terms, account requirements, call participant consent, and operational limits.
4. Build a standalone interoperability prototype before connecting it to the VPN TUN path.
5. Complete threat modelling, fuzzing, resource-exhaustion tests, and real Android performance/battery benchmarks.
6. Provide a non-VK transport fallback and a clear failure state when VK is unavailable.

No VK transport implementation or undocumented VK endpoint dependency is added by this document.
