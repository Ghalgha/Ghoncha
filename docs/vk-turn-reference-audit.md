# VK TURN reference repository audit

Audit date: 2026-11-06. This is a source-level architecture review of the ten repositories supplied for GHONCHA. It is not a security audit, a compatibility guarantee, or permission to copy code.

## 1. Main conclusion

The supplied projects implement a TURN-relay transport obtained through VK Calls, generally with DTLS between the client and the user's own server. This is not the generic WebRTC DataChannel architecture described in the earlier draft of `docs/vk-calls-transport.md`.

The common high-level pattern is:

```text
Android VPN/TUN -> local packet engine -> DTLS -> TURN client
  -> VK Calls TURN relay -> user's server -> DTLS -> local VPN backend
```

The TURN relay provides reachability between allocations/peers. It is not the VPN gateway. The user's server terminates the end-to-end DTLS/tunnel session and forwards packets to its local WireGuard/Hysteria/CSQTT backend.

## 2. Repository-by-repository findings

### 2.1 `cacggghp/vk-turn-proxy`

Repository: https://github.com/cacggghp/vk-turn-proxy

- Go client/server reference and the earliest project in this list.
- README describes WireGuard/Hysteria UDP payloads wrapped in DTLS 1.2 and transported through VK (or historically Yandex) TURN using STUN ChannelData.
- Supports UDP and TCP paths to TURN, multiple parallel workers, local loopback listener, server-side UDP forwarding, Docker/systemd deployment, and a VLESS/TCP mode in later revisions.
- TURN credentials are obtained from a call link.
- Useful as the simplest protocol-flow reference and baseline for the client/server separation.
- Do not assume its defaults, hardcoded TURN addresses, worker counts, or call-link lifetime remain valid.

License reported by GitHub: GPL-3.0. Any code reuse or derivative distribution must be reviewed against GPL-3.0 obligations.

### 2.2 `Urtyom-Alyanov/turn-proxy`

Repository: https://github.com/Urtyom-Alyanov/turn-proxy

- Rust client and server; explicitly describes wrapping arbitrary UDP traffic in DTLS over TURN.
- Client uses a TURN library and a relay connection abstraction, then wraps it in a DTLS connection.
- The inspected client config generates a self-signed certificate and sets `insecure_skip_verify = true`. This is a serious peer-authentication weakness; GHONCHA must not copy this setting.
- The inspected TURN setup creates a client, listens, and allocates a relay; the bridge runs upstream/downstream flows with cancellation and bounded shutdown timeouts.
- README says the current implementation is UDP-only; TCP-over-DTLS/multiplexing is not guaranteed.
- Useful for Rust TURN/DTLS layering and adapter boundaries, but not as a production-ready security template.

GitHub metadata reports MPL-2.0 at repository level, while README specifies server AGPL-3.0 and client MPL-2.0. Treat the components separately and inspect the exact license files before reuse.

### 2.3 `MYSOREZ/vk-turn-proxy-android`

Repository: https://github.com/MYSOREZ/vk-turn-proxy-android

- Kotlin Android application for the `cacggghp/vk-turn-proxy` core.
- README documents local WireGuard endpoint redirection, MTU 1280 example, process start/stop, server setup, worker controls, UDP selection, and a manual/raw argument path.
- Useful for Android VPN/service lifecycle, configuration UX, SSH/deployment and operational diagnostics.
- It is a wrapper/client distribution around a separate core, not a replacement Rust packet engine.

License: GPL-3.0. Respect copyleft if code is reused.

### 2.4 `amurcanov/proxy-turn-vk-android` (WDTT)

Repository: https://github.com/amurcanov/proxy-turn-vk-android

- Archived on 2026-09-11; its README points to `amurcanov/csqtt` as the successor.
- Android app plus embedded Go client and Go server.
- Inspected `creds_vkcalls.go` shows a multi-step VK Calls credential bootstrap: anonymous token, call preview, anonymous call token, Calls/OK CDN anonymous login, then join-by-link; the response yields TURN username, credential, and URI list.
- The code distinguishes VK API errors, Calls/OK CDN errors, call-unavailable failures, network/decode failures, and captcha/security gates.
- Useful as a concrete source for the shape of the credential bootstrap and Android integration, but its internal endpoints and browser/TLS mimicry are not a stable public VK API contract.

License: GPL-3.0 according to repository metadata. Archived; do not treat as maintained.

### 2.5 `SpaceNeuroX/proxy-turn-vk-android` (qWDTT)

Repository: https://github.com/SpaceNeuroX/proxy-turn-vk-android

- Android fork/successor based on WDTT; README explicitly states it uses original WDTT Android and server sources as a technical base.
- README describes VPN over VK Calls TURN to a user-owned VPS; project license is GPL-3.0.
- Tree includes Go client files for credential bootstrap, TURN/DTLS transport, session, obfuscation and TUN FD handling, plus server files for connections, packet buffers, NAT, WireGuard, optimization and statistics.
- Useful for studying later Android integration and operational evolution of the WDTT codebase.
- Default branch is `master`, not `main`.

License: GPL-3.0. Derived code retains relevant upstream obligations.

### 2.6 `amurcanov/csqtt`

Repository: https://github.com/amurcanov/csqtt

- Newer Rust client/server successor to WDTT; Android Kotlin app with Rust client and Rust Linux server.
- The client tree includes a dedicated TURN engine, STUN codec, TURN endpoint parsing, UDP and TCP/TLS stream transports, packet pools, worker/session management, VK call bootstrap, statistics, repair/recovery and tests.
- Inspected `turn_core.rs` models Allocate, Refresh, CreatePermission and ChannelBind, nonce/authentication retries, allocation maintenance, permission/channel refresh, bounded control/event queues and state transitions.
- Inspected `turn.rs` uses bounded incoming/outgoing queues, packet pools, driver events and explicit cleanup; `turn_stream.rs` frames TURN stream data and bounds its queues.
- `turn_endpoint.rs` parses `turn:` / `turns:` endpoints and transport query parameters.
- `vk_js_calls.rs` demonstrates an account-authorized call-creation/session flow and a credential broker. This is Calls-specific integration, not simply a documented VK public API method.
- Android source has dedicated VK API/auth/call managers, TURN transport policy, network tracking, VPN lifecycle, secret storage and worker-count policy.
- This is the most valuable modern architecture reference in the supplied list, especially for Rust TURN state management and Android integration.
- It also contains implementation-specific protocol details and custom behavior. Review every part; do not transplant wholesale or assume it is standards-compliant just because it is written in Rust.

License: README states PolyForm Noncommercial License 1.0.0. This is a major reuse restriction: do not copy or derive GHONCHA code from this repository unless the project's intended use is compatible with that license or separate permission is obtained.

### 2.7 `Endlad2/LaLune`

Repository: https://github.com/Endlad2/LaLune

- Cross-platform Flutter UI with platform backends in Rust/Kotlin/Swift and a CSQTT core.
- README describes Android VpnService, Rust core, HTTP/SSE local backend, OpenWRT and desktop support.
- Useful for studying separation between cross-platform UI, platform backend, TUN lifecycle, local control API, deployment and cross-platform packaging.
- Its description says TURN is used for NAT traversal and traffic is masked as VK Calls; this is a CSQTT-family integration, not a public VK SDK DataChannel implementation.

GitHub metadata reports no recognized SPDX license (`NOASSERTION`). Do not reuse code until an explicit license is verified.

### 2.8 `w3struk/csqttr`

Repository: https://github.com/w3struk/csqttr

- Recent CSQTTR rebirth/fork with Kotlin Android and Rust core; README explicitly references the original CSQTT lineage.
- Tree contains dedicated VK auth/call management, TURN subnet and transport policies, network tracking, TUN recovery, worker policies, diagnostics and extensive Android tests.
- Useful for studying the evolution of Android policy boundaries and test coverage.
- Repository was recently updated, but its metadata reports `NOASSERTION` license. No code reuse until licensing and provenance are clarified.

### 2.9 `danusha2345/csqtt-android`

Repository: https://github.com/danusha2345/csqtt-android

- CSQTT Android client and Linux server using VK TURN; README describes Android and OpenWRT support, TURN UDP/TCP/TLS, local SOCKS5 mode, audio/video modes, worker groups, VPN lifecycle, server deployment and config synchronization.
- It identifies itself as a maintained fork of `amurcanov/csqtt`.
- Useful for operational and cross-platform testing ideas, but its source lineage and exact delta from upstream need commit-level comparison before drawing implementation conclusions.

GitHub metadata reports `NOASSERTION` license. The README says non-commercial use; verify the exact license and upstream permissions before any reuse.

### 2.10 `Afteroid/csqttr`

Repository: https://github.com/Afteroid/csqttr

- CSQTTR Rebirth Android/Kotlin project in the same CSQTT family.
- README describes VPN-over-TURN/RTP and call profiles, VK account management, app routing, deploy and UI workflows.
- Tree contains extensive tests for TUN transport probes, VK account UI, SSH/deployment, routing and profile lifecycle.
- Useful as a source of test scenarios and Android UX/lifecycle edge cases, not as an independent TURN protocol baseline.

GitHub metadata reports `NOASSERTION` license. Verify permissions before code reuse.

## 3. What GHONCHA should learn from these projects

1. **Use TURN as the carrier, DTLS as the protected client-server transport, and a separate authenticated VPN gateway.** Do not confuse TURN relay with the VPN gateway.
2. **Build the TURN engine as a real state machine.** Allocate, permission, channel binding, refresh, nonce changes, timeouts, deallocation and transport-specific framing all need explicit states and tests.
3. **Separate credential acquisition from data plane.** VK Calls bootstrap is an unstable provider integration; the Rust data plane should consume a generic, short-lived `TurnCredentials` value and should not know how credentials were obtained.
4. **Keep Android responsibilities narrow.** Android owns VpnService, TUN FD, network observation, socket protection/binding, user authorization and interactive security prompts. Rust owns TURN/DTLS packet transport, queues, workers, tunnel state and metrics.
5. **Benchmark concurrency rather than copying worker counts.** Multi-allocation/worker designs are a tunable experiment, not an unconditional speed optimization.
6. **Design transport fallback honestly.** UDP, TCP and TLS have different reachability, congestion and energy costs. Do not assume one is universally best.
7. **Do not copy security shortcuts.** In particular, skip-verification DTLS, custom crypto, weak credential persistence, unbounded queues, and automated security-challenge bypass are not acceptable production defaults.
8. **Use source projects as design evidence, not as unreviewed dependencies.** Verify exact commits, transitive dependencies, vulnerability status, license and provenance before reuse.

## 4. License and provenance summary

| Repository | GitHub/license information | Reuse position |
|---|---|---|
| cacggghp/vk-turn-proxy | GPL-3.0 | Copyleft obligations apply |
| Urtyom-Alyanov/turn-proxy | MPL-2.0 metadata; README says server AGPL-3.0/client MPL-2.0 | Inspect component license files |
| MYSOREZ/vk-turn-proxy-android | GPL-3.0 | Copyleft obligations apply |
| amurcanov/proxy-turn-vk-android | GPL-3.0; archived | Copyleft; archived |
| SpaceNeuroX/proxy-turn-vk-android | GPL-3.0 | Copyleft; derived from WDTT |
| amurcanov/csqtt | PolyForm Noncommercial 1.0.0 | Do not reuse for commercial use without permission |
| Endlad2/LaLune | NOASSERTION | No reuse until license is verified |
| w3struk/csqttr | NOASSERTION | No reuse until license is verified |
| danusha2345/csqtt-android | NOASSERTION in repository metadata; README says non-commercial | Verify exact license and upstream permission |
| Afteroid/csqttr | NOASSERTION | No reuse until license is verified |

GHONCHA can independently implement standards-based TURN and DTLS behavior. Any copied or derivative source requires a separate license/provenance decision before it enters the repository.

## 5. Implementation sequence for GHONCHA

1. Finish the VK credential-provider contract and document which steps use public VK API versus Calls-specific undocumented endpoints.
2. Implement a standalone TURN protocol test harness with synthetic credentials and a controlled TURN server.
3. Implement and test DTLS peer authentication between a Rust client and Rust server without VK.
4. Add a VK Calls credential provider behind a feature/configuration boundary, with explicit user consent and safe handling of interactive challenges.
5. Validate the complete TURN + DTLS + gateway path, then integrate with Android TUN.
6. Benchmark one allocation first; add multi-worker/multi-allocation only if repeatable tests show a net benefit.
