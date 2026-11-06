# GHONCHA power efficiency

Status: implementation requirements and measurement plan.

## 1. Objective

Minimize incremental battery drain while preserving tunnel availability, security, and useful throughput. Do not optimize battery life by silently weakening authentication, replay protection, or packet delivery.

No battery-life claim is valid without measurements on physical Android devices. Report results separately for Wi-Fi and cellular, screen-on and screen-off, idle and active traffic, and normal and battery-saver modes.

## 2. Energy-critical design rules

- Keep the packet data plane in Rust. Do not cross JNI/UniFFI for individual packets.
- Use event-driven I/O loops for active transport sessions. Do not create a task, thread, timer, or wakeup for every packet.
- Batch socket reads, writes, transport events, and TUN processing within explicit event and byte budgets.
- Reuse caller-owned packet buffers and bounded pools. Avoid per-packet heap allocation and full-packet copies.
- Apply backpressure before queues grow. Queue limits must be based on bytes as well as record count.
- Keep only the sessions and sockets required by the selected concurrency target. Do not impose a universal single-session limit: independent TURN flows may be needed to reach the user's available bandwidth.
- During path migration, allow temporary overlap only for a bounded handover window. Close the old path after authenticated traffic succeeds on the new path, unless it is still needed to satisfy the selected concurrency target.
- Never hold a wake lock during retry delays, idle waits, or credential refresh scheduling.
- Do not run continuous endpoint probes in the background. Probe only configured endpoints, only when a state transition or recovery decision requires it.
- Use Android network callbacks rather than polling connectivity state.
- Cancel stale timers and invalidate path measurements when the Android network generation changes.

## 3. Idle behavior and keepalives

- Application data sent on the path resets the idle timer; do not send a separate keepalive while outbound data already maintains the mapping.
- Schedule a one-shot timer from a measured path idle timeout. Do not use a fixed aggressive interval across all operators and network types.
- Apply a safety margin to the measured timeout and clamp it to configured minimum and maximum intervals.
- If no trustworthy timeout is known, do not invent one. Learn it through bounded, low-frequency validation during connection setup or controlled diagnostics.
- If the measured timeout is shorter than the minimum safe interval, report the path as unsuitable for low-power idle operation rather than sending frequent probes indefinitely.
- TURN allocation refresh, TURN permission/channel refresh, NAT mapping maintenance, and DTLS handshake retransmission are separate timers. Schedule each from its own protocol deadline.
- Every timer must expose its next deadline to the event loop. Avoid periodic polling that wakes the CPU when no work is due.
- Keepalive records must be authenticated by the established session and must not contain arbitrary unauthenticated dummy data.
- After a network handover, discard the old network's idle-timeout measurements and relearn them for the new path.

## 4. User-selectable connection profiles

The Android app must expose exactly three primary connection profiles on the home screen. The user can change the profile while the VPN is connected. A profile change is a live reconfiguration: it must not tear down the TUN interface, reset VPN keys, or unnecessarily recreate healthy transport sessions.

### 4.1 Unlimited

- No product-imposed fixed stream-count or throughput cap.
- Discover the useful concurrency of the current path by gradually increasing independent TURN flows and measuring aggregate goodput.
- Stop increasing concurrency when added flows no longer provide a material goodput improvement, or when latency, loss, server limits, thermal load, or resource budgets regress.
- Respect server-advertised and locally configured hard safety limits. "Unlimited" means no arbitrary user-facing cap, not infinite resource use or bypassing server policy.
- Keep increasing concurrency only while the measured path benefits. Do not equate OS threads, SCTP streams, TURN Channels, TURN allocations, and independent transport flows.

### 4.2 Standard

- Target 30–40 independent TURN data flows when the selected transport supports them; use 35 as the initial target.
- Treat this as a target, not a guarantee. The controller must reduce or increase the actual count within server and transport limits when measurements show that the target is unsuitable.
- Start flows gradually, spread load across them, and avoid a synchronized burst of handshakes.
- Detect individual flow failure and replace only the failed flow where the protocol permits; do not restart the whole group for one failed flow.
- If the current transport does not support 30–40 independent flows, show the actual supported count and do not simulate it with unrelated logical channels.

### 4.3 Energy saving

- Start with the minimum viable number of independent flows (initial target: one), and add another only when measured demand or queue growth shows that the current capacity is insufficient.
- Prioritize interactive low-volume traffic, including messaging, ordinary web browsing, and small downloads. Do not promise a specific speed until measured.
- Batch and reuse buffers, suppress redundant keepalives during application traffic, avoid speculative probes, reduce nonessential diagnostics, and use bounded retry budgets.
- When demand subsides, drain and retire excess flows safely, retaining the minimum number required for transport health and configured throughput.
- Never violate TURN refresh deadlines, NAT/path lifetime requirements, authentication, encryption, or replay protection to save power.
- Do not keep the mode artificially slow: if interactive traffic becomes impaired, add capacity temporarily and return to the minimum viable count after the burst.

## 5. Live profile switching

- Profile changes must be accepted while connected and applied by the Rust control plane without restarting the VPN service.
- Apply changes incrementally: create additional flows before raising the target; drain flows before closing them when lowering the target.
- Preserve in-flight packet delivery where possible. Bound the overlap period and total temporary resources.
- Use a generation/version on profile commands and events so stale asynchronous results cannot revert a newer user choice.
- If a requested profile cannot be fully applied, keep the tunnel working, expose the effective flow count and a clear reason, and do not claim that the requested profile is active.
- A profile switch must not weaken cryptographic settings or change peer identity.

## 6. Three-profile speed test on the home screen

The home screen must provide a speed-test action that evaluates all three profiles on the current network and presents a side-by-side comparison. The test is optional, user-initiated, and must not silently run in the background.

- Run a short warm-up, then test Unlimited, Standard, and Energy saving under comparable conditions. Randomize or rotate test order between runs to reduce order bias.
- Use a GHONCHA-controlled test endpoint and a bounded test payload. Do not use arbitrary third-party speed-test services or send user traffic to the test endpoint.
- Measure download and upload goodput, median and p95 latency, jitter, packet loss, test duration, effective flow count, and failure/retry count for each profile.
- Report the actual flow count, not only the requested target. Label results as measurements for the current network and time, not guaranteed future speeds.
- A short speed test can compare throughput and latency, but it cannot reliably predict battery life in mAh/hour. Show energy as "not measured" unless a sufficiently long, controlled device-side power measurement is available.
- Provide a clear stop action and cancel outstanding test work when the user leaves the test or disconnects.
- Do not run the three tests concurrently: they would compete for bandwidth and invalidate the comparison. Run them sequentially with a cooldown or link-idle check between profiles.
- If the VPN is already carrying user traffic, either defer the test until the user confirms a brief test window or mark the result as contaminated; never silently interrupt or throttle user traffic.
- After the test, let the user select a profile. Applying that selection must use the live-switch procedure above.

The home-screen comparison should show, per profile: download, upload, latency, jitter, loss, actual flow count, and test status. It should identify the fastest profile, but must not automatically select a profile without user consent.

## 7. Screen-off and Android battery saver

### Screen off

- Do not change cryptographic requirements or silently disconnect the tunnel.
- Suppress nonessential diagnostics, discovery, and speculative probes.
- Maintain only timers required for session validity and the selected path.
- Continue forwarding user traffic. Do not assume screen-off means idle; background messaging, sync, audio, and other applications may still use the VPN.
- Let the selected connection profile govern concurrency. Do not silently switch profiles solely because the screen turned off.

### Android Battery Saver

- Observe the system power-save state and adapt nonessential work, without overriding the user's selected profile.
- Keep the selected profile visible and distinguish the user-selected profile from temporary OS power restrictions.
- Reduce diagnostic sampling and speculative work; use bounded retry budgets.
- Never exceed a measured NAT/relay timeout to save power; if the path cannot be maintained safely, expose the limitation and wait for a meaningful network event.
- Do not silently reduce the user's throughput target. If OS restrictions or resource limits prevent the requested profile, report the effective state.

### Network unavailable

- Stop active retries when no usable network exists. Retain only non-secret cached configuration and schedule recovery from connectivity events.
- Do not hold a wake lock or repeatedly resolve DNS without a network.

## 8. Cryptographic and transport costs

- Perform DTLS handshake, certificate pin validation, and key derivation only at session establishment or deliberate rekey.
- Keep the established SRTP contexts alive across packets; never reconstruct contexts per packet.
- Enforce replay protection with a bounded sliding window.
- Rotate keys according to protocol limits and policy, not arbitrary short intervals that increase radio and CPU work.
- Avoid duplicate encryption layers when the threat model does not require them. The inner VPN authentication remains end-to-end; outer transport protection is independently authenticated.
- Measure cipher and packetization overhead on target Android ABIs. Hardware acceleration availability must be measured, not assumed.
- Reject an SRTP implementation for production if its packet hot path creates avoidable per-packet allocations or copies and a repeatable benchmark shows material CPU or battery cost.

## 9. Required measurements

Collect measurements in controlled runs with a stable device, fixed screen brightness, fixed radio conditions, and a recorded OS/build version.

| Scenario | Required observations |
|---|---|
| Baseline, VPN off | Idle and active power draw |
| VPN connected, no application traffic | Incremental idle drain, wakeups, radio activity |
| Low-rate traffic | CPU, packets/s, wakeups, battery drain |
| Sustained download and upload | Goodput, CPU, temperature, battery drain |
| 1, 2, 4, 8, 16, 24, 32, 40 and higher flow counts | Aggregate goodput, per-flow goodput, RTT, loss, CPU, energy |
| Loss and high RTT | Retransmissions, queue depth, CPU, recovery |
| Wi-Fi to cellular handover | Interruption, overlap duration, extra energy |
| Screen off for extended period | Background wakeups, idle drain |
| Battery saver enabled | Session stability, wakeups, throughput, drain |
| Restricted network / unreachable relay | Retry count, radio wakeups, time to quiescence |
| Each user profile | Goodput, latency, flow count, CPU, energy per delivered byte |

Report at minimum:
- incremental mAh per hour and percentage points per hour;
- CPU time and average CPU utilization;
- wakeups and active radio time;
- throughput and goodput;
- median, p95 and p99 RTT;
- jitter, loss and reordering;
- reconnect time and handover interruption;
- device temperature and thermal throttling;
- active transport sessions, independent TURN flows, and logical streams as separate counts;
- allocation count and bytes allocated per packet in the data path.

Compare against the same device and network without GHONCHA. Repeat each scenario enough times to report variance, not only the best run. Test profile switching while connected, both screen-on and screen-off.

## 10. Acceptance gates

- No unbounded queues, busy loops, packet-per-task scheduling, or periodic connectivity polling.
- No keepalive when outbound application traffic already maintains the path.
- No retries while the network is unavailable.
- No stale timer or network event may revive an obsolete socket or session.
- No per-packet FFI crossing.
- No per-packet allocation in the selected production packet path unless measurements demonstrate it is negligible on every supported device class.
- Battery-saving mode must reduce measured energy per delivered byte or idle drain without violating protocol lifetimes or security invariants.
- Standard mode must verify whether the 30–40-flow target is supported and useful on the current path.
- Unlimited mode must increase concurrency only while aggregate goodput benefits and safety limits are respected.
- All three profiles must be switchable while connected without a VPN tunnel restart.
- The three-profile speed test must not run concurrently across profiles and must not silently interfere with user traffic.
- Performance changes are accepted only when repeated device measurements show a real improvement without unacceptable regressions in throughput, latency, loss, or reliability.
