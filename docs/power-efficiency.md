# GHONCHA power efficiency

Status: implementation requirements and measurement plan.

## 1. Objective

Minimize incremental battery drain while preserving tunnel availability, security, and useful throughput. Do not optimize battery life by silently weakening authentication, replay protection, or packet delivery.

No battery-life claim is valid without measurements on physical Android devices. Report results separately for Wi-Fi and cellular, screen-on and screen-off, idle and active traffic, and normal and battery-saver modes.

## 2. Energy-critical design rules

- Keep the packet data plane in Rust. Do not cross JNI/UniFFI for individual packets.
- Use one event-driven I/O loop per active transport session. Do not create a task, thread, timer, or wakeup for every packet.
- Batch socket reads, writes, transport events, and TUN processing within explicit event and byte budgets.
- Reuse caller-owned packet buffers and bounded pools. Avoid per-packet heap allocation and full-packet copies.
- Apply backpressure before queues grow. Queue limits must be based on bytes as well as record count.
- Keep only the minimum required sockets, relay allocations, and transport sessions active.
- During path migration, allow temporary overlap only for a bounded handover window. Close the old path immediately after authenticated traffic succeeds on the new path.
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

## 4. Operating modes

### Active traffic

Prioritize throughput and bounded latency. Batch packet processing, reuse buffers, and avoid extra keepalives while traffic is flowing. Adapt queue sizes and pacing to measured congestion rather than increasing worker count.

### Connected and idle

Keep the authenticated session alive only when required by measured relay/NAT behavior and provider lifecycle. Sleep until the earliest actual protocol deadline. Do not probe multiple candidate transports in parallel.

### Screen off

Do not change cryptographic requirements or silently disconnect the tunnel. Suppress nonessential diagnostics, discovery, and speculative probes. Maintain only timers required for session validity and the selected path.

### Battery saver

Prefer one active path, longer permitted idle intervals, fewer diagnostic samples, and bounded retry budgets. Do not exceed a measured NAT/relay timeout to save power; if the path cannot be maintained safely, expose the limitation and wait for a meaningful network event.

### Network unavailable

Stop active retries when no usable network exists. Retain only non-secret cached configuration and schedule recovery from connectivity events. Do not hold a wake lock or repeatedly resolve DNS without a network.

## 5. Cryptographic and transport costs

- Perform DTLS handshake, certificate pin validation, and key derivation only at session establishment or deliberate rekey.
- Keep the established SRTP contexts alive across packets; never reconstruct contexts per packet.
- Enforce replay protection with a bounded sliding window.
- Rotate keys according to protocol limits and policy, not arbitrary short intervals that increase radio and CPU work.
- Avoid duplicate encryption layers when the threat model does not require them. The inner VPN authentication remains end-to-end; outer transport protection is independently authenticated.
- Measure cipher and packetization overhead on target Android ABIs. Hardware acceleration availability must be measured, not assumed.
- Reject an SRTP implementation for production if its packet hot path creates avoidable per-packet allocations or copies and a repeatable benchmark shows material CPU or battery cost.

## 6. Required measurements

Collect measurements in controlled runs with a stable device, fixed screen brightness, fixed radio conditions, and a recorded OS/build version.

| Scenario | Required observations |
|---|---|
| Baseline, VPN off | Idle and active power draw |
| VPN connected, no application traffic | Incremental idle drain, wakeups, radio activity |
| Low-rate traffic | CPU, packets/s, wakeups, battery drain |
| Sustained download and upload | Goodput, CPU, temperature, battery drain |
| Loss and high RTT | Retransmissions, queue depth, CPU, recovery |
| Wi-Fi to cellular handover | Interruption, overlap duration, extra energy |
| Screen off for extended period | Background wakeups, idle drain |
| Battery saver enabled | Session stability, wakeups, throughput, drain |
| Restricted network / unreachable relay | Retry count, radio wakeups, time to quiescence |

Report at minimum:
- incremental mAh per hour and percentage points per hour;
- CPU time and average CPU utilization;
- wakeups and active radio time;
- throughput and goodput;
- median, p95 and p99 RTT;
- jitter, loss and reordering;
- reconnect time and handover interruption;
- device temperature and thermal throttling;
- allocation count and bytes allocated per packet in the data path.

Compare against the same device and network without GHONCHA. Repeat each scenario enough times to report variance, not only the best run.

## 7. Acceptance gates

- No unbounded queues, busy loops, packet-per-task scheduling, or periodic connectivity polling.
- No keepalive when outbound application traffic already maintains the path.
- No retries while the network is unavailable.
- No stale timer or network event may revive an obsolete socket or session.
- No per-packet FFI crossing.
- No per-packet allocation in the selected production packet path unless measurements demonstrate it is negligible on every supported device class.
- Battery-saver mode must reduce measured idle energy without violating protocol lifetimes or security invariants.
- Performance changes are accepted only when repeated device measurements show a real improvement without unacceptable regressions in throughput, latency, loss, or reliability.
