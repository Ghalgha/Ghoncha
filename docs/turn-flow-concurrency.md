# TURN independent-flow concurrency

Status: implementation specification; the flow manager and multi-allocation runtime are not implemented yet.

## Terminology

GHONCHA uses **independent flow** to mean one independently established TURN allocation and its client-side transport path. It does not mean an OS thread, task, TURN Channel, peer permission, RTP stream, or packet queue.

A TURN allocation is identified by its client/server transport 5-tuple and owns its relayed transport address, authentication state, expiry, permissions, and channel bindings. RFC 8656 requires a second allocation to use a different 5-tuple; for a UDP client this normally means a distinct local source port (and therefore a distinct bound UDP socket) for each allocation. A TURN Channel is only a framing/binding optimization inside one allocation and does not create another independent allocation.

References:
- [RFC 8656, Sections 5–6: allocations and 5-tuples](https://www.rfc-editor.org/rfc/rfc8656.html#section-5)
- [RFC 8656, Section 17: security considerations and allocation quotas](https://www.rfc-editor.org/rfc/rfc8656.html#section-17)

## Required allocation model

Each active UDP flow owns:

- one UDP socket bound to the selected Android `Network`, with a unique local source port;
- one `TurnUdpEngine` and its complete allocation state;
- independent Allocate/authentication, permission, ChannelBind, Refresh, and deletion lifecycles;
- its own bounded transmit/receive accounting and health observations;
- the network-generation value under which it was created.

The socket owner must call `VpnService.protect()` before sending through the socket and must bind it to the selected Android network. The Sans-I/O TURN engine must not create sockets, threads, timers, or an async runtime. A flow's socket and engine are created and retired together.

A dual-stack relay allocation is not automatically two independent concurrency flows. It is one allocation with the address-family behavior negotiated for that allocation. Likewise, multiple peers or channels within one allocation do not increase the independent-allocation count.

## Flow manager contract

The future manager should be a bounded control-plane/data-plane component with caller-owned storage. It must:

1. Allocate one slot per configured maximum independent flow; never allocate memory proportional to packet rate.
2. Assign a unique local UDP port and socket to each new allocation. If the platform cannot provide another usable socket/port, report a transport capacity limit rather than pretending the flow exists.
3. Advance each allocation's protocol state independently. A permission, channel, refresh, or socket failure in one slot must not corrupt other slots.
4. Add at most a configured small number of allocations per ramp interval. Do not burst-create 30–40 allocations at profile selection time.
5. Drain a retiring flow: stop assigning new records to it, allow bounded in-flight work to complete, send allocation deletion when possible, then close its socket.
6. On network-generation change, invalidate old measurements and timers, stop using stale sockets, and establish replacement allocations on the new network under a bounded overlap budget.
7. Bound all per-flow and aggregate queues by both record count and bytes. Apply backpressure to the packet engine rather than dropping unbounded work into queues.
8. Use a stable flow-selection policy that preserves packet ordering for each inner transport flow. Do not stripe consecutive packets of one inner flow across TURN allocations unless the tunnel layer explicitly tolerates and repairs reordering.
9. Use fair scheduling so one busy allocation cannot starve others. Keep per-flow counters and report active, establishing, draining, failed, and capacity-limited states separately.
10. Never interpret the profile's desired count as a guarantee that the TURN service, account, network, or Android device will allow that many allocations.

## Profile behavior

The profile policy in `crates/transport-api/src/profiles.rs` is a desired-concurrency policy, not an allocation manager:

- **Unlimited:** start with one allocation; add gradually only while measured marginal goodput remains useful. There is no product-imposed maximum, but adapter, service quota, network, and device limits remain binding.
- **Standard:** ramp toward 35 allocations, within the 30–40 target range, subject to the actual adapter and service limits.
- **EnergySaving:** start and idle at one allocation; add only when measured demand or sustained queue pressure requires it; retire excess allocations after a sustained idle interval.

RFC 8656 recommends that TURN servers enforce per-username allocation-count and bandwidth quotas and reject allocations beyond quota with 486 (Allocation Quota Exceeded). Consequently, profile resolution must consume the adapter's currently known capacity and runtime allocation failures must lower the effective capacity. Do not assume that valid credentials imply permission for 35 or more allocations.

The current profile API starts with one flow for every profile and emits one-step recommendations. The runtime must implement gradual ramping, cooldown/hysteresis, failure backoff, and drain completion. A profile switch changes the desired count; it must not restart the VPN tunnel. If an adapter cannot resize live, surface that limitation explicitly.

## Throughput and scheduling constraints

Independent allocations can expose additional parallel capacity when a relay, gateway, or network path limits each allocation. They do not guarantee linear scaling: all allocations may share the same client radio, access link, NAT, relay host, gateway CPU, or server-side quota. Each added allocation also consumes socket state, TURN server resources, refresh traffic, radio wakeups, and battery.

The controller must use measured marginal application goodput, not a fixed assumed Mbps-per-allocation value. Evaluate each added allocation after its setup and warm-up period; stop increasing concurrency when marginal gain falls below the configured useful threshold, loss/latency rises materially, or resource limits are reached. Keep throughput measurements separate from protocol-control traffic.

Packet scheduling should prefer flow affinity (for example, a stable hash of the inner 5-tuple) so packets belonging to the same inner flow remain on one allocation. Reassign affinity only when a flow is added, removed, or fails, and account for any transient reordering. A global round-robin scheduler across packets is not acceptable for a transport carrying latency-sensitive TCP/UDP traffic.

## Implementation and verification gates

Before enabling multi-allocation concurrency in a user build:

- Add deterministic Sans-I/O tests for slot lifecycle, allocation isolation, bounded ramping, backpressure, drain, partial failure, and network-generation invalidation.
- Add socket-layer integration tests proving distinct local ports and distinct 5-tuples for simultaneous allocations.
- Test allocation quota exhaustion (486), stale nonce, permission expiry, channel expiry, refresh failure, and server restart.
- Test Wi-Fi/cellular handover with bounded overlap and no stale-socket reuse.
- Benchmark 1, 2, 4, 8, 16, 32, and 40 allocations where the service permits; record aggregate and per-allocation goodput, RTT, jitter, loss, CPU, memory, radio wakeups, and energy on real Android devices.
- Compare stable flow-affinity scheduling against alternative scheduling under packet reordering and mixed interactive/bulk traffic.
- Do not publish a per-flow throughput guarantee or battery-saving claim without repeatable measurements across devices and networks.

Until these gates pass, the existing `TurnUdpEngine` remains a single-allocation protocol adapter and the profile API remains policy/orchestration scaffolding only.
