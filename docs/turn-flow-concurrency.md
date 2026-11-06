# TURN independent-flow concurrency

Status: implementation specification; the flow manager and multi-allocation runtime are not implemented yet.

## Terminology

GHONCHA uses **independent flow** to mean one independently established TURN allocation and its client-side transport path. It does not mean an OS thread, task, TURN Channel, peer permission, RTP stream, or packet queue.

A TURN allocation is identified by its client/server transport 5-tuple and owns its relayed transport address, authentication state, expiry, permissions, and channel bindings. RFC 8656 requires a second allocation to use a different 5-tuple; for a UDP client this normally means a distinct local source port (and therefore a distinct bound UDP socket) for each allocation. A TURN Channel is only a framing/binding optimization inside one allocation and does not create another independent allocation.

References:
- [RFC 8656, Sections 5–6: allocations and 5-tuples](https://www.rfc-editor.org/rfc/rfc8656.html#section-5)
- [RFC 8656, Section 17: security considerations and allocation quotas](https://www.rfc-editor.org/rfc/rfc8656.html#section-17)

## What the implementation study established

The source-level study of several independent TURN-over-calling-transport clients established the following recurring design patterns. These are architectural observations, not performance guarantees.

### One worker owns one transport session

A data worker is not just a thread reading from a shared TURN socket. In the more complete implementations, each worker creates and owns:

- one distinct UDP socket bound to an ephemeral local port, or one distinct TCP/TLS connection;
- one TURN client and one independent TURN Allocation;
- its own authentication, Allocate, Permission, ChannelBind, Refresh, and Deallocate lifecycle;
- one end-to-end protected session to the remote tunnel endpoint;
- bounded send/receive queues and its own health/retry state.

For UDP, binding each socket independently to port zero lets the OS assign distinct local ports. For TCP/TLS, each independent transport connection has its own TCP 5-tuple. The runtime must expose the actual local and remote socket addresses so uniqueness can be verified, not inferred from a worker ID.

The protected tunnel session is layered over the TURN allocation. The TURN allocation is not itself the VPN gateway: the remote GHONCHA gateway still terminates the end-to-end tunnel and processes inner IP packets.

### Many workers do not require one OS thread each

The studied Rust design uses asynchronous tasks supervised by a multi-thread Tokio runtime. Each worker runs an independent session state machine; its allocation has its own protocol driver and bounded I/O queues. Runtime threads are selected from available CPU parallelism rather than creating a native thread for every allocation. One examined implementation used a starting heuristic of approximately one runtime thread per eight configured workers, capped by available parallelism. That ratio is a reference point only, not a GHONCHA default: Android CPU topology, scheduler behavior, blocking operations, and power cost must be measured.

The Go implementation follows a different model: goroutines supervise worker groups, while each session owns separate reader, writer, and keepalive goroutines. This is also not one OS thread per worker. Both approaches confirm that **allocation concurrency and execution-thread count are separate controls**.

GHONCHA should begin with a small bounded async runtime and non-blocking I/O. Do not create one native thread per TURN allocation. Do not run blocking DNS, filesystem, or SDK work on the packet-processing executor; isolate unavoidable blocking operations.

### Credential cohorts and quota handling

A mature implementation groups workers into credential cohorts. A cohort obtains TURN credentials once and leases them to a bounded number of independent allocation attempts. The studied implementation used cohorts of ten, serialized credential acquisition, and paced allocation starts at roughly 100 ms intervals. It tracked allocation attempts, successful allocations, stale credentials, quota rejection, and credential rotation separately.

This is evidence that credential acquisition and allocation establishment are different concurrency bottlenecks. A valid credential does not imply unlimited allocations. RFC 8656 permits servers to enforce per-user allocation quotas and return 486 (Allocation Quota Exceeded). GHONCHA must not assume that a single VK Calls credential can sustain 30–40 allocations, nor assume that each worker necessarily requires a fresh VK call. Credential-to-allocation cardinality must be measured against the actual VK-issued credentials and server behavior.

The implementation should represent credential leases explicitly, track the number of active and in-progress allocations per lease, and stop issuing new allocations when quota errors indicate exhaustion. Quota backoff must not cause every worker to refresh credentials simultaneously.

### Worker supervision and recovery

The studied designs isolate session failure: one worker can fail, release its allocation, wait with bounded backoff, and reconnect without restarting the entire tunnel. Group supervisors observe worker completion and only replace workers that are still within the desired target. Cancellation tokens or equivalent generation-scoped cancellation prevent stale workers from resurrecting after shutdown or network handover.

GHONCHA should distinguish at least:
- allocation establishment failure;
- credential/authentication failure;
- quota exhaustion;
- active allocation transport failure;
- end-to-end session failure;
- local network loss;
- intentional drain due to profile reduction.

A quota failure must reduce the effective capacity estimate; a transient socket failure should not. Retry jitter and a shared credential-fetch gate are required to prevent synchronized retry storms.

### Packet distribution: round-robin is not enough

A simple dispatcher in one implementation sends packets in small round-robin batches (twelve packets per worker), falling back to another worker if a bounded send queue is full. It uses a packet pool, per-worker queues, and a shared return queue. This is simple and parallel, but a packet-level or short-batch round-robin policy can move consecutive packets of the same TCP flow between independent paths. Different RTTs and queue depths can reorder packets and harm TCP performance.

A more advanced dispatcher parses the inner IPv4/IPv6 5-tuple and tracks flow state. It uses per-worker deficit/token accounting to select a healthy allocation with available capacity. Small latency-sensitive UDP flows can remain sticky to one worker; bulk TCP/UDP flows can be moved at bounded flowlet/burst boundaries instead of switching on every packet. The studied design used a bounded flow table, idle expiry, a burst budget, and per-worker congestion feedback.

GHONCHA should implement this in stages:

1. **Initial safe policy:** stable inner 5-tuple affinity to one allocation. This preserves ordering and is straightforward to test.
2. **Measured balancing:** select an allocation for each new inner flow using health, queue occupancy, and measured service rate.
3. **Optional flowlet scheduling:** only after reordering tests, allow bulk flows to migrate at explicit idle/burst boundaries. Keep small interactive UDP flows sticky.
4. **Failure recovery:** remap only flows assigned to a failed/draining allocation, with bounded transient reordering and observable remap counters.

Do not use global packet round-robin as the default scheduler. Fragmented IP packets must retain one allocation assignment for the complete reassembled inner datagram or be handled by an explicitly tested fragmentation-aware policy.

### Bounded memory and backpressure

The studied implementations use bounded per-worker send queues, bounded aggregate ingress queues, reusable packet buffers, and explicit handling for queue-full conditions. One design uses a fixed packet pool and a bounded lock-free queue; another uses fixed-capacity channels. Neither permits memory growth proportional to packet rate.

GHONCHA should cap both records and bytes, not only channel item count. Queue-full behavior must be explicit: apply backpressure where possible, drop according to a documented priority policy where unavoidable, and count every drop. Control-plane messages must not be starved by bulk data. Avoid per-packet task creation, per-packet heap allocation, and copies between layers.

### Start pacing and dynamic scaling

The reference implementations avoid starting all allocations at once. One uses a global start pacer; another starts workers in credential groups with a delay between workers and gates subsequent groups on credential/spawn progress. This reduces simultaneous VK credential requests, TURN Allocate bursts, CPU spikes, and radio activity.

For GHONCHA, use one central ramp controller rather than independent worker loops deciding to scale themselves. The controller should:
- start with one allocation;
- add at most one allocation per ramp interval by default;
- permit a small configurable burst only when measurements justify it;
- observe setup completion and a warm-up window before judging marginal goodput;
- stop increasing on quota, loss, RTT, queue, CPU, or energy limits;
- use cooldown/hysteresis to prevent oscillation;
- drain allocations gradually on profile reduction.

The exact ramp interval must be measured. The 100 ms value observed elsewhere is not automatically suitable for VK Calls or Android.

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
