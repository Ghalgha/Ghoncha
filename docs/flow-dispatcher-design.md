# GHONCHA flow dispatcher design

Status: design specification; no multi-allocation dispatcher is implemented yet.

## Objective

The dispatcher must maximize useful end-to-end application goodput while preserving correctness, latency, fairness, bounded memory, and predictable energy use. The number of TURN allocations is only available parallel capacity; it is not a scheduling strategy.

GHONCHA must not assume that adding allocations automatically increases throughput. A weak dispatcher can leave capacity unused, overload a subset of allocations, or reduce throughput through packet reordering.

## Failure mode to guard against

A hash dispatcher may calculate a flow-to-worker assignment but fail to implement the intended migration/rebalancing behavior. In that state, a few long-lived high-volume flows can remain pinned to slow or congested allocations while other allocations are idle. The configured worker count can look healthy even though useful capacity is not being used.

Treat this as a first-class failure hypothesis, not as a proven explanation for every low-throughput result. Instrument the scheduler so this failure is visible.

A stable hash alone is not sufficient. It provides affinity, but does not guarantee balanced load, account for heterogeneous path capacity, or move a flow away from a degraded allocation. Conversely, moving packets arbitrarily to chase instantaneous queue differences can reorder packets and damage TCP performance.

## Scheduling model

Use a layered scheduler with distinct decisions:

1. **Flow identification:** parse the inner IP packet and derive a canonical flow key from address family, source/destination addresses, protocol, and transport ports when present. Handle IPv4 fragments, IPv6 extension headers, ICMP, and non-initial fragments explicitly. Do not invent transport ports for fragments that do not contain them.
2. **Initial placement:** assign a new flow to an eligible allocation using measured service capacity, queue pressure, health, loss, RTT, and current assigned load. Use deterministic tie-breaking to avoid placement oscillation.
3. **Affinity:** keep packets of an established flow on the selected allocation while it remains healthy and within its operating envelope.
4. **Rebalancing:** move eligible bulk flows only at safe flowlet boundaries or another explicitly validated migration boundary. Never stripe consecutive packets of a TCP flow across allocations by default.
5. **Failure remapping:** when an allocation fails or is drained, remap only its affected flows. Record the reason and expected reordering exposure.

The flow table must be bounded by both entry count and memory bytes, have deterministic expiry, and expose eviction counters. A flow-table miss must have a safe deterministic placement path.

## Avoiding hash imbalance

A plain modulo hash over worker IDs is unsuitable as the complete policy: changing the worker count can remap many flows, and hash balance by flow count does not imply balance by byte rate.

The implementation should evaluate:
- rendezvous/consistent hashing for stable initial placement when the eligible set changes;
- weighted placement using measured allocation service rate rather than equal worker weights;
- per-allocation queued bytes, queue age, in-flight bytes, loss, RTT, and recent goodput;
- elephant-flow detection so a small number of high-volume flows do not dominate a worker unnoticed;
- bounded flowlet migration for eligible bulk traffic;
- hysteresis, minimum dwell time, and a cooldown after migration to prevent ping-pong.

Do not use instantaneous queue length as the only signal. It is noisy and can cause synchronized migration that moves congestion rather than relieving it. Smooth measurements over defined windows, retain raw counters for diagnosis, and require a meaningful predicted gain before migration.

## Flowlet migration

A flowlet is a burst of packets separated from the next burst by an idle gap. Migration is permitted only when the measured gap is large enough relative to path-delay difference to keep the probability of reordering within the configured bound.

The threshold must be adaptive to observed path RTT/variation and must have a conservative floor. If the scheduler cannot establish a safe boundary, keep the flow pinned. Do not claim that a generic fixed gap is safe across VK Calls paths.

For latency-sensitive interactive UDP, default to sticky placement. Bulk TCP and bulk UDP may be eligible for flowlet migration after real-path tests demonstrate that it improves goodput without unacceptable reordering, retransmissions, jitter, or loss.

## Fragmentation and flow identity

Fragment handling must be explicit:
- IPv4 non-initial fragments do not contain transport ports. Associate them with the first fragment using a bounded fragment-affinity cache keyed by source, destination, protocol, and IPv4 identification, with strict expiry.
- IPv6 fragments require equivalent fragment identification handling. Extension-header traversal must be bounded and standards-aware.
- If fragment association is unavailable or ambiguous, use a conservative fallback that keeps the datagram's fragments together where possible; never distribute fragments independently across allocations.
- Non-TCP/UDP traffic still needs stable keys and bounded state. ICMP query identifiers may be used when safely parsed; otherwise use a documented address/protocol affinity fallback.

The current packet parser's IPv6 extension-header limitations mean the dispatcher must not assume it can correctly derive every IPv6 transport flow yet. Gate advanced scheduling until parser coverage is implemented and tested.

## Capacity and feedback

Maintain independent observations for each allocation:
- delivered application bytes and packets;
- estimated service rate and marginal contribution;
- queue bytes, queue age, drops, and backpressure events;
- RTT distribution, jitter, loss, and retransmission indicators where observable;
- allocation age, refresh health, and transport errors;
- CPU and memory cost attributable to scheduling and I/O.

Distinguish relay-path performance from end-to-end gateway performance. A slow flow may be limited by the remote gateway, radio, or destination rather than its TURN allocation. Use controlled probes and application measurements carefully; do not infer per-allocation capacity from aggregate tunnel throughput alone.

The controller must compare marginal goodput before and after adding an allocation. It must also detect when an allocation contributes little because the dispatcher never sends it enough eligible traffic. That is a scheduler utilization defect, not evidence that the allocation itself is slow.

## Backpressure and fairness

Each allocation has bounded transmit and receive queues, bounded by records and bytes. The scheduler must:
- avoid assigning new bulk work to a saturated allocation;
- preserve flow affinity unless a validated migration boundary is reached;
- prevent one elephant flow from starving interactive traffic;
- apply a documented priority policy to control, interactive, and bulk classes;
- account for queue-full drops and rejected enqueue attempts;
- use fair service across eligible allocations without packet-level round-robin that breaks flow ordering.

Control traffic must not be starved by bulk queues. Do not create a task, thread, timer, or heap allocation per packet.

## Profile integration

The three profiles change the desired allocation budget and scheduling aggressiveness, not packet correctness:

- **Unlimited:** add allocations while measured marginal end-to-end goodput remains useful and service/device/network limits permit. Use adaptive weighted placement and carefully gated flowlet migration when validated.
- **Standard:** ramp toward the 30–40 allocation target range, normally around 35, but keep conservative flow affinity and bounded rebalancing.
- **EnergySaving:** minimize active allocations and scheduler work. Prefer sticky placement; avoid continuous probes and frequent remapping. Expand only under sustained demand/queue pressure.

A live profile change must update scheduler policy without restarting the VPN. Reconfiguration must preserve packet ordering for flows that remain on the same allocation and explicitly account for flows whose allocation is drained.

## Required telemetry

Expose at least:
- active/eligible/healthy allocation counts;
- per-allocation assigned flow count and assigned bytes;
- per-allocation delivered bytes, goodput, queue bytes/age, drops, RTT, jitter, and loss;
- number of flows pinned, migrated, remapped, and rejected for migration;
- migration reason, source/destination allocation, and observed before/after performance;
- flow-table hits, misses, evictions, fragment-cache hits/misses/expiry;
- allocation utilization and time spent idle while eligible flows are queued elsewhere;
- scheduler CPU time and memory footprint.

A dashboard showing only active worker count and aggregate speed is insufficient to diagnose dispatcher failure.

## Verification plan

Before enabling adaptive dispatch in a user build:

1. Unit-test canonical flow keys for IPv4, IPv6, TCP, UDP, ICMP, fragments, malformed headers, and unsupported extension chains.
2. Prove stable affinity: packets of one flow remain on one allocation unless a recorded migration/remap event occurs.
3. Test heterogeneous allocation capacities and demonstrate that weighted placement improves byte distribution without oscillation.
4. Create elephant-flow and many-small-flow workloads; compare flow-count balance with byte-rate balance.
5. Inject queue saturation, RTT changes, loss, allocation failure, quota rejection, and network handover.
6. Test flowlet migration with controlled path-delay asymmetry and packet capture; measure reordering, TCP retransmissions, goodput, jitter, and loss.
7. Compare at least: single allocation, stable hash affinity, weighted new-flow placement, and flowlet migration.
8. Run mixed interactive and bulk workloads over Wi-Fi and cellular on real Android devices.
9. Verify that the dispatcher uses additional allocations when useful eligible traffic exists, and does not confuse idle allocations with a lack of transport capacity.
10. Publish no claim of superior throughput until repeatable measurements show gains without unacceptable latency, energy, or correctness regressions.

## Implementation sequence

1. Complete packet parsing needed for safe flow keys, including bounded IPv6 extension-header and fragment handling.
2. Implement deterministic bounded flow table and stable affinity only.
3. Add per-allocation telemetry and utilization diagnostics.
4. Add weighted placement for new flows.
5. Add hysteresis and controlled failure/drain remapping.
6. Prototype flowlet migration behind an experimental feature flag.
7. Enable adaptive migration by default only after benchmark and real-device gates pass.

Until then, stable flow affinity is the correctness baseline. More allocations must never be presented as proof of effective parallelism.
