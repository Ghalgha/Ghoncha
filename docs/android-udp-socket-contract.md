# Android UDP socket contract

Status: implementation contract; no Android application module or Kotlin socket adapter exists in this repository yet.

## Purpose

The TURN UDP driver owns one socket for one TURN Allocation. The Android layer is responsible for creating that socket on the intended underlay network and ensuring that tunnel transport packets do not re-enter the VPN TUN interface.

The Rust `TurnDatagramSocket` trait is only the I/O boundary. It does not call Android APIs and must not pretend that a generic `std::net::UdpSocket` is protected or bound to a particular Android `Network`.

## Required creation sequence

For every Allocation and every replacement socket:

1. Resolve the TURN server endpoint against the intended underlay network. Do not use an address cached from a previous network generation without revalidation.
2. Create a fresh, unconnected UDP socket.
3. Call `VpnService.protect(socket)` (or `protect(fd)`) and require a `true` result. On failure, close the socket and abort creation. Never send a probe or TURN request before protection succeeds.
4. Bind the unconnected socket to the selected Android `Network` using the supported `Network.bindSocket(...)` API. Treat binding failure as socket-creation failure; do not silently fall back to the process default network.
5. Bind a local address/port if required by the socket implementation, then configure non-blocking I/O and register it with the shared event loop.
6. Only after all preceding steps succeed, hand ownership to the Rust TURN driver and allow the first Allocate request.

The exact ordering of local bind and `Network.bindSocket` must follow the Android API overload and minimum SDK selected by the eventual app module. The invariant is that the socket is unconnected, protected, and bound to the selected Network before its first packet.

## Runtime invariants

- One independently managed socket per TURN Allocation. Do not multiplex multiple Allocations through one socket unless the TURN implementation explicitly supports that model.
- One shared event loop/runtime may drive many sockets. Do not create one operating-system thread or one async task per packet.
- Preserve the socket's native error for diagnostics; map only `WouldBlock` and fatal failure into the portable Rust error categories.
- A successful UDP send must report the complete datagram length. A short send is a fatal socket-contract violation; retire the socket and its Allocation state.
- Receive into bounded caller-owned storage. The platform adapter must detect datagram truncation where its API permits; never forward a truncated datagram as valid TURN input.
- A fatal I/O error, protection failure, or network-generation change invalidates the socket. Do not reuse it on a different underlay network.
- On network handover, create and protect replacement sockets on the new Network, establish replacement Allocations, then drain and retire old Allocations using the manager's deallocation lifecycle. Do not mutate the binding of a live socket and assume its existing TURN allocation moved with it.
- Call `VpnService.setUnderlyingNetworks(...)` when explicitly binding the VPN's upstream sockets and whenever the set of underlying Networks changes, as required by Android's API contract.
- Socket close and TURN server-side Allocation deletion are distinct events. A locally closed socket does not prove that the server released its Allocation; retain capacity accounting until deletion is confirmed or the server-side allocation expires under the recovery policy.

## Rust boundary

The Android adapter should implement `TurnDatagramSocket` over an owned native socket handle. The adapter must keep the handle alive for the entire driver lifetime and close it exactly once after the driver stops. The control plane may pass the socket handle/ownership token into Rust, but packet payloads must not cross FFI one packet at a time.

The current `TurnUdpDriver` does not create Android sockets, call `protect()`, bind a `Network`, register readiness events, or perform Android lifecycle callbacks. These remain unimplemented integration work.

## Required Android integration tests

Before claiming Android transport support, add instrumentation or device tests that verify:

- protection failure prevents the first send and closes the socket;
- the socket's observed route is the selected underlay Network, not the VPN TUN;
- a TURN Allocate request and response complete over the protected socket;
- `WouldBlock` preserves the queued datagram and later writable readiness sends it exactly once;
- a fatal send/receive error retires the socket and does not resurrect a stale Allocation;
- network handover creates a new socket/Allocation generation and drains the old one;
- repeated connect/disconnect cycles do not leak file descriptors or server allocations;
- Wi-Fi and cellular are tested separately, including IPv4 and IPv6 where available.

## Android references

- [VpnService API](https://developer.android.com/reference/android/net/VpnService): `protect()` excludes the tunnel socket from VPN routing; a false result must be treated as failure.
- [Android VPN guide](https://developer.android.com/develop/connectivity/vpn): describes protecting the tunnel socket and binding sockets to a specific Network.
