# Android UDP socket contract

Status: the Android app contains a VpnService lifecycle shell, a no-route TUN interface, and native ownership transfer for the detached TUN descriptor. It also contains a testable UDP socket factory, real Android Network/VpnService callback adapter, and UDP descriptor-ownership boundary. The TUN descriptor is not yet consumed by a packet worker; no routes are installed and no traffic is forwarded.

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

`UnderlayNetworkMonitor` observes all candidate networks with `NET_CAPABILITY_INTERNET` and `NET_CAPABILITY_NOT_VPN`; it deliberately does not choose a preferred network. It publishes snapshots with validation, metering, transport flags, and a per-network generation. Capabilities or link-property changes advance that generation; loss removes it. A socket owner must capture the generation when opening a socket and compare it against `currentGeneration(network)` before every operation that can create or reuse an allocation. The generation registry is monotonic across loss/reconnect so a stale callback cannot become current merely because the same `Network` identity reappears.

The current `UnderlayDatagramSocketFactory` takes a network-scoped DNS resolver, `VpnService.protect()` callback, `Network.bindSocket()` callback, and network-generation number. It resolves before creating the socket, then calls `protect()`, binds to the selected network, binds an ephemeral local port, and switches the channel to non-blocking mode. The channel family is selected from the resolved IPv4/IPv6 address and checked against the resulting local address. `AndroidUnderlayDatagramSocketFactory` supplies the real Android `Network.getAllByName()`, `VpnService.protect()`, and `Network.bindSocket()` APIs. The factory rejects stale network generations before DNS and after preparation. `PreparedUnderlayDatagramSocket.transferToNative()` creates a stable `ParcelFileDescriptor` duplicate, passes its descriptor to JNI, and closes the Java channel only after native adoption succeeds. The native layer duplicates the descriptor again, verifies `SO_TYPE == SOCK_DGRAM`, sets `FD_CLOEXEC` and `O_NONBLOCK`, and stores the owned descriptor behind an opaque handle. This double-dup sequence also avoids the pre-API-29 `fromDatagramSocket()` descriptor-lifetime issue. `NativeUdpSocketHandle` closes the native duplicate unless Rust has taken ownership through `take_udp_socket()`. JVM tests cover factory ordering, DNS failure, unusable answers, invalid ports, address-family selection, non-blocking mode, and stale-generation rejection. Native JNI libraries are cross-compiled by CI for all four Android ABIs. Device-level descriptor adoption and TURN driver/reactor integration remain unverified.

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

The native crate now provides `take_android_udp_socket(handle)`: it consumes the JNI registry entry, converts the `OwnedFd` into `std::net::UdpSocket`, enforces non-blocking mode, and implements `TurnDatagramSocket`. The returned `AndroidUdpSocket` can be passed directly to `TurnUdpDriver::new`. Dropping the socket closes the native descriptor. The crate also provides a fixed-capacity, level-triggered `AndroidUdpPoller` based on `poll(2)`, with registration tokens, bounded event output, and explicit unregister-before-close semantics. The TURN driver now returns `next_deadline` as a `MonotonicTime` alongside each protocol poll result. `TurnUdpReactor::wait_duration(now, max_wait)` converts the earliest armed timer or ready work into a bounded OS-poller wait, avoiding periodic scans. The caller must re-read its monotonic clock after `poll(2)` returns, drain due allocation IDs, service matching drivers, and reschedule their next deadlines. `NativeUdpSocketHandle.transferToRust()` calls the JNI `consumeUdpSocket()` entry point, which removes the pending `OwnedFd`, creates a non-blocking `AndroidUdpSocket`, and stores it in a native adopted-socket registry under the same opaque token. Kotlin's closeable wrapper becomes inert only after this succeeds. The native runtime can later claim the socket with `take_adopted_udp_socket()`; until then it can be closed with `closeAdoptedUdpSocket()`. The poller is not yet wired to a persistent multi-allocation TURN manager or an Android VPN service. `TurnUdpDriver` now allocates its bounded control and peer-data queue stores on the heap through fallible constructors; the const record/byte limits remain unchanged, and driver construction reports `TurnError::AllocationFailed` instead of placing hundreds of kilobytes of queue storage on the caller's stack. The convenience queue `new()` constructors retain their infallible API and panic only if allocation fails; runtime code should use `try_new()`. Packet payloads must not cross FFI one packet at a time.

The Android VPN service now establishes a local TUN interface with one IPv4 host address and deliberately adds no routes. It detaches the `ParcelFileDescriptor` and transfers the raw fd to a dedicated Rust `OwnedFd` registry. The Kotlin closeable handle can close the native-owned descriptor; the future packet runtime can claim it through `take_tun_interface()`. Rust enforces `FD_CLOEXEC` and `O_NONBLOCK` on adoption. The service is not a functioning VPN: it starts no packet worker, does not read or write TUN packets, installs no routes, and displays an explicit notification that forwarding is inactive. Always-on VPN support is disabled until the full data plane is available.

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
