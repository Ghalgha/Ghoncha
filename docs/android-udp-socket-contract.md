# Android UDP socket contract

Status: the Android app contains a testable UDP socket factory, real Android Network/VpnService callback adapter, JNI descriptor ownership, a local TUN lifecycle service, and a heap-owned multi-allocation TURN runtime core. The runtime core dispatches timer and readiness work by opaque registration token, but the Android poller is not yet connected to it; TUN packet I/O, packet routing, and device-level route validation remain unimplemented.

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

The current `UnderlayDatagramSocketFactory` takes a network-scoped DNS resolver, `VpnService.protect()` callback, `Network.bindSocket()` callback, and network-generation number. It resolves before creating the socket, then calls `protect()`, binds to the selected network, binds an ephemeral local port, and switches the channel to non-blocking mode. The channel family is selected from the resolved IPv4/IPv6 address and checked against the resulting local address. `AndroidUnderlayDatagramSocketFactory` supplies the real Android `Network.getAllByName()`, `VpnService.protect()`, and `Network.bindSocket()` APIs. The factory rejects stale network generations before DNS and after preparation. `PreparedUnderlayDatagramSocket.transferToNative()` creates a stable `ParcelFileDescriptor` duplicate, passes its descriptor to JNI, and closes the Java channel only after native adoption succeeds. The native layer duplicates the descriptor again, verifies `SO_TYPE == SOCK_DGRAM`, sets `FD_CLOEXEC` and `O_NONBLOCK`, and stores the owned descriptor behind an opaque handle. This double-dup sequence also avoids the pre-API-29 `fromDatagramSocket()` descriptor-lifetime issue. `NativeUdpSocketHandle` closes the native duplicate unless Rust has taken ownership through `take_udp_socket()`. JVM tests cover factory ordering, DNS failure, unusable answers, invalid ports, address-family selection, non-blocking mode, and stale-generation rejection. Native JNI build verification is still pending. The native handle is not yet registered with the TURN driver or a poll/epoll reactor.

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

The native crate now provides `take_android_udp_socket(handle)`: it consumes the JNI registry entry, converts the `OwnedFd` into `std::net::UdpSocket`, enforces non-blocking mode, and implements `TurnDatagramSocket`. The returned `AndroidUdpSocket` can be passed directly to `TurnUdpDriver::new`. Dropping the socket closes the native descriptor. The crate also provides a fixed-capacity, level-triggered `AndroidUdpPoller` based on `poll(2)`, with registration tokens, bounded event output, and explicit unregister-before-close semantics. The TURN driver now returns `next_deadline` as a `MonotonicTime` alongside each protocol poll result. `TurnUdpReactor::wait_duration(now, max_wait)` converts the earliest armed timer or ready work into a bounded OS-poller wait, avoiding periodic scans. The caller must re-read its monotonic clock after `poll(2)` returns, drain due allocation IDs, service matching drivers, and reschedule their next deadlines. `NativeUdpSocketHandle.transferToRust()` calls the JNI `consumeUdpSocket()` entry point, which removes the pending `OwnedFd`, creates a non-blocking `AndroidUdpSocket`, and stores it in a native adopted-socket registry under the same opaque token. Kotlin's closeable wrapper becomes inert only after this succeeds. The native runtime can later claim the socket with `take_adopted_udp_socket()`; until then it can be closed with `closeAdoptedUdpSocket()`. The `TurnUdpRuntime<S, CAPACITY>` owns one boxed `TurnUdpDriver<S>` per allocation, maps stable poller tokens to drivers, exposes the earliest protocol deadline, advances due timers with a persistent bounded scan cursor, dispatches readiness to the matching driver, and reports whether each token has queued output so the platform can enable or disable writable interest. Box allocation is fallible and each driver's queue stores are allocated fallibly. The caller must unregister the token before `remove()` and dropping the returned driver. `AndroidTurnUdpRuntime<CAPACITY>` connects this portable runtime to the adopted Android socket registry and `AndroidUdpPoller`; it consumes adopted socket handles, creates TURN drivers, registers read interest, dispatches readiness, advances timers under a caller-supplied budget, enables writable interest only while output is queued, derives a bounded wait from the earliest deadline, and unregisters before removing a driver/socket. The integration remains synchronous: one lifecycle owner must serialize calls, run due timer work before waiting, service returned events, and stop before dropping the object. No worker is started, no TUN fd is polled, and peer payloads are not yet connected to the IP packet router. TURN control and peer-data queues use fallible heap allocation while preserving fixed capacity limits; runtime code should use `try_new()` rather than infallible convenience constructors. Packet payloads must not cross FFI one packet at a time.

`AndroidTurnUdpRuntime<CAPACITY>` now connects the adopted-socket registry, `AndroidUdpPoller`, and `TurnUdpRuntime<AndroidUdpSocket, CAPACITY>`. It consumes an adopted socket handle, creates a TURN driver, registers its stable token with read interest, dispatches poller events to the matching driver, advances protocol timers under a caller-supplied budget, and enables writable interest only while output is queued. It also derives a bounded poll timeout from the earliest TURN deadline and unregisters the token before removing the driver/socket. The integration object deliberately starts no thread: one lifecycle owner must serialize its methods, run timer work before waiting, service returned events, and stop before dropping the object. Socket errors are surfaced to that owner, which must retire the affected allocation. This stage still does not connect the runtime to `GhonchaVpnService`, poll the TUN fd, or route peer payloads into the IP packet router. The next stage is a service-owned worker with explicit cancellation/join semantics, followed by TUN readiness and packet routing.

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


## Runtime performance and network-resilience constraints

The Android TURN owner must remain event-driven. It must wait against the earliest protocol deadline, service only returned readiness events, and avoid busy polling or per-allocation worker threads. Keep writable interest disabled while no output is queued, use bounded per-call work budgets, and rely on protocol timers rather than background keepalive loops. Network fallback and recovery belong to the higher-level lifecycle owner and must be driven by measured reachability/failure state, bounded backoff, and validated transport compatibility. Before enabling a fallback, record the reason for the transition and enforce a cooldown to prevent rapid path flapping. Do not add dummy packets, random padding, or parallel probes to this low-level runtime; those add radio/CPU cost and do not establish censorship resistance.