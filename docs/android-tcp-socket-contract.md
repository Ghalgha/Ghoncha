# Android TCP underlay socket contract

Status: implementation contract for the TURN-over-TCP adapter. The Rust TURN engine does not create, connect, protect, or bind sockets. Android owns connection setup and transfers a connected stream to the Rust I/O layer.

## 1. Required connection sequence

For every TURN/TCP connection:

1. Resolve the TURN endpoint using the selected Android Network, not the process default network.
2. Create an unconnected SocketChannel and configure it non-blocking.
3. Call VpnService.protect(socket) and require a successful result.
4. Call Network.bindSocket(socket) while the socket is still unconnected.
5. Start SocketChannel.connect(endpoint).
6. Complete the non-blocking connect through finishConnect() after OP_CONNECT.
7. Verify the connected remote address and port match the selected TURN endpoint.
8. Transfer the connected descriptor and its ownership to the Rust I/O layer.

Illustrative Kotlin sequence:

~~~kotlin
val endpointAddress = network.getAllByName(turnHost).first()
val endpoint = InetSocketAddress(endpointAddress, turnPort)

val channel = SocketChannel.open()
channel.configureBlocking(false)
val socket = channel.socket()

check(vpnService.protect(socket)) {
    "VpnService.protect failed"
}
network.bindSocket(socket) // Must happen before connect.

val connectedImmediately = channel.connect(endpoint)
if (!connectedImmediately) {
    // Register OP_CONNECT and call finishConnect() when ready.
}
~~~

The example omits selector registration, error handling, descriptor transfer, and TLS. It is not a complete socket implementation.

Network.bindSocket(Socket) requires an unconnected socket. Do not connect first and attempt to bind afterwards. A failed protect or network bind is a hard setup failure; do not silently continue on the default network.

## 2. Socket ownership and I/O

- One connected TCP socket belongs to exactly one TURN client session.
- The socket is connected to the TURN server, not to the relayed peer.
- Rust receives the descriptor only after connection completion and remote endpoint validation.
- Define one owner for closing the descriptor. Kotlin and Rust must not both close it independently.
- Use readiness-driven non-blocking I/O. Do not run blocking InputStream or OutputStream operations on the VPN packet-processing thread.
- Limit each read and write service turn. The Rust driver accepts at most MAX_TURN_TCP_INPUT_CHUNK bytes per read and retains partial writes.
- A zero-byte read means EOF. A fatal read/write error retires the stream and its TURN allocation.
- Keep the stream connected to the exact server address checked by TurnTcpDriver; do not pass an arbitrary stream with a different peer endpoint.

## 3. TURN framing rules

The TCP connection carries TURN wire messages:

- STUN messages are parsed by their STUN header length.
- ChannelData messages use their TURN header and TCP padding rules.
- TCP may split one TURN message across reads or coalesce multiple messages into one read.
- The TURN parser must receive the byte stream exactly as read. Do not prepend the generic GHONCHA length-prefixed record header to TURN messages.
- Preserve byte order across partial writes. Never interleave the unwritten suffix of one TURN frame with another frame.
- A GHONCHA tunnel record is the peer payload inside TURN. Its own security and framing remain separate from TURN's framing.

The current adapter uses TURN over TCP with a UDP relay allocation. It does not implement RFC 6062 TCP relay allocations.

## 4. TLS

TLS must wrap the same connected, protected, network-bound TCP socket. The TLS implementation must:

- validate the TURN server certificate chain against the configured trust policy;
- verify the expected server name, not merely accept any valid certificate;
- use a maintained TLS implementation and an explicitly selected cryptographic provider;
- drive handshake reads and writes non-blockingly;
- preserve encrypted output across partial socket writes;
- expose only decrypted TURN stream bytes to TurnTcpEngine;
- fail closed on certificate, handshake, record-authentication, or truncation errors.

Do not treat TLS as implemented merely because the raw TCP driver accepts a generic stream socket. The current Rust driver supports a stream-socket abstraction; a production TLS wrapper and Android trust integration remain separate work.

## 5. Network handover and teardown

A connected TCP socket cannot be migrated to a different Android Network.

On network change:

1. Increment the network generation.
2. Stop admitting new tunnel records to the old stream.
3. Create a new socket and repeat protect, network binding, connect, and endpoint validation on the new Network.
4. Establish a fresh TURN session and verify it is ready.
5. Switch the transport selector to the new session.
6. Drain and deallocate the old TURN allocation when possible, then close the old socket.

Never reuse a socket from an earlier network generation or silently reconnect it through the process default network. If the new path fails, report the transport as unavailable rather than claiming the VPN is connected.

When sockets are explicitly bound to an Android Network, update VpnService.setUnderlyingNetworks() whenever the set of underlay networks used by the VPN changes.

## 6. Validation requirements

Android integration tests must cover:

- protect failure and network-bind failure;
- connection refusal, timeout, DNS failure, and endpoint mismatch;
- non-blocking connect completion and cancellation;
- split STUN headers, split STUN bodies, split ChannelData, and coalesced messages;
- partial writes, WouldBlock, EOF, and fatal socket errors;
- bounded parser buffering and bounded queue behavior;
- network handover while the old socket has queued bytes;
- TLS hostname mismatch, untrusted certificate, expired certificate, handshake failure, and abrupt close;
- ensuring the TURN socket never routes back through the VPN TUN interface.

Measure connection setup latency, RTT, jitter, throughput, queue delay, CPU, and battery use on both Wi-Fi and cellular networks.

## References

- [Android VpnService](https://developer.android.com/reference/android/net/VpnService)
- [Android Network.bindSocket](https://developer.android.com/reference/android/net/Network#bindSocket(java.net.Socket))
- [Android VPN guide](https://developer.android.com/develop/connectivity/vpn)
- [RFC 8656 — TURN](https://www.rfc-editor.org/rfc/rfc8656.html)
- [RFC 6062 — TURN TCP allocations](https://www.rfc-editor.org/rfc/rfc6062.html)
