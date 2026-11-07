package org.ghoncha.app

import java.io.Closeable
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * Kotlin's closeable owner for a UDP descriptor duplicated into the Rust registry.
 *
 * Closing this handle closes the native duplicate. Once a Rust reactor takes
 * ownership through the crate's internal take_udp_socket API, the reactor must
 * retire the OwnedFd itself and this wrapper must not be closed concurrently.
 */
internal class NativeUdpSocketHandle internal constructor(
    nativeHandle: Long,
    val serverAddress: InetSocketAddress,
    val localAddress: InetSocketAddress,
    val networkGeneration: Long,
) : Closeable {
    private val handle = AtomicLong(nativeHandle.also {
        require(it > 0) { "Native UDP handle must be positive" }
    })

    override fun close() {
        val value = handle.getAndSet(0)
        if (value != 0L) {
            check(NativeBootstrap.closeUdpSocket(value)) {
                "Native UDP socket handle was already transferred or closed"
            }
        }
    }
}
