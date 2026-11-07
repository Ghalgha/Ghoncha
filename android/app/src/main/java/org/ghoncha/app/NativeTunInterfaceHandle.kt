package org.ghoncha.app

import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.util.concurrent.atomic.AtomicLong

/**
 * Closeable Kotlin owner for a TUN descriptor adopted by the Rust registry.
 *
 * This handle does not mean that packets are being processed. The native
 * packet runtime must explicitly claim the descriptor before traffic can flow.
 */
internal class NativeTunInterfaceHandle internal constructor(
    handle: Long,
    private val closeNativeHandle: (Long) -> Boolean = { NativeBootstrap.closeTunInterface(it) },
) : Closeable {
    private val nativeHandle = AtomicLong(handle.also {
        require(it > 0) { "Native TUN handle must be positive" }
    })

    /**
     * Releases the token to a native runtime entry point. The caller must pass
     * it to that entry point exactly once; the Kotlin wrapper becomes inert.
     */
    fun transferToNativeRuntime(): Long {
        val handle = nativeHandle.getAndSet(0)
        check(handle > 0) { "Native TUN descriptor was already transferred or closed" }
        return handle
    }

    override fun close() {
        val handle = nativeHandle.getAndSet(0)
        if (handle != 0L) {
            check(closeNativeHandle(handle)) {
                "Native TUN descriptor was already transferred or closed"
            }
        }
    }

    companion object {
        /**
         * Detaches the Android-owned fd and transfers its ownership to JNI.
         * Native code closes the fd if registry adoption fails.
         */
        fun adopt(descriptor: ParcelFileDescriptor): NativeTunInterfaceHandle {
            val detachedFd = descriptor.detachFd()
            val handle = try {
                NativeBootstrap.adoptTunInterface(detachedFd)
            } catch (failure: Throwable) {
                // If JNI could not be entered (for example, a missing symbol),
                // restore an owning Android wrapper so the detached fd is closed.
                runCatching { ParcelFileDescriptor.adoptFd(detachedFd).close() }
                throw failure
            }
            check(handle > 0) { "Native layer rejected the TUN descriptor" }
            return NativeTunInterfaceHandle(handle)
        }
    }
}
