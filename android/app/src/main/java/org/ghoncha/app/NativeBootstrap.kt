package org.ghoncha.app

import android.content.Context

object NativeBootstrap {
    @JvmStatic
    external fun initialize(context: Context)

    /**
     * Duplicates a ParcelFileDescriptor-owned UDP socket into native ownership.
     * The caller remains responsible for closing the supplied descriptor.
     * Returns zero when the descriptor is not a valid UDP socket.
     */
    @JvmStatic
    external fun adoptUdpSocket(fd: Int): Long

    /** Closes a native socket handle that has not been transferred to Rust I/O. */
    @JvmStatic
    external fun closeUdpSocket(handle: Long): Boolean

    /** Consumes a pending handle and transfers its UDP socket into Rust ownership. */
    @JvmStatic
    external fun consumeUdpSocket(handle: Long): Boolean

    /** Closes a Rust-owned socket that has not yet entered a TURN driver. */
    @JvmStatic
    external fun closeAdoptedUdpSocket(handle: Long): Boolean
}

    /**
     * Takes ownership of a detached VpnService TUN file descriptor.
     * The descriptor is consumed and closed by native code on both success
     * and failure; the caller must never close it after this call.
     */
    @JvmStatic
    external fun adoptTunInterface(detachedFd: Int): Long

    /** Closes a TUN descriptor that has not yet entered the native packet runtime. */
    @JvmStatic
    external fun closeTunInterface(handle: Long): Boolean
