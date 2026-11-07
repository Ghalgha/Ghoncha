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
}
