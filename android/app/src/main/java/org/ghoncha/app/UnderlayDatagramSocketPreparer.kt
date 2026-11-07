package org.ghoncha.app

import java.net.DatagramSocket

/**
 * Applies the Android underlay-routing prerequisites to a newly created UDP socket.
 *
 * The caller transfers ownership of [socket] to this function. On success, ownership
 * is returned to the caller and the socket is protected and bound before it can send.
 * On any failure, the socket is closed and the original failure is rethrown.
 *
 * The callbacks are supplied by the VPN service so this small boundary can be tested
 * without constructing Android framework services.
 */
internal object UnderlayDatagramSocketPreparer {
    fun prepare(
        socket: DatagramSocket,
        protect: (DatagramSocket) -> Boolean,
        bindToNetwork: (DatagramSocket) -> Unit,
    ): DatagramSocket {
        try {
            check(!socket.isClosed) { "UDP socket is already closed" }
            check(!socket.isConnected) { "UDP socket must be unconnected before network binding" }

            check(protect(socket)) { "VpnService.protect failed" }
            bindToNetwork(socket)

            check(!socket.isClosed) { "UDP socket was closed during preparation" }
            check(!socket.isConnected) { "UDP socket became connected during preparation" }
            return socket
        } catch (failure: Throwable) {
            socket.close()
            throw failure
        }
    }
}
