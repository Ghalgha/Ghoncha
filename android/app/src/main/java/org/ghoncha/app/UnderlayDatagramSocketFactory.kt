package org.ghoncha.app

import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * A UDP socket prepared for one Android underlay-network generation.
 *
 * The socket is bound to the selected network and has an ephemeral local port.
 * The caller owns [socket] and must close it exactly once when the transport
 * session is retired. This object does not transfer the descriptor to Rust.
 */
internal data class PreparedUnderlayDatagramSocket(
    val socket: DatagramSocket,
    val serverAddress: InetSocketAddress,
    val localAddress: InetSocketAddress,
    val networkGeneration: Long,
)

/**
 * Creates UDP sockets without ever falling back to the process default network.
 *
 * DNS resolution is injected so Android callers can use Network.getAllByName().
 * The socket is protected and network-bound before it is locally bound or used.
 */
internal class UnderlayDatagramSocketFactory(
    private val networkGeneration: Long,
    private val resolveOnNetwork: (String) -> Array<InetAddress>,
    private val protect: (DatagramSocket) -> Boolean,
    private val bindToNetwork: (DatagramSocket) -> Unit,
) {
    fun open(host: String, port: Int): PreparedUnderlayDatagramSocket {
        require(host.isNotBlank()) { "TURN host must not be blank" }
        require(port in 1..65535) { "TURN port is out of range" }

        val address = resolveOnNetwork(host)
            .firstOrNull { !it.isAnyLocalAddress && !it.isMulticastAddress }
            ?: throw IllegalStateException("TURN host did not resolve to a usable address")

        val socket = DatagramSocket(null)
        try {
            UnderlayDatagramSocketPreparer.prepare(
                socket = socket,
                protect = protect,
                bindToNetwork = bindToNetwork,
            )
            socket.bind(InetSocketAddress(0))
            check(socket.isBound && !socket.isClosed && !socket.isConnected) {
                "UDP socket did not reach the prepared state"
            }

            val local = socket.localSocketAddress as? InetSocketAddress
                ?: error("UDP socket has no internet socket address")
            check(local.port != 0) { "UDP socket did not receive an ephemeral port" }

            return PreparedUnderlayDatagramSocket(
                socket = socket,
                serverAddress = InetSocketAddress(address, port),
                localAddress = local,
                networkGeneration = networkGeneration,
            )
        } catch (failure: Throwable) {
            socket.close()
            throw failure
        }
    }
}
