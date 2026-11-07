package org.ghoncha.app

import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardProtocolFamily
import java.nio.channels.DatagramChannel

/**
 * A UDP channel prepared for one Android underlay-network generation.
 *
 * [channel] is the sole ownership handle and must be closed exactly once.
 * [socket] is the channel's socket view, used only for Android protect/bind
 * operations. This object does not transfer the descriptor to Rust.
 */
internal data class PreparedUnderlayDatagramSocket(
    val channel: DatagramChannel,
    val serverAddress: InetSocketAddress,
    val localAddress: InetSocketAddress,
    val networkGeneration: Long,
) {
    val socket: DatagramSocket
        get() = channel.socket()
}

/**
 * Creates UDP channels without falling back to the process default network.
 *
 * DNS resolution is injected so Android callers can use Network.getAllByName().
 * The channel family is selected from the resolved address. The socket is
 * protected and network-bound before it is locally bound or used.
 */
internal class UnderlayDatagramSocketFactory(
    private val networkGeneration: Long,
    private val currentNetworkGeneration: () -> Long,
    private val resolveOnNetwork: (String) -> Array<InetAddress>,
    private val protect: (DatagramSocket) -> Boolean,
    private val bindToNetwork: (DatagramSocket) -> Unit,
) {
    fun open(host: String, port: Int): PreparedUnderlayDatagramSocket {
        require(host.isNotBlank()) { "TURN host must not be blank" }
        require(port in 1..65535) { "TURN port is out of range" }
        check(currentNetworkGeneration() == networkGeneration) {
            "Network changed before UDP socket creation"
        }

        val address = resolveOnNetwork(host)
            .firstOrNull { !it.isAnyLocalAddress && !it.isMulticastAddress }
            ?: throw IllegalStateException("TURN host did not resolve to a usable address")

        val family = when (address) {
            is Inet4Address -> StandardProtocolFamily.INET
            is Inet6Address -> StandardProtocolFamily.INET6
            else -> throw IllegalStateException("Unsupported TURN server address family")
        }
        val channel = DatagramChannel.open(family)
        try {
            val socket = channel.socket()
            UnderlayDatagramSocketPreparer.prepare(
                socket = socket,
                protect = protect,
                bindToNetwork = bindToNetwork,
            )
            socket.bind(InetSocketAddress(0))
            channel.configureBlocking(false)

            check(socket.isBound && !socket.isClosed && !socket.isConnected) {
                "UDP socket did not reach the prepared state"
            }

            val local = socket.localSocketAddress as? InetSocketAddress
                ?: error("UDP socket has no internet socket address")
            check(local.port != 0) { "UDP socket did not receive an ephemeral port" }
            check((local.address is Inet4Address) == (address is Inet4Address)) {
                "UDP socket and TURN endpoint address families differ"
            }
            check(currentNetworkGeneration() == networkGeneration) {
                "Network changed while UDP socket was being prepared"
            }

            return PreparedUnderlayDatagramSocket(
                channel = channel,
                serverAddress = InetSocketAddress(address, port),
                localAddress = local,
                networkGeneration = networkGeneration,
            )
        } catch (failure: Throwable) {
            channel.close()
            throw failure
        }
    }
}
