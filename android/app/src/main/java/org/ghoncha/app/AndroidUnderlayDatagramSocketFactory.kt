package org.ghoncha.app

import android.net.Network
import android.net.VpnService

/**
 * Android binding for the testable underlay UDP socket factory.
 *
 * Callers must pass the Network selected by the network-generation state
 * machine. This class never falls back to the process default network.
 */
internal class AndroidUnderlayDatagramSocketFactory(
    vpnService: VpnService,
    network: Network,
    networkGeneration: Long,
    currentNetworkGeneration: () -> Long,
) {
    private val delegate = UnderlayDatagramSocketFactory(
        networkGeneration = networkGeneration,
        currentNetworkGeneration = currentNetworkGeneration,
        resolveOnNetwork = network::getAllByName,
        protect = vpnService::protect,
        bindToNetwork = { socket -> network.bindSocket(socket) },
    )

    fun open(host: String, port: Int): PreparedUnderlayDatagramSocket =
        delegate.open(host, port)
}
