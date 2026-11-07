package org.ghoncha.app

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.io.Closeable

/**
 * Observes candidate underlay networks without selecting one on the caller's
 * behalf. Only networks advertising Internet capability and NOT_VPN are
 * reported, preventing the VPN's own interface from being selected as its
 * transport underlay.
 *
 * Every routing-relevant change advances that network's generation. Existing
 * sockets created with an older generation must be retired by the owner.
 */
internal class UnderlayNetworkMonitor(
    private val connectivityManager: ConnectivityManager,
    private val onNetworkChanged: (UnderlayNetworkSnapshot) -> Unit,
    private val onNetworkLost: (network: Network, lastGeneration: Long) -> Unit,
) : Closeable {
    private val lock = Any()
    private val generations = NetworkGenerationRegistry<Network>()
    private val snapshots = LinkedHashMap<Network, UnderlayNetworkSnapshot>()
    private var started = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val snapshot = synchronized(lock) {
                if (!started) return
                val generation = generations.activate(network)
                UnderlayNetworkSnapshot(
                    network = network,
                    generation = generation,
                    capabilitiesAvailable = false,
                    hasInternet = false,
                    validated = false,
                    metered = true,
                    wifi = false,
                    cellular = false,
                    ethernet = false,
                ).also { snapshots[network] = it }
            }
            onNetworkChanged(snapshot)
        }

        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities,
        ) {
            val snapshot = synchronized(lock) {
                if (!started) return
                val previous = snapshots[network]
                val changed = previous == null ||
                    !previous.capabilitiesAvailable ||
                    previous.hasInternet != capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_INTERNET,
                    ) ||
                    previous.validated != capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED,
                    ) ||
                    previous.metered == capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_NOT_METERED,
                    ) ||
                    previous.wifi != capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_WIFI,
                    ) ||
                    previous.cellular != capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_CELLULAR,
                    ) ||
                    previous.ethernet != capabilities.hasTransport(
                        NetworkCapabilities.TRANSPORT_ETHERNET,
                    )
                if (!changed) return

                val generation = if (previous == null) {
                    generations.activate(network)
                } else {
                    generations.advance(network) ?: generations.activate(network)
                }
                UnderlayNetworkSnapshot(
                    network = network,
                    generation = generation,
                    capabilitiesAvailable = true,
                    hasInternet = capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_INTERNET,
                    ),
                    validated = capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_VALIDATED,
                    ),
                    metered = !capabilities.hasCapability(
                        NetworkCapabilities.NET_CAPABILITY_NOT_METERED,
                    ),
                    wifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                    cellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                    ethernet = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
                ).also { snapshots[network] = it }
            }
            onNetworkChanged(snapshot)
        }

        override fun onLinkPropertiesChanged(
            network: Network,
            linkProperties: android.net.LinkProperties,
        ) {
            val snapshot = synchronized(lock) {
                if (!started) return
                val previous = snapshots[network] ?: return
                val generation = generations.advance(network) ?: return
                previous.copy(generation = generation).also { snapshots[network] = it }
            }
            onNetworkChanged(snapshot)
        }

        override fun onLost(network: Network) {
            val lostGeneration = synchronized(lock) {
                if (!started) return
                val previous = snapshots.remove(network) ?: return
                generations.deactivate(network) ?: previous.generation
            }
            onNetworkLost(network, lostGeneration)
        }
    }

    /** Starts observation once. A second call is harmless. */
    fun start() {
        synchronized(lock) {
            if (started) return
            started = true
        }
        try {
            connectivityManager.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                callback,
            )
        } catch (failure: Throwable) {
            synchronized(lock) {
                started = false
                snapshots.clear()
                generations.clear()
            }
            throw failure
        }
    }

    fun currentGeneration(network: Network): Long? =
        synchronized(lock) { generations.current(network) }

    fun currentNetworks(): List<UnderlayNetworkSnapshot> =
        synchronized(lock) { snapshots.values.toList() }

    override fun close() {
        val shouldUnregister = synchronized(lock) {
            if (!started) {
                false
            } else {
                started = false
                snapshots.clear()
                generations.clear()
                true
            }
        }
        if (shouldUnregister) {
            connectivityManager.unregisterNetworkCallback(callback)
        }
    }
}

internal data class UnderlayNetworkSnapshot(
    val network: Network,
    val generation: Long,
    val capabilitiesAvailable: Boolean,
    val hasInternet: Boolean,
    val validated: Boolean,
    val metered: Boolean,
    val wifi: Boolean,
    val cellular: Boolean,
    val ethernet: Boolean,
)
