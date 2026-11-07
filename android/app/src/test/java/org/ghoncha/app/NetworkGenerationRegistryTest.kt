package org.ghoncha.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkGenerationRegistryTest {
    @Test
    fun activationAndRoutingChangesAdvanceGeneration() {
        val registry = NetworkGenerationRegistry<String>()

        val first = registry.activate("wifi")
        val second = registry.advance("wifi")!!

        assertTrue(second > first)
        assertEquals(second, registry.current("wifi"))
    }

    @Test
    fun differentNetworksReceiveDistinctGenerations() {
        val registry = NetworkGenerationRegistry<String>()

        val wifi = registry.activate("wifi")
        val cellular = registry.activate("cellular")

        assertTrue(wifi != cellular)
    }

    @Test
    fun lostNetworkHasNoCurrentGenerationAndReactivationDoesNotReuseOldOne() {
        val registry = NetworkGenerationRegistry<String>()

        val first = registry.activate("wifi")
        assertEquals(first, registry.deactivate("wifi"))
        assertNull(registry.current("wifi"))

        val reconnected = registry.activate("wifi")
        assertTrue(reconnected > first)
    }

    @Test
    fun advancingAnUnknownNetworkDoesNotCreateIt() {
        val registry = NetworkGenerationRegistry<String>()

        assertNull(registry.advance("unknown"))
        assertNull(registry.current("unknown"))
    }

    @Test
    fun clearInvalidatesEveryActiveNetwork() {
        val registry = NetworkGenerationRegistry<String>()
        registry.activate("wifi")
        registry.activate("cellular")

        registry.clear()

        assertEquals(0, registry.currentNetworksCount())
    }

    private fun NetworkGenerationRegistry<String>.currentNetworksCount(): Int =
        listOfNotNull(current("wifi"), current("cellular")).size
}
