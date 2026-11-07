package org.ghoncha.app

import java.net.InetAddress
import java.net.UnknownHostException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class UnderlayDatagramSocketFactoryTest {
    @Test
    fun resolvesOnSelectedNetworkAndPreparesSocketBeforeReturningIt() {
        val calls = mutableListOf<String>()
        val expectedAddress = InetAddress.getByName("192.0.2.10")
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 17,
            currentNetworkGeneration = { 17L },
            resolveOnNetwork = {
                calls += "resolve:$it"
                arrayOf(expectedAddress)
            },
            protect = {
                calls += "protect"
                assertFalse(it.isClosed)
                true
            },
            bindToNetwork = {
                calls += "bind"
                assertFalse(it.isClosed)
                assertFalse(it.isConnected)
            },
        )

        val prepared = factory.open("turn.example.test", 3478)
        try {
            assertEquals(
                listOf("resolve:turn.example.test", "protect", "bind"),
                calls,
            )
            assertEquals(expectedAddress, prepared.serverAddress.address)
            assertEquals(3478, prepared.serverAddress.port)
            assertEquals(17L, prepared.networkGeneration)
            assertTrue(prepared.socket.isBound)
            assertFalse(prepared.channel.isBlocking)
            assertTrue(prepared.localAddress.address is java.net.Inet4Address)
            assertFalse(prepared.socket.isClosed)
            assertFalse(prepared.socket.isConnected)
            assertTrue(prepared.localAddress.port in 1..65535)
            assertEquals(prepared.localAddress, prepared.socket.localSocketAddress)
        } finally {
            prepared.channel.close()
        }
    }

    @Test
    fun unusableDnsAnswersFailBeforeSocketProtectionOrBinding() {
        var protected = false
        var bound = false
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 1,
            currentNetworkGeneration = { 1L },
            resolveOnNetwork = { emptyArray() },
            protect = {
                protected = true
                true
            },
            bindToNetwork = { bound = true },
        )

        assertThrows(IllegalStateException::class.java) {
            factory.open("missing.example.test", 3478)
        }
        assertFalse(protected)
        assertFalse(bound)
    }

    @Test
    fun rejectsInvalidPortBeforeResolvingHost() {
        var resolved = false
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 1,
            currentNetworkGeneration = { 1L },
            resolveOnNetwork = {
                resolved = true
                throw UnknownHostException(it)
            },
            protect = { true },
            bindToNetwork = {},
        )

        assertThrows(IllegalArgumentException::class.java) {
            factory.open("turn.example.test", 0)
        }
        assertFalse(resolved)
    }

    @Test
    fun rejectsNetworkThatChangesDuringSocketPreparation() {
        var currentGeneration = 5L
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 5,
            currentNetworkGeneration = { currentGeneration },
            resolveOnNetwork = { arrayOf(InetAddress.getByName("192.0.2.20")) },
            protect = { true },
            bindToNetwork = { currentGeneration = 6L },
        )

        assertThrows(IllegalStateException::class.java) {
            factory.open("turn.example.test", 3478)
        }
    }

    @Test
    fun rejectsStaleNetworkBeforeDnsResolution() {
        var resolved = false
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 5,
            currentNetworkGeneration = { 6L },
            resolveOnNetwork = {
                resolved = true
                emptyArray()
            },
            protect = { true },
            bindToNetwork = {},
        )

        assertThrows(IllegalStateException::class.java) {
            factory.open("turn.example.test", 3478)
        }
        assertFalse(resolved)
    }

    @Test
    fun rejectsAnyLocalAndMulticastDnsAnswers() {
        val factory = UnderlayDatagramSocketFactory(
            networkGeneration = 1,
            currentNetworkGeneration = { 1L },
            resolveOnNetwork = {
                arrayOf(
                    InetAddress.getByName("0.0.0.0"),
                    InetAddress.getByName("224.0.0.1"),
                )
            },
            protect = { true },
            bindToNetwork = {},
        )

        assertThrows(IllegalStateException::class.java) {
            factory.open("turn.example.test", 3478)
        }
    }
}
