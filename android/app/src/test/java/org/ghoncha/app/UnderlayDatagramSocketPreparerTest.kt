package org.ghoncha.app

import java.net.DatagramSocket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlayDatagramSocketPreparerTest {
    @Test
    fun protectsBeforeBindingAndReturnsPreparedSocket() {
        val socket = DatagramSocket(null)
        val calls = mutableListOf<String>()

        val prepared = UnderlayDatagramSocketPreparer.prepare(
            socket,
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

        assertSame(socket, prepared)
        assertEquals(listOf("protect", "bind"), calls)
        assertFalse(socket.isClosed)
        socket.close()
    }

    @Test
    fun protectionFailureClosesSocketAndNeverBinds() {
        val socket = DatagramSocket(null)
        var bindCalled = false

        val failure = assertThrows(IllegalStateException::class.java) {
            UnderlayDatagramSocketPreparer.prepare(
                socket,
                protect = { false },
                bindToNetwork = { bindCalled = true },
            )
        }

        assertTrue(failure.message!!.contains("protect"))
        assertFalse(bindCalled)
        assertTrue(socket.isClosed)
    }

    @Test
    fun networkBindingFailureClosesSocket() {
        val socket = DatagramSocket(null)

        assertThrows(IllegalArgumentException::class.java) {
            UnderlayDatagramSocketPreparer.prepare(
                socket,
                protect = { true },
                bindToNetwork = { throw IllegalArgumentException("bind failed") },
            )
        }

        assertTrue(socket.isClosed)
    }

    @Test
    fun connectedSocketIsRejectedAndClosed() {
        val socket = DatagramSocket(null)
        socket.connect(java.net.InetSocketAddress("127.0.0.1", 9))

        assertThrows(IllegalStateException::class.java) {
            UnderlayDatagramSocketPreparer.prepare(
                socket,
                protect = { true },
                bindToNetwork = {},
            )
        }

        assertTrue(socket.isClosed)
    }
}
