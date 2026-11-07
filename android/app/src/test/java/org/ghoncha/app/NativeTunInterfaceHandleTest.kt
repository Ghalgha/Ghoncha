package org.ghoncha.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeTunInterfaceHandleTest {
    @Test
    fun closeReleasesNativeHandleExactlyOnce() {
        val closed = mutableListOf<Long>()
        val handle = NativeTunInterfaceHandle(17) {
            closed += it
            true
        }

        handle.close()
        handle.close()

        assertEquals(listOf(17L), closed)
    }

    @Test
    fun transferMakesKotlinOwnerInert() {
        var closeCalled = false
        val handle = NativeTunInterfaceHandle(23) {
            closeCalled = true
            true
        }

        assertEquals(23L, handle.transferToNativeRuntime())
        handle.close()

        assertFalse(closeCalled)
        assertThrows(IllegalStateException::class.java) {
            handle.transferToNativeRuntime()
        }
    }

    @Test
    fun closeReportsNativeOwnershipMismatch() {
        val handle = NativeTunInterfaceHandle(29) { false }

        assertThrows(IllegalStateException::class.java) {
            handle.close()
        }
    }

    @Test
    fun handleMustBePositive() {
        assertThrows(IllegalArgumentException::class.java) {
            NativeTunInterfaceHandle(0) { true }
        }
    }
}
