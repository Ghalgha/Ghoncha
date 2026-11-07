package org.ghoncha.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkApiUrlPolicyTest {
    @Test
    fun acceptsOnlyVkApiHttpsOrigin() {
        assertTrue(VkApiUrlPolicy.allows("https://api.vk.com/method/calls.getAnonymousToken"))
        assertTrue(VkApiUrlPolicy.allows("https://API.VK.COM:443/method/example"))
    }

    @Test
    fun rejectsOtherSchemesHostsAndPorts() {
        assertFalse(VkApiUrlPolicy.allows("http://api.vk.com/method/example"))
        assertFalse(VkApiUrlPolicy.allows("https://vk.com/method/example"))
        assertFalse(VkApiUrlPolicy.allows("https://api.vk.com.attacker.invalid/method/example"))
        assertFalse(VkApiUrlPolicy.allows("https://api.vk.com:8443/method/example"))
    }

    @Test
    fun rejectsUserInfoFragmentsAndMalformedUrls() {
        assertFalse(VkApiUrlPolicy.allows("https://user@api.vk.com/method/example"))
        assertFalse(VkApiUrlPolicy.allows("https://api.vk.com/method/example#fragment"))
        assertFalse(VkApiUrlPolicy.allows("not a URL"))
    }
}
