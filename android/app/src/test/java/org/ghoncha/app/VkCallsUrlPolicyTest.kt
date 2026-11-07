package org.ghoncha.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkCallsUrlPolicyTest {
    @Test
    fun acceptsObservedVkCallsHttpsHosts() {
        assertTrue(VkCallsUrlPolicy.allows("https://api.vk.com/method/calls.getAnonymousToken"))
        assertTrue(VkCallsUrlPolicy.allows("https://api.vk.ru/method/calls.getAnonymousToken"))
        assertTrue(VkCallsUrlPolicy.allows("https://login.vk.ru/?act=get_anonym_token"))
        assertTrue(VkCallsUrlPolicy.allows("https://calls.okcdn.ru/fb.do?method=auth.anonymLogin"))
        assertTrue(VkCallsUrlPolicy.allows("https://API.VK.COM:443/method/example"))
    }

    @Test
    fun rejectsOtherSchemesHostsAndPorts() {
        assertFalse(VkCallsUrlPolicy.allows("http://api.vk.com/method/example"))
        assertFalse(VkCallsUrlPolicy.allows("https://vk.com/method/example"))
        assertFalse(VkCallsUrlPolicy.allows("https://attacker.invalid/fb.do"))
        assertFalse(VkCallsUrlPolicy.allows("https://api.vk.com.attacker.invalid/method/example"))
        assertFalse(VkCallsUrlPolicy.allows("https://api.vk.com:8443/method/example"))
    }

    @Test
    fun rejectsUserInfoFragmentsAndMalformedUrls() {
        assertFalse(VkCallsUrlPolicy.allows("https://user@api.vk.com/method/example"))
        assertFalse(VkCallsUrlPolicy.allows("https://api.vk.com/method/example#fragment"))
        assertFalse(VkCallsUrlPolicy.allows("not a URL"))
    }
}
