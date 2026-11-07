package org.ghoncha.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VkChallengeUrlPolicyTest {
    @Test
    fun acceptsAllowlistedHttpsOrigins() {
        assertTrue(VkChallengeUrlPolicy.allows("https://vk.com/captcha"))
        assertTrue(VkChallengeUrlPolicy.allows("https://login.vk.com/"))
        assertTrue(VkChallengeUrlPolicy.allows("https://id.vk.ru/captcha"))
        assertTrue(VkChallengeUrlPolicy.allows("https://www.vk.ru:443/path"))
    }

    @Test
    fun rejectsNonHttpsAndUnexpectedPorts() {
        assertFalse(VkChallengeUrlPolicy.allows("http://vk.com/captcha"))
        assertFalse(VkChallengeUrlPolicy.allows("https://vk.com:8443/captcha"))
    }

    @Test
    fun rejectsLookalikeAndUntrustedHosts() {
        assertFalse(VkChallengeUrlPolicy.allows("https://vk.com.attacker.example/"))
        assertFalse(VkChallengeUrlPolicy.allows("https://attacker-vk.com/"))
        assertFalse(VkChallengeUrlPolicy.allows("https://example.com/"))
    }

    @Test
    fun rejectsUserInfoAndMalformedUris() {
        assertFalse(VkChallengeUrlPolicy.allows("https://user@vk.com/"))
        assertFalse(VkChallengeUrlPolicy.allows("https://vk.com@attacker.example/"))
        assertFalse(VkChallengeUrlPolicy.allows("not a URL"))
        assertFalse(VkChallengeUrlPolicy.allows("javascript:alert(1)"))
    }
}
