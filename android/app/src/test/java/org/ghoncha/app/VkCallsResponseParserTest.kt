package org.ghoncha.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VkCallsResponseParserTest {
    @Test
    fun parsesTurnCredentialsWithoutExposingThemInResultTypeName() {
        val result = VkCallsResponseParser.parse(
            """{"turn_server":{"username":"temporary-user","credential":"temporary-secret","urls":["turn:relay.example:3478?transport=udp","turns:relay.example:5349?transport=tcp"]}}"""
                .toByteArray(),
        )

        assertTrue(result is VkCallsResult.Credentials)
        result as VkCallsResult.Credentials
        assertEquals("temporary-user", result.username)
        assertEquals("temporary-secret", result.credential)
        assertEquals(2, result.urls.size)
    }

    @Test
    fun parsesVkCaptchaErrorAndPreservesCorrelationFields() {
        val result = VkCallsResponseParser.parse(
            """{"error":{"error_code":14,"redirect_uri":"https://id.vk.ru/captcha?session_token=opaque","captcha_sid":12345,"captcha_ts":1712345678,"captcha_attempt":2}}"""
                .toByteArray(),
        )

        assertTrue(result is VkCallsResult.Challenge)
        result as VkCallsResult.Challenge
        assertEquals("12345", result.captchaSid)
        assertEquals("1712345678", result.captchaTs)
        assertEquals("2", result.captchaAttempt)
    }

    @Test
    fun classifiesRateLimitAndRejectsUntrustedChallengeUrl() {
        assertTrue(
            VkCallsResponseParser.parse(
                """{"error":{"error_code":29,"error_msg":"Rate limit"}}""".toByteArray(),
            ) is VkCallsResult.RateLimited,
        )
        assertTrue(
            VkCallsResponseParser.parse(
                """{"error":{"error_code":14,"redirect_uri":"https://id.vk.ru.attacker.invalid/captcha","captcha_sid":"1"}}"""
                    .toByteArray(),
            ) is VkCallsResult.InvalidResponse,
        )
    }

    @Test
    fun rejectsMalformedCredentialPayloadsAndUnsafeTurnUris() {
        assertTrue(
            VkCallsResponseParser.parse(
                """{"turn_server":{"username":"u","credential":"p","urls":["https://relay.example:3478"]}}"""
                    .toByteArray(),
            ) is VkCallsResult.InvalidResponse,
        )
        assertTrue(
            VkCallsResponseParser.parse("not-json".toByteArray()) is VkCallsResult.InvalidResponse,
        )
    }
}
