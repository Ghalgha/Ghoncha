package org.ghoncha.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotNull
import org.junit.Test

class VkCallsChallengeTransactionTest {
    private fun challenge() = VkCallsResult.Challenge(
        redirectUri = "https://id.vk.ru/captcha?session_token=opaque",
        captchaSid = "sid-1",
        captchaTs = "123",
        captchaAttempt = "2",
    )

    @Test
    fun bindsAnswerToOriginalRequestAndConsumesChallengeOnce() {
        val original = "access_token=private&method=calls.getAnonymousToken".toByteArray()
        val transaction = VkCallsChallengeTransaction(
            challengeId = 7,
            originalUrl = "https://api.vk.ru/method/calls.getAnonymousToken",
            originalBody = original,
            challenge = challenge(),
            expiresAtElapsedRealtimeMs = 5_000,
        )
        original.fill(0)

        assertNull(transaction.submit(8, "answer", 1_000))
        val submission = transaction.submit(7, "opaque-success-token", 1_000)
        assertNotNull(submission)
        submission!!
        assertEquals("https://api.vk.ru/method/calls.getAnonymousToken", submission.originalUrl)
        assertArrayEquals(
            "access_token=private&method=calls.getAnonymousToken".toByteArray(),
            submission.originalBody,
        )
        assertEquals("sid-1", submission.captchaSid)
        assertEquals("opaque-success-token", submission.response)
        val retryBody = java.net.URLDecoder.decode(
            submission.buildRetryBody().toString(Charsets.UTF_8),
            Charsets.UTF_8.name(),
        )
        assertTrue(retryBody.contains("access_token=private"))
        assertTrue(retryBody.contains("method=calls.getAnonymousToken"))
        assertTrue(retryBody.contains("captcha_key="))
        assertTrue(retryBody.contains("captcha_sid=sid-1"))
        assertTrue(retryBody.contains("is_sound_captcha=0"))
        assertTrue(retryBody.contains("success_token=opaque-success-token"))
        assertTrue(retryBody.contains("captcha_ts=123"))
        assertTrue(retryBody.contains("captcha_attempt=2"))
        assertNull(transaction.submit(7, "second-answer", 1_001))
    }

    @Test
    fun rejectsExpiredBlankOversizedAndControlCharacterResponses() {
        val expired = VkCallsChallengeTransaction(
            1, "https://api.vk.ru/method/test", byteArrayOf(1), challenge(), 100,
        )
        assertNull(expired.submit(1, "answer", 100))
        assertNull(
            VkCallsChallengeTransaction(
                2, "https://api.vk.ru/method/test", byteArrayOf(1), challenge(), null,
            ).submit(2, "  ", 1),
        )
        assertNull(
            VkCallsChallengeTransaction(
                3, "https://api.vk.ru/method/test", byteArrayOf(1), challenge(), null,
            ).submit(3, "bad\nanswer", 1),
        )
    }

    @Test
    fun retryDefaultsMissingAttemptAndRejectsAlreadyPresentChallengeFields() {
        val noAttempt = VkCallsResult.Challenge(
            redirectUri = "https://id.vk.ru/captcha?session_token=opaque",
            captchaSid = "sid",
            captchaTs = null,
            captchaAttempt = null,
        )
        val submission = VkCallsChallengeTransaction(
            5,
            "https://api.vk.ru/method/calls.getAnonymousToken",
            "access_token=private".toByteArray(),
            noAttempt,
            null,
        ).submit(5, "token + /=", 1)!!
        val decoded = java.net.URLDecoder.decode(
            submission.buildRetryBody().toString(Charsets.UTF_8),
            Charsets.UTF_8.name(),
        )
        assertTrue(decoded.contains("success_token=token + /="))
        assertTrue(decoded.contains("captcha_ts="))
        assertTrue(decoded.contains("captcha_attempt=1"))

        val duplicate = VkCallsChallengeTransaction(
            6,
            "https://api.vk.ru/method/calls.getAnonymousToken",
            "access_token=private&captcha_sid=old".toByteArray(),
            noAttempt,
            null,
        ).submit(6, "token", 1)!!
        try {
            duplicate.buildRetryBody()
            throw AssertionError("Expected duplicate challenge fields to be rejected")
        } catch (_: IllegalArgumentException) {
            // Expected: never send ambiguous duplicate form keys.
        }
    }

    @Test
    fun submissionReturnsDefensiveCopiesOfOriginalBody() {
        val transaction = VkCallsChallengeTransaction(
            4, "https://api.vk.ru/method/test", byteArrayOf(1, 2, 3), challenge(), null,
        )
        val submission = transaction.submit(4, "answer", 1)!!
        val exposed = submission.originalBody
        exposed.fill(0)
        assertArrayEquals(byteArrayOf(1, 2, 3), submission.originalBody)
    }
}
