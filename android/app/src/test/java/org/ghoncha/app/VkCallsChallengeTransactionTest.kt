package org.ghoncha.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
