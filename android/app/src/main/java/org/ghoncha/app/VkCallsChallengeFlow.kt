package org.ghoncha.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import java.io.IOException

/**
 * Complete Android handoff for one VK Calls CAPTCHA transaction.
 *
 * The caller launches [createIntent] with an ActivityResultLauncher, then
 * passes its result to [complete] on a worker thread. This class retries the
 * original VK operation and returns the parsed server outcome; a WebView token
 * alone never changes the provider to Ready.
 */
internal class VkCallsChallengeFlow(
    challengeId: Long,
    originalUrl: String,
    originalBody: ByteArray,
    private val challenge: VkCallsResult.Challenge,
    expiresAtElapsedRealtimeMs: Long?,
) {
    private val transaction = VkCallsChallengeTransaction(
        challengeId = challengeId,
        originalUrl = originalUrl,
        originalBody = originalBody,
        challenge = challenge,
        expiresAtElapsedRealtimeMs = expiresAtElapsedRealtimeMs,
    )

    fun createIntent(context: Context): Intent =
        VkChallengeWebViewActivity.createIntent(
            context = context,
            challengeUrl = challenge.redirectUri,
            challengeId = transaction.challengeId,
        )

    /**
     * Consumes the Activity result and performs the VK retry.
     *
     * Call on a worker thread because the retry performs blocking HTTPS I/O.
     * [nowElapsedRealtimeMs] must be Android's monotonic elapsed clock.
     */
    fun complete(
        resultCode: Int,
        data: Intent?,
        session: VkCallsHttpsSession,
        nowElapsedRealtimeMs: Long,
    ): VkCallsResult {
        if (resultCode != Activity.RESULT_OK) return VkCallsResult.ChallengeCancelled
        val handoff = VkChallengeWebViewActivity.parseResult(resultCode, data)
            ?: return VkCallsResult.InvalidResponse
        val submission = transaction.submit(
            suppliedChallengeId = handoff.challengeId,
            response = handoff.successToken,
            nowElapsedRealtimeMs = nowElapsedRealtimeMs,
        ) ?: return VkCallsResult.InvalidResponse

        val response = try {
            submission.retry(session)
        } catch (_: IOException) {
            return VkCallsResult.NetworkUnavailable
        } catch (_: IllegalArgumentException) {
            return VkCallsResult.InvalidResponse
        }

        if (response.statusCode == 429) return VkCallsResult.RateLimited
        val parsed = VkCallsResponseParser.parse(response.body)
        return if (response.statusCode in 200..299 || parsed is VkCallsResult.Challenge ||
            parsed is VkCallsResult.RateLimited
        ) {
            parsed
        } else {
            VkCallsResult.ProviderFailure
        }
    }
}
