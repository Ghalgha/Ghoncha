package org.ghoncha.app

/**
 * One in-memory VK Calls challenge transaction.
 *
 * It binds the original HTTPS operation to exactly one interactive challenge
 * response. It deliberately does not encode undocumented VK retry parameters:
 * the provider adapter must validate the live protocol schema before building
 * the retry request.
 */
internal class VkCallsChallengeTransaction(
    val challengeId: Long,
    originalUrl: String,
    originalBody: ByteArray,
    challenge: VkCallsResult.Challenge,
    private val expiresAtElapsedRealtimeMs: Long?,
) {
    private val requestUrl: String
    private val requestBody: ByteArray = originalBody.copyOf()
    private val redirectUri: String = challenge.redirectUri
    private val captchaSid: String = challenge.captchaSid
    private val captchaTs: String? = challenge.captchaTs
    private val captchaAttempt: String? = challenge.captchaAttempt
    private var consumed = false

    init {
        require(challengeId > 0) { "Challenge ID must be positive" }
        require(VkCallsUrlPolicy.allows(originalUrl)) { "Untrusted original VK request URL" }
        require(originalBody.isNotEmpty() && originalBody.size <= MAX_REQUEST_BYTES) {
            "Original VK request body is outside the allowed size"
        }
        require(expiresAtElapsedRealtimeMs == null || expiresAtElapsedRealtimeMs > 0) {
            "Invalid challenge expiry"
        }
        requestUrl = originalUrl
    }

    /**
     * Consumes this challenge once and returns the retained operation context.
     * [nowElapsedRealtimeMs] must come from Android's monotonic elapsed clock.
     */
    @Synchronized
    fun submit(
        suppliedChallengeId: Long,
        response: String,
        nowElapsedRealtimeMs: Long,
    ): VkCallsChallengeSubmission? {
        if (consumed || suppliedChallengeId != challengeId) return null
        if (expiresAtElapsedRealtimeMs?.let { nowElapsedRealtimeMs >= it } == true) {
            consumed = true
            return null
        }
        if (response.isBlank() || response.length > MAX_CHALLENGE_RESPONSE_CHARS) return null
        if (response.any { it.isISOControl() }) return null

        consumed = true
        return VkCallsChallengeSubmission(
            originalUrl = requestUrl,
            originalBody = requestBody.copyOf(),
            redirectUri = redirectUri,
            captchaSid = captchaSid,
            captchaTs = captchaTs,
            captchaAttempt = captchaAttempt,
            response = response,
        )
    }

    private companion object {
        const val MAX_REQUEST_BYTES = 1 shl 20
        const val MAX_CHALLENGE_RESPONSE_CHARS = 16 * 1024
    }
}

/** Sensitive retry context; intentionally has no generated toString(). */
internal class VkCallsChallengeSubmission(
    val originalUrl: String,
    originalBody: ByteArray,
    val redirectUri: String,
    val captchaSid: String,
    val captchaTs: String?,
    val captchaAttempt: String?,
    val response: String,
) {
    private val retainedBody = originalBody.copyOf()
    val originalBody: ByteArray
        get() = retainedBody.copyOf()
}
