package org.ghoncha.app

/**
 * One in-memory VK Calls challenge transaction.
 *
 * It binds the original HTTPS operation to exactly one interactive challenge
 * response. The retry form follows the currently observed VK API CAPTCHA
 * contract (captcha_sid, empty captcha_key, is_sound_captcha, success_token,
 * captcha_ts, captcha_attempt). VK does not publish a stable Calls backend
 * contract, so this adapter remains isolated from the generic transport API.
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
    private var retryAttempted = false

    val originalBody: ByteArray
        get() = retainedBody.copyOf()

    /**
     * Resends the exact original form operation with VK's observed challenge
     * fields. A submission is one-shot even if the network call fails; obtain a
     * fresh server challenge before another attempt.
     */
    @Synchronized
    fun retry(session: VkCallsHttpsSession): VkCallsHttpResponse {
        check(!retryAttempted) { "VK challenge submission was already sent" }
        retryAttempted = true
        return session.postForm(originalUrl, buildRetryBody())
    }

    /** Encodes the VK challenge response into the original form body. */
    fun buildRetryBody(): ByteArray {
        val body = retainedBody.toString(Charsets.UTF_8)
        require(body.isNotBlank()) { "Original VK form body is empty" }

        val reserved = setOf(
            "captcha_key",
            "captcha_sid",
            "is_sound_captcha",
            "success_token",
            "captcha_ts",
            "captcha_attempt",
        )
        val existing = body.split('&').asSequence()
            .map { it.substringBefore('=') }
            .map { URLDecoder.decode(it, Charsets.UTF_8.name()) }
            .toSet()
        require(existing.intersect(reserved).isEmpty()) {
            "Original VK request already contains CAPTCHA response fields"
        }

        val fields = listOf(
            "captcha_key" to "",
            "captcha_sid" to captchaSid,
            "is_sound_captcha" to "0",
            "success_token" to response,
            "captcha_ts" to captchaTs.orEmpty(),
            "captcha_attempt" to captchaAttempt?.takeIf { it.isNotBlank() } ?: "1",
        )
        val suffix = fields.joinToString("&") { (key, value) ->
            "${URLEncoder.encode(key, Charsets.UTF_8.name())}=${URLEncoder.encode(value, Charsets.UTF_8.name())}"
        }
        val separator = if (body.endsWith('&')) "" else "&"
        val result = (body + separator + suffix).toByteArray(Charsets.UTF_8)
        require(result.size <= MAX_REQUEST_BYTES) {
            "VK challenge retry body exceeds the configured size limit"
        }
        return result
    }

    private companion object {
        const val MAX_REQUEST_BYTES = 1 shl 20
    }
}
