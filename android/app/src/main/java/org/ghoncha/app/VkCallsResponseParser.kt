package org.ghoncha.app

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI

/**
 * Strict decoder for observed VK Calls response envelopes.
 *
 * This decoder does not make network requests, solve challenges, or assume
 * undocumented endpoint stability. It accepts only the fields needed by the
 * provider boundary and deliberately avoids data-class toString() on secrets.
 */
internal object VkCallsResponseParser {
    fun parse(body: ByteArray): VkCallsResult {
        if (body.isEmpty() || body.size > MAX_RESPONSE_BYTES) {
            return VkCallsResult.InvalidResponse
        }
        val root = try {
            JSONObject(body.toString(Charsets.UTF_8))
        } catch (_: Exception) {
            return VkCallsResult.InvalidResponse
        }

        val error = root.optJSONObject("error")
        if (error != null) return parseError(error)
        val errorText = root.optString("error").takeIf { it.isNotBlank() && it != "null" }
        if (errorText != null) return VkCallsResult.ProviderFailure

        val payload = root.optJSONObject("response") ?: root
        val turnServer = payload.optJSONObject("turn_server")
            ?: return VkCallsResult.InvalidResponse

        val username = turnServer.optString("username").takeIf { it.isNotBlank() && it != "null" }
            ?: return VkCallsResult.InvalidResponse
        val credential = turnServer.optString("credential").takeIf { it.isNotBlank() && it != "null" }
            ?: return VkCallsResult.InvalidResponse
        val urls = parseUrls(turnServer.optJSONArray("urls"))
            ?: return VkCallsResult.InvalidResponse

        return VkCallsResult.Credentials(
            username = username,
            credential = credential,
            urls = urls,
        )
    }

    private fun parseError(error: JSONObject): VkCallsResult {
        val code = error.optInt("error_code", Int.MIN_VALUE)
        if (code == VK_CAPTCHA_ERROR) {
            val redirectUri = error.optString("redirect_uri")
                .takeIf { it.isNotBlank() && it != "null" }
                ?: return VkCallsResult.InvalidResponse
            if (!VkChallengeUrlPolicy.allows(redirectUri)) {
                return VkCallsResult.InvalidResponse
            }
            val captchaSid = scalarString(error, "captcha_sid")
                ?: return VkCallsResult.InvalidResponse
            val captchaTs = scalarString(error, "captcha_ts")
            val captchaAttempt = scalarString(error, "captcha_attempt")
            return VkCallsResult.Challenge(
                redirectUri = redirectUri,
                captchaSid = captchaSid,
                captchaTs = captchaTs,
                captchaAttempt = captchaAttempt,
            )
        }
        if (code == VK_RATE_LIMIT_ERROR) return VkCallsResult.RateLimited
        return VkCallsResult.ProviderFailure
    }

    private fun scalarString(json: JSONObject, key: String): String? {
        if (!json.has(key) || json.isNull(key)) return null
        val value = json.opt(key)
        return when (value) {
            is String -> value.takeIf { it.isNotBlank() }
            is Number -> value.toString()
            else -> null
        }
    }

    private fun parseUrls(array: JSONArray?): List<String>? {
        if (array == null || array.length() == 0 || array.length() > MAX_ENDPOINTS) return null
        val result = ArrayList<String>(array.length())
        for (index in 0 until array.length()) {
            val value = array.optString(index).takeIf { it.isNotBlank() && it != "null" }
                ?: return null
            val uri = try {
                URI(value)
            } catch (_: Exception) {
                return null
            }
            val scheme = uri.scheme?.lowercase()
            if (scheme !in setOf("turn", "turns") || uri.rawUserInfo != null) return null

            // RFC 7065 TURN URIs are commonly opaque: turn:host:port?transport=udp.
            // Parse the authority separately instead of relying on URI.host.
            val authority = if (uri.isOpaque) {
                uri.rawSchemeSpecificPart.substringBefore('?')
            } else {
                uri.rawAuthority ?: return null
            }
            val endpoint = try {
                URI("https://$authority")
            } catch (_: Exception) {
                return null
            }
            if (
                endpoint.host.isNullOrBlank() ||
                endpoint.userInfo != null ||
                (endpoint.port != -1 && endpoint.port !in 1..65535)
            ) return null
            result += value
        }
        return result
    }

    private const val VK_CAPTCHA_ERROR = 14
    private const val VK_RATE_LIMIT_ERROR = 29
    private const val MAX_RESPONSE_BYTES = 1 shl 20
    private const val MAX_ENDPOINTS = 16
}

internal sealed class VkCallsResult {
    class Credentials(
        val username: String,
        val credential: String,
        val urls: List<String>,
    ) : VkCallsResult()

    class Challenge(
        val redirectUri: String,
        val captchaSid: String,
        val captchaTs: String?,
        val captchaAttempt: String?,
    ) : VkCallsResult()

    object RateLimited : VkCallsResult()
    object ProviderFailure : VkCallsResult()
    object InvalidResponse : VkCallsResult()
}
