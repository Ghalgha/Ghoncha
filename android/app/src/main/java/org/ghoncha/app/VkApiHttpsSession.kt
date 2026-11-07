package org.ghoncha.app

import android.webkit.CookieManager
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * A bounded HTTPS request session for the documented VK API origin.
 *
 * The Android WebView and this client use the same platform CookieManager.
 * Cookies are read only for the request origin and response Set-Cookie values
 * are returned to that store; they are never exposed to the Rust data plane,
 * intents, logs, or persistent application preferences.
 *
 * This is a transport primitive, not a VK Calls endpoint implementation.
 * Callers must retain non-cookie request context (tokens, call identifiers,
 * challenge metadata and original parameters) in their provider session.
 */
internal class VkApiHttpsSession(
    private val cookieManager: CookieManager = CookieManager.getInstance(),
) {
    /**
     * Sends one form-encoded POST without following redirects or changing host.
     * Invoke from a worker thread; this method performs blocking network I/O.
     */
    @Synchronized
    fun postForm(url: String, body: ByteArray): VkApiHttpResponse {
        require(VkApiUrlPolicy.allows(url)) { "Untrusted VK API URL" }
        require(body.isNotEmpty() && body.size <= MAX_REQUEST_BYTES) {
            "VK API request body is outside the allowed size"
        }

        val connection = (URL(url).openConnection() as? HttpsURLConnection)
            ?: throw IllegalArgumentException("VK API requires HTTPS")
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.doOutput = true
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )

            // CookieManager scopes the returned header to this exact request URL.
            cookieManager.getCookie(url)
                ?.takeIf { it.isNotBlank() }
                ?.let { connection.setRequestProperty("Cookie", it) }

            connection.setFixedLengthStreamingMode(body.size)
            connection.outputStream.use { output -> output.write(body) }

            val status = connection.responseCode
            storeResponseCookies(url, connection)
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val response = stream?.use { readBounded(it, MAX_RESPONSE_BYTES) } ?: ByteArray(0)

            return VkApiHttpResponse(status, response)
        } finally {
            connection.disconnect()
        }
    }

    private fun storeResponseCookies(url: String, connection: HttpsURLConnection) {
        val setCookies = connection.headerFields.entries
            .filter { (name, _) -> name.equals("Set-Cookie", ignoreCase = true) }
            .flatMap { it.value.orEmpty() }
        for (cookie in setCookies) {
            val latch = CountDownLatch(1)
            cookieManager.setCookie(url, cookie) { latch.countDown() }
            check(latch.await(COOKIE_STORE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                "Timed out updating the VK WebView cookie store"
            }
        }
        if (setCookies.isNotEmpty()) cookieManager.flush()
    }

    private fun readBounded(input: InputStream, maximum: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maximum, 8 * 1024))
        val buffer = ByteArray(8 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            require(output.size() <= maximum - count) {
                "VK API response exceeds the configured size limit"
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000
        const val READ_TIMEOUT_MS = 20_000
        const val COOKIE_STORE_TIMEOUT_MS = 2_000L
        const val MAX_REQUEST_BYTES = 1 shl 20
        const val MAX_RESPONSE_BYTES = 1 shl 20
    }
}

/**
 * Response deliberately has no data-class-generated toString(): bodies may
 * contain short-lived credentials or account/session material.
 */
internal class VkApiHttpResponse(
    val statusCode: Int,
    val body: ByteArray,
)

/** Exact-origin allowlist for the VK public API HTTPS endpoint. */
internal object VkApiUrlPolicy {
    private const val API_HOST = "api.vk.com"

    fun allows(value: String): Boolean = try {
        val uri = URI(value)
        uri.scheme.equals("https", ignoreCase = true) &&
            uri.host.equals(API_HOST, ignoreCase = true) &&
            uri.userInfo == null &&
            (uri.port == -1 || uri.port == 443) &&
            uri.rawFragment == null
    } catch (_: Exception) {
        false
    }
}
