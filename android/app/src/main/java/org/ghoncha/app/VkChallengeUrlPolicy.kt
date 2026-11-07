package org.ghoncha.app

import java.net.URI

/**
 * Strict allowlist for the top-level VK challenge document and trusted VK
 * challenge frames. This is a navigation boundary, not an API endpoint list.
 */
internal object VkChallengeUrlPolicy {
    private val allowedHosts = setOf(
        "vk.com",
        "www.vk.com",
        "id.vk.com",
        "login.vk.com",
        "vk.ru",
        "www.vk.ru",
        "id.vk.ru",
        "login.vk.ru",
    )

    val originRules: Set<String> = allowedHosts.map { "https://$it" }.toSet()

    fun allows(value: String): Boolean = try {
        val uri = URI(value)
        val host = uri.host?.lowercase() ?: return false
        uri.scheme == "https" &&
            uri.userInfo == null &&
            (uri.port == -1 || uri.port == 443) &&
            host in allowedHosts
    } catch (_: Exception) {
        false
    }
}
