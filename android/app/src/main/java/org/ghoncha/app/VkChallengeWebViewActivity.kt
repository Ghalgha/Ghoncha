package org.ghoncha.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.SafeBrowsingResponse
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.net.URI

/**
 * First-party WebView surface for a user-authorized VK challenge.
 *
 * The WebView keeps its own real Android WebView identity and cookie store.
 * This class deliberately does not spoof the user agent, inject synthetic
 * pointer events, randomize browser properties, or export cookies to callers.
 * The caller must independently verify challenge acceptance with VK.
 */
class VkChallengeWebViewActivity : Activity() {
    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val challengeUrl = intent.getStringExtra(EXTRA_CHALLENGE_URL)
        if (challengeUrl == null || !isAllowedUrl(challengeUrl)) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }

        val instructions = TextView(this).apply {
            text = "Завершите проверку VK в этом окне. После проверки GHONCHA подтвердит результат на стороне VK."
            textSize = 14f
            setPadding(20, 16, 20, 16)
        }
        root.addView(
            instructions,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )

        webView = WebView(this)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            safeBrowsingEnabled = true
        }
        CookieManager.getInstance().setAcceptCookie(true)
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView,
                request: WebResourceRequest,
            ): Boolean {
                return !isAllowedUrl(request.url.toString())
            }

            override fun onSafeBrowsingHit(
                view: WebView,
                request: WebResourceRequest,
                threatType: Int,
                callback: SafeBrowsingResponse,
            ) {
                callback.backToSafety(true)
            }
        }
        webView.webChromeClient = WebChromeClient()
        root.addView(
            webView,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f,
            ),
        )

        val actions = LinearLayout(this).apply {
            gravity = Gravity.END
            setPadding(12, 8, 12, 8)
        }
        val cancel = Button(this).apply {
            text = "Отмена"
            setOnClickListener {
                setResult(RESULT_CANCELED)
                finish()
            }
        }
        val completed = Button(this).apply {
            text = "Проверка завершена"
            setOnClickListener {
                CookieManager.getInstance().flush()
                setResult(RESULT_OK)
                finish()
            }
        }
        actions.addView(cancel)
        actions.addView(completed)
        root.addView(
            actions,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )

        setContentView(root)
        webView.loadUrl(challengeUrl)
    }

    override fun onDestroy() {
        if (::webView.isInitialized) {
            webView.stopLoading()
            webView.webChromeClient = null
            webView.webViewClient = WebViewClient()
            webView.destroy()
        }
        super.onDestroy()
    }

    private fun isAllowedUrl(value: String): Boolean {
        return try {
            val uri = URI(value)
            val host = uri.host?.lowercase() ?: return false
            uri.scheme == "https" &&
                uri.userInfo == null &&
                (uri.port == -1 || uri.port == 443) &&
                host in ALLOWED_HOSTS
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        fun createIntent(context: Context, challengeUrl: String): Intent =
            Intent(context, VkChallengeWebViewActivity::class.java)
                .putExtra(EXTRA_CHALLENGE_URL, challengeUrl)

        const val EXTRA_CHALLENGE_URL = "org.ghoncha.app.VK_CHALLENGE_URL"

        private val ALLOWED_HOSTS = setOf(
            "vk.com",
            "www.vk.com",
            "id.vk.com",
            "login.vk.com",
            "vk.ru",
            "www.vk.ru",
            "id.vk.ru",
            "login.vk.ru",
        )
    }
}
