package org.ghoncha.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
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
import androidx.webkit.ScriptHandler
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject

/**
 * First-party WebView surface for a user-authorized VK challenge.
 *
 * The WebView keeps its normal Android identity and cookie store. A
 * document-start observer reports only the success_token returned by the
 * VK captchaNotRobot.check endpoint. The token is an untrusted challenge
 * response, not proof of acceptance; the credential provider must verify it
 * with VK before changing provider state or publishing TURN credentials.
 *
 * No fingerprint spoofing, synthetic pointer events, or automated gestures
 * are performed here.
 */
data class VkChallengeResult(val successToken: String?)

class VkChallengeWebViewActivity : Activity() {
    private lateinit var webView: WebView
    private lateinit var status: TextView
    private lateinit var completedButton: Button
    private var challengeToken: String? = null
    private var messageBridgeInstalled = false
    private var observerScript: ScriptHandler? = null

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
            text = "Пройдите проверку VK вручную. Полученный ответ вернётся в GHONCHA; его принятие необходимо подтвердить отдельным запросом к VK."
            textSize = 14f
            setPadding(20, 16, 20, 8)
        }
        root.addView(
            instructions,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )

        status = TextView(this).apply {
            text = "Ожидание проверки…"
            textSize = 13f
            setPadding(20, 4, 20, 12)
        }
        root.addView(
            status,
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
        installChallengeObserver()
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(
                view: WebView,
                request: WebResourceRequest,
            ): Boolean {
                // Keep third-party challenge assets/frames working. Only the
                // top-level browsing context is constrained to VK origins.
                return request.isForMainFrame && !isAllowedUrl(request.url.toString())
            }

            override fun onPageStarted(view: WebView, url: String, favicon: android.graphics.Bitmap?) {
                // Also validate server redirects, including redirects initiated
                // by POST requests for which shouldOverrideUrlLoading is not a
                // reliable enforcement point.
                if (!isAllowedUrl(url)) {
                    view.stopLoading()
                    setResult(RESULT_CANCELED)
                    finish()
                }
            }

            override fun onRenderProcessGone(
                view: WebView,
                detail: android.webkit.RenderProcessGoneDetail,
            ): Boolean {
                status.text = "Процесс WebView завершился. Повторите проверку."
                setResult(RESULT_CANCELED)
                finish()
                return true
            }

            @android.annotation.TargetApi(27)
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
        completedButton = Button(this).apply {
            text = "Вернуться в GHONCHA"
            isEnabled = false
            setOnClickListener {
                val token = challengeToken ?: return@setOnClickListener
                CookieManager.getInstance().flush()
                val result = Intent().apply {
                    putExtra(EXTRA_USER_CONFIRMED, true)
                    putExtra(EXTRA_CHALLENGE_TOKEN, token)
                }
                setResult(RESULT_OK, result)
                finish()
            }
        }
        actions.addView(cancel)
        actions.addView(completedButton)
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

    private fun installChallengeObserver() {
        if (
            !WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER) ||
            !WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)
        ) {
            status.text =
                "Автопередача ответа недоступна в этой версии WebView. Завершите проверку и вернитесь в GHONCHA."
            return
        }

        try {
            WebViewCompat.addWebMessageListener(
                webView,
                BRIDGE_NAME,
                ALLOWED_ORIGIN_RULES,
            ) { view, message, sourceOrigin, _, _ ->
                val messageData = message.data ?: return@addWebMessageListener
                if (
                    view !== webView ||
                    !isAllowedOrigin(sourceOrigin) ||
                    messageData.length > MAX_BRIDGE_MESSAGE_LENGTH
                ) {
                    return@addWebMessageListener
                }

                val token = try {
                    val payload = JSONObject(messageData)
                    if (payload.optString("type") != BRIDGE_MESSAGE_TYPE) {
                        null
                    } else {
                        payload.optString("token")
                            .takeIf { it.isNotBlank() && it.length <= MAX_TOKEN_LENGTH }
                    }
                } catch (_: Exception) {
                    null
                }

                if (token != null) {
                    challengeToken = token
                    completedButton.isEnabled = true
                    status.text =
                        "Ответ CAPTCHA получен. Ожидается проверка VK после возврата в GHONCHA."
                }
            }
            messageBridgeInstalled = true
            observerScript = WebViewCompat.addDocumentStartJavaScript(
                webView,
                CHALLENGE_OBSERVER_SCRIPT,
                ALLOWED_ORIGIN_RULES,
            )
        } catch (_: RuntimeException) {
            observerScript?.let { runCatching { it.remove() } }
            observerScript = null
            if (messageBridgeInstalled) {
                runCatching { WebViewCompat.removeWebMessageListener(webView, BRIDGE_NAME) }
                messageBridgeInstalled = false
            }
            status.text =
                "Автопередача ответа недоступна. Завершите проверку и вернитесь в GHONCHA."
        }
    }

    override fun onDestroy() {
        if (::webView.isInitialized) {
            observerScript?.let { runCatching { it.remove() } }
            observerScript = null
            if (messageBridgeInstalled) {
                runCatching { WebViewCompat.removeWebMessageListener(webView, BRIDGE_NAME) }
                messageBridgeInstalled = false
            }
            webView.stopLoading()
            webView.webChromeClient = null
            webView.webViewClient = WebViewClient()
            webView.destroy()
        }
        challengeToken = null
        super.onDestroy()
    }

    private fun isAllowedUrl(value: String): Boolean =
        VkChallengeUrlPolicy.allows(value)

    private fun isAllowedOrigin(origin: Uri): Boolean =
        VkChallengeUrlPolicy.allows(origin.toString())

    companion object {
        fun createIntent(context: Context, challengeUrl: String): Intent {
            require(VkChallengeUrlPolicy.allows(challengeUrl)) {
                "Challenge URL must use an allowlisted VK HTTPS origin"
            }
            return Intent(context, VkChallengeWebViewActivity::class.java)
                .putExtra(EXTRA_CHALLENGE_URL, challengeUrl)
        }

        const val EXTRA_CHALLENGE_URL = "org.ghoncha.app.VK_CHALLENGE_URL"
        const val EXTRA_CHALLENGE_TOKEN = "org.ghoncha.app.VK_CHALLENGE_TOKEN"
        const val EXTRA_USER_CONFIRMED = "org.ghoncha.app.VK_USER_CONFIRMED"

        /**
         * Converts the activity result into a typed handoff. A non-null result
         * means only that the user returned from the WebView; successToken may
         * still be null and must never be treated as server acceptance.
         */
        fun parseResult(resultCode: Int, data: Intent?): VkChallengeResult? {
            if (
                resultCode != Activity.RESULT_OK ||
                data?.getBooleanExtra(EXTRA_USER_CONFIRMED, false) != true
            ) {
                return null
            }
            return VkChallengeResult(
                successToken = data.getStringExtra(EXTRA_CHALLENGE_TOKEN)
                    ?.takeIf { it.isNotBlank() && it.length <= MAX_TOKEN_LENGTH },
            )
        }

        private const val BRIDGE_NAME = "GhonchaCaptcha"
        private const val BRIDGE_MESSAGE_TYPE = "vk_captcha_success_token"
        private const val MAX_BRIDGE_MESSAGE_LENGTH = 16 * 1024
        private const val MAX_TOKEN_LENGTH = 8 * 1024

        private val ALLOWED_ORIGIN_RULES = VkChallengeUrlPolicy.originRules

        /**
         * Observe the VK challenge response without changing the request,
         * response, browser fingerprint, or user interaction. The response
         * body is cloned/read so the page receives its original response.
         */
        private val CHALLENGE_OBSERVER_SCRIPT = """
            (() => {
              if (window.__ghonchaCaptchaObserverInstalled) return;
              window.__ghonchaCaptchaObserverInstalled = true;

              const report = (url, body) => {
                if (typeof url !== "string" ||
                    !url.includes("captchaNotRobot.check") ||
                    typeof body !== "string" ||
                    body.length > 65536) return;

                try {
                  const parsed = JSON.parse(body);
                  const token = parsed &&
                    parsed.data &&
                    parsed.data.response &&
                    parsed.data.response.success_token;
                  if (typeof token === "string" &&
                      token.length > 0 &&
                      token.length <= $MAX_TOKEN_LENGTH &&
                      window.$BRIDGE_NAME) {
                    window.$BRIDGE_NAME.postMessage(JSON.stringify({
                      type: "$BRIDGE_MESSAGE_TYPE",
                      token: token
                    }));
                  }
                } catch (_) {}
              };

              const originalFetch = window.fetch;
              if (typeof originalFetch === "function") {
                window.fetch = function(input, init) {
                  const url = input && typeof input.url === "string"
                    ? input.url
                    : String(input);
                  return originalFetch.apply(this, arguments).then(response => {
                    try {
                      response.clone().text().then(body => report(url, body)).catch(() => {});
                    } catch (_) {}
                    return response;
                  });
                };
              }

              const originalOpen = XMLHttpRequest.prototype.open;
              const originalSend = XMLHttpRequest.prototype.send;
              XMLHttpRequest.prototype.open = function(method, url) {
                this.__ghonchaCaptchaUrl = String(url);
                return originalOpen.apply(this, arguments);
              };
              XMLHttpRequest.prototype.send = function() {
                this.addEventListener("load", function() {
                  try {
                    const body = this.responseType === "json"
                      ? JSON.stringify(this.response)
                      : this.responseType === "" || this.responseType === "text"
                        ? this.responseText
                        : null;
                    report(this.__ghonchaCaptchaUrl, body);
                  } catch (_) {}
                }, { once: true });
                return originalSend.apply(this, arguments);
              };
            })();
        """.trimIndent()
    }
}
