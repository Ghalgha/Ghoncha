package org.ghoncha.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Minimal lifecycle test surface.
 *
 * The TUN test intentionally installs no routes and forwards no packets. It is
 * not presented as a working VPN connection.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply {
            text = getString(R.string.vpn_tun_test_description)
            textSize = 16f
        }

        val prepareTun = Button(this).apply {
            text = getString(R.string.vpn_prepare_tun)
            setOnClickListener {
                val consentIntent = VpnService.prepare(this@MainActivity)
                if (consentIntent == null) {
                    startTunService()
                } else {
                    startActivityForResult(consentIntent, REQUEST_VPN_PERMISSION)
                }
            }
        }

        val stopTun = Button(this).apply {
            text = getString(R.string.vpn_stop)
            setOnClickListener {
                startService(
                    Intent(this@MainActivity, GhonchaVpnService::class.java)
                        .setAction(GhonchaVpnService.ACTION_STOP),
                )
                status.text = getString(R.string.vpn_tun_stopped)
            }
        }

        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(32, 48, 32, 32)
                addView(
                    TextView(this@MainActivity).apply {
                        text = getString(R.string.app_name)
                        textSize = 24f
                    },
                )
                addView(status)
                addView(prepareTun)
                addView(stopTun)
            },
        )
    }

    @Deprecated("Uses the platform VPN consent activity result contract.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN_PERMISSION) return
        if (resultCode == RESULT_OK) {
            startTunService()
        } else {
            status.text = getString(R.string.vpn_permission_denied)
        }
    }

    private fun startTunService() {
        val intent = Intent(this, GhonchaVpnService::class.java)
            .setAction(GhonchaVpnService.ACTION_PREPARE_TUN)
        startForegroundService(intent)
        status.text = getString(R.string.vpn_tun_start_requested)
    }

    companion object {
        private const val REQUEST_VPN_PERMISSION = 71
    }
}
