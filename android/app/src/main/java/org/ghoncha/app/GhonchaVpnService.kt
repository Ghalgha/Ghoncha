package org.ghoncha.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

/**
 * Owns Android's VPN service lifecycle and the local TUN descriptor.
 *
 * This stage deliberately installs no IP routes and starts no packet worker:
 * the TUN fd is adopted by Rust for lifecycle validation only. The app must
 * not report a working VPN or claim that device traffic is being forwarded
 * until the native packet/TURN runtime is implemented.
 */
class GhonchaVpnService : VpnService() {
    private val stateLock = Any()
    private var tunHandle: NativeTunInterfaceHandle? = null
    private var networkMonitor: UnderlayNetworkMonitor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        val connectivity = getSystemService(ConnectivityManager::class.java)
        networkMonitor = UnderlayNetworkMonitor(
            connectivityManager = connectivity,
            onNetworkChanged = { /* Snapshot is retained by the monitor for the runtime owner. */ },
            onNetworkLost = { _, _ -> /* The future runtime will retire that network generation. */ },
        ).also { it.start() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_PREPARE_TUN -> prepareTunInterface()
            ACTION_STOP -> stopTunnel()
            else -> {
                stopSelf(startId)
                return START_NOT_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun prepareTunInterface() {
        if (VpnService.prepare(this) != null) {
            stopSelf()
            return
        }

        synchronized(stateLock) {
            if (tunHandle != null) {
                startForegroundCompat(buildNotification())
                return
            }
            var descriptor: ParcelFileDescriptor? = null
            try {
                descriptor = Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(TUN_MTU)
                    .addAddress(TUN_IPV4_ADDRESS, TUN_IPV4_PREFIX)
                    // No addRoute() calls here: no device traffic is diverted
                    // into a data plane that does not exist yet.
                    .establish()
                    ?: throw IllegalStateException("Android refused to establish the TUN interface")

                tunHandle = NativeTunInterfaceHandle.adopt(descriptor)
                descriptor = null // detachFd() transferred the descriptor to Rust.
                // Promote only after establish() has made this an active VPN.
                startForegroundCompat(buildNotification())
                updateNotification()
            } catch (failure: Throwable) {
                descriptor?.close()
                try {
                    tunHandle?.close()
                } catch (closeFailure: Throwable) {
                    failure.addSuppressed(closeFailure)
                } finally {
                    tunHandle = null
                    android.util.Log.e(TAG, "Unable to establish the local TUN interface", failure)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    private fun stopTunnel() {
        val handle = synchronized(stateLock) {
            tunHandle.also { tunHandle = null }
        }
        try {
            handle?.close()
        } catch (failure: Throwable) {
            android.util.Log.e(TAG, "Unable to close the native TUN handle", failure)
        } finally {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        val handle = synchronized(stateLock) {
            tunHandle.also { tunHandle = null }
        }
        try {
            handle?.close()
        } catch (failure: Throwable) {
            android.util.Log.e(TAG, "Unable to close the native TUN handle during destruction", failure)
        }
        try {
            networkMonitor?.close()
        } catch (failure: Throwable) {
            android.util.Log.e(TAG, "Unable to unregister underlay network monitor", failure)
        } finally {
            networkMonitor = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            super.onDestroy()
        }
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = Intent(this, GhonchaVpnService::class.java).setAction(ACTION_STOP)
        val stopPendingIntent = PendingIntent.getService(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_tun_not_forwarding))
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_media_pause,
                    getString(R.string.vpn_stop),
                    stopPendingIntent,
                ).build(),
            )
            .build()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification())
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        const val ACTION_PREPARE_TUN = "org.ghoncha.app.action.PREPARE_TUN"
        const val ACTION_STOP = "org.ghoncha.app.action.STOP_VPN"

        private const val TAG = "GhonchaVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "ghoncha_vpn"
        private const val NOTIFICATION_ID = 41
        private const val TUN_MTU = 1500
        private const val TUN_IPV4_ADDRESS = "10.255.255.1"
        private const val TUN_IPV4_PREFIX = 32
    }
}
