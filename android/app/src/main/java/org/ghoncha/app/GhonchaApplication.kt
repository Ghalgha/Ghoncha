package org.ghoncha.app

import android.app.Application

class GhonchaApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Fail application startup if native verifier loading or Android trust-store
        // initialization fails. Never continue with an insecure TLS configuration.
        System.loadLibrary("ghoncha_platform_android")
        NativeBootstrap.initialize(this)
    }
}
