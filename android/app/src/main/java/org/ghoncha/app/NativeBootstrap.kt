package org.ghoncha.app

import android.content.Context

internal object NativeBootstrap {
    @JvmStatic
    external fun initialize(context: Context)
}
