package org.ghoncha.app

import android.content.Context

object NativeBootstrap {
    @JvmStatic
    external fun initialize(context: Context)
}
