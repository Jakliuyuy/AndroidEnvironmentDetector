package com.security.environment

import android.app.Application
import android.util.Log
import com.security.environment.data.jni.SecurityEngineNative

class SecurityApp : Application() {

    override fun onCreate() {
        super.onCreate()
        val nativeLoaded = SecurityEngineNative.isNativeAvailable()
        Log.i("SecurityApp", "SecurityEngineNative loaded: $nativeLoaded")
    }
}
