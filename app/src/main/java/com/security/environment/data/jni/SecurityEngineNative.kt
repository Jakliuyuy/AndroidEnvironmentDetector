package com.security.environment.data.jni

import androidx.annotation.Keep
import com.security.environment.data.model.NativeDetectionItem

@Keep
class SecurityEngineNative {

    companion object {
        private var isLoaded = false

        init {
            try {
                System.loadLibrary("security_engine")
                isLoaded = true
            } catch (e: UnsatisfiedLinkError) {
                isLoaded = false
            }
        }

        fun isNativeAvailable(): Boolean = isLoaded
    }

    external fun executeAllChecks(): Array<NativeDetectionItem>
    external fun executeCategoryChecks(categoryIndex: Int): Array<NativeDetectionItem>
    external fun readSystemPropertyNative(key: String): String?
    external fun checkDirectSyscallAvailable(): Boolean

    external fun checkMapsNative(): NativeDetectionItem
    external fun checkMountsNative(): NativeDetectionItem
    external fun checkStatusNative(): NativeDetectionItem
    external fun getTracerPidNative(): Int

    external fun checkKernelSuNative(): NativeDetectionItem
    external fun checkApatchNative(): NativeDetectionItem
    external fun checkKernelRootNative(): NativeDetectionItem
    external fun checkAntiHookNative(): NativeDetectionItem

    external fun parseMapsBufferNative(buffer: String): NativeDetectionItem
    external fun parseMountinfoBufferNative(buffer: String): NativeDetectionItem
    external fun parseStatusBufferNative(buffer: String): NativeDetectionItem
}
