package com.security.environment.data.parser

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.NativeDetectionItem

data class MapsParseResult(
    val hasHookLibrary: Boolean,
    val hookLibraryNames: List<String>,
    val hasAnonymousExecutable: Boolean,
    val anonymousExecutableCount: Int,
    val sampleAnonymousRegion: String,
    val suspiciousTotal: Int,
    val evidence: String
) {
    fun toNativeDetectionItem(): NativeDetectionItem {
        val status = if (hasHookLibrary || hasAnonymousExecutable) {
            DetectionStatus.DANGER.ordinal
        } else {
            DetectionStatus.PASS.ordinal
        }
        return NativeDetectionItem(
            id = "SEC-R3-04",
            name = "内存映射与动态插桩检测 (/proc/self/maps)",
            category = DetectionCategory.HOOK.ordinal,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL.ordinal
        )
    }
}

object NativeMapsParser {

    private val SUSPICIOUS_LIBS = listOf(
        "frida-agent",
        "frida-gadget",
        "linjector",
        "gadget.so",
        "liblspd.so",
        "libxposed",
        "libsandhook",
        "libpine",
        "libwhale",
        "libepic",
        "XposedBridge.jar",
        "edxposed",
        "libsubstrate.so",
        "zygisk",
        "riru"
    )

    private val ANON_EXEC_WHITELIST = setOf(
        "[anon:dalvik-jit-code-cache]",
        "[anon:dalvik-data-code-cache]",
        "[anon:dalvik-zygote-jit-code-cache]",
        "[anon:dalvik-alloc-space]",
        "[stack]",
        "[vectors]",
        "[vdso]",
        "[vsyscall]"
    )

    fun parse(mapsContent: String): MapsParseResult {
        if (mapsContent.isBlank()) {
            return MapsParseResult(
                hasHookLibrary = false,
                hookLibraryNames = emptyList(),
                hasAnonymousExecutable = false,
                anonymousExecutableCount = 0,
                sampleAnonymousRegion = "",
                suspiciousTotal = 0,
                evidence = "empty_maps"
            )
        }

        val detectedLibs = mutableListOf<String>()
        var anonExecCount = 0
        var sampleRegion = ""

        mapsContent.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty()) return@forEach

            // Format: address perms offset dev inode pathname
            val tokens = trimmed.split(Regex("\\s+"))
            if (tokens.size < 5) return@forEach

            val address = tokens[0]
            val perms = tokens[1]
            val pathname = if (tokens.size >= 6) tokens.drop(5).joinToString(" ").trim() else ""

            // 1. Hook / dynamic instrumentation libraries check
            if (pathname.isNotEmpty()) {
                for (lib in SUSPICIOUS_LIBS) {
                    if (pathname.contains(lib, ignoreCase = true)) {
                        if (!detectedLibs.contains(lib)) {
                            detectedLibs.add(lib)
                        }
                    }
                }
            }

            // 2. Anonymous executable memory check
            if (perms.contains('x')) {
                val isAnon = pathname.isEmpty() || pathname.startsWith("[anon")
                if (isAnon && !ANON_EXEC_WHITELIST.contains(pathname)) {
                    anonExecCount++
                    if (sampleRegion.isEmpty()) {
                        val pathDesc = if (pathname.isEmpty()) "[anon-unnamed]" else pathname
                        sampleRegion = "$address $perms $pathDesc"
                    }
                }
            }
        }

        val hasHook = detectedLibs.isNotEmpty()
        val hasAnonExec = anonExecCount > 0
        val totalSuspicious = detectedLibs.size + anonExecCount

        val evBuilder = StringBuilder()
        if (hasHook) {
            evBuilder.append("hook_libs=[${detectedLibs.joinToString(",")}] ")
        }
        if (hasAnonExec) {
            evBuilder.append("anon_rx_count=$anonExecCount sample=$sampleRegion")
        }
        val evidence = if (evBuilder.isEmpty()) {
            "maps_clean, no hook libs or anomalous executable pages detected"
        } else {
            evBuilder.toString().trim()
        }

        return MapsParseResult(
            hasHookLibrary = hasHook,
            hookLibraryNames = detectedLibs,
            hasAnonymousExecutable = hasAnonExec,
            anonymousExecutableCount = anonExecCount,
            sampleAnonymousRegion = sampleRegion,
            suspiciousTotal = totalSuspicious,
            evidence = evidence
        )
    }
}
