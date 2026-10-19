package com.security.environment.data.parser

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.NativeDetectionItem

data class MountsParseResult(
    val hasMagicMount: Boolean,
    val magicMountPoints: List<String>,
    val hasKernelSuOrApatch: Boolean,
    val rootSignatures: List<String>,
    val anomaliesCount: Int,
    val evidence: String
) {
    fun toNativeDetectionItem(): NativeDetectionItem {
        val status = if (hasMagicMount || hasKernelSuOrApatch) {
            DetectionStatus.DANGER.ordinal
        } else {
            DetectionStatus.PASS.ordinal
        }
        return NativeDetectionItem(
            id = "SEC-R2-02",
            name = "挂载点异常与新型Root特征 (/proc/self/mountinfo)",
            category = DetectionCategory.ROOT.ordinal,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL.ordinal
        )
    }
}

object NativeMountsParser {

    private val ROOT_MOUNT_SIGNATURES = listOf(
        "/data/adb/ksu",
        "/data/adb/ap",
        "/data/adb/modules",
        "magisk",
        "core/mirror",
        "core/img",
        "/sbin/.magisk",
        "mirror/system",
        "rootdir",
        "kernelsu",
        "apd"
    )

    private val PROTECTED_SYSTEM_MOUNTS = setOf(
        "/system",
        "/system_ext",
        "/vendor",
        "/product",
        "/odm"
    )

    fun parse(mountContent: String): MountsParseResult {
        if (mountContent.isBlank()) {
            return MountsParseResult(
                hasMagicMount = false,
                magicMountPoints = emptyList(),
                hasKernelSuOrApatch = false,
                rootSignatures = emptyList(),
                anomaliesCount = 0,
                evidence = "empty_mountinfo"
            )
        }

        val detectedSignatures = mutableListOf<String>()
        val magicMounts = mutableListOf<String>()

        mountContent.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach

            // 1. Signature scan
            for (sig in ROOT_MOUNT_SIGNATURES) {
                if (trimmed.contains(sig, ignoreCase = true)) {
                    if (!detectedSignatures.contains(sig)) {
                        detectedSignatures.add(sig)
                    }
                }
            }

            // 2. Parse mountinfo or mount entry
            val tokens = trimmed.split(Regex("\\s+"))
            if (tokens.size >= 5) {
                var mountPoint = tokens[4]
                var fstype = ""

                // Check for '-' separator in /proc/self/mountinfo
                val hyphenIdx = tokens.indexOf("-")
                if (hyphenIdx != -1 && hyphenIdx + 1 < tokens.size) {
                    fstype = tokens[hyphenIdx + 1]
                } else if (tokens.size >= 3) {
                    // /proc/mounts format: [src] [mount_point] [fstype] ...
                    mountPoint = tokens[1]
                    fstype = tokens[2]
                }

                val normalizedMountPoint = mountPoint.trimEnd('/')
                if (PROTECTED_SYSTEM_MOUNTS.contains(normalizedMountPoint)) {
                    if (fstype.equals("tmpfs", ignoreCase = true) || fstype.equals("overlay", ignoreCase = true)) {
                        val desc = "$normalizedMountPoint($fstype)"
                        if (!magicMounts.contains(desc)) {
                            magicMounts.add(desc)
                        }
                    }
                }
            }
        }

        val hasMagic = magicMounts.isNotEmpty()
        val hasRootSig = detectedSignatures.isNotEmpty()
        val totalAnomalies = magicMounts.size + detectedSignatures.size

        val evBuilder = StringBuilder()
        if (hasMagic) {
            evBuilder.append("magic_mount_inversion=[${magicMounts.joinToString(",")}] ")
        }
        if (hasRootSig) {
            evBuilder.append("root_signatures=[${detectedSignatures.joinToString(",")}] ")
        }
        val evidence = if (evBuilder.isEmpty()) {
            "mountinfo_clean, standard partition filesystems verified"
        } else {
            evBuilder.toString().trim()
        }

        return MountsParseResult(
            hasMagicMount = hasMagic,
            magicMountPoints = magicMounts,
            hasKernelSuOrApatch = hasRootSig,
            rootSignatures = detectedSignatures,
            anomaliesCount = totalAnomalies,
            evidence = evidence
        )
    }
}
