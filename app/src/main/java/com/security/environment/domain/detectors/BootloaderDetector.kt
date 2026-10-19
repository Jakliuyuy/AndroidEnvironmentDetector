package com.security.environment.domain.detectors

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment

class BootloaderDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkBootloaderLock())
        results.add(checkVerifiedBootState())
        results.add(checkVbmetaState())
        results.add(checkSelinuxMode())
        results.add(checkBuildTags())
        return results
    }

    /**
     * SEC-R1-01: Bootloader 硬件锁状态
     */
    fun checkBootloaderLock(): DetectionItem {
        val flashLocked = env.getSystemProperty("ro.boot.flash.locked")?.trim()
        val bootLocked = env.getSystemProperty("ro.boot.locked")?.trim()
        val secureProp = env.getSystemProperty("ro.secure")?.trim()

        val isUnlocked = flashLocked == "0" || bootLocked == "0"
        val isExplicitlyLocked = flashLocked == "1" || bootLocked == "1"

        val status = when {
            isUnlocked -> DetectionStatus.DANGER
            isExplicitlyLocked -> DetectionStatus.PASS
            secureProp == "0" -> DetectionStatus.WARN
            else -> DetectionStatus.PASS
        }

        val evidence = buildString {
            append("flash.locked=").append(flashLocked ?: "unset")
            append(", boot.locked=").append(bootLocked ?: "unset")
            append(", ro.secure=").append(secureProp ?: "unset")
        }

        val description = if (isUnlocked) {
            "Bootloader 处于解锁状态，设备底层安全信任链已破坏"
        } else {
            "Bootloader 处于锁定状态，固件完整性校验已开启"
        }

        return DetectionItem(
            id = "SEC-R1-01",
            name = "Bootloader 锁状态",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = description,
            remediation = if (isUnlocked) "请重新锁定 Bootloader 以防止底层固件被任意替换" else ""
        )
    }

    /**
     * SEC-R1-02: AVB (Android Verified Boot) 引导验证状态
     */
    fun checkVerifiedBootState(): DetectionItem {
        val state = env.getSystemProperty("ro.boot.verifiedbootstate")?.lowercase()?.trim()

        val (status, desc) = when (state) {
            "green" -> DetectionStatus.PASS to "AVB 验证正常 (green)，系统未受篡改"
            "yellow" -> DetectionStatus.DANGER to "AVB 自签名证书启动 (yellow)，使用了非厂商信任根"
            "orange" -> DetectionStatus.DANGER to "AVB 已解锁 (orange)，设备处于可自由修改分区状态"
            "red" -> DetectionStatus.DANGER to "AVB 启动校验失败 (red)，固件损坏或遭到破坏"
            null, "" -> DetectionStatus.PASS to "AVB 状态未明确上报 (unset)"
            else -> DetectionStatus.WARN to "未知的 AVB 引导状态: $state"
        }

        return DetectionItem(
            id = "SEC-R1-02",
            name = "AVB 引导链校验",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = "verifiedbootstate=${state ?: "unset"}",
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (status == DetectionStatus.DANGER) "请恢复官方系统并重新启用 Verified Boot" else ""
        )
    }

    /**
     * SEC-R1-03: VBMeta 分区校验状态
     */
    fun checkVbmetaState(): DetectionItem {
        val vbmetaState = env.getSystemProperty("ro.boot.vbmeta.device_state")?.lowercase()?.trim()
        val vbmetaDigest = env.getSystemProperty("ro.boot.vbmeta.digest")

        val isUnlocked = vbmetaState == "unlocked"
        val status = if (isUnlocked) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = "vbmeta.device_state=${vbmetaState ?: "unset"}, digest=${vbmetaDigest ?: "unset"}"
        val desc = if (isUnlocked) {
            "VBMeta 分区处于解锁状态，禁止安全启动防御"
        } else {
            "VBMeta 分区锁定状态正常"
        }

        return DetectionItem(
            id = "SEC-R1-03",
            name = "VBMeta 分区校验",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isUnlocked) "请刷入官方 vbmeta 镜像并开启锁定保护" else ""
        )
    }

    /**
     * SEC-R1-04: SELinux 运行模式与进程安全上下文
     */
    fun checkSelinuxMode(): DetectionItem {
        // 1. Check enforce file
        val enforceContent = env.readFile("/sys/fs/selinux/enforce")?.trim()

        // 2. Check mount
        val mounts = env.readFile("/proc/mounts") ?: ""
        val hasSelinuxMount = mounts.contains("selinuxfs")

        // 3. Check process context
        val currentContext = env.readFile("/proc/self/attr/current")?.trim() ?: "unknown"
        val isTaintedContext = currentContext.contains(":su:") ||
                currentContext.contains(":magisk:") ||
                currentContext.contains(":kernel:") ||
                currentContext.contains(":init:")

        val status: DetectionStatus
        val desc: String

        when {
            isTaintedContext -> {
                status = DetectionStatus.DANGER
                desc = "SELinux 进程域异常篡改: $currentContext"
            }
            enforceContent == "1" -> {
                status = DetectionStatus.PASS
                desc = "SELinux 处于严格强制执行模式 (Enforcing)"
            }
            enforceContent == "0" -> {
                status = DetectionStatus.DANGER
                desc = "SELinux 处于宽容模式 (Permissive)，安全防护被绕过"
            }
            !hasSelinuxMount -> {
                status = DetectionStatus.DANGER
                desc = "SELinux 未挂载或已被内核禁用 (Disabled)"
            }
            else -> {
                status = DetectionStatus.WARN
                desc = "无法确认 SELinux 状态，读取受限"
            }
        }

        val evidence = "enforce=${enforceContent ?: "none"}, mount=$hasSelinuxMount, context=$currentContext"

        return DetectionItem(
            id = "SEC-R1-04",
            name = "SELinux 运行模式与上下文",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (status == DetectionStatus.DANGER) "请将 SELinux 恢复为 Enforcing 模式" else ""
        )
    }

    /**
     * SEC-R1-05: 固件签名与系统构建标记
     */
    fun checkBuildTags(): DetectionItem {
        val buildTags = env.getSystemProperty("ro.build.tags") ?: ""
        val buildType = env.getSystemProperty("ro.build.type") ?: ""

        val hasTestKeys = buildTags.contains("test-keys") || buildTags.contains("dev-keys")
        val isDebuggableBuild = buildType == "userdebug" || buildType == "eng"

        val status = when {
            hasTestKeys -> DetectionStatus.DANGER
            isDebuggableBuild -> DetectionStatus.WARN
            else -> DetectionStatus.PASS
        }

        val desc = when {
            hasTestKeys -> "系统使用第三方测试密钥签名 (test-keys/dev-keys)，非官方官方固件"
            isDebuggableBuild -> "系统为工程调试版本 (userdebug/eng)"
            else -> "系统签名与发布类型正常 (release-keys/user)"
        }

        return DetectionItem(
            id = "SEC-R1-05",
            name = "系统签名与构建标记",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = "ro.build.tags=$buildTags, ro.build.type=$buildType",
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (status != DetectionStatus.PASS) "建议使用厂商官方正式发布的 Release 固件" else ""
        )
    }
}
