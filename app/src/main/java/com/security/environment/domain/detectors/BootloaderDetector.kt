package com.security.environment.domain.detectors

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment
import com.security.environment.domain.attestation.KeyAttestationResult
import com.security.environment.domain.attestation.VerifiedBootState

class BootloaderDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    fun detect(includeHardwareAttestation: Boolean = false): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkBootloaderLock())
        results.add(checkVerifiedBootState())
        results.add(checkVbmetaState())
        results.add(checkSelinuxMode())
        results.add(checkBuildTags())
        if (includeHardwareAttestation) {
            results.add(checkHardwareKeyAttestation())
        }
        return results
    }

    /**
     * SEC-R1-01: Bootloader 硬件锁状态
     * 具备与 AndroidKeyStore 硬件证明 (Key Attestation) 的交叉校验能力，防止 Magisk resetprop 篡改伪造
     */
    fun checkBootloaderLock(): DetectionItem {
        val flashLocked = env.getSystemProperty("ro.boot.flash.locked")?.trim()
        val bootLocked = env.getSystemProperty("ro.boot.locked")?.trim()
        val secureProp = env.getSystemProperty("ro.secure")?.trim()

        val isUnlocked = flashLocked == "0" || bootLocked == "0"
        val isExplicitlyLocked = flashLocked == "1" || bootLocked == "1"

        var status = when {
            isUnlocked -> DetectionStatus.DANGER
            isExplicitlyLocked -> DetectionStatus.PASS
            secureProp == "0" -> DetectionStatus.WARN
            else -> DetectionStatus.PASS
        }

        var description = if (isUnlocked) {
            "Bootloader 处于解锁状态，设备底层安全信任链已破坏"
        } else {
            "Bootloader 处于锁定状态，固件完整性校验已开启"
        }

        val evidenceParts = mutableListOf<String>()
        evidenceParts.add("flash.locked=${flashLocked ?: "unset"}")
        evidenceParts.add("boot.locked=${bootLocked ?: "unset"}")
        evidenceParts.add("ro.secure=${secureProp ?: "unset"}")

        // 硬件密钥证明交叉校验 (Cross-validation against Hardware Attestation)
        val attestation = env.getHardwareKeyAttestation()
        if (attestation is KeyAttestationResult.Success) {
            val hwLocked = attestation.isDeviceLocked
            val hwBacking = if (attestation.isHardwareBacked) "TEE" else "Software"

            if (hwLocked != null) {
                if (!hwLocked) {
                    // 硬件证明表明底层已被解锁
                    if (isExplicitlyLocked || status == DetectionStatus.PASS) {
                        status = DetectionStatus.DANGER
                        description = "检测到 Bootloader 锁状态伪造：系统属性声称已锁定，但芯片级硬件证明 (Key Attestation) 确认设备底层实际已被解锁！"
                        evidenceParts.add("[Spoofing Detected: ro.boot.flash.locked overridden by hardware attestation (hw_locked=false)]")
                    } else {
                        status = DetectionStatus.DANGER
                        description = "Bootloader 处于解锁状态 (经硬件密钥证明确认)"
                        evidenceParts.add("hw_locked=false ($hwBacking)")
                    }
                } else {
                    evidenceParts.add("hw_locked=true ($hwBacking)")
                }
            }
        }

        return DetectionItem(
            id = "SEC-R1-01",
            name = "Bootloader 锁状态",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = evidenceParts.joinToString(", "),
            method = DetectionMethod.DIRECT_SYSCALL,
            description = description,
            remediation = if (status == DetectionStatus.DANGER) "请重新锁定 Bootloader 以防止底层固件被任意替换" else ""
        )
    }

    /**
     * SEC-R1-02: AVB (Android Verified Boot) 引导验证状态
     * 交叉验证硬件证明中的 VerifiedBootState，防止系统属性被劫持为 green
     */
    fun checkVerifiedBootState(): DetectionItem {
        val state = env.getSystemProperty("ro.boot.verifiedbootstate")?.lowercase()?.trim()

        var (status, desc) = when (state) {
            "green" -> DetectionStatus.PASS to "AVB 验证正常 (green)，系统未受篡改"
            "yellow" -> DetectionStatus.DANGER to "AVB 自签名证书启动 (yellow)，使用了非厂商信任根"
            "orange" -> DetectionStatus.DANGER to "AVB 已解锁 (orange)，设备处于可自由修改分区状态"
            "red" -> DetectionStatus.DANGER to "AVB 启动校验失败 (red)，固件损坏或遭到破坏"
            null, "" -> DetectionStatus.PASS to "AVB 状态未明确上报 (unset)"
            else -> DetectionStatus.WARN to "未知的 AVB 引导状态: $state"
        }

        val evidenceParts = mutableListOf<String>()
        evidenceParts.add("verifiedbootstate=${state ?: "unset"}")

        // 硬件密钥证明交叉校验 (Cross-validation against Hardware Attestation)
        val attestation = env.getHardwareKeyAttestation()
        if (attestation is KeyAttestationResult.Success) {
            val hwState = attestation.verifiedBootState
            val hwBacking = if (attestation.isHardwareBacked) "TEE" else "Software"

            if (hwState != null) {
                if (hwState != VerifiedBootState.VERIFIED) {
                    if (state == "green" || status == DetectionStatus.PASS) {
                        status = DetectionStatus.DANGER
                        desc = "检测到 AVB 引导状态伪造：系统属性声称 green，但芯片级硬件证明确认真实引导状态为 ${hwState.name}！"
                        evidenceParts.add("[Spoofing Detected: ro.boot.verifiedbootstate=green overridden by hardware attestation (hw_state=${hwState.name})]")
                    } else {
                        status = DetectionStatus.DANGER
                        desc = "AVB 引导验证异常 (经硬件密钥证明确认: ${hwState.name})"
                        evidenceParts.add("hw_state=${hwState.name} ($hwBacking)")
                    }
                } else {
                    evidenceParts.add("hw_state=VERIFIED ($hwBacking)")
                }
            }
        }

        return DetectionItem(
            id = "SEC-R1-02",
            name = "AVB 引导链校验",
            category = DetectionCategory.BOOTLOADER,
            status = status,
            evidence = evidenceParts.joinToString(", "),
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

    /**
     * SEC-R1-06: 硬件芯片级密钥证明 (Hardware Key Attestation)
     * 利用 Android KeyStore 在硬件安全域 (TEE / StrongBox) 中生成密钥对并提取包含 OID 1.3.6.1.4.1.11129.2.1.17
     * 的证书链证明记录，直接验证底层硬件级 Bootloader 锁定与 Verified Boot 真实状态。
     */
    fun checkHardwareKeyAttestation(): DetectionItem {
        val result = env.getHardwareKeyAttestation()
        return when (result) {
            is KeyAttestationResult.Success -> {
                val record = result.record
                val rot = record.rootOfTrust
                val isLocked = rot?.deviceLocked ?: false
                val bootState = rot?.verifiedBootState ?: VerifiedBootState.FAILED
                val isSecure = isLocked && bootState == VerifiedBootState.VERIFIED

                val status = if (isSecure) DetectionStatus.PASS else DetectionStatus.DANGER
                val desc = if (isSecure) {
                    "硬件芯片级密钥证明 (Key Attestation) 通过：TEE/StrongBox 确认设备处于官方锁定与验证状态"
                } else {
                    "硬件芯片级密钥证明 (Key Attestation) 报警：硬件安全域指示设备处于非安全状态 (locked=$isLocked, state=${bootState.name})"
                }

                val secLevel = record.attestationSecurityLevel.name
                val evidence = "securityLevel=$secLevel, hw_locked=$isLocked, hw_state=${bootState.name}, keymaster=${record.keymasterVersion}"

                DetectionItem(
                    id = "SEC-R1-06",
                    name = "硬件芯片级密钥证明",
                    category = DetectionCategory.BOOTLOADER,
                    status = status,
                    evidence = evidence,
                    method = DetectionMethod.JAVA,
                    description = desc,
                    remediation = if (!isSecure) "设备底层未通过硬件安全认证，请检查 Bootloader 与系统完整性" else ""
                )
            }
            is KeyAttestationResult.Unavailable -> {
                DetectionItem(
                    id = "SEC-R1-06",
                    name = "硬件芯片级密钥证明",
                    category = DetectionCategory.BOOTLOADER,
                    status = DetectionStatus.PASS,
                    evidence = "status=UNAVAILABLE (${result.reason})",
                    method = DetectionMethod.JAVA,
                    description = "当前环境或设备不支持硬件 KeyStore 密钥证明，已平滑降级至系统属性校验",
                    remediation = ""
                )
            }
            is KeyAttestationResult.Failed -> {
                DetectionItem(
                    id = "SEC-R1-06",
                    name = "硬件芯片级密钥证明",
                    category = DetectionCategory.BOOTLOADER,
                    status = DetectionStatus.WARN,
                    evidence = "status=FAILED (${result.reason})",
                    method = DetectionMethod.JAVA,
                    description = "硬件 KeyStore 证明执行异常: ${result.reason}",
                    remediation = "可尝试重新检测或在支持 TEE 的物理真机上运行"
                )
            }
        }
    }
}
