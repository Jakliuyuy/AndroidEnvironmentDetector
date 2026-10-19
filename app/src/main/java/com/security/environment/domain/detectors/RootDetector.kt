package com.security.environment.domain.detectors

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment
import java.io.File

class RootDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    companion object {
        val SU_STATIC_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/su/bin/su",
            "/su/xbin/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon"
        )

        val ROOT_MANAGER_PACKAGES = listOf(
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "io.github.huskydg.magisk",
            "me.weishu.kernelsu",
            "org.apatch",
            "org.apatch.gui",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.zhiqupk.root"
        )
    }

    fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkSuBinaryPathsAndPathScan())
        results.add(checkSuExecutionProbe())
        results.add(checkKernelSuAndApatch())
        results.add(checkMagiskMagicMountAndSockets())
        results.add(checkZygiskTraces())
        results.add(checkRootManagerPackages())
        return results
    }

    /**
     * SEC-R2-01: 传统 16 静态路径扫描与动态 PATH 环境变量遍历
     */
    fun checkSuBinaryPathsAndPathScan(): DetectionItem {
        val foundPaths = mutableListOf<String>()

        // 1. Scan 16 static paths
        for (path in SU_STATIC_PATHS) {
            if (env.fileExists(path)) {
                foundPaths.add(path)
            }
        }

        // 2. Dynamic PATH environment traversal
        val envPath = env.getEnvironmentVariable("PATH") ?: ""
        val pathDirs = envPath.split(":").filter { it.isNotBlank() }
        for (dir in pathDirs) {
            val candidate = if (dir.endsWith("/")) "${dir}su" else "$dir/su"
            if (!foundPaths.contains(candidate) && env.fileExists(candidate)) {
                foundPaths.add(candidate)
            }
        }

        val isFound = foundPaths.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "su_found: " + foundPaths.joinToString(", ")
        } else {
            "all_16_paths_clean, path_traversed=${pathDirs.size}"
        }

        val desc = if (isFound) {
            "检测到系统中存在可执行提权二进制文件 su"
        } else {
            "静态与 PATH 环境变量未发现 su 二进制文件"
        }

        return DetectionItem(
            id = "SEC-R2-01",
            name = "SU 二进制与 PATH 扫描",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "设备已被 Root 提权，请卸载 Root 方案或重刷官方固件" else ""
        )
    }

    /**
     * SEC-R2-02: 超时保护的 su 命令进程执行探测
     */
    fun checkSuExecutionProbe(): DetectionItem {
        // Run su -v with 500ms timeout
        val res = env.executeCommand(listOf("su", "-v"), timeoutMs = 500)

        val isSuccess = res.exitCode == 0 && !res.timedOut
        val stdoutLower = res.stdout.lowercase().trim()
        val isSuExecutable = isSuccess && (
                stdoutLower.contains("magisk") ||
                stdoutLower.contains("superuser") ||
                stdoutLower.contains("ksud") ||
                stdoutLower.matches(Regex(".*\\d+\\.\\d+.*")) ||
                stdoutLower.contains("su")
        )

        val status = if (isSuExecutable) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = buildString {
            append("exitCode=").append(res.exitCode)
            if (res.timedOut) append(", timedOut=true")
            append(", output=").append(res.stdout.trim().take(60))
        }

        val desc = if (isSuExecutable) {
            "su 二进制可直接执行并返回版本响应，存在提权接口"
        } else {
            "su 执行探测未响应或不存在提权接口"
        }

        return DetectionItem(
            id = "SEC-R2-02",
            name = "SU 提权执行探测",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isSuExecutable) "请清除 su 权限服务以避免应用被非法截流" else ""
        )
    }

    /**
     * SEC-R2-03: KernelSU 与 APatch 隐藏特征检测
     */
    fun checkKernelSuAndApatch(): DetectionItem {
        val anomalies = mutableListOf<String>()

        // 1. Kernel version string scan
        val procVersion = env.readFile("/proc/version") ?: ""
        val lowerVer = procVersion.lowercase()
        if (lowerVer.contains("kernelsu") || lowerVer.contains("ksu")) {
            anomalies.add("proc_version:KernelSU")
        }
        if (lowerVer.contains("apatch") || lowerVer.contains("kernelpatch")) {
            anomalies.add("proc_version:APatch")
        }

        // 2. Module & management directories
        if (env.fileExists("/data/adb/ksu")) anomalies.add("dir:/data/adb/ksu")
        if (env.fileExists("/data/adb/ap")) anomalies.add("dir:/data/adb/ap")
        if (env.fileExists("/data/adb/modules")) anomalies.add("dir:/data/adb/modules")

        // 3. Mountinfo overlayfs check on system partitions
        val mountinfo = env.readFile("/proc/self/mountinfo") ?: env.readFile("/proc/mounts") ?: ""
        val lines = mountinfo.lines()
        for (line in lines) {
            if (line.isBlank() || line.startsWith("#")) continue
            val lower = line.lowercase()
            if (lower.contains("overlay") &&
                (lower.contains("/system") || lower.contains("/vendor") || lower.contains("/product"))
            ) {
                if (lower.contains("ksu") || lower.contains("/data/adb") || lower.contains("apd")) {
                    anomalies.add("overlayfs_mount_tamper")
                    break
                }
            }
        }

        val isFound = anomalies.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "ksu_apatch_traces: " + anomalies.joinToString("; ")
        } else {
            "kernel_clean, no_ksu_apatch_overlays"
        }

        val desc = if (isFound) {
            "检测到新型内核级 Root 框架 (KernelSU / APatch) 注入或挂载痕迹"
        } else {
            "未检测到 KernelSU / APatch 内核级 Root 痕迹"
        }

        return DetectionItem(
            id = "SEC-R2-03",
            name = "KernelSU / APatch 内核探测",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "检测到内核补丁提权，请还原官方内核与分区" else ""
        )
    }

    /**
     * SEC-R2-04: Magisk Magic Mount 文件系统倒错与 Unix Socket 检测
     */
    fun checkMagiskMagicMountAndSockets(): DetectionItem {
        val anomalies = mutableListOf<String>()

        // 1. Mountinfo file system type inversion
        val mountinfo = env.readFile("/proc/self/mountinfo") ?: env.readFile("/proc/mounts") ?: ""
        for (line in mountinfo.lines()) {
            if (line.isBlank() || line.startsWith("#")) continue
            val tokens = line.split(Regex("\\s+"))
            if (tokens.size >= 5) {
                // Check if protected partition is mounted on tmpfs or overlay
                val lineLower = line.lowercase()
                val isProtectedSystem = lineLower.contains(" /system ") ||
                        lineLower.contains(" /vendor ") ||
                        lineLower.contains(" /product ") ||
                        lineLower.contains(" /system_ext ")

                if (isProtectedSystem && (lineLower.contains("tmpfs") || lineLower.contains("overlay"))) {
                    anomalies.add("magic_mount_inversion:${tokens.getOrNull(4) ?: "partition"}")
                }

                if (lineLower.contains("magisk") || lineLower.contains("core/mirror") || lineLower.contains("/sbin/.magisk")) {
                    anomalies.add("magisk_mount_source")
                }
            }
        }

        // 2. Check /proc/net/unix
        val netUnix = env.readFile("/proc/net/unix") ?: ""
        if (netUnix.contains("magisk") || netUnix.contains("ksud")) {
            anomalies.add("unix_domain_socket_daemon")
        }

        val isFound = anomalies.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "magisk_artifacts: " + anomalies.distinct().joinToString("; ")
        } else {
            "mountinfo_filesystem_clean"
        }

        val desc = if (isFound) {
            "检测到 Magisk Magic Mount 文件系统倒错或 Magisk 守护进程套接字"
        } else {
            "系统核心分区文件系统挂载与套接字状态正常"
        }

        return DetectionItem(
            id = "SEC-R2-04",
            name = "Magisk 挂载倒错与套接字",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "请完全卸载 Magisk 及模块恢复原生文件系统" else ""
        )
    }

    /**
     * SEC-R2-05: Zygisk / Riru 注入模块痕迹
     */
    fun checkZygiskTraces(): DetectionItem {
        val maps = env.readFile("/proc/self/maps") ?: ""
        val anomalies = mutableListOf<String>()

        for (line in maps.lines()) {
            val lower = line.lowercase()
            if (lower.contains("zygisk") || lower.contains("riru")) {
                anomalies.add(line.trim().take(80))
            }
        }

        val isFound = anomalies.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "zygisk_maps_found: " + anomalies.first()
        } else {
            "maps_zygisk_clean"
        }

        val desc = if (isFound) {
            "进程内存空间中检测到 Zygisk / Riru 注入模块"
        } else {
            "未检测到 Zygote 阶段注入框架残留"
        }

        return DetectionItem(
            id = "SEC-R2-05",
            name = "Zygisk / Riru 内存注入",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "请关闭 Zygisk 并在 Magisk 中撤销注入" else ""
        )
    }

    /**
     * SEC-R2-06: 常见 Root 管理器应用安装扫描
     */
    fun checkRootManagerPackages(): DetectionItem {
        val foundPackages = mutableListOf<String>()

        for (pkg in ROOT_MANAGER_PACKAGES) {
            // Probe /data/data/<pkg> or /data/user/0/<pkg>
            if (env.fileExists("/data/data/$pkg") || env.fileExists("/data/user/0/$pkg")) {
                foundPackages.add(pkg)
            }
        }

        val isFound = foundPackages.isNotEmpty()
        val status = if (isFound) DetectionStatus.WARN else DetectionStatus.PASS

        val evidence = if (isFound) {
            "packages_found: " + foundPackages.joinToString(", ")
        } else {
            "scanned_${ROOT_MANAGER_PACKAGES.size}_root_packages_clean"
        }

        val desc = if (isFound) {
            "检测到系统中安装了已知的 Root 管理工具"
        } else {
            "未发现已安装的 Root 管理器应用"
        }

        return DetectionItem(
            id = "SEC-R2-06",
            name = "Root 管理器应用安装",
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "建议卸载 Magisk/KernelSU 等提权管理器" else ""
        )
    }
}
