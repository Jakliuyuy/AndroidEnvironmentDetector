package com.security.environment.domain.detectors

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings
import com.security.environment.data.jni.SecurityEngineNative
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.parser.NativeStatusParser
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment

class DebugDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    private val nativeEngine = SecurityEngineNative()

    fun detect(context: Context? = null): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkJdwpDebugger(context))
        results.add(checkAdbSetting(context))
        results.add(checkTracerPid())
        results.add(checkDefensivePtrace())
        return results
    }

    /**
     * SEC-R4-05: JDWP 动态调试器与应用 Debuggable 状态
     */
    fun checkJdwpDebugger(
        context: Context? = null,
        simulatedConnected: Boolean? = null,
        simulatedDebuggable: Boolean? = null
    ): DetectionItem {
        val isConnected = simulatedConnected ?: try {
            Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        } catch (_: Throwable) {
            false
        }

        val isDebuggable = simulatedDebuggable ?: try {
            if (context != null) {
                (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            } else {
                false
            }
        } catch (_: Throwable) {
            false
        }

        val (status, desc) = when {
            isConnected -> DetectionStatus.DANGER to "检测到 JDWP 调试器已连接，应用正处于单步调试状态"
            isDebuggable -> DetectionStatus.WARN to "应用处于 Debuggable 可调试编译模式"
            else -> DetectionStatus.PASS to "JDWP 调试器未连接，应用调试标志正常"
        }

        val evidence = "isDebuggerConnected=$isConnected, debuggable=$isDebuggable"

        return DetectionItem(
            id = "SEC-R4-05",
            name = "JDWP 调试器连接检测",
            category = DetectionCategory.DEBUGGING,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isConnected) "请断开 Android Studio 或 JDB 调试连接" else ""
        )
    }

    /**
     * SEC-R4-06: 开发者选项与 ADB 调试开关状态
     */
    fun checkAdbSetting(context: Context? = null, simulatedAdbEnabled: Boolean? = null): DetectionItem {
        val adbSetting = simulatedAdbEnabled ?: try {
            if (context != null) {
                Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
            } else {
                false
            }
        } catch (_: Throwable) {
            false
        }

        val adbdSvc = env.getSystemProperty("init.svc.adbd")
        val isAdbRunning = adbSetting || adbdSvc == "running"

        val status = if (isAdbRunning) DetectionStatus.WARN else DetectionStatus.PASS

        val evidence = "adb_setting=$adbSetting, init.svc.adbd=${adbdSvc ?: "unknown"}"
        val desc = if (isAdbRunning) {
            "设备开启了 USB 调试模式或 adbd 守护进程处于活跃状态"
        } else {
            "ADB 调试开关未开启，未检测到 adbd 进程"
        }

        return DetectionItem(
            id = "SEC-R4-06",
            name = "ADB 调试开关状态",
            category = DetectionCategory.DEBUGGING,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isAdbRunning) "建议在开发者选项中关闭 USB 调试" else ""
        )
    }

    /**
     * SEC-R4-07: /proc/self/status TracerPid 进程追踪与 GDB/LLDB 挂钩
     */
    fun checkTracerPid(): DetectionItem {
        val statusContent = env.readFile("/proc/self/status") ?: ""
        val parsed = NativeStatusParser.parse(statusContent)

        val isTraced = parsed.isTraced
        val status = if (isTraced) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isTraced) {
            "TracerPid=${parsed.tracerPid}, state=${parsed.state}"
        } else {
            "TracerPid=0, state=${parsed.state}"
        }

        val desc = if (isTraced) {
            "检测到外部进程正在挂钩与调试本进程 (TracerPid: ${parsed.tracerPid})"
        } else {
            "当前进程未被调试器 (ptrace/gdb) 附加跟踪"
        }

        return DetectionItem(
            id = "SEC-R4-07",
            name = "TracerPid 调试依附跟踪",
            category = DetectionCategory.DEBUGGING,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isTraced) "检测到外部调试附加，请终止调试器进程" else ""
        )
    }

    /**
     * SEC-R4-08: 防御性 PTRACE_TRACEME 自跟踪保护
     */
    fun checkDefensivePtrace(simulatedSuccess: Boolean? = null): DetectionItem {
        // If native is available, check TracerPid or direct syscall
        val isAttached = if (simulatedSuccess != null) {
            !simulatedSuccess
        } else if (SecurityEngineNative.isNativeAvailable()) {
            val tracerPid = try { nativeEngine.getTracerPidNative() } catch (_: Throwable) { 0 }
            tracerPid > 0
        } else {
            false
        }

        val status = if (isAttached) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isAttached) {
            "ptrace_denied_or_already_traced (EPERM)"
        } else {
            "ptrace_traceme_available_or_active"
        }

        val desc = if (isAttached) {
            "自跟踪防御失败，已有外部调试器挂钩附加本进程"
        } else {
            "进程具备防调试附加能力或已建立自跟踪占位保护"
        }

        return DetectionItem(
            id = "SEC-R4-08",
            name = "防 ptrace 附加探测",
            category = DetectionCategory.DEBUGGING,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isAttached) "请关闭外部分析工具对应用的内存附加" else ""
        )
    }
}
