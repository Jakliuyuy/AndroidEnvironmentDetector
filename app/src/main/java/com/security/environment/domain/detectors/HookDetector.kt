package com.security.environment.domain.detectors

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.parser.NativeMapsParser
import com.security.environment.domain.DefaultSystemEnvironment
import com.security.environment.domain.SystemEnvironment

class HookDetector(
    private val env: SystemEnvironment = DefaultSystemEnvironment()
) {

    companion object {
        val XPOSED_CLASSES = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "org.lsposed.lspd.core.Main",
            "org.meowcat.edxposed.manager",
            "com.saurik.substrate.MS\$MethodHook"
        )

        val HOOK_STACK_KEYWORDS = listOf(
            "de.robv.android.xposed",
            "lsposed",
            "edxposed",
            "handlehookedmethod",
            "invokeoriginalmethodnative",
            "sandhook",
            "pine",
            "epic"
        )

        val FRIDA_THREADS = setOf(
            "gmain",
            "gdbus",
            "gum-js-loop",
            "pool-frida",
            "frida-gadget"
        )
    }

    fun detect(): List<DetectionItem> {
        val results = mutableListOf<DetectionItem>()
        results.add(checkXposedClassloaderReflection())
        results.add(checkHookStacktrace())
        results.add(checkFridaPortAndHandshake())
        results.add(checkFridaThreadsAndPipes())
        results.add(checkMapsHookAndAnonymousRxMemory())
        return results
    }

    /**
     * SEC-R3-01: Xposed / LSPosed 框架核心类反射加载
     */
    fun checkXposedClassloaderReflection(): DetectionItem {
        val foundClasses = mutableListOf<String>()

        for (className in XPOSED_CLASSES) {
            val clazz = env.loadClassOrNull(className)
            if (clazz != null) {
                foundClasses.add(className)
            }
        }

        val isFound = foundClasses.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "xposed_classes_loaded: " + foundClasses.joinToString(", ")
        } else {
            "xposed_classes_not_found"
        }

        val desc = if (isFound) {
            "检测到 Xposed/LSPosed 核心类已注入当前进程类加载器中"
        } else {
            "未在 ClassLoader 中发现已知 Hook 框架核心类"
        }

        return DetectionItem(
            id = "SEC-R3-01",
            name = "Xposed / LSPosed 类加载探测",
            category = DetectionCategory.HOOK,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "请在 LSPosed 管理器中取消对本应用的勾选与注入" else ""
        )
    }

    /**
     * SEC-R3-02: 运行时异常堆栈回溯探测 (Stacktrace Inspection)
     */
    fun checkHookStacktrace(): DetectionItem {
        val stackTrace = env.getStackTrace()
        val taintedFrames = mutableListOf<String>()

        for (element in stackTrace) {
            val frameStr = "${element.className}.${element.methodName}".lowercase()
            for (keyword in HOOK_STACK_KEYWORDS) {
                if (frameStr.contains(keyword)) {
                    taintedFrames.add("${element.className}.${element.methodName}")
                    break
                }
            }
        }

        val isFound = taintedFrames.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "tainted_frames: " + taintedFrames.take(3).joinToString("; ")
        } else {
            "clean_stacktrace_depth=${stackTrace.size}"
        }

        val desc = if (isFound) {
            "主动堆栈回溯发现 Hook 框架执行跳板帧特征"
        } else {
            "主动堆栈回溯未检测到动态注入劫持帧"
        }

        return DetectionItem(
            id = "SEC-R3-02",
            name = "动态 Hook 堆栈调用帧分析",
            category = DetectionCategory.HOOK,
            status = status,
            evidence = evidence,
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "检测到方法被动态 Hook 拦截，请关闭 Hook 模块" else ""
        )
    }

    /**
     * SEC-R3-03: Frida 端口与 D-Bus AUTH 协议握手探测
     */
    fun checkFridaPortAndHandshake(): DetectionItem {
        val candidatePorts = mutableSetOf(27042, 27043)

        // Parse /proc/net/tcp to find listening local ports
        val tcpContent = env.readFile("/proc/net/tcp") ?: ""
        val tcpLines = tcpContent.lines()
        for (line in tcpLines) {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size >= 4) {
                val state = parts[3]
                // 0A is LISTEN state
                if (state.equals("0A", ignoreCase = true)) {
                    val localAddress = parts[1]
                    val addrParts = localAddress.split(":")
                    if (addrParts.size == 2) {
                        try {
                            val port = addrParts[1].toInt(16)
                            val ipHex = addrParts[0]
                            // 0100007F is 127.0.0.1, 00000000 is 0.0.0.0
                            if (ipHex == "0100007F" || ipHex == "00000000") {
                                candidatePorts.add(port)
                            }
                        } catch (_: Throwable) {
                            // ignore parse error
                        }
                    }
                }
            }
        }

        // Probe candidate ports with D-Bus AUTH handshake
        val dBusAuthPayload = "\u0000AUTH\r\n".toByteArray(Charsets.US_ASCII)
        var fridaPortDetected = -1
        var fridaEvidence = "none"

        for (port in candidatePorts) {
            val response = env.probeSocket("127.0.0.1", port, dBusAuthPayload, timeoutMs = 200)
            if (response != null && response.isNotEmpty()) {
                val respStr = String(response, Charsets.US_ASCII)
                if (respStr.contains("REJECT")) {
                    fridaPortDetected = port
                    fridaEvidence = "port=$port, handshake=REJECT"
                    break
                }
            }
        }

        val isFound = fridaPortDetected != -1
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val desc = if (isFound) {
            "检测到本地监听的 Frida 控制端端口 ($fridaPortDetected) 并通过 D-Bus 握手确证"
        } else {
            "未发现开放的 Frida 控制服务端口 (已扫描 ${candidatePorts.size} 处本地端口)"
        }

        return DetectionItem(
            id = "SEC-R3-03",
            name = "Frida 端口与 D-Bus 握手探测",
            category = DetectionCategory.HOOK,
            status = status,
            evidence = if (isFound) fridaEvidence else "frida_ports_clean",
            method = DetectionMethod.JAVA,
            description = desc,
            remediation = if (isFound) "请终止 frida-server 进程并拔出调试数据线" else ""
        )
    }

    /**
     * SEC-R3-04: Frida 运行辅助线程与命名管道特征扫描
     */
    fun checkFridaThreadsAndPipes(): DetectionItem {
        val foundThreads = mutableListOf<String>()

        // 1. Thread names scan in /proc/self/task/
        val taskDirs = env.listDirectory("/proc/self/task")
        for (tid in taskDirs) {
            val comm = env.readFile("/proc/self/task/$tid/comm")?.trim()
            if (comm != null && FRIDA_THREADS.contains(comm.lowercase())) {
                foundThreads.add(comm)
            }
        }

        // 2. Named pipes in /proc/self/fd
        val foundPipes = mutableListOf<String>()
        val fdList = env.listDirectory("/proc/self/fd")
        for (fd in fdList.take(64)) {
            val fdTarget = env.readLink("/proc/self/fd/$fd") ?: ""
            if (fdTarget.contains("linjector") || fdTarget.contains("frida-")) {
                foundPipes.add(fdTarget.take(40))
            }
        }

        val isFound = foundThreads.isNotEmpty() || foundPipes.isNotEmpty()
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = if (isFound) {
            "threads=" + foundThreads.joinToString(",") + "; pipes=" + foundPipes.joinToString(",")
        } else {
            "threads_clean (${taskDirs.size} tasks inspected)"
        }

        val desc = if (isFound) {
            "检测到活跃的 Frida 辅助引擎线程或命名管道通信"
        } else {
            "进程线程池中未检测到 Frida 引擎特征线程"
        }

        return DetectionItem(
            id = "SEC-R3-04",
            name = "Frida 辅助线程与管道检测",
            category = DetectionCategory.HOOK,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "检测到 Frida 动态注入运行，请停止插桩" else ""
        )
    }

    /**
     * SEC-R3-05: /proc/self/maps 内存映射与匿名可执行代码段 (r-xp)
     */
    fun checkMapsHookAndAnonymousRxMemory(): DetectionItem {
        val mapsContent = env.readFile("/proc/self/maps") ?: ""
        val parsed = NativeMapsParser.parse(mapsContent)

        val isFound = parsed.hasHookLibrary || parsed.hasAnonymousExecutable
        val status = if (isFound) DetectionStatus.DANGER else DetectionStatus.PASS

        val evidence = when {
            parsed.hasHookLibrary -> "hook_libs_found: " + parsed.hookLibraryNames.joinToString(", ")
            parsed.hasAnonymousExecutable -> "anon_rx_found: count=${parsed.anonymousExecutableCount}, sample=${parsed.sampleAnonymousRegion}"
            else -> parsed.evidence
        }

        val desc = if (isFound) {
            "检测到内存空间映射了 Hook 注入库或异常匿名可执行段 (r-xp)"
        } else {
            "进程虚拟内存映射与可执行权限段分布正常"
        }

        return DetectionItem(
            id = "SEC-R3-05",
            name = "内存映射与匿名可执行段 (r-xp)",
            category = DetectionCategory.HOOK,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = desc,
            remediation = if (isFound) "检测到未知内存注入与 Hook 映射，请清除内存注入工具" else ""
        )
    }
}
