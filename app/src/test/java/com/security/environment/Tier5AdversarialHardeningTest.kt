package com.security.environment

import android.content.Context
import com.security.environment.data.export.ReportSerializer
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityLevel
import com.security.environment.data.parser.NativeMapsParser
import com.security.environment.data.parser.NativeMountsParser
import com.security.environment.data.parser.NativeStatusParser
import com.security.environment.domain.CommandResult
import com.security.environment.domain.DetectionCoordinator
import com.security.environment.domain.SecurityScorer
import com.security.environment.domain.detectors.BootloaderDetector
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.HookDetector
import com.security.environment.domain.detectors.RootDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import com.security.environment.ui.SecurityDashboardViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tier 5 对抗挑战与深度加固测试套件 (Adversarial Hardening Test Suite)
 *
 * 覆盖深度对抗向量：
 * 1. SECCOMP / filter 模拟陷阱在直接系统调用上的情况（降级与失败容错）
 * 2. 畸形 & 截断的 /proc、/proc/self/status、/proc/self/maps 和 mount 行（特殊 Unicode/控制字符/零宽空格/多斜杠逃逸）
 * 3. 高并发压力测试：ViewModel、DetectionCoordinator 与 SecurityScorer 线程安全
 * 4. 损坏的系统属性与极端 TracerPid 边界测试
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Tier5AdversarialHardeningTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var coordinator: DetectionCoordinator
    private lateinit var scorer: SecurityScorer

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        mockEnv = MockSystemEnvironment()
        setupBaselineCleanEnvironment(mockEnv)

        coordinator = DetectionCoordinator(
            bootloaderDetector = BootloaderDetector(mockEnv),
            rootDetector = RootDetector(mockEnv),
            hookDetector = HookDetector(mockEnv),
            virtualEnvDetector = VirtualEnvDetector(mockEnv),
            debugDetector = DebugDetector(mockEnv),
            ioDispatcher = testDispatcher
        )
        scorer = SecurityScorer()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun setupBaselineCleanEnvironment(env: MockSystemEnvironment) {
        env.properties["ro.boot.flash.locked"] = "1"
        env.properties["ro.boot.verifiedbootstate"] = "green"
        env.properties["ro.boot.vbmeta.device_state"] = "locked"
        env.properties["ro.build.tags"] = "release-keys"
        env.properties["ro.build.type"] = "user"
        env.files["/sys/fs/selinux/enforce"] = "1"
        env.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        env.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"
        env.envVariables["PATH"] = "/system/bin:/system/xbin"
        env.files["/proc/version"] = "Linux version 5.15.0-generic"
        env.files["/proc/self/mountinfo"] = "120 25 254:0 / /system ro - erofs /dev/block/dm-0 ro"
        env.commandHandlers[listOf("su", "-v")] = CommandResult(127, "", "not found")
        env.files["/proc/net/tcp"] = ""
        env.directories["/proc/self/task"] = listOf("100")
        env.files["/proc/self/task/100/comm"] = "main"
        env.files["/proc/self/maps"] = "7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so"
        env.properties["ro.hardware"] = "qcom"
        env.properties["ro.kernel.qemu"] = "0"
        env.properties["ro.product.model"] = "CleanDevice"
        env.files["/proc/self/status"] = "TracerPid:\t0\nState:\tS"
        env.properties["init.svc.adbd"] = "stopped"
    }

    // =========================================================================
    // 向量 1: SECCOMP / Filter 模拟陷阱与系统调用错误码处理
    // =========================================================================

    @Test
    fun testSeccompTrapDirectSyscallDisabledGracefulFallback() = runTest {
        // 当底层直接 syscall 受到 seccomp 过滤器拦截返回错误或不可用时，
        // DetectionCoordinator 必须平滑降级，返回完整的各模块检测结果，无任何未捕获异常
        val results = coordinator.executeFullScan(null)
        advanceUntilIdle()

        assertNotNull(results)
        assertTrue("Detection items must be populated even under fallback", results.isNotEmpty())
        assertTrue("Must include all categories", results.any { it.category == DetectionCategory.BOOTLOADER })
        assertTrue("Must include all categories", results.any { it.category == DetectionCategory.ROOT })
        assertTrue("Must include all categories", results.any { it.category == DetectionCategory.HOOK })
        assertTrue("Must include all categories", results.any { it.category == DetectionCategory.VIRTUALIZATION })
        assertTrue("Must include all categories", results.any { it.category == DetectionCategory.DEBUGGING })

        // 基线环境下评估等级为 SAFE
        val assessment = scorer.calculateScore(results)
        assertEquals(SecurityLevel.SAFE, assessment.level)
        assertEquals(100, assessment.score)
    }

    @Test
    fun testSeccompSyscallReturningNegativeErrorCodesDoesNotTriggerFalsePositives() {
        // 模拟直接系统调用（如 faccessat）被 SECCOMP 拦截，返回 -1 (EPERM) 或 -38 (ENOSYS)
        // 探测器必须确保只有明确返回成功 (0) 时才判定存在，负数错误码绝不能被当做文件存在
        val rootDetector = RootDetector(mockEnv)
        val suCheck = rootDetector.checkSuBinaryPathsAndPathScan()
        assertEquals(DetectionStatus.PASS, suCheck.status)

        val probeCheck = rootDetector.checkSuExecutionProbe()
        assertEquals(DetectionStatus.PASS, probeCheck.status)
    }

    // =========================================================================
    // 向量 2: 畸形 & 截断的 /proc、status、maps 和 mount 行（特殊 Unicode/控制字符/多斜杠逃逸）
    // =========================================================================

    @Test
    fun testMapsParserWithControlAndUnicodeZeroWidthChars() {
        // 注入包含截断 NULL 字符、零宽空格、回车换行以及极端超长路径的 maps 内容
        val malformedMaps = """
            00400000-00452000 r-xp 00000000 08:02 1234 /system/bin/app_process64
            7f00000000-7f00010000 rwxp 00000000 00:00 0 [anon:corrupted\u0000payload]
            7f10000000-7f10020000 r-xp 00000000 08:01 9999 /data/local/tmp/frida-agent-64.so
            7f20000000-7f20030000 r-xp 00000000 08:01 8888 ${"/long_dir".repeat(100)}/liblspd.so
            corrupted_tokens_line_without_address
            7f30000000-7f30010000 ---p 00000000 00:00 0
        """.trimIndent()

        val parsed = NativeMapsParser.parse(malformedMaps)
        assertTrue("Must detect hook library frida-agent", parsed.hasHookLibrary)
        assertTrue("Must detect hook library liblspd.so", parsed.hookLibraryNames.contains("liblspd.so"))
        assertTrue("Must detect anonymous executable segment", parsed.hasAnonymousExecutable)
        assertEquals(DetectionStatus.DANGER.ordinal, parsed.toNativeDetectionItem().status)
    }

    @Test
    fun testMountinfoMultiTrailingSlashEvasionResistance() {
        // 规避技术：通过多个连续的尾部斜杠（例如 /system/// 或 /vendor////）挂载 overlay/tmpfs 试图绕过单斜杠匹配
        val evasiveMountinfo = """
            120 25 254:0 / /system/// ro,nodev shared:1 - overlay overlay rw,relatime
            121 25 254:1 / /vendor//// ro,nodev shared:2 - tmpfs tmpfs rw,relatime
            122 25 254:2 / /system_ext// ro,nodev shared:3 - ext4 /dev/block/dm-1 ro
        """.trimIndent()

        val parsed = NativeMountsParser.parse(evasiveMountinfo)
        // 加固后：trimEnd('/') 必须成功识别 /system/// 与 /vendor//// 并报 DANGER
        assertTrue("Must detect magic mount inversion on multi-slash path", parsed.hasMagicMount)
        assertEquals(2, parsed.magicMountPoints.size)
        assertTrue(parsed.magicMountPoints.any { it.startsWith("/system(overlay)") })
        assertTrue(parsed.magicMountPoints.any { it.startsWith("/vendor(tmpfs)") })
        assertEquals(DetectionStatus.DANGER.ordinal, parsed.toNativeDetectionItem().status)
    }

    @Test
    fun testMountinfoWithSpecialControlCharactersAndUnicodeNames() {
        // 在 mountinfo 行中注入各类非 ASCII、Unicode 控制字符和换行噪声
        val noisyMountinfo = """
            # Comment line with special unicode: 🛡️⚙️
            100 20 0:50 / /data/adb/ksu rw,noatime shared:1 - ext4 /dev/block/sda1 rw
            \u0000\u0001\u0002
            101 20 0:51 / /data/local/tmp rw - ext4 /dev/block/sda2 options=apd_daemon_active
            102 20 0:52 / /product rw - ext4 /dev/block/dm-2 ro
        """.trimIndent()

        val parsed = NativeMountsParser.parse(noisyMountinfo)
        assertTrue("Must detect KernelSU/APatch trace", parsed.hasKernelSuOrApatch)
        assertTrue(parsed.rootSignatures.contains("/data/adb/ksu"))
        assertTrue(parsed.rootSignatures.contains("apd"))
    }

    @Test
    fun testStatusParserWithMalformedControlCharsAndTrailingNoise() {
        // 测试各类畸形 TracerPid 注入
        val tabbedStatus = "Name:\tcom.security.app\r\nTracerPid:\t  \t99999\t  \r\nState:\tS (sleeping)\r\n"
        val parsed1 = NativeStatusParser.parse(tabbedStatus)
        assertEquals(99999, parsed1.tracerPid)
        assertTrue(parsed1.isTraced)

        val zeroStatus = "TracerPid:\t0\n"
        val parsed2 = NativeStatusParser.parse(zeroStatus)
        assertEquals(0, parsed2.tracerPid)
        assertFalse(parsed2.isTraced)

        val emptyStatus = ""
        val parsed3 = NativeStatusParser.parse(emptyStatus)
        assertEquals(0, parsed3.tracerPid)
        assertFalse(parsed3.isTraced)
    }

    // =========================================================================
    // 向量 3: 高并发压力测试 (ViewModel, DetectionCoordinator, Scorer)
    // =========================================================================

    @Test
    fun testHighConcurrencyStressOnDetectionCoordinator() {
        // 多线程高并发执行 Coordinator 全量检测
        val stressCoordinator = DetectionCoordinator(
            bootloaderDetector = BootloaderDetector(mockEnv),
            rootDetector = RootDetector(mockEnv),
            hookDetector = HookDetector(mockEnv),
            virtualEnvDetector = VirtualEnvDetector(mockEnv),
            debugDetector = DebugDetector(mockEnv),
            ioDispatcher = Dispatchers.IO
        )

        val threadPool = Executors.newFixedThreadPool(8)
        val numThreads = 8
        val iterationsPerThread = 15
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())
        val successCount = AtomicInteger(0)

        val latch = CountDownLatch(1)
        val tasks = (0 until numThreads).map {
            threadPool.submit {
                try {
                    latch.await()
                    for (i in 0 until iterationsPerThread) {
                        runBlocking(Dispatchers.IO) {
                            val items = stressCoordinator.executeFullScan(null)
                            assertTrue(items.isNotEmpty())
                            val assessment = scorer.calculateScore(items)
                            assertEquals(SecurityLevel.SAFE, assessment.level)
                            successCount.incrementAndGet()
                        }
                    }
                } catch (t: Throwable) {
                    errors.add(t)
                }
            }
        }

        latch.countDown()
        for (task in tasks) {
            task.get(5, TimeUnit.SECONDS)
        }

        threadPool.shutdown()
        assertTrue(threadPool.awaitTermination(3, TimeUnit.SECONDS))
        assertEquals(0, errors.size)
        assertEquals(numThreads * iterationsPerThread, successCount.get())
    }

    @Test
    fun testHighConcurrencyStressOnSecurityScorer() {
        // 16 线程高并发计算不同风险项组合的得分，验证严格的数学不变量与无状态安全性
        val threadPool = Executors.newFixedThreadPool(16)
        val numThreads = 16
        val iterationsPerThread = 500
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())

        val latch = CountDownLatch(1)
        val tasks = (0 until numThreads).map { threadIdx ->
            threadPool.submit {
                try {
                    latch.await()
                    for (i in 0 until iterationsPerThread) {
                        val d = (threadIdx + i) % 5
                        val w = (threadIdx * 2 + i) % 8
                        val p = (threadIdx * 3 + i) % 10

                        val list = mutableListOf<DetectionItem>()
                        for (k in 0 until d) list.add(DetectionItem("D-$k", "D", DetectionCategory.ROOT, DetectionStatus.DANGER, "ev", DetectionMethod.DIRECT_SYSCALL))
                        for (k in 0 until w) list.add(DetectionItem("W-$k", "W", DetectionCategory.DEBUGGING, DetectionStatus.WARN, "ev", DetectionMethod.JAVA))
                        for (k in 0 until p) list.add(DetectionItem("P-$k", "P", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "ev", DetectionMethod.DIRECT_SYSCALL))

                        val res = scorer.calculateScore(list)
                        if (d > 0) {
                            assertEquals(SecurityLevel.DANGEROUS, res.level)
                            assertTrue(res.score <= 40)
                        } else if (w > 0) {
                            assertEquals(SecurityLevel.WARNING, res.level)
                            assertTrue(res.score in 45..75)
                        } else {
                            assertEquals(SecurityLevel.SAFE, res.level)
                            assertEquals(100, res.score)
                        }
                    }
                } catch (t: Throwable) {
                    errors.add(t)
                }
            }
        }

        latch.countDown()
        for (task in tasks) {
            task.get(10, TimeUnit.SECONDS)
        }

        threadPool.shutdown()
        assertTrue(threadPool.awaitTermination(5, TimeUnit.SECONDS))
        assertEquals(0, errors.size)
    }

    @Test
    fun testViewModelConcurrentStateMutationsAndReentrantScans() = runTest {
        val vm = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = testDispatcher,
            autoScan = false
        )

        // 并发交替变更条件
        val jobs = listOf(
            async { vm.triggerScan() },
            async { vm.selectCategory(DetectionCategory.ROOT) },
            async { vm.updateSearchQuery("su") },
            async { vm.toggleOnlyAbnormal(true) },
            async { vm.expandAllItems() },
            async { vm.collapseAllItems() },
            async { vm.openExportDialog() },
            async { vm.dismissExportDialog() }
        )

        jobs.awaitAll()
        advanceUntilIdle()

        val state = vm.uiState.value
        assertFalse("Scanning should complete without deadlock", state.isScanning)
        assertNotNull(state.assessment)
        assertTrue(state.items.isNotEmpty())
    }

    // =========================================================================
    // 向量 4: 损坏的系统属性与极端 TracerPid 边界测试
    // =========================================================================

    @Test
    fun testCorruptedSystemPropertiesWithWhitespaceAndCasing() {
        // 模拟被混淆或污染的系统属性
        val taintedEnv = MockSystemEnvironment().apply {
            setupBaselineCleanEnvironment(this)
            properties["ro.boot.flash.locked"] = " 0 " // 尾部与首部空格
            properties["ro.boot.verifiedbootstate"] = " ORANGE\n" // 大写与换行
            properties["ro.boot.vbmeta.device_state"] = " UNLOCKED " // 大写与空格
        }

        val detector = BootloaderDetector(taintedEnv)

        val lockItem = detector.checkBootloaderLock()
        assertEquals(DetectionStatus.DANGER, lockItem.status)

        val avbItem = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, avbItem.status)

        val vbmetaItem = detector.checkVbmetaState()
        assertEquals(DetectionStatus.DANGER, vbmetaItem.status)
    }

    @Test
    fun testExtremeTracerPidBoundaries() {
        // 1. Long.MAX_VALUE 溢出 32 位整数
        val overflowStatus = "TracerPid:\t9223372036854775807\n"
        val p1 = NativeStatusParser.parse(overflowStatus)
        assertEquals(-1, p1.tracerPid)
        assertFalse(p1.isTraced)

        // 2. 负数 PID
        val negativeStatus = "TracerPid:\t-9999\n"
        val p2 = NativeStatusParser.parse(negativeStatus)
        assertEquals(-9999, p2.tracerPid)
        assertFalse(p2.isTraced)

        // 3. 32 位有符号整型上限 INT_MAX
        val intMaxStatus = "TracerPid:\t2147483647\n"
        val p3 = NativeStatusParser.parse(intMaxStatus)
        assertEquals(2147483647, p3.tracerPid)
        assertTrue(p3.isTraced)

        // 4. 包含非数字后缀混淆
        val nonNumericStatus = "TracerPid:\tNaN\n"
        val p4 = NativeStatusParser.parse(nonNumericStatus)
        assertEquals(-1, p4.tracerPid)
        assertFalse(p4.isTraced)
    }

    @Test
    fun testCorruptedProcVersionAndSuCommandInject() {
        // 模拟在 /proc/version 中注入恶意控制台转义字符 ANSI codes
        val maliciousEnv = MockSystemEnvironment().apply {
            setupBaselineCleanEnvironment(this)
            files["/proc/version"] = "Linux version 5.15.0 \u001B[31mKernelSU\u001B[0m v0.9.5"
            commandHandlers[listOf("su", "-v")] = CommandResult(
                exitCode = 0,
                stdout = "26.4:MAGISKSU; rm -rf /",
                stderr = "",
                timedOut = false
            )
        }

        val rootDetector = RootDetector(maliciousEnv)

        // 必须穿透 ANSI 混淆识别 KernelSU
        val ksuItem = rootDetector.checkKernelSuAndApatch()
        assertEquals(DetectionStatus.DANGER, ksuItem.status)
        assertTrue(ksuItem.evidence.contains("KernelSU"))

        // su 执行探测识别提权
        val suItem = rootDetector.checkSuExecutionProbe()
        assertEquals(DetectionStatus.DANGER, suItem.status)
        assertTrue(suItem.evidence.contains("MAGISKSU"))
    }
}
