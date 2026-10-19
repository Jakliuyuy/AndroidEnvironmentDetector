package com.security.environment

import com.security.environment.data.export.ReportSerializer
import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityAssessment
import com.security.environment.data.model.SecurityLevel
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Milestone 4 深度对抗性挑战与极端压力测试套件
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ChallengerM4AdversarialTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var coordinator: DetectionCoordinator
    private lateinit var scorer: SecurityScorer

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        mockEnv = MockSystemEnvironment()
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"
        mockEnv.properties["ro.boot.vbmeta.device_state"] = "locked"
        mockEnv.properties["ro.build.tags"] = "release-keys"
        mockEnv.properties["ro.build.type"] = "user"
        mockEnv.files["/sys/fs/selinux/enforce"] = "1"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"
        mockEnv.envVariables["PATH"] = "/system/bin"
        mockEnv.files["/proc/version"] = "Linux version 5.15.0"
        mockEnv.files["/proc/self/mountinfo"] = "120 25 254:0 / /system ro - erofs /dev/block/dm-0 ro"
        mockEnv.commandHandlers[listOf("su", "-v")] = CommandResult(127, "", "not found")
        mockEnv.files["/proc/net/tcp"] = ""
        mockEnv.directories["/proc/self/task"] = listOf("100")
        mockEnv.files["/proc/self/task/100/comm"] = "main"
        mockEnv.files["/proc/self/maps"] = "7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so"
        mockEnv.properties["ro.hardware"] = "qcom"
        mockEnv.properties["ro.kernel.qemu"] = "0"
        mockEnv.properties["ro.product.model"] = "CleanDevice"
        mockEnv.files["/proc/self/status"] = "TracerPid:\t0\nState:\tS"
        mockEnv.properties["init.svc.adbd"] = "stopped"

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

    // =========================================================================
    // 挑战维度 1: JSON 格式、特殊字符与 Schema 契约校验
    // =========================================================================

    @Test
    fun challengeJsonSchemaStrictCompliance() {
        // 构建包含各种极端取值的单项集合
        val assessment = SecurityAssessment(
            score = 15,
            level = SecurityLevel.DANGEROUS,
            dangerCount = 2,
            warnCount = 3,
            passCount = 5,
            summary = "Critical Alert: Multiple exploits detected"
        )

        val items = listOf(
            DetectionItem("SEC-R1-01", "Bootloader State", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "ro.boot.flash.locked=1", DetectionMethod.DIRECT_SYSCALL, "desc", ""),
            DetectionItem("SEC-R2-01", "SU Path", DetectionCategory.ROOT, DetectionStatus.DANGER, "/sbin/su", DetectionMethod.LIBC, "desc", "remedy"),
            DetectionItem("SEC-R3-01", "Frida Socket", DetectionCategory.HOOK, DetectionStatus.WARN, "port 27042 open", DetectionMethod.JAVA, "desc", "remedy")
        )

        val jsonString = ReportSerializer.serializeToJson(
            items = items,
            assessment = assessment,
            reportId = "strict-test-uuid",
            timestampMs = 1774032000000L
        )

        val root = JSONObject(jsonString)

        // 契约验证: 必须包含 PROJECT.md 中规定的所有规范顶级字段
        assertTrue("Must contain appVersion", root.has("appVersion"))
        assertEquals("1.0.0", root.getString("appVersion"))
        assertTrue("Must contain timestamp", root.has("timestamp"))
        assertEquals(1774032000000L, root.getLong("timestamp"))
        assertTrue("Must contain deviceInfo", root.has("deviceInfo"))
        assertTrue("Must contain assessment", root.has("assessment"))
        assertTrue("Must contain items", root.has("items"))

        // deviceInfo 必需子字段
        val dev = root.getJSONObject("deviceInfo")
        val requiredDevKeys = listOf("brand", "model", "fingerprint", "androidVersion", "apiLevel", "arch")
        for (key in requiredDevKeys) {
            assertTrue("deviceInfo must contain $key", dev.has(key))
        }

        // assessment 必需子字段
        val assess = root.getJSONObject("assessment")
        assertEquals(15, assess.getInt("score"))
        assertEquals("DANGEROUS", assess.getString("level"))
        assertEquals(2, assess.getInt("dangerCount"))
        assertEquals(3, assess.getInt("warnCount"))
        assertEquals(5, assess.getInt("passCount"))

        // items 必需子字段
        val itemsArray = root.getJSONArray("items")
        assertEquals(3, itemsArray.length())
        for (i in 0 until itemsArray.length()) {
            val itemObj = itemsArray.getJSONObject(i)
            assertTrue(itemObj.has("id"))
            assertTrue(itemObj.has("name"))
            assertTrue(itemObj.has("category"))
            assertTrue(itemObj.has("status"))
            assertTrue(itemObj.has("evidence"))
            assertTrue(itemObj.has("method"))
        }
    }

    @Test
    fun challengeAdversarialSpecialCharactersInJsonAndPlainText() {
        // 构造包含各类对抗性注入载荷的证据与文本
        val payloadEvidence = """
            {"injected_json": true, "nested": [1, 2, "{\"sub\": null}"]}
            LineBreak \r\n and Tab \t and NullByte \u0000
            HTML: <script>alert('XSS')</script>
            SQLi: ' OR '1'='1' -- 
            Path: ../../../../etc/shadow
            Unicode: 🛡️🔍⚠️🚨 日本語 한국어 русский \uD83D\uDE00
            Backslash: C:\\Windows\\System32\\cmd.exe
            Double Quotes: "hello" and Single Quotes: 'world'
        """.trimIndent()

        val complexItem = DetectionItem(
            id = "SEC-ADVERSARIAL-PAYLOAD",
            name = "Payload Check <test> & \"injection\"",
            category = DetectionCategory.HOOK,
            status = DetectionStatus.DANGER,
            evidence = payloadEvidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = "Description with special characters: \\b\\f\\r\\n\\t and symbols !@#$%^&*()_+{}[]",
            remediation = "Fix remediation with payload: rm -rf /; sudo shutdown -h now"
        )

        val assessment = SecurityAssessment(0, SecurityLevel.DANGEROUS, 1, 0, 0, "Adversarial Assessment")

        // 1. 测试 JSON 序列化对抗性
        val jsonStr = ReportSerializer.serializeToJson(
            items = listOf(complexItem),
            assessment = assessment
        )

        // 必须能够正确被标准 JSON 解析器反序列化而无任何语法错误
        val parsedJson = JSONObject(jsonStr)
        val parsedItem = parsedJson.getJSONArray("items").getJSONObject(0)
        assertEquals(complexItem.id, parsedItem.getString("id"))
        assertEquals(complexItem.name, parsedItem.getString("name"))
        assertEquals(payloadEvidence, parsedItem.getString("evidence"))
        assertEquals(complexItem.description, parsedItem.getString("description"))
        assertEquals(complexItem.remediation, parsedItem.getString("remediation"))

        // 2. 测试纯文本排版对抗性
        val textReport = ReportSerializer.serializeToPlainText(
            items = listOf(complexItem),
            assessment = assessment
        )

        assertTrue(textReport.contains("ANDROID ENVIRONMENT SECURITY REPORT"))
        assertTrue(textReport.contains(complexItem.name))
        assertTrue(textReport.contains("[DANGER]"))
        assertTrue(textReport.contains("Evidence:"))
        assertTrue(textReport.contains("Remedy:"))
        assertTrue(textReport.endsWith("==================================================\n") || textReport.endsWith("=================================================="))
    }

    @Test
    fun challengeEmptyItemsAndNullInputs() {
        val emptyAssessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, 0, "No issues detected")
        val json = ReportSerializer.serializeToJson(
            items = emptyList(),
            assessment = emptyAssessment,
            categorySummaries = emptyList()
        )

        val root = JSONObject(json)
        assertEquals(0, root.getJSONArray("items").length())
        assertEquals(0, root.getJSONObject("assessment").getInt("dangerCount"))

        val text = ReportSerializer.serializeToPlainText(
            items = emptyList(),
            assessment = emptyAssessment,
            categorySummaries = emptyList()
        )
        assertTrue(text.contains("Total Checks:   0"))
        assertTrue(text.contains("DETAILED DETECTION RESULTS (0):"))
    }

    @Test
    fun challengeHighVolumeReportSerializationPerformance() {
        // 生成 500 个复杂检测项的大规模报告，验证序列化性能与内存稳定性
        val largeItems = mutableListOf<DetectionItem>()
        for (i in 0 until 500) {
            val status = when (i % 3) {
                0 -> DetectionStatus.PASS
                1 -> DetectionStatus.WARN
                else -> DetectionStatus.DANGER
            }
            largeItems.add(
                DetectionItem(
                    id = "ITEM-STRESS-$i",
                    name = "Stress Check Rule #$i",
                    category = DetectionCategory.entries[i % DetectionCategory.entries.size],
                    status = status,
                    evidence = "Evidence string for rule $i with /proc/self/maps memory addresses 0x7f00000000-0x7f10000000 r-xp",
                    method = DetectionMethod.entries[i % DetectionMethod.entries.size],
                    description = "Description for stress item $i",
                    remediation = "Remediation step $i"
                )
            )
        }

        val assessment = SecurityAssessment(40, SecurityLevel.DANGEROUS, 166, 167, 167, "High Volume Assessment")

        val startTime = System.currentTimeMillis()
        val json = ReportSerializer.serializeToJson(largeItems, assessment)
        val text = ReportSerializer.serializeToPlainText(largeItems, assessment)
        val elapsed = System.currentTimeMillis() - startTime

        // 验证 500 项的序列化耗时必须在 2000ms 以内（纯 JVM 环境通常 < 200ms）
        assertTrue("Serialization must be fast (< 2000ms), actual: ${elapsed}ms", elapsed < 2000)

        val root = JSONObject(json)
        assertEquals(500, root.getJSONArray("items").length())
        assertTrue(text.contains("DETAILED DETECTION RESULTS (500):"))
    }

    // =========================================================================
    // 挑战维度 2: ViewModel 状态机、高并发重扫与快速切换类别
    // =========================================================================

    @Test
    fun challengeViewModelRapidConcurrentReScans() = runTest {
        val vm = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = testDispatcher,
            autoScan = false
        )

        // 快速连续触发 30 次 triggerScan()
        for (i in 1..30) {
            vm.triggerScan()
            assertTrue("ViewModel must remain in scanning state when triggered", vm.uiState.value.isScanning)
        }

        // 推进所有协程执行
        advanceUntilIdle()

        val finalState = vm.uiState.value
        // 最终状态必须处于已完成且非扫描状态，无死锁
        assertFalse("isScanning must be false after idle", finalState.isScanning)
        assertEquals(1.0f, finalState.scanProgress, 0.001f)
        assertTrue("Scanned items must be populated", finalState.items.isNotEmpty())
        assertNotNull(finalState.assessment)
        assertNull(finalState.errorMessage)
    }

    @Test
    fun challengeViewModelConcurrentCategoryAndSearchInterleaving() = runTest {
        val vm = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = testDispatcher,
            autoScan = false
        )

        // 触发扫描
        vm.triggerScan()
        assertTrue(vm.uiState.value.isScanning)

        // 在扫描仍在进行时，快速交替修改筛选条件
        vm.selectCategory(DetectionCategory.BOOTLOADER)
        vm.updateSearchQuery("su")
        vm.toggleOnlyAbnormal(true)
        vm.toggleItemExpanded("SEC-R1-01")

        assertEquals(DetectionCategory.BOOTLOADER, vm.uiState.value.selectedCategory)
        assertEquals("su", vm.uiState.value.searchQuery)
        assertTrue(vm.uiState.value.onlyAbnormal)
        assertTrue(vm.uiState.value.expandedItemIds.contains("SEC-R1-01"))

        // 完成扫描
        advanceUntilIdle()

        val stateAfterScan = vm.uiState.value
        assertFalse(stateAfterScan.isScanning)
        // 之前的用户界面筛选配置必须得到保持，不能被扫描结果重置覆盖
        assertEquals(DetectionCategory.BOOTLOADER, stateAfterScan.selectedCategory)
        assertEquals("su", stateAfterScan.searchQuery)
        assertTrue(stateAfterScan.onlyAbnormal)
        assertTrue(stateAfterScan.expandedItemIds.contains("SEC-R1-01"))
    }

    @Test
    fun challengeViewModelMultiThreadedStress() {
        // 使用真正的多线程线程池并发测试 ViewModel 的状态线程安全（防御 ConcurrentModificationException）
        val threadPool = Executors.newFixedThreadPool(8)
        val dispatcher = threadPool.asCoroutineDispatcher()

        val vm = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = dispatcher,
            autoScan = false
        )

        val latch = CountDownLatch(1)
        val numThreads = 8
        val iterationsPerThread = 50
        val errors = Collections.synchronizedList(mutableListOf<Throwable>())

        val tasks = (0 until numThreads).map { threadIdx ->
            threadPool.submit {
                try {
                    latch.await()
                    for (i in 0 until iterationsPerThread) {
                        when ((threadIdx + i) % 6) {
                            0 -> vm.triggerScan()
                            1 -> vm.selectCategory(DetectionCategory.entries[(threadIdx + i) % DetectionCategory.entries.size])
                            2 -> vm.updateSearchQuery("query_$i")
                            3 -> vm.toggleOnlyAbnormal((i % 2) == 0)
                            4 -> vm.toggleItemExpanded("ITEM_$i")
                            5 -> {
                                vm.openExportDialog()
                                vm.dismissExportDialog()
                            }
                        }
                        // 触发读取计算属性 filteredItems
                        val filtered = vm.uiState.value.filteredItems
                        val score = vm.uiState.value.overallScore
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

        // 验证没有抛出任何并发修改异常或崩溃
        if (errors.isNotEmpty()) {
            val first = errors.first()
            first.printStackTrace()
            throw AssertionError("Multi-threaded stress test failed with exception: ${first.message}", first)
        }
        assertTrue("Must have 0 concurrent errors", errors.isEmpty())
    }

    @Test
    fun challengeUiStateFilteringLogicUnderContradictoryCriteria() {
        val items = listOf(
            DetectionItem("SEC-R1-01", "Bootloader Locked", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "evidence 1", DetectionMethod.DIRECT_SYSCALL, "desc", ""),
            DetectionItem("SEC-R1-02", "SELinux Enforce", DetectionCategory.BOOTLOADER, DetectionStatus.WARN, "evidence 2", DetectionMethod.LIBC, "desc", ""),
            DetectionItem("SEC-R2-01", "SU Binary", DetectionCategory.ROOT, DetectionStatus.DANGER, "evidence 3", DetectionMethod.DIRECT_SYSCALL, "desc", "")
        )

        val baseState = com.security.environment.ui.SecurityDashboardUiState(
            items = items
        )

        // 1. 无过滤：全量 3 项
        assertEquals(3, baseState.filteredItems.size)

        // 2. 分类为 ROOT，并且仅看异常：只有 SEC-R2-01 (1项)
        val s1 = baseState.copy(selectedCategory = DetectionCategory.ROOT, onlyAbnormal = true)
        assertEquals(1, s1.filteredItems.size)
        assertEquals("SEC-R2-01", s1.filteredItems.first().id)

        // 3. 分类为 ROOT，但搜索词搜 "Bootloader"（互斥条件）：应为 0 项
        val s2 = baseState.copy(selectedCategory = DetectionCategory.ROOT, searchQuery = "Bootloader")
        assertEquals(0, s2.filteredItems.size)

        // 4. 仅看异常，但搜索词搜 "evidence 1"（PASS 项的证据）：应为 0 项
        val s3 = baseState.copy(onlyAbnormal = true, searchQuery = "evidence 1")
        assertEquals(0, s3.filteredItems.size)

        // 5. 仅看异常，搜索词搜 "evidence 2"（WARN 项的证据）：应有 1 项
        val s4 = baseState.copy(onlyAbnormal = true, searchQuery = "evidence 2")
        assertEquals(1, s4.filteredItems.size)
        assertEquals("SEC-R1-02", s4.filteredItems.first().id)
    }
}
