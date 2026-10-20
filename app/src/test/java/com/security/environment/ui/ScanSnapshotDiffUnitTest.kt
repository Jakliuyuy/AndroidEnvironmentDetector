package com.security.environment.ui

import com.security.environment.MockSystemEnvironment
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.snapshot.DetectionDiff
import com.security.environment.data.snapshot.ItemDiffType
import com.security.environment.data.snapshot.ScanSnapshotManager
import com.security.environment.domain.CommandResult
import com.security.environment.domain.DetectionCoordinator
import com.security.environment.domain.SecurityScorer
import com.security.environment.domain.detectors.BootloaderDetector
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.HookDetector
import com.security.environment.domain.detectors.RootDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class ScanSnapshotDiffUnitTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var snapshotDir: File
    private lateinit var snapshotManager: ScanSnapshotManager

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        snapshotDir = tempFolder.newFolder("scan_snapshots")
        snapshotManager = ScanSnapshotManager(storageDir = snapshotDir)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun createDummyItem(
        id: String,
        name: String = "Test Item $id",
        status: DetectionStatus = DetectionStatus.PASS,
        evidence: String = "evidence_$id"
    ): DetectionItem {
        return DetectionItem(
            id = id,
            name = name,
            category = DetectionCategory.ROOT,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL,
            description = "Test description for $id"
        )
    }

    @Test
    fun testFirstScanEstablishesBaselineWithoutChanges() {
        val items = listOf(
            createDummyItem("item_1", "SU Binary", DetectionStatus.PASS),
            createDummyItem("item_2", "SELinux Enforce", DetectionStatus.PASS)
        )

        // 首次比对，此时无历史快照文件
        assertFalse(snapshotManager.hasSnapshot())
        val result = snapshotManager.compareWithLastSnapshot(items, 1000L)

        assertFalse(result.hasChanges)
        assertEquals(0L, result.previousScanTimestamp)
        assertEquals(1000L, result.currentScanTimestamp)
        assertTrue(result.diffItems.isEmpty())
        assertEquals(0, result.newRisksCount)
        assertTrue(result.changeSummary.contains("首次全栈检测"))

        // 保存本次快照
        val saved = snapshotManager.saveSnapshot(items, 1000L)
        assertTrue(saved)
        assertTrue(snapshotManager.hasSnapshot())
        assertTrue(snapshotManager.snapshotFile.exists())
    }

    @Test
    fun testIdenticalSubsequentScansProduceNoDiff() {
        val items = listOf(
            createDummyItem("item_1", "SU Binary", DetectionStatus.PASS),
            createDummyItem("item_2", "SELinux Enforce", DetectionStatus.PASS)
        )

        snapshotManager.saveSnapshot(items, 1000L)

        val result = snapshotManager.compareWithLastSnapshot(items, 2000L)
        assertFalse(result.hasChanges)
        assertEquals(1000L, result.previousScanTimestamp)
        assertEquals(2000L, result.currentScanTimestamp)
        assertTrue(result.diffItems.isEmpty())
        assertTrue(result.changeSummary.contains("与上次检测快照一致"))
    }

    @Test
    fun testNewAbnormalDetectedWhenSafeItemBecomesDangerOrWarn() {
        val baseline = listOf(
            createDummyItem("item_su", "SU Binary Check", DetectionStatus.PASS),
            createDummyItem("item_xposed", "Xposed Framework", DetectionStatus.PASS),
            createDummyItem("item_debug", "Debugger Status", DetectionStatus.PASS)
        )
        snapshotManager.saveSnapshot(baseline, 1000L)

        // 本次扫描：SU 变为 DANGER，Xposed 变为 WARN，调试依然 PASS
        val current = listOf(
            createDummyItem("item_su", "SU Binary Check", DetectionStatus.DANGER, "found su binary"),
            createDummyItem("item_xposed", "Xposed Framework", DetectionStatus.WARN, "xposed bridge loaded"),
            createDummyItem("item_debug", "Debugger Status", DetectionStatus.PASS)
        )

        val result = snapshotManager.compareWithLastSnapshot(current, 2000L)
        assertTrue(result.hasChanges)
        assertEquals(2, result.diffItems.size)
        assertEquals(2, result.newRisksCount)
        assertEquals(0, result.changedCount)
        assertEquals(0, result.resolvedCount)

        val suDiff = result.diffItems.first { it.itemId == "item_su" }
        assertEquals(ItemDiffType.NEW_ABNORMAL, suDiff.diffType)
        assertEquals(DetectionStatus.PASS, suDiff.previousStatus)
        assertEquals(DetectionStatus.DANGER, suDiff.currentStatus)
        assertTrue(suDiff.description.contains("新增风险"))

        val xposedDiff = result.diffItems.first { it.itemId == "item_xposed" }
        assertEquals(ItemDiffType.NEW_ABNORMAL, xposedDiff.diffType)
        assertEquals(DetectionStatus.PASS, xposedDiff.previousStatus)
        assertEquals(DetectionStatus.WARN, xposedDiff.currentStatus)
    }

    @Test
    fun testStatusChangedDetectedBetweenAbnormalStates() {
        val baseline = listOf(
            createDummyItem("item_ksu", "KernelSU Probe", DetectionStatus.WARN, "initial suspicious prctl")
        )
        snapshotManager.saveSnapshot(baseline, 1000L)

        // 从 WARN 升级为 DANGER
        val current = listOf(
            createDummyItem("item_ksu", "KernelSU Probe", DetectionStatus.DANGER, "confirmed ksu handshake 0xDEADBEEF")
        )

        val result = snapshotManager.compareWithLastSnapshot(current, 2000L)
        assertTrue(result.hasChanges)
        assertEquals(1, result.diffItems.size)
        assertEquals(0, result.newRisksCount)
        assertEquals(1, result.changedCount)
        assertEquals(0, result.resolvedCount)

        val diff = result.diffItems.first()
        assertEquals(ItemDiffType.STATUS_CHANGED, diff.diffType)
        assertEquals(DetectionStatus.WARN, diff.previousStatus)
        assertEquals(DetectionStatus.DANGER, diff.currentStatus)
        assertTrue(diff.description.contains("状态变动"))
    }

    @Test
    fun testResolvedDetectedWhenDangerItemBecomesPass() {
        val baseline = listOf(
            createDummyItem("item_frida", "Frida Injection", DetectionStatus.DANGER, "gum-js-loop found")
        )
        snapshotManager.saveSnapshot(baseline, 1000L)

        // 风险解除
        val current = listOf(
            createDummyItem("item_frida", "Frida Injection", DetectionStatus.PASS, "clean maps")
        )

        val result = snapshotManager.compareWithLastSnapshot(current, 2000L)
        assertTrue(result.hasChanges)
        assertEquals(1, result.diffItems.size)
        assertEquals(0, result.newRisksCount)
        assertEquals(0, result.changedCount)
        assertEquals(1, result.resolvedCount)

        val diff = result.diffItems.first()
        assertEquals(ItemDiffType.RESOLVED, diff.diffType)
        assertEquals(DetectionStatus.DANGER, diff.previousStatus)
        assertEquals(DetectionStatus.PASS, diff.currentStatus)
        assertTrue(diff.description.contains("风险解除"))
    }

    @Test
    fun testMissingItemInCurrentScanResolvedIfPreviouslyAbnormal() {
        val baseline = listOf(
            createDummyItem("item_old_danger", "Temporary Danger", DetectionStatus.DANGER)
        )
        snapshotManager.saveSnapshot(baseline, 1000L)

        // 当前扫描项列表中没有 item_old_danger
        val current = emptyList<DetectionItem>()

        val result = snapshotManager.compareWithLastSnapshot(current, 2000L)
        assertTrue(result.hasChanges)
        assertEquals(1, result.diffItems.size)
        val diff = result.diffItems.first()
        assertEquals(ItemDiffType.RESOLVED, diff.diffType)
        assertTrue(diff.description.contains("风险已移除"))
    }

    @Test
    fun testCorruptedSnapshotFileHandlesGracefully() {
        val file = snapshotManager.snapshotFile
        file.writeText("INVALID_CORRUPTED_JSON_CONTENT{{{")

        val items = listOf(createDummyItem("item_1"))
        val result = snapshotManager.compareWithLastSnapshot(items, 3000L)

        assertFalse(result.hasChanges)
        assertTrue(result.diffItems.isEmpty())
        assertTrue(result.changeSummary.contains("快照解析失败"))
    }

    @Test
    fun testClearSnapshotDeletesFile() {
        snapshotManager.saveSnapshot(listOf(createDummyItem("test")), 1000L)
        assertTrue(snapshotManager.hasSnapshot())

        val cleared = snapshotManager.clearSnapshot()
        assertTrue(cleared)
        assertFalse(snapshotManager.hasSnapshot())
    }

    @Test
    fun testViewModelIntegrationWithSnapshotManager() = runTest {
        val mockEnv = MockSystemEnvironment().apply {
            properties["ro.boot.flash.locked"] = "1"
            properties["ro.boot.verifiedbootstate"] = "green"
            properties["ro.boot.vbmeta.device_state"] = "locked"
            properties["ro.build.tags"] = "release-keys"
            properties["ro.build.type"] = "user"
            files["/sys/fs/selinux/enforce"] = "1"
            files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
            files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"
            envVariables["PATH"] = "/system/bin"
            files["/proc/version"] = "Linux version 5.15.0"
            files["/proc/self/mountinfo"] = "120 25 254:0 / /system ro - erofs /dev/block/dm-0 ro"
            commandHandlers[listOf("su", "-v")] = CommandResult(127, "", "not found")
            files["/proc/net/tcp"] = ""
            directories["/proc/self/task"] = listOf("100")
            files["/proc/self/task/100/comm"] = "main"
            files["/proc/self/maps"] = "7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so"
            properties["ro.hardware"] = "qcom"
            properties["ro.kernel.qemu"] = "0"
            properties["ro.product.model"] = "CleanDevice"
            files["/proc/self/status"] = "TracerPid:\t0\nState:\tS"
            properties["init.svc.adbd"] = "stopped"
        }

        val coordinator = DetectionCoordinator(
            bootloaderDetector = BootloaderDetector(mockEnv),
            rootDetector = RootDetector(mockEnv),
            hookDetector = HookDetector(mockEnv),
            virtualEnvDetector = VirtualEnvDetector(mockEnv),
            debugDetector = DebugDetector(mockEnv),
            ioDispatcher = testDispatcher
        )
        val scorer = SecurityScorer()

        val vm = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = testDispatcher,
            autoScan = false,
            snapshotManager = snapshotManager
        )

        // 1. 第一次扫描：建立基线快照
        vm.triggerScan()
        advanceUntilIdle()

        val state1 = vm.uiState.value
        assertNotNull(state1.diffComparison)
        assertFalse(state1.diffComparison!!.hasChanges)
        assertTrue(snapshotManager.hasSnapshot())

        // 2. 注入 Root 威胁，模拟环境被篡改
        mockEnv.existingFiles.add("/system/xbin/su")

        // 3. 第二次扫描：检测到环境变更
        vm.triggerScan()
        advanceUntilIdle()

        val state2 = vm.uiState.value
        assertNotNull(state2.diffComparison)
        assertTrue(state2.diffComparison!!.hasChanges)
        assertTrue(state2.diffComparison!!.newRisksCount > 0)

        // 验证 item badge 数据映射 (SEC-R2-01: SU 二进制扫描)
        val suDiff = state2.getDiffForItem("SEC-R2-01")
        assertNotNull(suDiff)
        assertEquals(ItemDiffType.NEW_ABNORMAL, suDiff!!.diffType)

        // 4. 测试 Diff Banner 展开折叠切换
        assertFalse(state2.isDiffBannerExpanded)
        vm.toggleDiffBannerExpanded()
        assertTrue(vm.uiState.value.isDiffBannerExpanded)
        vm.toggleDiffBannerExpanded()
        assertFalse(vm.uiState.value.isDiffBannerExpanded)
    }
}
