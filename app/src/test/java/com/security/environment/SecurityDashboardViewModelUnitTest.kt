package com.security.environment

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
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SecurityDashboardViewModelUnitTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var coordinator: DetectionCoordinator
    private lateinit var scorer: SecurityScorer
    private lateinit var viewModel: SecurityDashboardViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        mockEnv = MockSystemEnvironment()

        // 默认配置一个干净环境
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

        viewModel = SecurityDashboardViewModel(
            coordinator = coordinator,
            scorer = scorer,
            defaultDispatcher = testDispatcher,
            autoScan = false
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun testInitialUiState() {
        val state = viewModel.uiState.value
        assertFalse(state.isScanning)
        assertEquals(0.0f, state.scanProgress, 0.001f)
        assertTrue(state.items.isEmpty())
        assertNull(state.selectedCategory)
        assertEquals("", state.searchQuery)
        assertFalse(state.onlyAbnormal)
        assertTrue(state.expandedItemIds.isEmpty())
        assertFalse(state.showExportDialog)
        assertEquals(100, state.overallScore)
        assertEquals(SecurityLevel.SAFE, state.securityLevel)
    }

    @Test
    fun testAsyncScanTransitionsStateCorrectly() = runTest {
        viewModel.triggerScan()
        // 刚触发时，处于扫描中
        assertTrue(viewModel.uiState.value.isScanning)

        advanceUntilIdle()

        val state = viewModel.uiState.value
        assertFalse(state.isScanning)
        assertEquals(1.0f, state.scanProgress, 0.001f)
        assertTrue("Scanned items should not be empty", state.items.isNotEmpty())
        assertNotNull(state.assessment)
        assertEquals(SecurityLevel.SAFE, state.securityLevel)
        assertEquals(100, state.overallScore)
        assertTrue(state.lastScanTimestamp > 0)
        assertFalse(state.exportedJson.isBlank())
        assertFalse(state.exportedPlainText.isBlank())
    }

    @Test
    fun testCategoryFiltering() = runTest {
        viewModel.triggerScan()
        advanceUntilIdle()

        val totalItems = viewModel.uiState.value.items.size
        assertTrue(totalItems > 0)

        // 选择 ROOT 类别
        viewModel.selectCategory(DetectionCategory.ROOT)
        var state = viewModel.uiState.value
        assertEquals(DetectionCategory.ROOT, state.selectedCategory)
        assertTrue(state.filteredItems.isNotEmpty())
        for (item in state.filteredItems) {
            assertEquals(DetectionCategory.ROOT, item.category)
        }

        // 再次点击相同类别应当反选，恢复全量
        viewModel.selectCategory(DetectionCategory.ROOT)
        state = viewModel.uiState.value
        assertNull(state.selectedCategory)
        assertEquals(totalItems, state.filteredItems.size)
    }

    @Test
    fun testSearchQueryFiltering() = runTest {
        viewModel.triggerScan()
        advanceUntilIdle()

        // 搜索 "Bootloader"
        viewModel.updateSearchQuery("Bootloader")
        val filtered = viewModel.uiState.value.filteredItems
        assertTrue(filtered.isNotEmpty())
        for (item in filtered) {
            val matches = item.name.contains("Bootloader", ignoreCase = true) ||
                    item.evidence.contains("Bootloader", ignoreCase = true) ||
                    item.id.contains("Bootloader", ignoreCase = true)
            assertTrue(matches)
        }

        // 清空搜索
        viewModel.updateSearchQuery("")
        assertEquals(viewModel.uiState.value.items.size, viewModel.uiState.value.filteredItems.size)
    }

    @Test
    fun testOnlyAbnormalFiltering() = runTest {
        // 注入 Root 威胁
        mockEnv.existingFiles.add("/system/xbin/su")
        viewModel.triggerScan()
        advanceUntilIdle()

        val fullCount = viewModel.uiState.value.items.size
        viewModel.toggleOnlyAbnormal(true)

        val abnormalItems = viewModel.uiState.value.filteredItems
        assertTrue(abnormalItems.isNotEmpty())
        assertTrue(abnormalItems.size < fullCount)
        for (item in abnormalItems) {
            assertTrue(item.status != DetectionStatus.PASS)
        }

        viewModel.toggleOnlyAbnormal(false)
        assertEquals(fullCount, viewModel.uiState.value.filteredItems.size)
    }

    @Test
    fun testItemExpandAndCollapse() = runTest {
        viewModel.triggerScan()
        advanceUntilIdle()

        val firstItem = viewModel.uiState.value.items.first()

        // 初始未展开
        assertFalse(viewModel.uiState.value.expandedItemIds.contains(firstItem.id))

        // 切换展开
        viewModel.toggleItemExpanded(firstItem.id)
        assertTrue(viewModel.uiState.value.expandedItemIds.contains(firstItem.id))

        // 切换折叠
        viewModel.toggleItemExpanded(firstItem.id)
        assertFalse(viewModel.uiState.value.expandedItemIds.contains(firstItem.id))

        // 全部展开
        viewModel.expandAllItems()
        assertEquals(viewModel.uiState.value.items.size, viewModel.uiState.value.expandedItemIds.size)

        // 全部折叠
        viewModel.collapseAllItems()
        assertTrue(viewModel.uiState.value.expandedItemIds.isEmpty())
    }

    @Test
    fun testExportDialogFlow() = runTest {
        viewModel.triggerScan()
        advanceUntilIdle()

        assertFalse(viewModel.uiState.value.showExportDialog)

        // 打开导出弹窗
        viewModel.openExportDialog()
        assertTrue(viewModel.uiState.value.showExportDialog)
        assertTrue(viewModel.uiState.value.exportedJson.contains("\"appVersion\": \"1.0.0\""))
        assertTrue(viewModel.uiState.value.exportedPlainText.contains("ANDROID ENVIRONMENT SECURITY REPORT"))

        // 关闭弹窗
        viewModel.dismissExportDialog()
        assertFalse(viewModel.uiState.value.showExportDialog)
    }
}
