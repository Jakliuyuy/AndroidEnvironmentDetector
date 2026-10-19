package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityLevel
import com.security.environment.domain.CommandResult
import com.security.environment.domain.DetectionCoordinator
import com.security.environment.domain.SecurityScorer
import com.security.environment.domain.detectors.BootloaderDetector
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.HookDetector
import com.security.environment.domain.detectors.RootDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DetectionCoordinatorUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var coordinator: DetectionCoordinator
    private lateinit var scorer: SecurityScorer

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        coordinator = DetectionCoordinator(
            bootloaderDetector = BootloaderDetector(mockEnv),
            rootDetector = RootDetector(mockEnv),
            hookDetector = HookDetector(mockEnv),
            virtualEnvDetector = VirtualEnvDetector(mockEnv),
            debugDetector = DebugDetector(mockEnv)
        )
        scorer = SecurityScorer()
    }

    private fun configureCleanDeviceEnv() {
        // Bootloader
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"
        mockEnv.properties["ro.boot.vbmeta.device_state"] = "locked"
        mockEnv.properties["ro.build.tags"] = "release-keys"
        mockEnv.properties["ro.build.type"] = "user"
        mockEnv.files["/sys/fs/selinux/enforce"] = "1"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"

        // Root
        mockEnv.envVariables["PATH"] = "/system/bin:/system/xbin"
        mockEnv.files["/proc/version"] = "Linux version 5.15.0-clean (builder@google)"
        mockEnv.files["/proc/self/mountinfo"] = "120 25 254:0 / /system ro - erofs /dev/block/dm-0 ro"
        mockEnv.commandHandlers[listOf("su", "-v")] = CommandResult(127, "", "not found")

        // Hook
        mockEnv.files["/proc/net/tcp"] = ""
        mockEnv.directories["/proc/self/task"] = listOf("100")
        mockEnv.files["/proc/self/task/100/comm"] = "main"
        mockEnv.files["/proc/self/maps"] = "7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so"

        // Virtual & Debug
        mockEnv.properties["ro.hardware"] = "qcom"
        mockEnv.properties["ro.kernel.qemu"] = "0"
        mockEnv.properties["ro.product.model"] = "Galaxy S24"
        mockEnv.files["/proc/self/status"] = "TracerPid:\t0\nState:\tS"
        mockEnv.properties["init.svc.adbd"] = "stopped"
    }

    @Test
    fun testCoordinatorFullScanOnCleanDeviceProducesSafeScore() = runTest {
        configureCleanDeviceEnv()

        val items = coordinator.executeFullScan()
        assertTrue("Should collect comprehensive items, actual: ${items.size}", items.size >= 15)

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.SAFE, assessment.level)
        assertEquals(100, assessment.score)
        assertEquals(0, assessment.dangerCount)
        assertEquals(0, assessment.warnCount)
    }

    @Test
    fun testCoordinatorFullScanWithProgressFlow() = runTest {
        configureCleanDeviceEnv()

        val progressList = mutableListOf<Float>()
        val flowResults = coordinator.executeFullScanWithProgress { p ->
            progressList.add(p)
        }.toList()

        assertEquals(1, flowResults.size)
        val items = flowResults[0]
        assertTrue(items.isNotEmpty())

        assertTrue("Progress should start near 0.1", progressList.first() <= 0.2f)
        assertTrue("Progress should complete at 1.0", progressList.last() >= 0.99f)
    }

    @Test
    fun testCategorySpecificScan() = runTest {
        configureCleanDeviceEnv()

        val rootItems = coordinator.executeCategoryScan(DetectionCategory.ROOT)
        assertTrue(rootItems.isNotEmpty())
        for (item in rootItems) {
            assertEquals(DetectionCategory.ROOT, item.category)
        }

        val blItems = coordinator.executeCategoryScan(DetectionCategory.BOOTLOADER)
        assertTrue(blItems.isNotEmpty())
        for (item in blItems) {
            assertEquals(DetectionCategory.BOOTLOADER, item.category)
        }
    }

    // =========================================================================
    // Mock Profile End-to-End Tests
    // =========================================================================

    @Test
    fun testRootedDeviceProfile() = runTest {
        configureCleanDeviceEnv()
        // Inject Root characteristics: SU binary + Magisk mount inversion
        mockEnv.existingFiles.add("/system/xbin/su")
        mockEnv.files["/proc/self/mountinfo"] = "120 25 0:45 / /system ro,relatime shared:1 - tmpfs tmpfs rw,seclabel"

        val items = coordinator.executeFullScan()
        val assessment = scorer.calculateScore(items)

        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue("Score for rooted device must be capped <= 40, actual: ${assessment.score}", assessment.score <= 40)
        assertTrue(assessment.dangerCount >= 2)
    }

    @Test
    fun testFridaHookDeviceProfile() = runTest {
        configureCleanDeviceEnv()
        // Inject Frida characteristics: D-Bus socket response + thread
        mockEnv.socketResponses["127.0.0.1" to 27042] = "REJECT\r\n".toByteArray(Charsets.US_ASCII)
        mockEnv.directories["/proc/self/task"] = listOf("100", "101")
        mockEnv.files["/proc/self/task/101/comm"] = "gum-js-loop"

        val items = coordinator.executeFullScan()
        val assessment = scorer.calculateScore(items)

        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue("Score for hooked device must be <= 40, actual: ${assessment.score}", assessment.score <= 40)
        assertTrue(assessment.dangerCount >= 2)
    }

    @Test
    fun testVirtualContainerProfile() = runTest {
        configureCleanDeviceEnv()
        // Inject Emulator & Container characteristics
        mockEnv.properties["ro.hardware"] = "goldfish"
        mockEnv.properties["ro.kernel.qemu"] = "1"
        mockEnv.properties["ro.product.model"] = "Android SDK built for x86"

        val items = coordinator.executeFullScan()
        val assessment = scorer.calculateScore(items)

        assertEquals(SecurityLevel.WARNING, assessment.level)
        assertTrue("Score for virtual container must be <= 75, actual: ${assessment.score}", assessment.score <= 75)
        assertEquals(0, assessment.dangerCount)
        assertTrue(assessment.warnCount >= 1)
    }

    @Test
    fun testDebuggerAttachedProfile() = runTest {
        configureCleanDeviceEnv()
        // Inject TracerPid
        mockEnv.files["/proc/self/status"] = "TracerPid:\t9999\nState:\tt"

        val items = coordinator.executeFullScan()
        val assessment = scorer.calculateScore(items)

        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue("Score when debugger attached must be <= 40, actual: ${assessment.score}", assessment.score <= 40)
        assertTrue(assessment.dangerCount >= 1)
    }
}
