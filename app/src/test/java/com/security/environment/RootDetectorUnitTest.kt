package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.CommandResult
import com.security.environment.domain.detectors.RootDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class RootDetectorUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var detector: RootDetector

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        detector = RootDetector(mockEnv)
    }

    @Test
    fun testCleanDevicePassesAllRootChecks() {
        mockEnv.envVariables["PATH"] = "/system/bin:/system/xbin:/vendor/bin"
        mockEnv.files["/proc/version"] = "Linux version 5.15.78-android13 (clean_kernel@build-host)"
        mockEnv.files["/proc/self/mountinfo"] = """
            120 25 254:0 / /system ro,nodev,noatime - erofs /dev/block/dm-0 ro
            121 25 254:1 / /vendor ro,nodev,noatime - erofs /dev/block/dm-1 ro
        """.trimIndent()
        mockEnv.files["/proc/self/maps"] = """
            7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so
        """.trimIndent()
        mockEnv.files["/proc/net/unix"] = """
            0000000000000000: 00000002 00000000 00010000 0001 01 12345 /dev/socket/logd
        """.trimIndent()
        mockEnv.commandHandlers[listOf("su", "-v")] = CommandResult(
            exitCode = 127,
            stdout = "",
            stderr = "sh: su: not found"
        )

        val results = detector.detect()
        assertEquals(6, results.size)
        for (item in results) {
            assertEquals("Item ${item.id} should be PASS on clean device", DetectionStatus.PASS, item.status)
            assertEquals(DetectionCategory.ROOT, item.category)
        }
    }

    @Test
    fun testStaticSuBinaryPathTriggersDanger() {
        mockEnv.existingFiles.add("/system/xbin/su")

        val item = detector.checkSuBinaryPathsAndPathScan()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R2-01", item.id)
        assertTrue(item.evidence.contains("/system/xbin/su"))
    }

    @Test
    fun testDynamicPathTraversalSuTriggersDanger() {
        mockEnv.envVariables["PATH"] = "/sbin:/custom/bin"
        mockEnv.existingFiles.add("/custom/bin/su")

        val item = detector.checkSuBinaryPathsAndPathScan()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("/custom/bin/su"))
    }

    @Test
    fun testSuExecutionProbeTriggersDanger() {
        mockEnv.commandHandlers[listOf("su", "-v")] = CommandResult(
            exitCode = 0,
            stdout = "26.1:MAGISK",
            stderr = ""
        )

        val item = detector.checkSuExecutionProbe()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R2-02", item.id)
        assertTrue(item.evidence.contains("MAGISK"))
    }

    @Test
    fun testKernelSuInProcVersionTriggersDanger() {
        mockEnv.files["/proc/version"] = "Linux version 5.10.136-KernelSU-v0.9.5 (android-build@google)"

        val item = detector.checkKernelSuAndApatch()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R2-03", item.id)
        assertTrue(item.evidence.contains("KernelSU"))
    }

    @Test
    fun testApatchInProcVersionTriggersDanger() {
        mockEnv.files["/proc/version"] = "Linux version 5.15.41-APatch-0.10.5 (dev@local)"

        val item = detector.checkKernelSuAndApatch()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("APatch"))
    }

    @Test
    fun testKernelSuModuleDirectoryTriggersDanger() {
        mockEnv.existingFiles.add("/data/adb/ksu")

        val item = detector.checkKernelSuAndApatch()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("dir:/data/adb/ksu"))
    }

    @Test
    fun testMagiskMagicMountInversionTriggersDanger() {
        // System partition mounted on tmpfs
        mockEnv.files["/proc/self/mountinfo"] = """
            120 25 0:45 / /system ro,relatime shared:1 - tmpfs tmpfs rw,seclabel
        """.trimIndent()

        val item = detector.checkMagiskMagicMountAndSockets()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R2-04", item.id)
        assertTrue(item.evidence.contains("magic_mount_inversion"))
    }

    @Test
    fun testMagiskUnixSocketTriggersDanger() {
        mockEnv.files["/proc/self/mountinfo"] = ""
        mockEnv.files["/proc/net/unix"] = """
            0000000000000000: 00000002 00000000 00010000 0001 01 99999 @/dev/magisk/daemon
        """.trimIndent()

        val item = detector.checkMagiskMagicMountAndSockets()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("unix_domain_socket_daemon"))
    }

    @Test
    fun testZygiskInMapsTriggersDanger() {
        mockEnv.files["/proc/self/maps"] = """
            7f8a000000-7f8a050000 r-xp 00000000 08:01 123456 /data/adb/modules/zygisk_module/libzygisk.so
        """.trimIndent()

        val item = detector.checkZygiskTraces()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R2-05", item.id)
        assertTrue(item.evidence.contains("zygisk"))
    }

    @Test
    fun testRootManagerPackageTriggersWarn() {
        mockEnv.existingFiles.add("/data/data/com.topjohnwu.magisk")

        val item = detector.checkRootManagerPackages()
        assertEquals(DetectionStatus.WARN, item.status)
        assertEquals("SEC-R2-06", item.id)
        assertTrue(item.evidence.contains("com.topjohnwu.magisk"))
    }
}
