package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.detectors.BootloaderDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class BootloaderDetectorUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var detector: BootloaderDetector

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        detector = BootloaderDetector(mockEnv)
    }

    @Test
    fun testCleanRetailDevicePassesAllBootloaderChecks() {
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"
        mockEnv.properties["ro.boot.vbmeta.device_state"] = "locked"
        mockEnv.properties["ro.build.tags"] = "release-keys"
        mockEnv.properties["ro.build.type"] = "user"
        mockEnv.files["/sys/fs/selinux/enforce"] = "1"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0:c123,c456"

        val results = detector.detect()
        assertEquals(5, results.size)
        for (item in results) {
            assertEquals("Item ${item.id} should be PASS", DetectionStatus.PASS, item.status)
            assertEquals(DetectionCategory.BOOTLOADER, item.category)
        }
    }

    @Test
    fun testBootloaderUnlockedTriggersDanger() {
        mockEnv.properties["ro.boot.flash.locked"] = "0"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"

        val item = detector.checkBootloaderLock()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R1-01", item.id)
        assertTrue(item.evidence.contains("flash.locked=0"))
        assertTrue(item.description.contains("解锁"))
    }

    @Test
    fun testVerifiedBootStateOrangeOrYellowTriggersDanger() {
        // Test orange
        mockEnv.properties["ro.boot.verifiedbootstate"] = "orange"
        var item = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("verifiedbootstate=orange"))

        // Test yellow
        mockEnv.properties["ro.boot.verifiedbootstate"] = "yellow"
        item = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("verifiedbootstate=yellow"))

        // Test red
        mockEnv.properties["ro.boot.verifiedbootstate"] = "red"
        item = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("verifiedbootstate=red"))
    }

    @Test
    fun testVbmetaUnlockedTriggersDanger() {
        mockEnv.properties["ro.boot.vbmeta.device_state"] = "unlocked"
        val item = detector.checkVbmetaState()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R1-03", item.id)
        assertTrue(item.evidence.contains("vbmeta.device_state=unlocked"))
    }

    @Test
    fun testSelinuxPermissiveTriggersDanger() {
        mockEnv.files["/sys/fs/selinux/enforce"] = "0"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"

        val item = detector.checkSelinuxMode()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R1-04", item.id)
        assertTrue(item.description.contains("宽容模式"))
    }

    @Test
    fun testSelinuxTaintedProcessDomainTriggersDanger() {
        mockEnv.files["/sys/fs/selinux/enforce"] = "1"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:su:s0"

        val item = detector.checkSelinuxMode()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.description.contains("进程域异常篡改"))
    }

    @Test
    fun testBuildTagsTestKeysTriggersDanger() {
        mockEnv.properties["ro.build.tags"] = "test-keys"
        mockEnv.properties["ro.build.type"] = "userdebug"

        val item = detector.checkBuildTags()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R1-05", item.id)
        assertTrue(item.evidence.contains("test-keys"))
    }

    @Test
    fun testBuildTypeUserdebugTriggersWarn() {
        mockEnv.properties["ro.build.tags"] = "release-keys"
        mockEnv.properties["ro.build.type"] = "userdebug"

        val item = detector.checkBuildTags()
        assertEquals(DetectionStatus.WARN, item.status)
        assertTrue(item.description.contains("工程调试"))
    }
}
