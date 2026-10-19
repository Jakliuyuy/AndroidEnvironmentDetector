package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class VirtualEnvAndDebugDetectorUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var virtualEnvDetector: VirtualEnvDetector
    private lateinit var debugDetector: DebugDetector

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        virtualEnvDetector = VirtualEnvDetector(mockEnv)
        debugDetector = DebugDetector(mockEnv)
    }

    // =========================================================================
    // VirtualEnvDetector Tests
    // =========================================================================

    @Test
    fun testCleanDevicePassesVirtualEnvChecks() {
        mockEnv.properties["ro.hardware"] = "qcom"
        mockEnv.properties["ro.kernel.qemu"] = "0"
        mockEnv.properties["ro.product.model"] = "Pixel 8"
        mockEnv.properties["ro.product.manufacturer"] = "Google"
        mockEnv.properties["ro.product.board"] = "shiba"
        mockEnv.properties["ro.build.fingerprint"] = "google/shiba/shiba:14/AP2A.240805.005/12025142:user/release-keys"

        val itemProps = virtualEnvDetector.checkEmulatorProperties()
        assertEquals(DetectionStatus.PASS, itemProps.status)
        assertEquals(DetectionCategory.VIRTUALIZATION, itemProps.category)

        val itemDrivers = virtualEnvDetector.checkQemuDriverFiles()
        assertEquals(DetectionStatus.PASS, itemDrivers.status)

        val itemContainer = virtualEnvDetector.checkDualAppAndContainerRedirection(
            simulatedPath = "/data/user/0/com.security.environment/files",
            simulatedUid = 10123
        )
        assertEquals(DetectionStatus.PASS, itemContainer.status)
    }

    @Test
    fun testEmulatorHardwarePropsTriggerWarn() {
        mockEnv.properties["ro.hardware"] = "goldfish"
        mockEnv.properties["ro.kernel.qemu"] = "1"
        mockEnv.properties["ro.product.model"] = "Android SDK built for x86"

        val item = virtualEnvDetector.checkEmulatorProperties()
        assertEquals(DetectionStatus.WARN, item.status)
        assertEquals("SEC-R4-01", item.id)
        assertTrue(item.evidence.contains("hardware=goldfish"))
        assertTrue(item.evidence.contains("ro.kernel.qemu=1"))
    }

    @Test
    fun testQemuDriverFilesTriggerDanger() {
        mockEnv.existingFiles.add("/dev/qemu_pipe")

        val item = virtualEnvDetector.checkQemuDriverFiles()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R4-02", item.id)
        assertTrue(item.evidence.contains("/dev/qemu_pipe"))
    }

    @Test
    fun testDualAppContainerPathRedirectionTriggersWarn() {
        val itemVirtual = virtualEnvDetector.checkDualAppAndContainerRedirection(
            simulatedPath = "/data/data/io.va.exposed/virtual/data/user/0/com.security.environment/files",
            simulatedUid = 10123
        )
        assertEquals(DetectionStatus.WARN, itemVirtual.status)
        assertEquals("SEC-R4-04", itemVirtual.id)
        assertTrue(itemVirtual.evidence.contains("virtual/"))

        val item999 = virtualEnvDetector.checkDualAppAndContainerRedirection(
            simulatedPath = "/data/user/999/com.security.environment/files",
            simulatedUid = 99910123
        )
        assertEquals(DetectionStatus.WARN, item999.status)
        assertTrue(item999.evidence.contains("dual_user_999"))
    }

    @Test
    fun testSensorsCountBelowThresholdTriggersWarn() {
        val item = virtualEnvDetector.checkBatteryAndSensors(simulatedSensorCount = 2)
        assertEquals(DetectionStatus.WARN, item.status)
        assertEquals("SEC-R4-03", item.id)
        assertTrue(item.evidence.contains("sensor_count=2"))
    }

    // =========================================================================
    // DebugDetector Tests
    // =========================================================================

    @Test
    fun testCleanDevicePassesDebugChecks() {
        mockEnv.files["/proc/self/status"] = """
            Name:	com.security.environment
            State:	S (sleeping)
            Pid:	1234
            TracerPid:	0
        """.trimIndent()
        mockEnv.properties["init.svc.adbd"] = "stopped"

        val itemJdwp = debugDetector.checkJdwpDebugger(simulatedConnected = false, simulatedDebuggable = false)
        assertEquals(DetectionStatus.PASS, itemJdwp.status)
        assertEquals(DetectionCategory.DEBUGGING, itemJdwp.category)

        val itemAdb = debugDetector.checkAdbSetting(simulatedAdbEnabled = false)
        assertEquals(DetectionStatus.PASS, itemAdb.status)

        val itemTracer = debugDetector.checkTracerPid()
        assertEquals(DetectionStatus.PASS, itemTracer.status)

        val itemPtrace = debugDetector.checkDefensivePtrace(simulatedSuccess = true)
        assertEquals(DetectionStatus.PASS, itemPtrace.status)
    }

    @Test
    fun testJdwpDebuggerConnectedTriggersDanger() {
        val item = debugDetector.checkJdwpDebugger(simulatedConnected = true, simulatedDebuggable = true)
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R4-05", item.id)
        assertTrue(item.evidence.contains("isDebuggerConnected=true"))
    }

    @Test
    fun testJdwpDebuggableWithoutConnectionTriggersWarn() {
        val item = debugDetector.checkJdwpDebugger(simulatedConnected = false, simulatedDebuggable = true)
        assertEquals(DetectionStatus.WARN, item.status)
        assertTrue(item.evidence.contains("debuggable=true"))
    }

    @Test
    fun testAdbEnabledTriggersWarn() {
        val item = debugDetector.checkAdbSetting(simulatedAdbEnabled = true)
        assertEquals(DetectionStatus.WARN, item.status)
        assertEquals("SEC-R4-06", item.id)
        assertTrue(item.evidence.contains("adb_setting=true"))
    }

    @Test
    fun testTracerPidAttachedTriggersDanger() {
        mockEnv.files["/proc/self/status"] = """
            Name:	com.security.environment
            State:	t (tracing stop)
            Pid:	1234
            TracerPid:	8888
        """.trimIndent()

        val item = debugDetector.checkTracerPid()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R4-07", item.id)
        assertTrue(item.evidence.contains("TracerPid=8888"))
    }

    @Test
    fun testDefensivePtraceFailureTriggersDanger() {
        val item = debugDetector.checkDefensivePtrace(simulatedSuccess = false)
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R4-08", item.id)
        assertTrue(item.evidence.contains("EPERM"))
    }
}
