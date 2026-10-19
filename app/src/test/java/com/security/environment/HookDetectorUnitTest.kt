package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.detectors.HookDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class HookDetectorUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var detector: HookDetector

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        detector = HookDetector(mockEnv)
    }

    @Test
    fun testCleanDevicePassesAllHookChecks() {
        mockEnv.files["/proc/net/tcp"] = """
            sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
             0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
        """.trimIndent() // port 8080 listening
        mockEnv.directories["/proc/self/task"] = listOf("1001", "1002")
        mockEnv.files["/proc/self/task/1001/comm"] = "main"
        mockEnv.files["/proc/self/task/1002/comm"] = "RenderThread"
        mockEnv.directories["/proc/self/fd"] = listOf("0", "1", "2")
        mockEnv.files["/proc/self/fd/0"] = "/dev/null"
        mockEnv.files["/proc/self/maps"] = """
            7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so
            7f90000000-7f90040000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]
        """.trimIndent()
        mockEnv.mockStackTrace = arrayOf(
            StackTraceElement("com.example.MainActivity", "onCreate", "MainActivity.kt", 25),
            StackTraceElement("android.app.Activity", "performCreate", "Activity.java", 8000)
        )

        val results = detector.detect()
        assertEquals(5, results.size)
        for (item in results) {
            assertEquals("Item ${item.id} should be PASS", DetectionStatus.PASS, item.status)
            assertEquals(DetectionCategory.HOOK, item.category)
        }
    }

    @Test
    fun testXposedClassLoadedTriggersDanger() {
        mockEnv.loadedClasses["de.robv.android.xposed.XposedBridge"] = String::class.java

        val item = detector.checkXposedClassloaderReflection()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R3-01", item.id)
        assertTrue(item.evidence.contains("XposedBridge"))
    }

    @Test
    fun testTaintedStacktraceTriggersDanger() {
        mockEnv.mockStackTrace = arrayOf(
            StackTraceElement("com.example.MainActivity", "onCreate", "MainActivity.kt", 25),
            StackTraceElement("de.robv.android.xposed.XposedBridge", "handleHookedMethod", "XposedBridge.java", 120),
            StackTraceElement("android.app.Activity", "performCreate", "Activity.java", 8000)
        )

        val item = detector.checkHookStacktrace()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R3-02", item.id)
        assertTrue(item.evidence.contains("handleHookedMethod"))
    }

    @Test
    fun testFridaSocketProbeRejectionTriggersDanger() {
        // Set listening port 27042
        mockEnv.socketResponses["127.0.0.1" to 27042] = "REJECT\r\n".toByteArray(Charsets.US_ASCII)

        val item = detector.checkFridaPortAndHandshake()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R3-03", item.id)
        assertTrue(item.evidence.contains("port=27042"))
        assertTrue(item.evidence.contains("REJECT"))
    }

    @Test
    fun testFridaThreadScanTriggersDanger() {
        mockEnv.directories["/proc/self/task"] = listOf("1001", "1002")
        mockEnv.files["/proc/self/task/1001/comm"] = "main"
        mockEnv.files["/proc/self/task/1002/comm"] = "gum-js-loop"

        val item = detector.checkFridaThreadsAndPipes()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R3-04", item.id)
        assertTrue(item.evidence.contains("gum-js-loop"))
    }

    @Test
    fun testFridaNamedPipeInFdTriggersDanger() {
        mockEnv.directories["/proc/self/task"] = listOf("1001")
        mockEnv.files["/proc/self/task/1001/comm"] = "main"
        mockEnv.directories["/proc/self/fd"] = listOf("3")
        mockEnv.files["/proc/self/fd/3"] = "/data/local/tmp/linjector-pipe"

        val item = detector.checkFridaThreadsAndPipes()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("linjector"))
    }

    @Test
    fun testMapsFridaAgentTriggersDanger() {
        mockEnv.files["/proc/self/maps"] = """
            7f8a000000-7f8a100000 r-xp 00000000 08:01 999999 /data/local/tmp/frida-agent-64.so
        """.trimIndent()

        val item = detector.checkMapsHookAndAnonymousRxMemory()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertEquals("SEC-R3-05", item.id)
        assertTrue(item.evidence.contains("frida-agent"))
    }

    @Test
    fun testMapsAnonymousExecutableTriggersDanger() {
        mockEnv.files["/proc/self/maps"] = """
            7f8a9c0000-7f8a9d0000 r-xp 00000000 00:00 0
        """.trimIndent()

        val item = detector.checkMapsHookAndAnonymousRxMemory()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("anon_rx_found"))
    }
}
