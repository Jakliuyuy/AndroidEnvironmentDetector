package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityLevel
import com.security.environment.domain.CommandResult
import com.security.environment.domain.SecurityScorer
import com.security.environment.domain.detectors.BootloaderDetector
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.HookDetector
import com.security.environment.domain.detectors.RootDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

/**
 * Empirical Challenger M3 Adversarial & Boundary Test Suite
 *
 * Designed to rigorously verify:
 * 1. Mathematical boundary guarantees of the Asymmetric Risk Override Model across the entire space.
 * 2. Scorer behavior under extreme scale / potential integer overflows.
 * 3. False-positive resistance and edge-case handling across R1-R4 detectors.
 */
class ChallengerM3AdversarialTest {

    private lateinit var scorer: SecurityScorer

    @Before
    fun setUp() {
        scorer = SecurityScorer()
    }

    private fun makeItem(id: String, category: DetectionCategory, status: DetectionStatus): DetectionItem {
        return DetectionItem(
            id = id,
            name = "Challenge $id",
            category = category,
            status = status,
            evidence = "challenger_evidence",
            method = DetectionMethod.DIRECT_SYSCALL
        )
    }

    // =========================================================================
    // 1. Asymmetric Scorer Mathematical Boundary Verification (Monte Carlo & Cartesian)
    // =========================================================================

    @Test
    fun testMathematicalBoundaryCartesianGrid() {
        // Test Cartesian product: D in 0..10, W in 0..15, P in 0..20
        for (d in 0..10) {
            for (w in 0..15) {
                for (p in 0..20) {
                    val items = ArrayList<DetectionItem>(d + w + p)
                    for (i in 0 until d) items.add(makeItem("D-$i", DetectionCategory.ROOT, DetectionStatus.DANGER))
                    for (i in 0 until w) items.add(makeItem("W-$i", DetectionCategory.DEBUGGING, DetectionStatus.WARN))
                    for (i in 0 until p) items.add(makeItem("P-$i", DetectionCategory.BOOTLOADER, DetectionStatus.PASS))

                    val result = scorer.calculateScore(items)

                    // Invariant 1: Any DANGER strictly caps score <= 40, level == DANGEROUS
                    if (d > 0) {
                        assertEquals("Failure at d=$d, w=$w, p=$p", SecurityLevel.DANGEROUS, result.level)
                        assertTrue("Score must be <= 40 for d=$d, w=$w, p=$p (was ${result.score})", result.score <= 40)
                        assertTrue("Score must be >= 0 for d=$d, w=$w, p=$p (was ${result.score})", result.score >= 0)
                    }
                    // Invariant 2: Any WARN (no DANGER) caps score <= 75 and >= 45, level == WARNING
                    else if (w > 0) {
                        assertEquals("Failure at d=$d, w=$w, p=$p", SecurityLevel.WARNING, result.level)
                        assertTrue("Score must be <= 75 for d=$d, w=$w, p=$p (was ${result.score})", result.score <= 75)
                        assertTrue("Score must be >= 45 for d=$d, w=$w, p=$p (was ${result.score})", result.score >= 45)
                    }
                    // Invariant 3: All PASS (or empty) yields 95-100, level == SAFE
                    else {
                        assertEquals("Failure at d=$d, w=$w, p=$p", SecurityLevel.SAFE, result.level)
                        assertTrue("Score must be in 95..100 for all pass (was ${result.score})", result.score in 95..100)
                    }

                    // Count invariant
                    assertEquals(d, result.dangerCount)
                    assertEquals(w, result.warnCount)
                    assertEquals(p, result.passCount)
                }
            }
        }
    }

    @Test
    fun testMathematicalBoundaryMonteCarloStress() {
        val rng = Random(42)
        // 2000 random combinations with extreme values
        for (iter in 0 until 2000) {
            val d = rng.nextInt(0, 50)
            val w = rng.nextInt(0, 50)
            val p = rng.nextInt(0, 50)

            val items = ArrayList<DetectionItem>(d + w + p)
            for (i in 0 until d) items.add(makeItem("D-$i", DetectionCategory.ROOT, DetectionStatus.DANGER))
            for (i in 0 until w) items.add(makeItem("W-$i", DetectionCategory.DEBUGGING, DetectionStatus.WARN))
            for (i in 0 until p) items.add(makeItem("P-$i", DetectionCategory.BOOTLOADER, DetectionStatus.PASS))

            val result = scorer.calculateScore(items)

            if (d > 0) {
                assertEquals(SecurityLevel.DANGEROUS, result.level)
                assertTrue("MonteCarlo score $d,$w,$p must be <= 40, was ${result.score}", result.score in 0..40)
            } else if (w > 0) {
                assertEquals(SecurityLevel.WARNING, result.level)
                assertTrue("MonteCarlo score $d,$w,$p must be in 45..75, was ${result.score}", result.score in 45..75)
            } else {
                assertEquals(SecurityLevel.SAFE, result.level)
                assertEquals(100, result.score)
            }
        }
    }

    @Test
    fun testExtremeItemCountOverflowResistance() {
        // 50,000 items stress test
        val items = ArrayList<DetectionItem>(50000)
        for (i in 0 until 10000) items.add(makeItem("D-$i", DetectionCategory.ROOT, DetectionStatus.DANGER))
        for (i in 0 until 20000) items.add(makeItem("W-$i", DetectionCategory.VIRTUALIZATION, DetectionStatus.WARN))
        for (i in 0 until 20000) items.add(makeItem("P-$i", DetectionCategory.HOOK, DetectionStatus.PASS))

        val result = scorer.calculateScore(items)
        assertEquals(SecurityLevel.DANGEROUS, result.level)
        assertEquals(0, result.score) // Must clamp cleanly at 0 without integer overflow
        assertEquals(10000, result.dangerCount)
        assertEquals(20000, result.warnCount)
        assertEquals(20000, result.passCount)
    }

    @Test
    fun testCategorySummariesMathematicalEquivalence() {
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.PASS),
            makeItem("SEC-R1-02", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.WARN),
            makeItem("SEC-R2-02", DetectionCategory.ROOT, DetectionStatus.WARN),
            makeItem("SEC-R3-01", DetectionCategory.HOOK, DetectionStatus.PASS),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.PASS),
            makeItem("SEC-R4-05", DetectionCategory.DEBUGGING, DetectionStatus.DANGER)
        )

        val summaries = scorer.calculateCategorySummaries(items)
        assertEquals(DetectionCategory.entries.size, summaries.size)

        var totalItemsSum = 0
        var totalPassSum = 0
        var totalWarnSum = 0
        var totalDangerSum = 0

        for (s in summaries) {
            assertEquals(s.totalCount, s.passCount + s.warnCount + s.dangerCount)
            totalItemsSum += s.totalCount
            totalPassSum += s.passCount
            totalWarnSum += s.warnCount
            totalDangerSum += s.dangerCount

            when {
                s.dangerCount > 0 -> assertEquals(DetectionStatus.DANGER, s.highestStatus)
                s.warnCount > 0 -> assertEquals(DetectionStatus.WARN, s.highestStatus)
                else -> assertEquals(DetectionStatus.PASS, s.highestStatus)
            }
        }

        assertEquals(items.size, totalItemsSum)
        assertEquals(3, totalPassSum)
        assertEquals(2, totalWarnSum)
        assertEquals(2, totalDangerSum)
    }

    // =========================================================================
    // 2. Detector Adversarial & Edge-Case Input Challenges
    // =========================================================================

    @Test
    fun testBootloaderDetectorWhitespaceAndCaseResilience() {
        val mockEnv = MockSystemEnvironment().apply {
            properties["ro.boot.flash.locked"] = " 0 " // Trailing spaces
            properties["ro.boot.verifiedbootstate"] = " Orange \n"
            properties["ro.boot.vbmeta.device_state"] = " UNLOCKED "
            files["/sys/fs/selinux/enforce"] = "0\n"
            files["/proc/self/attr/current"] = "u:r:untrusted_app:s0:c123,c456\n"
            files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw 0 0\n"
        }

        val detector = BootloaderDetector(mockEnv)

        // AVB test with whitespace and uppercase
        val avbItem = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, avbItem.status)
        assertTrue(avbItem.description.contains("已解锁"))

        // VBMeta test with whitespace and uppercase
        val vbmetaItem = detector.checkVbmetaState()
        assertEquals(DetectionStatus.DANGER, vbmetaItem.status)

        // SELinux: untrusted_app context is CLEAN, but enforce=0 is DANGER
        val selinuxItem = detector.checkSelinuxMode()
        assertEquals(DetectionStatus.DANGER, selinuxItem.status)
        assertTrue(selinuxItem.description.contains("宽容模式"))
    }

    @Test
    fun testBootloaderSELinuxCleanUntrustedAppContextNotFlagged() {
        val mockEnv = MockSystemEnvironment().apply {
            files["/sys/fs/selinux/enforce"] = "1"
            files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw 0 0"
            files["/proc/self/attr/current"] = "u:r:untrusted_app:s0:c512,c768"
        }

        val detector = BootloaderDetector(mockEnv)
        val selinuxItem = detector.checkSelinuxMode()
        assertEquals(DetectionStatus.PASS, selinuxItem.status)
        assertTrue(selinuxItem.description.contains("强制执行模式"))
    }

    @Test
    fun testRootDetectorSuExecutionProbeFalsePositiveImmunity() {
        // When su execution outputs "sh: su: not found" with exit code 127
        val mockEnv = MockSystemEnvironment().apply {
            commandHandlers[listOf("su", "-v")] = CommandResult(
                stdout = "sh: su: not found",
                stderr = "sh: su: not found",
                exitCode = 127,
                timedOut = false
            )
        }

        val detector = RootDetector(mockEnv)
        val probeItem = detector.checkSuExecutionProbe()
        // Must NOT falsely flag as DANGER because exitCode != 0
        assertEquals(DetectionStatus.PASS, probeItem.status)
    }

    @Test
    fun testRootDetectorSuExecutionProbeLegitimateSuDanger() {
        val mockEnv = MockSystemEnvironment().apply {
            commandHandlers[listOf("su", "-v")] = CommandResult(
                stdout = "26.4:MAGISKSU\n",
                stderr = "",
                exitCode = 0,
                timedOut = false
            )
        }

        val detector = RootDetector(mockEnv)
        val probeItem = detector.checkSuExecutionProbe()
        assertEquals(DetectionStatus.DANGER, probeItem.status)
        assertTrue(probeItem.evidence.contains("MAGISKSU"))
    }

    @Test
    fun testRootDetectorAdversarialMalformedPathTraversal() {
        val mockEnv = MockSystemEnvironment().apply {
            envVariables["PATH"] = ":::/data/local/tmp::/nonexistent/dir//: "
            existingFiles.add("/data/local/tmp/su")
        }

        val detector = RootDetector(mockEnv)
        val pathItem = detector.checkSuBinaryPathsAndPathScan()
        assertEquals(DetectionStatus.DANGER, pathItem.status)
        assertTrue(pathItem.evidence.contains("/data/local/tmp/su"))
    }

    @Test
    fun testHookDetectorStacktraceFalsePositiveRejection() {
        // Normal Android framework stack frames mentioning non-hook keywords
        val mockEnv = MockSystemEnvironment().apply {
            mockStackTrace = arrayOf(
                StackTraceElement("com.security.environment.MainActivity", "onCreate", "MainActivity.kt", 45),
                StackTraceElement("android.app.Activity", "performCreate", "Activity.java", 7000),
                StackTraceElement("android.app.Instrumentation", "callActivityOnCreate", "Instrumentation.java", 1200),
                StackTraceElement("android.app.ActivityThread", "performLaunchActivity", "ActivityThread.java", 3500)
            )
        }

        val detector = HookDetector(mockEnv)
        val stackItem = detector.checkHookStacktrace()
        assertEquals(DetectionStatus.PASS, stackItem.status)
    }

    @Test
    fun testHookDetectorStacktraceTaintedFramesDetection() {
        val mockEnv = MockSystemEnvironment().apply {
            mockStackTrace = arrayOf(
                StackTraceElement("de.robv.android.xposed.XposedBridge", "handleHookedMethod", "XposedBridge.java", 200),
                StackTraceElement("com.security.environment.MainActivity", "onCreate", "MainActivity.kt", 45)
            )
        }

        val detector = HookDetector(mockEnv)
        val stackItem = detector.checkHookStacktrace()
        assertEquals(DetectionStatus.DANGER, stackItem.status)
        assertTrue(stackItem.evidence.contains("de.robv.android.xposed"))
    }

    @Test
    fun testVirtualEnvDetectorGenuineDeviceImmunity() {
        val mockEnv = MockSystemEnvironment().apply {
            properties["ro.hardware"] = "qcom"
            properties["ro.kernel.qemu"] = "0"
            properties["ro.product.model"] = "2407FRK8EC" // Redmi K70 Ultra
            properties["ro.product.manufacturer"] = "Xiaomi"
            properties["ro.product.board"] = "corot"
            properties["ro.build.fingerprint"] = "Xiaomi/corot/corot:14/UKQ1.231003.002/V816.0.24.0.UNLCNXM:user/release-keys"
        }

        val detector = VirtualEnvDetector(mockEnv)
        val emuItem = detector.checkEmulatorProperties()
        assertEquals(DetectionStatus.PASS, emuItem.status)
    }

    @Test
    fun testDebugDetectorTracerPidWhitespaceAndFormat() {
        val mockEnv = MockSystemEnvironment().apply {
            files["/proc/self/status"] = """
                Name:	com.security.app
                Umask:	0077
                State:	t (tracing stop)
                Tgid:	12345
                Ngid:	0
                Pid:	12345
                PPid:	1200
                TracerPid:	   9876   
                Uid:	10123	10123	10123	10123
            """.trimIndent()
        }

        val detector = DebugDetector(mockEnv)
        val traceItem = detector.checkTracerPid()
        assertEquals(DetectionStatus.DANGER, traceItem.status)
        assertTrue(traceItem.evidence.contains("TracerPid=9876"))
    }
}
