package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityLevel
import com.security.environment.domain.SecurityScorer
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class SecurityScorerUnitTest {

    private lateinit var scorer: SecurityScorer

    @Before
    fun setUp() {
        scorer = SecurityScorer()
    }

    private fun makeItem(
        id: String,
        category: DetectionCategory,
        status: DetectionStatus
    ): DetectionItem {
        return DetectionItem(
            id = id,
            name = "Test $id",
            category = category,
            status = status,
            evidence = "mock_evidence",
            method = DetectionMethod.DIRECT_SYSCALL
        )
    }

    @Test
    fun testAllPassYieldsSafeScore() {
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.PASS),
            makeItem("SEC-R1-02", DetectionCategory.BOOTLOADER, DetectionStatus.PASS),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.PASS),
            makeItem("SEC-R3-01", DetectionCategory.HOOK, DetectionStatus.PASS),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.PASS),
            makeItem("SEC-R4-05", DetectionCategory.DEBUGGING, DetectionStatus.PASS)
        )

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.SAFE, assessment.level)
        assertTrue("All pass score must be 95-100", assessment.score in 95..100)
        assertEquals(6, assessment.passCount)
        assertEquals(0, assessment.warnCount)
        assertEquals(0, assessment.dangerCount)
        assertTrue(assessment.summary.contains("纯净安全"))
    }

    @Test
    fun testSingleDangerCapsScoreAt40OrBelow() {
        // 19 pass items, 1 danger item (e.g. Magisk detected)
        val items = mutableListOf<DetectionItem>()
        for (i in 1..19) {
            items.add(makeItem("PASS-$i", DetectionCategory.BOOTLOADER, DetectionStatus.PASS))
        }
        items.add(makeItem("SEC-R2-04", DetectionCategory.ROOT, DetectionStatus.DANGER))

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue("Single danger score must be capped at 40, actual: ${assessment.score}", assessment.score <= 40)
        assertTrue(assessment.score >= 0)
        assertEquals(1, assessment.dangerCount)
        assertEquals(19, assessment.passCount)
        assertTrue(assessment.summary.contains("高危"))
    }

    @Test
    fun testMultipleDangersFurtherDecreaseScore() {
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.DANGER),
            makeItem("SEC-R3-03", DetectionCategory.HOOK, DetectionStatus.DANGER),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.PASS)
        )

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue(assessment.score <= 40)
        assertTrue(assessment.score >= 0)
        assertEquals(3, assessment.dangerCount)
        assertEquals(1, assessment.passCount)
    }

    @Test
    fun testAsymmetricOverrideDangerOverridesWarn() {
        // Even if there are multiple warnings, presence of danger must force level to DANGEROUS and cap <= 40
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.WARN),
            makeItem("SEC-R4-06", DetectionCategory.DEBUGGING, DetectionStatus.WARN),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.PASS)
        )

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.DANGEROUS, assessment.level)
        assertTrue("Danger override must cap score <= 40, actual: ${assessment.score}", assessment.score <= 40)
        assertEquals(1, assessment.dangerCount)
        assertEquals(2, assessment.warnCount)
    }

    @Test
    fun testWarnOnlyCapsScoreAt75OrBelow() {
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.PASS),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.PASS),
            makeItem("SEC-R4-06", DetectionCategory.DEBUGGING, DetectionStatus.WARN)
        )

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.WARNING, assessment.level)
        assertTrue("Warn only score must be <= 75, actual: ${assessment.score}", assessment.score <= 75)
        assertTrue("Warn only score must be >= 45, actual: ${assessment.score}", assessment.score >= 45)
        assertEquals(1, assessment.warnCount)
        assertEquals(0, assessment.dangerCount)
        assertTrue(assessment.summary.contains("可疑"))
    }

    @Test
    fun testMultipleWarnsKeepScoreBetween45And75() {
        val items = listOf(
            makeItem("SEC-R1-05", DetectionCategory.BOOTLOADER, DetectionStatus.WARN),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.WARN),
            makeItem("SEC-R4-06", DetectionCategory.DEBUGGING, DetectionStatus.WARN),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.PASS)
        )

        val assessment = scorer.calculateScore(items)
        assertEquals(SecurityLevel.WARNING, assessment.level)
        assertTrue(assessment.score in 45..75)
        assertEquals(3, assessment.warnCount)
        assertEquals(0, assessment.dangerCount)
    }

    @Test
    fun testEmptyItemsListReturnsSafeDefault() {
        val assessment = scorer.calculateScore(emptyList())
        assertEquals(SecurityLevel.SAFE, assessment.level)
        assertEquals(100, assessment.score)
        assertEquals(0, assessment.dangerCount)
    }

    @Test
    fun testCategorySummariesBreakdown() {
        val items = listOf(
            makeItem("SEC-R1-01", DetectionCategory.BOOTLOADER, DetectionStatus.PASS),
            makeItem("SEC-R1-04", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER),
            makeItem("SEC-R2-01", DetectionCategory.ROOT, DetectionStatus.PASS),
            makeItem("SEC-R3-01", DetectionCategory.HOOK, DetectionStatus.WARN),
            makeItem("SEC-R4-01", DetectionCategory.VIRTUALIZATION, DetectionStatus.PASS)
        )

        val summaries = scorer.calculateCategorySummaries(items)
        assertEquals(5, summaries.size)

        val blSummary = summaries.first { it.category == DetectionCategory.BOOTLOADER }
        assertEquals(2, blSummary.totalCount)
        assertEquals(1, blSummary.passCount)
        assertEquals(0, blSummary.warnCount)
        assertEquals(1, blSummary.dangerCount)
        assertEquals(DetectionStatus.DANGER, blSummary.highestStatus)

        val hookSummary = summaries.first { it.category == DetectionCategory.HOOK }
        assertEquals(1, hookSummary.totalCount)
        assertEquals(1, hookSummary.warnCount)
        assertEquals(DetectionStatus.WARN, hookSummary.highestStatus)

        val rootSummary = summaries.first { it.category == DetectionCategory.ROOT }
        assertEquals(1, rootSummary.totalCount)
        assertEquals(DetectionStatus.PASS, rootSummary.highestStatus)
    }
}
