package com.security.environment.domain

import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityAssessment
import com.security.environment.data.model.SecurityLevel
import kotlin.math.max
import kotlin.math.min

class SecurityScorer {

    /**
     * 非对称风险覆盖评分模型 (Asymmetric Risk Override Model)
     * - DANGER 项存在 -> 立即封顶得分 <= 40，等级: DANGEROUS
     * - WARN 项存在 (且无 DANGER) -> 封顶得分 <= 75，等级: WARNING
     * - 全部项为 PASS -> 95-100，等级: SAFE
     */
    fun calculateScore(items: List<DetectionItem>): SecurityAssessment {
        if (items.isEmpty()) {
            return SecurityAssessment(
                score = 100,
                level = SecurityLevel.SAFE,
                dangerCount = 0,
                warnCount = 0,
                passCount = 0,
                summary = "未包含检测项，环境默认正常"
            )
        }

        var dangerCount = 0
        var warnCount = 0
        var passCount = 0

        for (item in items) {
            when (item.status) {
                DetectionStatus.DANGER -> dangerCount++
                DetectionStatus.WARN -> warnCount++
                DetectionStatus.PASS -> passCount++
            }
        }

        val score: Int
        val level: SecurityLevel
        val summary: String

        when {
            dangerCount > 0 -> {
                level = SecurityLevel.DANGEROUS
                // Cap <= 40, decrements as dangerCount and warnCount increase
                val calculated = 40 - (dangerCount - 1) * 8 - (warnCount * 2)
                score = max(0, min(40, calculated))
                summary = "检测到 $dangerCount 项高危安全威胁（Root提权/动态Hook/未锁定），系统处于极高风险状态"
            }
            warnCount > 0 -> {
                level = SecurityLevel.WARNING
                // Cap <= 75, decrements as warnCount increases
                val calculated = 75 - (warnCount - 1) * 5
                score = max(45, min(75, calculated))
                summary = "检测到 $warnCount 项可疑环境特征（调试开启/模拟器特征/设置异常），建议进一步排查"
            }
            else -> {
                level = SecurityLevel.SAFE
                score = 100
                summary = "系统运行环境纯净安全，未发现已知 Root、Hook、模拟器或调试篡改痕迹"
            }
        }

        return SecurityAssessment(
            score = score,
            level = level,
            dangerCount = dangerCount,
            warnCount = warnCount,
            passCount = passCount,
            summary = summary
        )
    }

    /**
     * 生成各维度的统计摘要
     */
    fun calculateCategorySummaries(items: List<DetectionItem>): List<CategorySummary> {
        val categories = DetectionCategory.entries
        val grouped = items.groupBy { it.category }

        return categories.map { cat ->
            val catItems = grouped[cat] ?: emptyList()
            var pass = 0
            var warn = 0
            var danger = 0

            for (it in catItems) {
                when (it.status) {
                    DetectionStatus.PASS -> pass++
                    DetectionStatus.WARN -> warn++
                    DetectionStatus.DANGER -> danger++
                }
            }

            val highestStatus = when {
                danger > 0 -> DetectionStatus.DANGER
                warn > 0 -> DetectionStatus.WARN
                else -> DetectionStatus.PASS
            }

            CategorySummary(
                category = cat,
                totalCount = catItems.size,
                passCount = pass,
                warnCount = warn,
                dangerCount = danger,
                highestStatus = highestStatus
            )
        }
    }
}
