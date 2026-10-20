package com.security.environment.ui

import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityAssessment
import com.security.environment.data.model.SecurityLevel
import com.security.environment.data.snapshot.DetectionDiff
import com.security.environment.data.snapshot.ScanComparisonResult

data class SecurityDashboardUiState(
    val isScanning: Boolean = false,
    val scanProgress: Float = 0.0f,
    val assessment: SecurityAssessment? = null,
    val items: List<DetectionItem> = emptyList(),
    val categorySummaries: List<CategorySummary> = emptyList(),
    val selectedCategory: DetectionCategory? = null,
    val searchQuery: String = "",
    val onlyAbnormal: Boolean = false,
    val expandedItemIds: Set<String> = emptySet(),
    val showExportDialog: Boolean = false,
    val exportedJson: String = "",
    val exportedPlainText: String = "",
    val isDirectSyscallSupported: Boolean = false,
    val errorMessage: String? = null,
    val lastScanTimestamp: Long = 0L,
    val diffComparison: ScanComparisonResult? = null,
    val isDiffBannerExpanded: Boolean = false,
    val diffMap: Map<String, DetectionDiff> = emptyMap()
) {
    fun getDiffForItem(itemId: String): DetectionDiff? = diffMap[itemId]
    /**
     * 计算经过搜索词、分类筛选和仅显示异常过滤后的列表
     */
    val filteredItems: List<DetectionItem>
        get() {
            return items.filter { item ->
                val categoryMatch = selectedCategory == null || item.category == selectedCategory
                val abnormalMatch = !onlyAbnormal || item.status != DetectionStatus.PASS
                val searchMatch = if (searchQuery.isBlank()) {
                    true
                } else {
                    val query = searchQuery.trim()
                    item.name.contains(query, ignoreCase = true) ||
                            item.evidence.contains(query, ignoreCase = true) ||
                            item.id.contains(query, ignoreCase = true) ||
                            item.description.contains(query, ignoreCase = true)
                }
                categoryMatch && abnormalMatch && searchMatch
            }
        }

    val overallScore: Int
        get() = assessment?.score ?: 100

    val securityLevel: SecurityLevel
        get() = assessment?.level ?: SecurityLevel.SAFE
}
