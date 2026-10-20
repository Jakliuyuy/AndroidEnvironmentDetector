package com.security.environment.ui

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.security.environment.data.export.ReportSerializer
import com.security.environment.data.jni.SecurityEngineNative
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.snapshot.ScanSnapshotManager
import com.security.environment.domain.DetectionCoordinator
import com.security.environment.domain.SecurityScorer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SecurityDashboardViewModel(
    private val coordinator: DetectionCoordinator = DetectionCoordinator(),
    private val scorer: SecurityScorer = SecurityScorer(),
    private val engineNative: SecurityEngineNative = SecurityEngineNative(),
    private val defaultDispatcher: CoroutineDispatcher = Dispatchers.Default,
    autoScan: Boolean = true,
    context: Context? = null,
    private val snapshotManager: ScanSnapshotManager? = null
) : ViewModel() {

    private var currentContext: Context? = context

    private fun getSnapshotManager(callContext: Context?): ScanSnapshotManager {
        val resolved = callContext ?: currentContext
        return snapshotManager ?: ScanSnapshotManager(context = resolved)
    }

    private val _uiState = MutableStateFlow(SecurityDashboardUiState())
    val uiState: StateFlow<SecurityDashboardUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
        checkNativeSupport()
        if (autoScan) {
            triggerScan(context)
        }
    }

    private fun checkNativeSupport() {
        val isSyscallOk = try {
            if (SecurityEngineNative.isNativeAvailable()) {
                engineNative.checkDirectSyscallAvailable()
            } else {
                false
            }
        } catch (_: Throwable) {
            false
        }
        _uiState.update { it.copy(isDirectSyscallSupported = isSyscallOk) }
    }

    /**
     * 触发异步非阻塞全量扫描
     */
    fun triggerScan(context: Context? = null) {
        if (context != null) {
            currentContext = context
        }
        scanJob?.cancel()
        _uiState.update {
            it.copy(
                isScanning = true,
                scanProgress = 0.0f,
                errorMessage = null
            )
        }
        scanJob = viewModelScope.launch {
            try {
                // 在 Default/IO 调度器上执行全量扫描
                withContext(defaultDispatcher) {
                    coordinator.executeFullScanWithProgress(context) { progress ->
                        _uiState.update { it.copy(scanProgress = progress) }
                    }.collect { items ->
                        val assessment = scorer.calculateScore(items)
                        val summaries = scorer.calculateCategorySummaries(items)
                        val json = ReportSerializer.serializeToJson(
                            items = items,
                            assessment = assessment,
                            categorySummaries = summaries
                        )
                        val text = ReportSerializer.serializeToPlainText(
                            items = items,
                            assessment = assessment,
                            categorySummaries = summaries
                        )

                        val currentTimestamp = System.currentTimeMillis()
                        val manager = getSnapshotManager(context)
                        val comparison = manager.compareWithLastSnapshot(items, currentTimestamp)
                        manager.saveSnapshot(items, currentTimestamp)
                        val diffMap = comparison.diffItems.associateBy { it.itemId }

                        _uiState.update {
                            it.copy(
                                isScanning = false,
                                scanProgress = 1.0f,
                                items = items,
                                assessment = assessment,
                                categorySummaries = summaries,
                                exportedJson = json,
                                exportedPlainText = text,
                                lastScanTimestamp = currentTimestamp,
                                diffComparison = comparison,
                                diffMap = diffMap
                            )
                        }
                    }
                }
            } catch (e: CancellationException) {
                // Job 被取消，正常退出
                throw e
            } catch (e: Throwable) {
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        errorMessage = "扫描发生异常: ${e.message}"
                    )
                }
            }
        }
    }

    /**
     * 切换选中的类别筛选
     */
    fun selectCategory(category: DetectionCategory?) {
        _uiState.update { current ->
            val next = if (current.selectedCategory == category) null else category
            current.copy(selectedCategory = next)
        }
    }

    /**
     * 更新搜索关键词
     */
    fun updateSearchQuery(query: String) {
        _uiState.update { it.copy(searchQuery = query) }
    }

    /**
     * 切换“仅显示异常项”
     */
    fun toggleOnlyAbnormal(onlyAbnormal: Boolean) {
        _uiState.update { it.copy(onlyAbnormal = onlyAbnormal) }
    }

    /**
     * 单个卡片展开/折叠
     */
    fun toggleItemExpanded(itemId: String) {
        _uiState.update { state ->
            val set = state.expandedItemIds.toMutableSet()
            if (set.contains(itemId)) {
                set.remove(itemId)
            } else {
                set.add(itemId)
            }
            state.copy(expandedItemIds = set)
        }
    }

    /**
     * 展开全部卡片
     */
    fun expandAllItems() {
        _uiState.update { state ->
            state.copy(expandedItemIds = state.items.map { it.id }.toSet())
        }
    }

    /**
     * 折叠全部卡片
     */
    fun collapseAllItems() {
        _uiState.update { state ->
            state.copy(expandedItemIds = emptySet())
        }
    }

    /**
     * 打开导出诊断报告弹窗
     */
    fun openExportDialog() {
        val currentItems = _uiState.value.items
        val assessment = _uiState.value.assessment ?: scorer.calculateScore(currentItems)
        val summaries = _uiState.value.categorySummaries.ifEmpty { scorer.calculateCategorySummaries(currentItems) }

        val json = ReportSerializer.serializeToJson(
            items = currentItems,
            assessment = assessment,
            categorySummaries = summaries
        )
        val text = ReportSerializer.serializeToPlainText(
            items = currentItems,
            assessment = assessment,
            categorySummaries = summaries
        )

        _uiState.update {
            it.copy(
                showExportDialog = true,
                exportedJson = json,
                exportedPlainText = text
            )
        }
    }

    /**
     * 关闭导出诊断报告弹窗
     */
    fun dismissExportDialog() {
        _uiState.update { it.copy(showExportDialog = false) }
    }

    /**
     * 展开/折叠历史快照差异横幅
     */
    fun toggleDiffBannerExpanded() {
        _uiState.update { it.copy(isDiffBannerExpanded = !it.isDiffBannerExpanded) }
    }
}
