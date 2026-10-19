package com.security.environment.domain

import android.content.Context
import com.security.environment.data.jni.SecurityEngineNative
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.detectors.BootloaderDetector
import com.security.environment.domain.detectors.DebugDetector
import com.security.environment.domain.detectors.HookDetector
import com.security.environment.domain.detectors.RootDetector
import com.security.environment.domain.detectors.VirtualEnvDetector
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext

class DetectionCoordinator(
    private val bootloaderDetector: BootloaderDetector = BootloaderDetector(),
    private val rootDetector: RootDetector = RootDetector(),
    private val hookDetector: HookDetector = HookDetector(),
    private val virtualEnvDetector: VirtualEnvDetector = VirtualEnvDetector(),
    private val debugDetector: DebugDetector = DebugDetector(),
    private val nativeEngine: SecurityEngineNative = SecurityEngineNative(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /**
     * 同步全量检测（挂起函数，保证在 IO 线程执行）
     */
    suspend fun executeFullScan(context: Context? = null): List<DetectionItem> = withContext(ioDispatcher) {
        val allResults = mutableListOf<DetectionItem>()

        // 1. Native Low-level Direct Syscall Checks
        val nativeItems = if (SecurityEngineNative.isNativeAvailable()) {
            try {
                nativeEngine.executeAllChecks().map { it.toDomain() }
            } catch (_: Throwable) {
                emptyList()
            }
        } else {
            emptyList()
        }

        // 2. High-level Domain Detectors
        val blItems = bootloaderDetector.detect()
        val rootItems = rootDetector.detect()
        val hookItems = hookDetector.detect()
        val virtualItems = virtualEnvDetector.detect(context)
        val debugItems = debugDetector.detect(context)

        // Merge native and high-level items, prioritizing strictest status for duplicate IDs
        val mergedMap = LinkedHashMap<String, DetectionItem>()

        // Put native items first
        for (item in nativeItems) {
            mergedMap[item.id] = item
        }

        // Merge high-level items
        val highLevelItems = blItems + rootItems + hookItems + virtualItems + debugItems
        for (item in highLevelItems) {
            val existing = mergedMap[item.id]
            if (existing == null) {
                mergedMap[item.id] = item
            } else {
                // If either is DANGER, status becomes DANGER
                val combinedStatus = when {
                    existing.status == DetectionStatus.DANGER || item.status == DetectionStatus.DANGER -> DetectionStatus.DANGER
                    existing.status == DetectionStatus.WARN || item.status == DetectionStatus.WARN -> DetectionStatus.WARN
                    else -> DetectionStatus.PASS
                }
                val combinedEvidence = "${existing.evidence} | ${item.evidence}"
                mergedMap[item.id] = existing.copy(
                    status = combinedStatus,
                    evidence = combinedEvidence,
                    description = if (item.description.isNotEmpty()) item.description else existing.description
                )
            }
        }

        mergedMap.values.toList()
    }

    /**
     * 具备进度回调的流式扫描，供 UI 实时驱动进度动画
     */
    fun executeFullScanWithProgress(
        context: Context? = null,
        onProgress: (Float) -> Unit = {}
    ): Flow<List<DetectionItem>> = flow {
        val mergedMap = LinkedHashMap<String, DetectionItem>()

        // Step 1: Native Engine Checks (0% -> 20%)
        onProgress(0.1f)
        if (SecurityEngineNative.isNativeAvailable()) {
            try {
                val nativeList = nativeEngine.executeAllChecks().map { it.toDomain() }
                for (item in nativeList) {
                    mergedMap[item.id] = item
                }
            } catch (_: Throwable) {
                // fallback gracefully
            }
        }
        onProgress(0.2f)

        // Step 2: Bootloader Checks (20% -> 40%)
        val blItems = bootloaderDetector.detect()
        mergeItems(mergedMap, blItems)
        onProgress(0.4f)

        // Step 3: Root Checks (40% -> 60%)
        val rootItems = rootDetector.detect()
        mergeItems(mergedMap, rootItems)
        onProgress(0.6f)

        // Step 4: Hook Checks (60% -> 80%)
        val hookItems = hookDetector.detect()
        mergeItems(mergedMap, hookItems)
        onProgress(0.8f)

        // Step 5: Virtual & Debug Checks (80% -> 100%)
        val virtualItems = virtualEnvDetector.detect(context)
        val debugItems = debugDetector.detect(context)
        mergeItems(mergedMap, virtualItems)
        mergeItems(mergedMap, debugItems)
        onProgress(1.0f)

        emit(mergedMap.values.toList())
    }.flowOn(ioDispatcher)

    /**
     * 单个分类专项检测
     */
    suspend fun executeCategoryScan(
        category: DetectionCategory,
        context: Context? = null
    ): List<DetectionItem> = withContext(ioDispatcher) {
        val fullList = executeFullScan(context)
        fullList.filter { it.category == category }
    }

    private fun mergeItems(targetMap: MutableMap<String, DetectionItem>, incoming: List<DetectionItem>) {
        for (item in incoming) {
            val existing = targetMap[item.id]
            if (existing == null) {
                targetMap[item.id] = item
            } else {
                val combinedStatus = when {
                    existing.status == DetectionStatus.DANGER || item.status == DetectionStatus.DANGER -> DetectionStatus.DANGER
                    existing.status == DetectionStatus.WARN || item.status == DetectionStatus.WARN -> DetectionStatus.WARN
                    else -> DetectionStatus.PASS
                }
                val combinedEvidence = "${existing.evidence} | ${item.evidence}"
                targetMap[item.id] = existing.copy(
                    status = combinedStatus,
                    evidence = combinedEvidence,
                    description = if (item.description.isNotEmpty()) item.description else existing.description
                )
            }
        }
    }
}
