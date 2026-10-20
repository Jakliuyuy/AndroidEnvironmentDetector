package com.security.environment.data.snapshot

import android.content.Context
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionStatus
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException

enum class ItemDiffType {
    NEW_ABNORMAL,     // 新增异常 (上次 PASS 或不存在，本次 WARN/DANGER)
    STATUS_CHANGED,   // 状态变动 (如 WARN 变 DANGER 或 DANGER 降至 WARN)
    RESOLVED,         // 风险消除 (上次 WARN/DANGER，本次恢复 PASS)
    UNCHANGED         // 状态无改变
}

data class DetectionDiff(
    val itemId: String,
    val name: String,
    val diffType: ItemDiffType,
    val previousStatus: DetectionStatus?,
    val currentStatus: DetectionStatus,
    val previousEvidence: String,
    val currentEvidence: String,
    val description: String
)

data class ScanComparisonResult(
    val hasChanges: Boolean,
    val previousScanTimestamp: Long,
    val currentScanTimestamp: Long,
    val diffItems: List<DetectionDiff>,
    val changeSummary: String,
    val newRisksCount: Int = 0,
    val changedCount: Int = 0,
    val resolvedCount: Int = 0
)

class ScanSnapshotManager(
    private val context: Context? = null,
    private val storageDir: File? = null,
    private val fileName: String = DEFAULT_SNAPSHOT_FILENAME
) {

    companion object {
        const val DEFAULT_SNAPSHOT_FILENAME = "scan_snapshot_last.json"
        private const val CURRENT_SNAPSHOT_VERSION = 1
    }

    private fun resolveSnapshotFile(): File {
        val baseDir = storageDir ?: context?.filesDir ?: File(System.getProperty("java.io.tmpdir") ?: ".")
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }
        return File(baseDir, fileName)
    }

    val snapshotFile: File
        get() = resolveSnapshotFile()

    /**
     * 判断是否存在上一次保存的历史快照
     */
    fun hasSnapshot(): Boolean {
        return try {
            val file = resolveSnapshotFile()
            file.exists() && file.length() > 0
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * 清理/删除当前快照（测试或重置基线使用）
     */
    fun clearSnapshot(): Boolean {
        return try {
            val file = resolveSnapshotFile()
            if (file.exists()) file.delete() else true
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * 将当前扫描结果保存至内部存储快照文件
     */
    fun saveSnapshot(items: List<DetectionItem>, timestamp: Long = System.currentTimeMillis()): Boolean {
        return try {
            val root = JSONObject().apply {
                put("version", CURRENT_SNAPSHOT_VERSION)
                put("timestamp", timestamp)
                val arr = JSONArray()
                for (item in items) {
                    val itemObj = JSONObject().apply {
                        put("id", item.id)
                        put("name", item.name)
                        put("status", item.status.name)
                        put("evidence", item.evidence)
                    }
                    arr.put(itemObj)
                }
                put("items", arr)
            }

            val targetFile = resolveSnapshotFile()
            targetFile.writeText(root.toString(2))
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 读取上一份快照并与当前检测结果进行比对，生成结构化差异
     */
    fun compareWithLastSnapshot(
        currentItems: List<DetectionItem>,
        currentTimestamp: Long = System.currentTimeMillis()
    ): ScanComparisonResult {
        val targetFile = resolveSnapshotFile()
        if (!targetFile.exists() || targetFile.length() == 0L) {
            return ScanComparisonResult(
                hasChanges = false,
                previousScanTimestamp = 0L,
                currentScanTimestamp = currentTimestamp,
                diffItems = emptyList(),
                changeSummary = "首次全栈检测，已建立安全基线快照",
                newRisksCount = 0,
                changedCount = 0,
                resolvedCount = 0
            )
        }

        return try {
            val content = targetFile.readText()
            val root = JSONObject(content)
            val prevTimestamp = root.optLong("timestamp", 0L)
            val prevArray = root.optJSONArray("items") ?: JSONArray()

            data class PrevItemData(val status: DetectionStatus, val evidence: String, val name: String)
            val prevMap = mutableMapOf<String, PrevItemData>()

            for (i in 0 until prevArray.length()) {
                val obj = prevArray.optJSONObject(i) ?: continue
                val id = obj.optString("id", "")
                if (id.isBlank()) continue
                val name = obj.optString("name", id)
                val statusStr = obj.optString("status", DetectionStatus.PASS.name)
                val status = try {
                    DetectionStatus.valueOf(statusStr)
                } catch (_: Throwable) {
                    DetectionStatus.PASS
                }
                val evidence = obj.optString("evidence", "")
                prevMap[id] = PrevItemData(status, evidence, name)
            }

            val diffs = mutableListOf<DetectionDiff>()
            val visitedIds = mutableSetOf<String>()

            for (curr in currentItems) {
                visitedIds.add(curr.id)
                val prev = prevMap[curr.id]

                if (prev == null) {
                    // 历史中未记录该检测项
                    if (curr.status != DetectionStatus.PASS) {
                        diffs.add(
                            DetectionDiff(
                                itemId = curr.id,
                                name = curr.name,
                                diffType = ItemDiffType.NEW_ABNORMAL,
                                previousStatus = null,
                                currentStatus = curr.status,
                                previousEvidence = "",
                                currentEvidence = curr.evidence,
                                description = "新增异常特征: [${curr.name}] (${curr.status.name})"
                            )
                        )
                    }
                } else {
                    if (prev.status != curr.status) {
                        val diffType = when {
                            curr.status == DetectionStatus.PASS -> ItemDiffType.RESOLVED
                            prev.status == DetectionStatus.PASS -> ItemDiffType.NEW_ABNORMAL
                            else -> ItemDiffType.STATUS_CHANGED
                        }

                        val desc = when (diffType) {
                            ItemDiffType.NEW_ABNORMAL -> "新增风险: [${curr.name}] 状态变为 ${curr.status.name}"
                            ItemDiffType.RESOLVED -> "风险解除: [${curr.name}] 恢复通过 (曾为 ${prev.status.name})"
                            ItemDiffType.STATUS_CHANGED -> "状态变动: [${curr.name}] 从 ${prev.status.name} 变为 ${curr.status.name}"
                            ItemDiffType.UNCHANGED -> ""
                        }

                        diffs.add(
                            DetectionDiff(
                                itemId = curr.id,
                                name = curr.name,
                                diffType = diffType,
                                previousStatus = prev.status,
                                currentStatus = curr.status,
                                previousEvidence = prev.evidence,
                                currentEvidence = curr.evidence,
                                description = desc
                            )
                        )
                    }
                }
            }

            // 检查历史快照中存在且为异常，但当前项被移除的极端情况
            for ((prevId, prevData) in prevMap) {
                if (!visitedIds.contains(prevId) && prevData.status != DetectionStatus.PASS) {
                    diffs.add(
                        DetectionDiff(
                            itemId = prevId,
                            name = prevData.name,
                            diffType = ItemDiffType.RESOLVED,
                            previousStatus = prevData.status,
                            currentStatus = DetectionStatus.PASS,
                            previousEvidence = prevData.evidence,
                            currentEvidence = "",
                            description = "风险已移除: [${prevData.name}] 规则在当前环境已不触发"
                        )
                    )
                }
            }

            val hasChanges = diffs.isNotEmpty()
            val newRisks = diffs.count { it.diffType == ItemDiffType.NEW_ABNORMAL }
            val changed = diffs.count { it.diffType == ItemDiffType.STATUS_CHANGED }
            val resolved = diffs.count { it.diffType == ItemDiffType.RESOLVED }

            val summary = if (hasChanges) {
                "检测到环境状态变动: 新增风险 $newRisks 项, 状态变更 $changed 项, 风险解除 $resolved 项"
            } else {
                "与上次检测快照一致，未检测到环境变更"
            }

            ScanComparisonResult(
                hasChanges = hasChanges,
                previousScanTimestamp = prevTimestamp,
                currentScanTimestamp = currentTimestamp,
                diffItems = diffs,
                changeSummary = summary,
                newRisksCount = newRisks,
                changedCount = changed,
                resolvedCount = resolved
            )
        } catch (_: Exception) {
            ScanComparisonResult(
                hasChanges = false,
                previousScanTimestamp = 0L,
                currentScanTimestamp = currentTimestamp,
                diffItems = emptyList(),
                changeSummary = "快照解析失败，建立新基线",
                newRisksCount = 0,
                changedCount = 0,
                resolvedCount = 0
            )
        }
    }
}
