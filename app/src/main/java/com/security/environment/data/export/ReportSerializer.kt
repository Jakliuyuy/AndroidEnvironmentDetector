package com.security.environment.data.export

import android.os.Build
import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityAssessment
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

object ReportSerializer {

    const val APP_VERSION = "1.0.0"

    /**
     * 获取当前系统或测试注入的设备信息
     */
    fun getDefaultDeviceMetadata(): Map<String, Any> {
        val supportedAbis = try {
            Build.SUPPORTED_ABIS?.toList() ?: listOf("arm64-v8a")
        } catch (_: Throwable) {
            listOf("arm64-v8a")
        }

        return mapOf(
            "brand" to (safeGetBuildString { Build.BRAND } ?: "Android"),
            "manufacturer" to (safeGetBuildString { Build.MANUFACTURER } ?: "Google"),
            "model" to (safeGetBuildString { Build.MODEL } ?: "Generic Android Device"),
            "device" to (safeGetBuildString { Build.DEVICE } ?: "generic_arm64"),
            "fingerprint" to (safeGetBuildString { Build.FINGERPRINT } ?: "google/generic:11/RQ3A/test-keys"),
            "androidVersion" to (safeGetBuildString { Build.VERSION.RELEASE } ?: "11"),
            "apiLevel" to (safeGetBuildInt { Build.VERSION.SDK_INT } ?: 30),
            "arch" to (System.getProperty("os.arch") ?: "aarch64"),
            "supportedAbis" to supportedAbis,
            "kernelVersion" to (System.getProperty("os.version") ?: "5.10.0-generic")
        )
    }

    private inline fun safeGetBuildString(getter: () -> String?): String? {
        return try {
            val v = getter()
            if (v.isNullOrBlank()) null else v
        } catch (_: Throwable) {
            null
        }
    }

    private inline fun safeGetBuildInt(getter: () -> Int): Int? {
        return try {
            getter()
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * 将检测结果序列化为格式化 JSON 字符串
     */
    fun serializeToJson(
        items: List<DetectionItem>,
        assessment: SecurityAssessment,
        categorySummaries: List<CategorySummary> = emptyList(),
        customDeviceInfo: Map<String, Any>? = null,
        reportId: String = UUID.randomUUID().toString(),
        timestampMs: Long = System.currentTimeMillis()
    ): String {
        val root = JSONObject()

        // 1. Metadata
        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val isoDateStr = isoFormat.format(Date(timestampMs))

        root.put("appVersion", APP_VERSION)
        root.put("reportId", reportId)
        root.put("timestamp", timestampMs)
        root.put("timestampMs", timestampMs)
        root.put("generatedAtIso", isoDateStr)

        val reportMetadataJson = JSONObject().apply {
            put("reportId", reportId)
            put("generatedAtIso", isoDateStr)
            put("timestampMs", timestampMs)
            put("appVersion", APP_VERSION)
        }
        root.put("reportMetadata", reportMetadataJson)

        // 2. Device Info
        val deviceMap = customDeviceInfo ?: getDefaultDeviceMetadata()
        val deviceInfoJson = JSONObject()
        for ((key, value) in deviceMap) {
            if (value is List<*>) {
                val array = JSONArray()
                for (elem in value) {
                    array.put(elem)
                }
                deviceInfoJson.put(key, array)
            } else {
                deviceInfoJson.put(key, value)
            }
        }
        // Ensure primary keys exist
        if (!deviceInfoJson.has("brand")) deviceInfoJson.put("brand", "Android")
        if (!deviceInfoJson.has("model")) deviceInfoJson.put("model", "Device")
        if (!deviceInfoJson.has("fingerprint")) deviceInfoJson.put("fingerprint", "unknown")
        if (!deviceInfoJson.has("androidVersion")) deviceInfoJson.put("androidVersion", "11")
        if (!deviceInfoJson.has("apiLevel")) deviceInfoJson.put("apiLevel", 30)
        if (!deviceInfoJson.has("arch")) deviceInfoJson.put("arch", "arm64-v8a")

        root.put("deviceInfo", deviceInfoJson)

        // 3. Assessment
        val assessmentJson = JSONObject().apply {
            put("score", assessment.score)
            put("level", assessment.level.name)
            put("grade", assessment.level.name)
            put("dangerCount", assessment.dangerCount)
            put("warnCount", assessment.warnCount)
            put("passCount", assessment.passCount)
            put("totalChecks", items.size)
            put("summary", assessment.summary)
        }
        root.put("assessment", assessmentJson)
        root.put("securityAssessment", assessmentJson)

        // 4. Category Summaries
        val summariesList = if (categorySummaries.isNotEmpty()) {
            categorySummaries
        } else {
            DetectionCategory.entries.map { cat ->
                val catItems = items.filter { it.category == cat }
                val pass = catItems.count { it.status == DetectionStatus.PASS }
                val warn = catItems.count { it.status == DetectionStatus.WARN }
                val danger = catItems.count { it.status == DetectionStatus.DANGER }
                val highest = when {
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
                    highestStatus = highest
                )
            }
        }

        val summariesArray = JSONArray()
        for (cs in summariesList) {
            val sObj = JSONObject().apply {
                put("category", cs.category.name)
                put("categoryId", cs.category.idName)
                put("title", cs.category.title)
                put("total", cs.totalCount)
                put("totalCount", cs.totalCount)
                put("passed", cs.passCount)
                put("passCount", cs.passCount)
                put("warned", cs.warnCount)
                put("warnCount", cs.warnCount)
                put("danger", cs.dangerCount)
                put("dangerCount", cs.dangerCount)
                put("highestStatus", cs.highestStatus.name)
            }
            summariesArray.put(sObj)
        }
        root.put("categorySummaries", summariesArray)

        // 5. Detection Items (24+ checks)
        val itemsArray = JSONArray()
        for (item in items) {
            val iObj = JSONObject().apply {
                put("id", item.id)
                put("name", item.name)
                put("category", item.category.name)
                put("status", item.status.name)
                put("evidence", item.evidence)
                put("method", item.method.name)
                put("description", item.description)
                put("remediation", item.remediation)
            }
            itemsArray.put(iObj)
        }
        root.put("items", itemsArray)
        root.put("detailedResults", itemsArray)

        return root.toString(2)
    }

    /**
     * 生成人类可读的纯文本诊断报告
     */
    fun serializeToPlainText(
        items: List<DetectionItem>,
        assessment: SecurityAssessment,
        categorySummaries: List<CategorySummary> = emptyList(),
        customDeviceInfo: Map<String, Any>? = null,
        reportId: String = UUID.randomUUID().toString(),
        timestampMs: Long = System.currentTimeMillis()
    ): String {
        val deviceMap = customDeviceInfo ?: getDefaultDeviceMetadata()
        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val isoDateStr = isoFormat.format(Date(timestampMs))

        val sb = StringBuilder()
        sb.appendLine("==================================================")
        sb.appendLine("       ANDROID ENVIRONMENT SECURITY REPORT        ")
        sb.appendLine("==================================================")
        sb.appendLine("Report ID:    $reportId")
        sb.appendLine("Generated:    $isoDateStr")
        sb.appendLine("App Version:  $APP_VERSION")
        sb.appendLine("Device:       ${deviceMap["brand"]} ${deviceMap["model"]} (Android ${deviceMap["androidVersion"]}, API ${deviceMap["apiLevel"]})")
        sb.appendLine("Fingerprint:  ${deviceMap["fingerprint"]}")
        sb.appendLine("Arch:         ${deviceMap["arch"]}")
        sb.appendLine("--------------------------------------------------")
        sb.appendLine("ASSESSMENT SUMMARY:")
        sb.appendLine("Overall Level: [${assessment.level.name}] (${assessment.level.title})")
        sb.appendLine("Security Score: ${assessment.score} / 100")
        sb.appendLine("Total Checks:   ${items.size}")
        sb.appendLine("Breakdown:      Pass=${assessment.passCount}, Warn=${assessment.warnCount}, Danger=${assessment.dangerCount}")
        sb.appendLine("Verdict:        ${assessment.summary}")
        sb.appendLine("--------------------------------------------------")
        sb.appendLine("CATEGORY SUMMARIES:")

        val summariesList = if (categorySummaries.isNotEmpty()) {
            categorySummaries
        } else {
            DetectionCategory.entries.map { cat ->
                val catItems = items.filter { it.category == cat }
                CategorySummary(
                    category = cat,
                    totalCount = catItems.size,
                    passCount = catItems.count { it.status == DetectionStatus.PASS },
                    warnCount = catItems.count { it.status == DetectionStatus.WARN },
                    dangerCount = catItems.count { it.status == DetectionStatus.DANGER },
                    highestStatus = when {
                        catItems.any { it.status == DetectionStatus.DANGER } -> DetectionStatus.DANGER
                        catItems.any { it.status == DetectionStatus.WARN } -> DetectionStatus.WARN
                        else -> DetectionStatus.PASS
                    }
                )
            }
        }

        for (cs in summariesList) {
            val statusTag = when (cs.highestStatus) {
                DetectionStatus.PASS -> "[PASS]  "
                DetectionStatus.WARN -> "[WARN]  "
                DetectionStatus.DANGER -> "[DANGER]"
            }
            sb.appendLine("$statusTag ${cs.category.title}: ${cs.totalCount} checks (P:${cs.passCount}, W:${cs.warnCount}, D:${cs.dangerCount})")
        }

        sb.appendLine("--------------------------------------------------")
        sb.appendLine("DETAILED DETECTION RESULTS (${items.size}):")
        for (item in items) {
            val tag = when (item.status) {
                DetectionStatus.PASS -> "[PASS]  "
                DetectionStatus.WARN -> "[WARN]  "
                DetectionStatus.DANGER -> "[DANGER]"
            }
            sb.appendLine("$tag [${item.category.idName}] ${item.name} (${item.method.displayName})")
            sb.appendLine("         Evidence: ${item.evidence}")
            if (item.description.isNotBlank()) {
                sb.appendLine("         Desc:     ${item.description}")
            }
            if (item.remediation.isNotBlank() && item.status != DetectionStatus.PASS) {
                sb.appendLine("         Remedy:   ${item.remediation}")
            }
        }
        sb.appendLine("==================================================")
        return sb.toString()
    }
}
