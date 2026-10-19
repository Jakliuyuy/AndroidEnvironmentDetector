package com.security.environment.data.export

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.core.content.FileProvider
import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.SecurityAssessment
import java.io.File

object ReportExportHelper {

    /**
     * 将报告文本复制到系统剪贴板
     */
    fun copyToClipboard(
        context: Context,
        content: String,
        label: String = "Environment Security Report",
        showToast: Boolean = true
    ): Boolean {
        return try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText(label, content)
            clipboard.setPrimaryClip(clip)
            if (showToast) {
                Toast.makeText(context, "诊断报告已复制到剪贴板", Toast.LENGTH_SHORT).show()
            }
            true
        } catch (e: Throwable) {
            if (showToast) {
                Toast.makeText(context, "复制失败: ${e.message}", Toast.LENGTH_SHORT).show()
            }
            false
        }
    }

    /**
     * 通过 Android Intent 系统分享发送诊断报告文件
     */
    fun shareReport(
        context: Context,
        content: String,
        isJson: Boolean = true,
        title: String = "分享环境安全检测报告"
    ): Boolean {
        return try {
            val extension = if (isJson) "json" else "txt"
            val mimeType = if (isJson) "application/json" else "text/plain"
            val fileName = "security_report_${System.currentTimeMillis()}.$extension"

            val cacheDir = context.cacheDir
            val reportFile = File(cacheDir, fileName)
            reportFile.writeText(content, Charsets.UTF_8)

            val authority = "${context.packageName}.fileprovider"
            val contentUri = FileProvider.getUriForFile(context, authority, reportFile)

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = mimeType
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_SUBJECT, "Android Environment Security Assessment Report")
                putExtra(Intent.EXTRA_TEXT, "由 Android 环境安全检测工具自动生成的系统完整性诊断报告")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            val chooser = Intent.createChooser(shareIntent, title).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(chooser)
            true
        } catch (e: Throwable) {
            Toast.makeText(context, "分享报告失败: ${e.message}", Toast.LENGTH_SHORT).show()
            false
        }
    }

    /**
     * 便捷方法：生成 JSON 并分享
     */
    fun exportAndShareJson(
        context: Context,
        items: List<DetectionItem>,
        assessment: SecurityAssessment,
        categorySummaries: List<CategorySummary> = emptyList()
    ): Boolean {
        val json = ReportSerializer.serializeToJson(items, assessment, categorySummaries)
        return shareReport(context, json, isJson = true)
    }

    /**
     * 便捷方法：生成 JSON 并复制到剪贴板
     */
    fun exportAndCopyJson(
        context: Context,
        items: List<DetectionItem>,
        assessment: SecurityAssessment,
        categorySummaries: List<CategorySummary> = emptyList()
    ): Boolean {
        val json = ReportSerializer.serializeToJson(items, assessment, categorySummaries)
        return copyToClipboard(context, json, label = "Security Report JSON")
    }
}
