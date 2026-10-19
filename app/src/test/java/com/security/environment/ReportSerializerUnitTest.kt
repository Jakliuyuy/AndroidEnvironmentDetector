package com.security.environment

import com.security.environment.data.export.ReportSerializer
import com.security.environment.data.model.CategorySummary
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionItem
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.SecurityAssessment
import com.security.environment.data.model.SecurityLevel
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReportSerializerUnitTest {

    private lateinit var sampleItems: List<DetectionItem>
    private lateinit var sampleAssessment: SecurityAssessment
    private lateinit var sampleCategorySummaries: List<CategorySummary>
    private lateinit var sampleDeviceInfo: Map<String, Any>

    @Before
    fun setUp() {
        sampleItems = listOf(
            DetectionItem(
                id = "SEC-R1-01",
                name = "Bootloader 锁状态",
                category = DetectionCategory.BOOTLOADER,
                status = DetectionStatus.PASS,
                evidence = "ro.boot.flash.locked=1",
                method = DetectionMethod.DIRECT_SYSCALL,
                description = "校验 Bootloader 锁定标志位",
                remediation = ""
            ),
            DetectionItem(
                id = "SEC-R2-01",
                name = "常规 SU 文件探测",
                category = DetectionCategory.ROOT,
                status = DetectionStatus.DANGER,
                evidence = "/system/xbin/su (inode: 12044, perms: 0755, flags: \"O_RDONLY\")",
                method = DetectionMethod.DIRECT_SYSCALL,
                description = "发现系统存在可执行的 su 二进制文件",
                remediation = "卸载 Magisk/KernelSU 或刷入官方固件"
            ),
            DetectionItem(
                id = "SEC-R3-01",
                name = "Frida 默认端口探测",
                category = DetectionCategory.HOOK,
                status = DetectionStatus.WARN,
                evidence = "tcp 127.0.0.1:27042 responding with \"REJECT\\r\\n\"",
                method = DetectionMethod.LIBC,
                description = "发现本地回环存在 Frida 默认控制端口响应",
                remediation = "关闭分析进程及后台调试服务"
            ),
            DetectionItem(
                id = "SEC-R4-01",
                name = "QEMU 驱动与虚拟化硬件",
                category = DetectionCategory.VIRTUALIZATION,
                status = DetectionStatus.PASS,
                evidence = "ro.kernel.qemu=0, ro.hardware=qcom",
                method = DetectionMethod.DIRECT_SYSCALL,
                description = "硬件属性未见常见模拟器指纹",
                remediation = ""
            ),
            DetectionItem(
                id = "SEC-R4-02",
                name = "TracerPid 追踪进程状态",
                category = DetectionCategory.DEBUGGING,
                status = DetectionStatus.PASS,
                evidence = "TracerPid: 0 in /proc/self/status",
                method = DetectionMethod.DIRECT_SYSCALL,
                description = "当前进程未被 ptrace 调试追踪",
                remediation = ""
            )
        )

        sampleAssessment = SecurityAssessment(
            score = 38,
            level = SecurityLevel.DANGEROUS,
            dangerCount = 1,
            warnCount = 1,
            passCount = 3,
            summary = "检测到 1 项高危安全威胁（Root提权/动态Hook/未锁定），系统处于极高风险状态"
        )

        sampleCategorySummaries = listOf(
            CategorySummary(DetectionCategory.BOOTLOADER, 1, 1, 0, 0, DetectionStatus.PASS),
            CategorySummary(DetectionCategory.ROOT, 1, 0, 0, 1, DetectionStatus.DANGER),
            CategorySummary(DetectionCategory.HOOK, 1, 0, 1, 0, DetectionStatus.WARN),
            CategorySummary(DetectionCategory.VIRTUALIZATION, 1, 1, 0, 0, DetectionStatus.PASS),
            CategorySummary(DetectionCategory.DEBUGGING, 1, 1, 0, 0, DetectionStatus.PASS)
        )

        sampleDeviceInfo = mapOf(
            "brand" to "Google",
            "manufacturer" to "Google",
            "model" to "Pixel 8 Pro",
            "device" to "husky",
            "fingerprint" to "google/husky/husky:14/UD1A.230803.041/10808477:user/release-keys",
            "androidVersion" to "14",
            "apiLevel" to 34,
            "arch" to "arm64-v8a",
            "supportedAbis" to listOf("arm64-v8a"),
            "kernelVersion" to "5.15.110-android14-11-ge4f014490"
        )
    }

    @Test
    fun testJsonStructureAndRequiredFields() {
        val jsonStr = ReportSerializer.serializeToJson(
            items = sampleItems,
            assessment = sampleAssessment,
            categorySummaries = sampleCategorySummaries,
            customDeviceInfo = sampleDeviceInfo,
            reportId = "test-report-uuid-001",
            timestampMs = 1729370000000L
        )

        assertNotNull(jsonStr)
        assertTrue(jsonStr.isNotBlank())

        val json = JSONObject(jsonStr)

        // 验证 PROJECT.md 规定的关键字段
        assertEquals("1.0.0", json.getString("appVersion"))
        assertEquals("test-report-uuid-001", json.getString("reportId"))
        assertEquals(1729370000000L, json.getLong("timestamp"))

        // 验证 deviceInfo
        assertTrue(json.has("deviceInfo"))
        val devObj = json.getJSONObject("deviceInfo")
        assertEquals("Google", devObj.getString("brand"))
        assertEquals("Pixel 8 Pro", devObj.getString("model"))
        assertEquals(34, devObj.getInt("apiLevel"))
        assertEquals("arm64-v8a", devObj.getString("arch"))

        // 验证 assessment
        assertTrue(json.has("assessment"))
        val assessObj = json.getJSONObject("assessment")
        assertEquals(38, assessObj.getInt("score"))
        assertEquals("DANGEROUS", assessObj.getString("level"))
        assertEquals(1, assessObj.getInt("dangerCount"))
        assertEquals(1, assessObj.getInt("warnCount"))
        assertEquals(3, assessObj.getInt("passCount"))
        assertEquals(5, assessObj.getInt("totalChecks"))

        // 验证 items
        assertTrue(json.has("items"))
        val itemsArr = json.getJSONArray("items")
        assertEquals(5, itemsArr.length())

        val firstItem = itemsArr.getJSONObject(0)
        assertEquals("SEC-R1-01", firstItem.getString("id"))
        assertEquals("Bootloader 锁状态", firstItem.getString("name"))
        assertEquals("BOOTLOADER", firstItem.getString("category"))
        assertEquals("PASS", firstItem.getString("status"))
        assertEquals("DIRECT_SYSCALL", firstItem.getString("method"))
        assertEquals("ro.boot.flash.locked=1", firstItem.getString("evidence"))

        // 验证 handoff.md 兼容性字段
        assertTrue(json.has("reportMetadata"))
        assertTrue(json.has("securityAssessment"))
        assertTrue(json.has("categorySummaries"))
        assertTrue(json.has("detailedResults"))
    }

    @Test
    fun testEscapingAndSpecialCharacters() {
        val complexItem = DetectionItem(
            id = "SEC-TEST-ESCAPE",
            name = "特殊转义字符与注入测试 <script> & \"quotes\"",
            category = DetectionCategory.HOOK,
            status = DetectionStatus.WARN,
            evidence = "Path with quotes: \"/data/local/tmp/frida-agent.so\"\nNewlines\tTabs\\Backslashes & Unicode: 中文测试 🔒",
            method = DetectionMethod.LIBC,
            description = "说明文本含引号 'single' 与 \"double\" 及斜杠 /proc/self/maps",
            remediation = "避免使用 <script> 标签"
        )

        val jsonStr = ReportSerializer.serializeToJson(
            items = listOf(complexItem),
            assessment = sampleAssessment,
            customDeviceInfo = sampleDeviceInfo
        )

        // 验证能成功反序列化为 JSONObject，无语法异常
        val json = JSONObject(jsonStr)
        val itemsArr = json.getJSONArray("items")
        assertEquals(1, itemsArr.length())

        val parsed = itemsArr.getJSONObject(0)
        assertEquals(complexItem.id, parsed.getString("id"))
        assertEquals(complexItem.name, parsed.getString("name"))
        assertEquals(complexItem.evidence, parsed.getString("evidence"))
        assertEquals(complexItem.description, parsed.getString("description"))
        assertEquals(complexItem.remediation, parsed.getString("remediation"))
    }

    @Test
    fun testCategorySummariesInJson() {
        val jsonStr = ReportSerializer.serializeToJson(
            items = sampleItems,
            assessment = sampleAssessment,
            categorySummaries = sampleCategorySummaries,
            customDeviceInfo = sampleDeviceInfo
        )

        val json = JSONObject(jsonStr)
        val summariesArr = json.getJSONArray("categorySummaries")
        assertEquals(5, summariesArr.length())

        var foundRoot = false
        for (i in 0 until summariesArr.length()) {
            val catObj = summariesArr.getJSONObject(i)
            if (catObj.getString("category") == "ROOT") {
                foundRoot = true
                assertEquals(1, catObj.getInt("total"))
                assertEquals(1, catObj.getInt("danger"))
                assertEquals("DANGER", catObj.getString("highestStatus"))
            }
        }
        assertTrue("Category summaries should contain ROOT", foundRoot)
    }

    @Test
    fun testPlainTextReportFormatting() {
        val textReport = ReportSerializer.serializeToPlainText(
            items = sampleItems,
            assessment = sampleAssessment,
            categorySummaries = sampleCategorySummaries,
            customDeviceInfo = sampleDeviceInfo,
            reportId = "text-report-uuid-002",
            timestampMs = 1729370000000L
        )

        assertNotNull(textReport)
        assertTrue(textReport.contains("ANDROID ENVIRONMENT SECURITY REPORT"))
        assertTrue(textReport.contains("Report ID:    text-report-uuid-002"))
        assertTrue(textReport.contains("Device:       Google Pixel 8 Pro"))
        assertTrue(textReport.contains("Overall Level: [DANGEROUS] (危险)"))
        assertTrue(textReport.contains("Security Score: 38 / 100"))
        assertTrue(textReport.contains("Breakdown:      Pass=3, Warn=1, Danger=1"))
        assertTrue(textReport.contains("[DANGER] [root] 常规 SU 文件探测"))
        assertTrue(textReport.contains("Evidence: /system/xbin/su"))
        assertTrue(textReport.contains("Remedy:   卸载 Magisk/KernelSU 或刷入官方固件"))
        assertTrue(textReport.contains("[PASS]   [bootloader] Bootloader 锁状态"))
    }

    @Test
    fun testDefaultDeviceMetadataDoesNotCrash() {
        // 在 JVM 测试环境中 safeGetBuildString 能优雅降级，不会抛出异常
        val meta = ReportSerializer.getDefaultDeviceMetadata()
        assertNotNull(meta)
        assertTrue(meta.containsKey("brand"))
        assertTrue(meta.containsKey("model"))
        assertTrue(meta.containsKey("arch"))
    }
}
