package com.security.environment.data.model

import androidx.annotation.Keep

@Keep
data class NativeDetectionItem(
    val id: String,
    val name: String,
    val category: Int,
    val status: Int,
    val evidence: String,
    val method: Int
) {
    fun toDomain(): DetectionItem {
        return DetectionItem(
            id = id,
            name = name,
            category = DetectionCategory.fromOrdinal(category),
            status = DetectionStatus.fromOrdinal(status),
            evidence = evidence,
            method = DetectionMethod.fromOrdinal(method),
            description = "Native check id: $id"
        )
    }
}

enum class DetectionStatus(val severity: Int) {
    PASS(0),
    WARN(1),
    DANGER(2);

    companion object {
        fun fromOrdinal(ordinal: Int): DetectionStatus = entries.getOrElse(ordinal) { PASS }
    }
}

enum class DetectionCategory(val idName: String, val title: String) {
    BOOTLOADER("bootloader", "Bootloader & 系统完整性"),
    ROOT("root", "Root 提权与隐藏框架"),
    HOOK("hook", "动态 Hook 与内存注入"),
    VIRTUALIZATION("virtual", "虚拟环境与多开"),
    DEBUGGING("debug", "调试状态与追踪");

    companion object {
        fun fromOrdinal(ordinal: Int): DetectionCategory = entries.getOrElse(ordinal) { BOOTLOADER }
    }
}

enum class DetectionMethod(val displayName: String) {
    JAVA("Java Framework API"),
    LIBC("Native Libc POSIX"),
    DIRECT_SYSCALL("Direct Inline Syscall");

    companion object {
        fun fromOrdinal(ordinal: Int): DetectionMethod = entries.getOrElse(ordinal) { JAVA }
    }
}

data class DetectionItem(
    val id: String,
    val name: String,
    val category: DetectionCategory,
    val status: DetectionStatus,
    val evidence: String,
    val method: DetectionMethod,
    val description: String = "",
    val remediation: String = ""
)

enum class SecurityLevel(val title: String) {
    SAFE("安全"),
    WARNING("警告"),
    DANGEROUS("危险")
}

data class SecurityAssessment(
    val score: Int,              // 0 to 100
    val level: SecurityLevel,    // SAFE, WARNING, DANGEROUS
    val dangerCount: Int,
    val warnCount: Int,
    val passCount: Int,
    val summary: String
)

data class CategorySummary(
    val category: DetectionCategory,
    val totalCount: Int,
    val passCount: Int,
    val warnCount: Int,
    val dangerCount: Int,
    val highestStatus: DetectionStatus
)

