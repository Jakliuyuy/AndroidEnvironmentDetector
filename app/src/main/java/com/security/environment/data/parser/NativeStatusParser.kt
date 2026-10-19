package com.security.environment.data.parser

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.NativeDetectionItem

data class StatusParseResult(
    val tracerPid: Int,
    val isTraced: Boolean,
    val state: String,
    val evidence: String
) {
    fun toNativeDetectionItem(): NativeDetectionItem {
        val status = if (isTraced) {
            DetectionStatus.DANGER.ordinal
        } else {
            DetectionStatus.PASS.ordinal
        }
        return NativeDetectionItem(
            id = "SEC-R4-04",
            name = "进程跟踪调试状态检测 (TracerPid)",
            category = DetectionCategory.DEBUGGING.ordinal,
            status = status,
            evidence = evidence,
            method = DetectionMethod.DIRECT_SYSCALL.ordinal
        )
    }
}

object NativeStatusParser {

    fun parse(statusContent: String): StatusParseResult {
        if (statusContent.isBlank()) {
            return StatusParseResult(
                tracerPid = 0,
                isTraced = false,
                state = "unknown",
                evidence = "no_status_data"
            )
        }

        var tracerPid = 0
        var foundTracer = false
        var state = "unknown"

        statusContent.lineSequence().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.startsWith("TracerPid:")) {
                val valStr = trimmed.removePrefix("TracerPid:").trim()
                tracerPid = valStr.toIntOrNull() ?: -1
                foundTracer = true
            } else if (trimmed.startsWith("State:")) {
                state = trimmed.removePrefix("State:").trim()
            }
        }

        val isTraced = tracerPid > 0
        val evidence = if (foundTracer) {
            "TracerPid=$tracerPid, State=$state"
        } else {
            "TracerPid_not_found, State=$state"
        }

        return StatusParseResult(
            tracerPid = tracerPid,
            isTraced = isTraced,
            state = state,
            evidence = evidence
        )
    }
}
