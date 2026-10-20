package com.security.environment.domain.attestation

/**
 * Android Key Attestation 安全级别枚举
 * 0: SOFTWARE - 纯软件实现，无硬件安全域保证
 * 1: TRUSTED_ENVIRONMENT - 基于硬件 TEE (TrustZone) 隔离执行环境
 * 2: STRONGBOX - 基于独立硬件安全芯片 (StrongBox Keymaster / Titan M / SE)
 */
enum class AttestationSecurityLevel(val code: Int, val description: String) {
    SOFTWARE(0, "Software (纯软件安全域)"),
    TRUSTED_ENVIRONMENT(1, "TEE (可信执行环境)"),
    STRONGBOX(2, "StrongBox (独立安全芯片)"),
    UNKNOWN(-1, "Unknown (未知安全级别)");

    companion object {
        fun fromCode(code: Int): AttestationSecurityLevel {
            return entries.firstOrNull { it.code == code } ?: UNKNOWN
        }
    }
}
