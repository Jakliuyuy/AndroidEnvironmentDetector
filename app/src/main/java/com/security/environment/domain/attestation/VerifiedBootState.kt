package com.security.environment.domain.attestation

/**
 * Android Verified Boot (AVB) 引导状态枚举
 * 对应 Android Key Attestation 规范中的 VerifiedBootState:
 * 0: VERIFIED - 官方厂商公钥签名验证通过（绿色状态）
 * 1: SELF_SIGNED - 自定义/自签名信任根证书验证（黄色状态）
 * 2: UNVERIFIED - Bootloader 已解锁，未验证启动（橙色状态）
 * 3: FAILED - 启动验证失败（红色状态）
 */
enum class VerifiedBootState(val code: Int, val description: String) {
    VERIFIED(0, "Verified (官方厂商签名认证)"),
    SELF_SIGNED(1, "SelfSigned (自签名证书启动)"),
    UNVERIFIED(2, "Unverified (Bootloader 已解锁)"),
    FAILED(3, "Failed (系统启动验证失败)");

    companion object {
        fun fromCode(code: Int): VerifiedBootState {
            return entries.firstOrNull { it.code == code } ?: FAILED
        }
    }
}
