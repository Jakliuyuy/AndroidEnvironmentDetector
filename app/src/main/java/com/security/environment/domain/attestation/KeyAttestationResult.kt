package com.security.environment.domain.attestation

import java.security.cert.X509Certificate

sealed class KeyAttestationResult {

    /**
     * 密钥证明生成与解析成功
     */
    data class Success(
        val record: KeyAttestationRecord,
        val certificateChain: List<X509Certificate> = emptyList(),
        val isHardwareBacked: Boolean = true
    ) : KeyAttestationResult() {
        val verifiedBootState: VerifiedBootState?
            get() = record.verifiedBootState

        val isDeviceLocked: Boolean?
            get() = record.isDeviceLocked
    }

    /**
     * 证明过程遇到明确错误（例如证书解析失败、Extension 缺失等）
     */
    data class Failed(
        val reason: String,
        val cause: Throwable? = null
    ) : KeyAttestationResult()

    /**
     * 当前环境不可用（无 AndroidKeyStore 硬件支持、模拟器环境或低版本系统降级）
     */
    data class Unavailable(
        val reason: String = "KeyStore hardware attestation unavailable on current device/environment"
    ) : KeyAttestationResult()
}
