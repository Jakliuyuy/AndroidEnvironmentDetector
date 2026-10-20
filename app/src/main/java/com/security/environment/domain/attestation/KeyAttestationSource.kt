package com.security.environment.domain.attestation

/**
 * 硬件密钥证明数据源接口
 * 抽象设备底层 AndroidKeyStore 交互，解耦业务逻辑与 JVM 单元测试桩
 */
interface KeyAttestationSource {
    /**
     * 请求执行硬件密钥证明并返回提取结果
     * @param challenge 证明随机挑战值（防重放），为 null 时自动生成安全随机数
     */
    fun getAttestationResult(challenge: ByteArray? = null): KeyAttestationResult
}
