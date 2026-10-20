package com.security.environment.domain.attestation

/**
 * Android Key Attestation 信任根 (RootOfTrust, Tag 704) 数据结构
 */
data class RootOfTrustRecord(
    val verifiedBootKey: ByteArray?,
    val deviceLocked: Boolean,
    val verifiedBootState: VerifiedBootState,
    val verifiedBootHash: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RootOfTrustRecord

        if (verifiedBootKey != null) {
            if (other.verifiedBootKey == null) return false
            if (!verifiedBootKey.contentEquals(other.verifiedBootKey)) return false
        } else if (other.verifiedBootKey != null) return false

        if (deviceLocked != other.deviceLocked) return false
        if (verifiedBootState != other.verifiedBootState) return false

        if (verifiedBootHash != null) {
            if (other.verifiedBootHash == null) return false
            if (!verifiedBootHash.contentEquals(other.verifiedBootHash)) return false
        } else if (other.verifiedBootHash != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = verifiedBootKey?.contentHashCode() ?: 0
        result = 31 * result + deviceLocked.hashCode()
        result = 31 * result + verifiedBootState.hashCode()
        result = 31 * result + (verifiedBootHash?.contentHashCode() ?: 0)
        return result
    }

    val verifiedBootKeyHex: String?
        get() = verifiedBootKey?.joinToString("") { "%02x".format(it) }

    val verifiedBootHashHex: String?
        get() = verifiedBootHash?.joinToString("") { "%02x".format(it) }
}

/**
 * Android Key Attestation 证书扩展记录 (OID 1.3.6.1.4.1.11129.2.1.17)
 */
data class KeyAttestationRecord(
    val attestationVersion: Int,
    val attestationSecurityLevel: AttestationSecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: AttestationSecurityLevel,
    val attestationChallenge: ByteArray?,
    val uniqueId: ByteArray?,
    val teeRootOfTrust: RootOfTrustRecord?,
    val softwareRootOfTrust: RootOfTrustRecord?
) {
    /**
     * 优选由硬件 TEE/StrongBox 保证的 RootOfTrust，若无则回退至软件记录
     */
    val rootOfTrust: RootOfTrustRecord?
        get() = teeRootOfTrust ?: softwareRootOfTrust

    val verifiedBootState: VerifiedBootState?
        get() = rootOfTrust?.verifiedBootState

    val isDeviceLocked: Boolean?
        get() = rootOfTrust?.deviceLocked

    val isHardwareBacked: Boolean
        get() = attestationSecurityLevel == AttestationSecurityLevel.TRUSTED_ENVIRONMENT ||
                attestationSecurityLevel == AttestationSecurityLevel.STRONGBOX

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyAttestationRecord

        if (attestationVersion != other.attestationVersion) return false
        if (attestationSecurityLevel != other.attestationSecurityLevel) return false
        if (keymasterVersion != other.keymasterVersion) return false
        if (keymasterSecurityLevel != other.keymasterSecurityLevel) return false
        if (!attestationChallenge.contentEquals(other.attestationChallenge)) return false
        if (!uniqueId.contentEquals(other.uniqueId)) return false
        if (teeRootOfTrust != other.teeRootOfTrust) return false
        if (softwareRootOfTrust != other.softwareRootOfTrust) return false

        return true
    }

    override fun hashCode(): Int {
        var result = attestationVersion
        result = 31 * result + attestationSecurityLevel.hashCode()
        result = 31 * result + keymasterVersion
        result = 31 * result + keymasterSecurityLevel.hashCode()
        result = 31 * result + (attestationChallenge?.contentHashCode() ?: 0)
        result = 31 * result + (uniqueId?.contentHashCode() ?: 0)
        result = 31 * result + (teeRootOfTrust?.hashCode() ?: 0)
        result = 31 * result + (softwareRootOfTrust?.hashCode() ?: 0)
        return result
    }
}
