package com.security.environment.domain.attestation

import java.security.cert.X509Certificate

/**
 * 纯 Kotlin 实现的零依赖 ASN.1 DER 解码器与 Android Key Attestation 扩展解析器
 * 
 * 专门解析 Android Key Attestation 规范扩展:
 * OID: 1.3.6.1.4.1.11129.2.1.17 (Key Description)
 * 提取 RootOfTrust (Tag 704):
 *   - deviceLocked (BOOLEAN)
 *   - verifiedBootState (ENUMERATED: 0=Verified, 1=SelfSigned, 2=Unverified, 3=Failed)
 *   - verifiedBootKey (OCTET STRING)
 *   - verifiedBootHash (OCTET STRING, optional)
 */
object KeyAttestationParser {

    const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    const val TAG_ROOT_OF_TRUST = 704

    // ASN.1 Universal Tags
    private const val TAG_BOOLEAN = 0x01
    private const val TAG_INTEGER = 0x02
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_NULL = 0x05
    private const val TAG_OID = 0x06
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_SEQUENCE = 0x30
    private const val TAG_SET = 0x31

    // ASN.1 Classes
    private const val CLASS_UNIVERSAL = 0
    private const val CLASS_APPLICATION = 1
    private const val CLASS_CONTEXT_SPECIFIC = 2
    private const val CLASS_PRIVATE = 3

    data class Asn1Tag(
        val tagClass: Int,
        val isConstructed: Boolean,
        val tagNumber: Int
    )

    class DerReader(
        val bytes: ByteArray,
        var offset: Int = 0,
        val limit: Int = bytes.size
    ) {
        fun hasNext(): Boolean = offset < limit

        fun remaining(): Int = (limit - offset).coerceAtLeast(0)

        fun readTag(): Asn1Tag {
            if (offset >= limit) {
                throw IllegalArgumentException("Unexpected EOF while reading ASN.1 tag at offset $offset")
            }
            val firstByte = bytes[offset++].toInt() and 0xFF
            val tagClass = (firstByte and 0xC0) ushr 6
            val isConstructed = (firstByte and 0x20) != 0
            var tagNumber = firstByte and 0x1F

            if (tagNumber == 0x1F) {
                // Multi-byte tag number encoding (Base-128)
                tagNumber = 0
                while (offset < limit) {
                    val b = bytes[offset++].toInt() and 0xFF
                    tagNumber = (tagNumber shl 7) or (b and 0x7F)
                    if ((b and 0x80) == 0) {
                        break
                    }
                }
            }

            return Asn1Tag(tagClass, isConstructed, tagNumber)
        }

        fun peekTag(): Asn1Tag {
            val saved = offset
            return try {
                readTag()
            } finally {
                offset = saved
            }
        }

        fun readLength(): Int {
            if (offset >= limit) {
                throw IllegalArgumentException("Unexpected EOF while reading ASN.1 length at offset $offset")
            }
            val first = bytes[offset++].toInt() and 0xFF
            if ((first and 0x80) == 0) {
                // Short form: 0..127
                return first
            }

            val numBytes = first and 0x7F
            if (numBytes == 0) {
                throw IllegalArgumentException("Indefinite length encoding is unsupported in DER at offset $offset")
            }
            if (numBytes > 4) {
                throw IllegalArgumentException("DER length exceeds 4 bytes ($numBytes) at offset $offset")
            }

            var length = 0
            for (i in 0 until numBytes) {
                if (offset >= limit) {
                    throw IllegalArgumentException("Truncated DER length at offset $offset")
                }
                val b = bytes[offset++].toInt() and 0xFF
                length = (length shl 8) or b
            }

            if (length < 0 || offset + length > limit) {
                throw IllegalArgumentException("Invalid DER length $length exceeds boundary ($limit) at offset $offset")
            }
            return length
        }

        fun readInteger(): Int {
            val tag = readTag()
            if (tag.tagNumber != TAG_INTEGER && tag.tagNumber != TAG_ENUMERATED) {
                throw IllegalArgumentException("Expected INTEGER/ENUMERATED but got tag ${tag.tagNumber}")
            }
            val length = readLength()
            if (length == 0 || length > 4) {
                // Skip if length > 4 and return approximate or throw
                if (length > 4) {
                    val valueBytes = readBytes(length)
                    var res = 0
                    for (b in valueBytes) {
                        res = (res shl 8) or (b.toInt() and 0xFF)
                    }
                    return res
                }
                throw IllegalArgumentException("Invalid INTEGER length: $length")
            }

            // Big-endian signed integer
            var value = bytes[offset++].toInt() // preserves sign for first byte
            for (i in 1 until length) {
                value = (value shl 8) or (bytes[offset++].toInt() and 0xFF)
            }
            return value
        }

        fun readBoolean(): Boolean {
            val tag = readTag()
            if (tag.tagNumber != TAG_BOOLEAN) {
                throw IllegalArgumentException("Expected BOOLEAN but got tag ${tag.tagNumber}")
            }
            val length = readLength()
            if (length < 1) {
                throw IllegalArgumentException("Invalid BOOLEAN length: $length")
            }
            val boolVal = bytes[offset++].toInt() != 0
            // If extra bytes, skip them
            if (length > 1) {
                offset += (length - 1)
            }
            return boolVal
        }

        fun readOctetString(): ByteArray {
            val tag = readTag()
            if (tag.tagNumber != TAG_OCTET_STRING) {
                throw IllegalArgumentException("Expected OCTET STRING but got tag ${tag.tagNumber}")
            }
            val length = readLength()
            return readBytes(length)
        }

        fun readBytes(length: Int): ByteArray {
            if (offset + length > limit) {
                throw IllegalArgumentException("Attempt to read $length bytes beyond limit $limit at $offset")
            }
            val result = bytes.copyOfRange(offset, offset + length)
            offset += length
            return result
        }

        fun enterSequence(): DerReader {
            val tag = readTag()
            if (tag.tagNumber != (TAG_SEQUENCE and 0x1F) && (tag.tagNumber != TAG_SEQUENCE)) {
                throw IllegalArgumentException("Expected SEQUENCE (0x30) but got tag ${tag.tagNumber}")
            }
            val length = readLength()
            val childLimit = offset + length
            val childReader = DerReader(bytes, offset, childLimit)
            offset = childLimit
            return childReader
        }

        fun enterChild(length: Int): DerReader {
            val childLimit = offset + length
            val childReader = DerReader(bytes, offset, childLimit)
            offset = childLimit
            return childReader
        }
    }

    /**
     * 从 X509 证书中提取并解析 Key Attestation 扩展
     */
    fun parseFromCertificate(certificate: X509Certificate): KeyAttestationRecord? {
        val extensionValue = certificate.getExtensionValue(KEY_ATTESTATION_OID) ?: return null
        return parseFromExtension(extensionValue)
    }

    /**
     * 解析 X509Certificate.getExtensionValue 返回的 DER 编码字节
     * (首层包含 OCTET STRING 封装)
     */
    fun parseFromExtension(extensionBytes: ByteArray): KeyAttestationRecord? {
        return try {
            val unwrapped = unwrapOctetString(extensionBytes)
            parseKeyDescription(unwrapped)
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * 剥离外层 DER OCTET STRING (Tag 0x04) 包装
     */
    fun unwrapOctetString(bytes: ByteArray): ByteArray {
        if (bytes.isEmpty()) return bytes
        val reader = DerReader(bytes)
        val tag = reader.readTag()
        return if (tag.tagNumber == TAG_OCTET_STRING) {
            val len = reader.readLength()
            reader.readBytes(len)
        } else {
            // Already unwrapped
            bytes
        }
    }

    /**
     * 直接解析 KeyDescription SEQUENCE DER 字节
     */
    fun parseKeyDescription(bytes: ByteArray): KeyAttestationRecord? {
        return try {
            val reader = DerReader(bytes)
            val seqReader = reader.enterSequence()

            val attestationVersion = seqReader.readInteger()
            val attestationSecurityLevel = AttestationSecurityLevel.fromCode(seqReader.readInteger())
            val keymasterVersion = seqReader.readInteger()
            val keymasterSecurityLevel = AttestationSecurityLevel.fromCode(seqReader.readInteger())
            val attestationChallenge = seqReader.readOctetString()
            val uniqueId = seqReader.readOctetString()

            // [6] softwareEnforced (AuthorizationList)
            var softwareRootOfTrust: RootOfTrustRecord? = null
            if (seqReader.hasNext()) {
                val swReader = seqReader.enterSequence()
                softwareRootOfTrust = extractRootOfTrust(swReader)
            }

            // [7] teeEnforced (AuthorizationList)
            var teeRootOfTrust: RootOfTrustRecord? = null
            if (seqReader.hasNext()) {
                val teeReader = seqReader.enterSequence()
                teeRootOfTrust = extractRootOfTrust(teeReader)
            }

            // Fallback search in entire payload if not found in standard fields
            if (teeRootOfTrust == null && softwareRootOfTrust == null) {
                teeRootOfTrust = searchTag704Deep(bytes)
            }

            KeyAttestationRecord(
                attestationVersion = attestationVersion,
                attestationSecurityLevel = attestationSecurityLevel,
                keymasterVersion = keymasterVersion,
                keymasterSecurityLevel = keymasterSecurityLevel,
                attestationChallenge = attestationChallenge,
                uniqueId = uniqueId,
                teeRootOfTrust = teeRootOfTrust,
                softwareRootOfTrust = softwareRootOfTrust
            )
        } catch (_: Throwable) {
            // If strict sequence parse fails, try direct deep scan for Tag 704
            searchTag704Deep(bytes)?.let { rootOfTrust ->
                KeyAttestationRecord(
                    attestationVersion = 3,
                    attestationSecurityLevel = AttestationSecurityLevel.TRUSTED_ENVIRONMENT,
                    keymasterVersion = 4,
                    keymasterSecurityLevel = AttestationSecurityLevel.TRUSTED_ENVIRONMENT,
                    attestationChallenge = null,
                    uniqueId = null,
                    teeRootOfTrust = rootOfTrust,
                    softwareRootOfTrust = null
                )
            }
        }
    }

    /**
     * 从 AuthorizationList 中查找 Tag 704 (rootOfTrust)
     */
    private fun extractRootOfTrust(reader: DerReader): RootOfTrustRecord? {
        while (reader.hasNext()) {
            val tag = reader.readTag()
            val len = reader.readLength()
            val childEnd = reader.offset + len

            if (tag.tagClass == CLASS_CONTEXT_SPECIFIC && tag.tagNumber == TAG_ROOT_OF_TRUST) {
                val childReader = DerReader(reader.bytes, reader.offset, childEnd)
                reader.offset = childEnd
                return parseRootOfTrustSequence(childReader)
            } else {
                reader.offset = childEnd
            }
        }
        return null
    }

    /**
     * 解析 RootOfTrust SEQUENCE:
     * RootOfTrust ::= SEQUENCE {
     *     verifiedBootKey     OCTET_STRING,
     *     deviceLocked        BOOLEAN,
     *     verifiedBootState   VerifiedBootState (ENUMERATED),
     *     verifiedBootHash    OCTET_STRING OPTIONAL
     * }
     */
    fun parseRootOfTrustSequence(reader: DerReader): RootOfTrustRecord? {
        return try {
            // Check if wrapped in SEQUENCE (0x30)
            val itemReader = if (reader.peekTag().tagNumber == (TAG_SEQUENCE and 0x1F) ||
                reader.peekTag().tagNumber == TAG_SEQUENCE
            ) {
                reader.enterSequence()
            } else {
                reader
            }

            var verifiedBootKey: ByteArray? = null
            var deviceLocked: Boolean? = null
            var verifiedBootState: VerifiedBootState? = null
            var verifiedBootHash: ByteArray? = null

            var octetStringCount = 0

            while (itemReader.hasNext()) {
                val tag = itemReader.peekTag()
                when (tag.tagNumber) {
                    TAG_BOOLEAN -> {
                        deviceLocked = itemReader.readBoolean()
                    }
                    TAG_ENUMERATED, TAG_INTEGER -> {
                        val code = itemReader.readInteger()
                        verifiedBootState = VerifiedBootState.fromCode(code)
                    }
                    TAG_OCTET_STRING -> {
                        val bytes = itemReader.readOctetString()
                        octetStringCount++
                        if (octetStringCount == 1) {
                            verifiedBootKey = bytes
                        } else {
                            verifiedBootHash = bytes
                        }
                    }
                    else -> {
                        // Skip unknown field
                        itemReader.readTag()
                        val len = itemReader.readLength()
                        itemReader.offset += len
                    }
                }
            }

            if (deviceLocked != null && verifiedBootState != null) {
                RootOfTrustRecord(
                    verifiedBootKey = verifiedBootKey,
                    deviceLocked = deviceLocked,
                    verifiedBootState = verifiedBootState,
                    verifiedBootHash = verifiedBootHash
                )
            } else {
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * 深度扫描查找 Tag 704 (0xBF, 0x85, 0x40)，防止定制 ROM 字段位移
     */
    private fun searchTag704Deep(bytes: ByteArray): RootOfTrustRecord? {
        for (i in 0 until bytes.size - 4) {
            // 0xBF, 0x85, 0x40 is Tag [704]
            if (bytes[i] == 0xBF.toByte() && bytes[i + 1] == 0x85.toByte() && bytes[i + 2] == 0x40.toByte()) {
                try {
                    val reader = DerReader(bytes, offset = i)
                    reader.readTag() // consume 704
                    val len = reader.readLength()
                    val rotReader = DerReader(bytes, reader.offset, reader.offset + len)
                    val result = parseRootOfTrustSequence(rotReader)
                    if (result != null) return result
                } catch (_: Throwable) {
                    // continue search
                }
            }
        }
        return null
    }

    /**
     * 辅助构造器：用于生成符合规范的 DER 编码字节数组（可用于单元测试）
     */
    object DerBuilder {
        fun encodeLength(length: Int): ByteArray {
            return if (length < 128) {
                byteArrayOf(length.toByte())
            } else if (length <= 0xFF) {
                byteArrayOf(0x81.toByte(), length.toByte())
            } else if (length <= 0xFFFF) {
                byteArrayOf(
                    0x82.toByte(),
                    ((length ushr 8) and 0xFF).toByte(),
                    (length and 0xFF).toByte()
                )
            } else {
                byteArrayOf(
                    0x84.toByte(),
                    ((length ushr 24) and 0xFF).toByte(),
                    ((length ushr 16) and 0xFF).toByte(),
                    ((length ushr 8) and 0xFF).toByte(),
                    (length and 0xFF).toByte()
                )
            }
        }

        fun encodeSequence(payload: ByteArray): ByteArray {
            val lenBytes = encodeLength(payload.size)
            return byteArrayOf(0x30.toByte()) + lenBytes + payload
        }

        fun encodeInteger(value: Int): ByteArray {
            return byteArrayOf(0x02.toByte(), 0x01.toByte(), (value and 0xFF).toByte())
        }

        fun encodeEnumerated(value: Int): ByteArray {
            return byteArrayOf(0x0A.toByte(), 0x01.toByte(), (value and 0xFF).toByte())
        }

        fun encodeBoolean(value: Boolean): ByteArray {
            return byteArrayOf(0x01.toByte(), 0x01.toByte(), if (value) 0xFF.toByte() else 0x00.toByte())
        }

        fun encodeOctetString(bytes: ByteArray): ByteArray {
            val lenBytes = encodeLength(bytes.size)
            return byteArrayOf(0x04.toByte()) + lenBytes + bytes
        }

        fun encodeTag704(payload: ByteArray): ByteArray {
            // Tag 704 = 0xBF, 0x85, 0x40
            val tagBytes = byteArrayOf(0xBF.toByte(), 0x85.toByte(), 0x40.toByte())
            val lenBytes = encodeLength(payload.size)
            return tagBytes + lenBytes + payload
        }

        /**
         * 构造完整的 KeyDescription DER 字节
         */
        fun buildKeyDescription(
            attestationVersion: Int = 3,
            attestationSecurityLevel: Int = 1, // TEE
            keymasterVersion: Int = 4,
            keymasterSecurityLevel: Int = 1, // TEE
            challenge: ByteArray = byteArrayOf(1, 2, 3, 4),
            uniqueId: ByteArray = ByteArray(0),
            verifiedBootKey: ByteArray = ByteArray(32) { 0xAA.toByte() },
            deviceLocked: Boolean = true,
            verifiedBootState: Int = 0, // Verified
            verifiedBootHash: ByteArray? = ByteArray(32) { 0xBB.toByte() }
        ): ByteArray {
            // 1. Build RootOfTrust payload
            var rotPayload = encodeOctetString(verifiedBootKey) +
                    encodeBoolean(deviceLocked) +
                    encodeEnumerated(verifiedBootState)
            if (verifiedBootHash != null) {
                rotPayload += encodeOctetString(verifiedBootHash)
            }
            val rotSeq = encodeSequence(rotPayload)
            val tag704 = encodeTag704(rotSeq)

            // 2. Build teeEnforced AuthorizationList
            val teeEnforcedSeq = encodeSequence(tag704)

            // 3. softwareEnforced AuthorizationList (empty sequence)
            val swEnforcedSeq = encodeSequence(ByteArray(0))

            // 4. Assemble KeyDescription
            val keyDescPayload = encodeInteger(attestationVersion) +
                    encodeEnumerated(attestationSecurityLevel) +
                    encodeInteger(keymasterVersion) +
                    encodeEnumerated(keymasterSecurityLevel) +
                    encodeOctetString(challenge) +
                    encodeOctetString(uniqueId) +
                    swEnforcedSeq +
                    teeEnforcedSeq

            return encodeSequence(keyDescPayload)
        }
    }
}
