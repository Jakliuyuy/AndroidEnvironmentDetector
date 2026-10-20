package com.security.environment.attestation

import com.security.environment.domain.attestation.AttestationSecurityLevel
import com.security.environment.domain.attestation.KeyAttestationParser
import com.security.environment.domain.attestation.VerifiedBootState
import org.junit.Assert.*
import org.junit.Test

class KeyAttestationParserUnitTest {

    @Test
    fun testParseValidVerifiedAndLockedRecord() {
        val bootKey = ByteArray(32) { (it + 1).toByte() }
        val bootHash = ByteArray(32) { (0xFF - it).toByte() }
        val challenge = byteArrayOf(0x10, 0x20, 0x30, 0x40)

        val derBytes = KeyAttestationParser.DerBuilder.buildKeyDescription(
            attestationVersion = 3,
            attestationSecurityLevel = 1, // TEE
            keymasterVersion = 4,
            keymasterSecurityLevel = 1, // TEE
            challenge = challenge,
            verifiedBootKey = bootKey,
            deviceLocked = true,
            verifiedBootState = 0, // Verified
            verifiedBootHash = bootHash
        )

        // Test direct KeyDescription parse
        val record = KeyAttestationParser.parseKeyDescription(derBytes)
        assertNotNull("Record should not be null", record)
        assertEquals(3, record!!.attestationVersion)
        assertEquals(AttestationSecurityLevel.TRUSTED_ENVIRONMENT, record.attestationSecurityLevel)
        assertEquals(4, record.keymasterVersion)
        assertEquals(AttestationSecurityLevel.TRUSTED_ENVIRONMENT, record.keymasterSecurityLevel)
        assertArrayEquals(challenge, record.attestationChallenge)

        val rootOfTrust = record.rootOfTrust
        assertNotNull("Root of trust should be present", rootOfTrust)
        assertTrue("Device should be locked", rootOfTrust!!.deviceLocked)
        assertEquals(VerifiedBootState.VERIFIED, rootOfTrust.verifiedBootState)
        assertArrayEquals(bootKey, rootOfTrust.verifiedBootKey)
        assertArrayEquals(bootHash, rootOfTrust.verifiedBootHash)
        assertTrue(record.isHardwareBacked)
    }

    @Test
    fun testParseUnverifiedAndUnlockedRecord() {
        val derBytes = KeyAttestationParser.DerBuilder.buildKeyDescription(
            attestationVersion = 2,
            attestationSecurityLevel = 1,
            deviceLocked = false,
            verifiedBootState = 2 // Unverified (Unlocked bootloader)
        )

        val record = KeyAttestationParser.parseKeyDescription(derBytes)
        assertNotNull(record)
        assertFalse("Device should be unlocked", record!!.isDeviceLocked!!)
        assertEquals(VerifiedBootState.UNVERIFIED, record.verifiedBootState)
    }

    @Test
    fun testParseSelfSignedRecord() {
        val derBytes = KeyAttestationParser.DerBuilder.buildKeyDescription(
            deviceLocked = true,
            verifiedBootState = 1 // SelfSigned
        )

        val record = KeyAttestationParser.parseKeyDescription(derBytes)
        assertNotNull(record)
        assertTrue(record!!.isDeviceLocked!!)
        assertEquals(VerifiedBootState.SELF_SIGNED, record.verifiedBootState)
    }

    @Test
    fun testParseFailedRecord() {
        val derBytes = KeyAttestationParser.DerBuilder.buildKeyDescription(
            deviceLocked = false,
            verifiedBootState = 3 // Failed
        )

        val record = KeyAttestationParser.parseKeyDescription(derBytes)
        assertNotNull(record)
        assertFalse(record!!.isDeviceLocked!!)
        assertEquals(VerifiedBootState.FAILED, record.verifiedBootState)
    }

    @Test
    fun testOctetStringWrappedExtensionParsing() {
        val rawDer = KeyAttestationParser.DerBuilder.buildKeyDescription(
            deviceLocked = true,
            verifiedBootState = 0
        )
        // Wrap with outer OCTET STRING (0x04) as returned by X509Certificate.getExtensionValue
        val wrapped = KeyAttestationParser.DerBuilder.encodeOctetString(rawDer)

        val record = KeyAttestationParser.parseFromExtension(wrapped)
        assertNotNull("Should successfully unwrap OCTET STRING and parse KeyDescription", record)
        assertTrue(record!!.isDeviceLocked!!)
        assertEquals(VerifiedBootState.VERIFIED, record.verifiedBootState)
    }

    @Test
    fun testMultiByteTag704Decoding() {
        // Tag 704 in DER: 0xBF, 0x85, 0x40
        val payload = KeyAttestationParser.DerBuilder.encodeBoolean(true) +
                KeyAttestationParser.DerBuilder.encodeEnumerated(0)
        val seq = KeyAttestationParser.DerBuilder.encodeSequence(payload)
        val tagged = KeyAttestationParser.DerBuilder.encodeTag704(seq)

        val reader = KeyAttestationParser.DerReader(tagged)
        val tag = reader.readTag()

        assertEquals(2, tag.tagClass) // Context-specific
        assertTrue(tag.isConstructed)
        assertEquals(704, tag.tagNumber)

        val length = reader.readLength()
        assertEquals(seq.size, length)
    }

    @Test
    fun testMalformedDerHandlingReturnsNullWithoutCrash() {
        // Empty bytes
        assertNull(KeyAttestationParser.parseFromExtension(ByteArray(0)))
        assertNull(KeyAttestationParser.parseKeyDescription(ByteArray(0)))

        // Truncated header
        assertNull(KeyAttestationParser.parseKeyDescription(byteArrayOf(0x30, 0x50, 0x02)))

        // Invalid length
        assertNull(KeyAttestationParser.parseKeyDescription(byteArrayOf(0x30, 0x84.toByte(), 0x7F, 0x7F, 0x7F, 0x7F)))

        // Random garbage bytes
        val garbage = ByteArray(64) { (it * 37 % 256).toByte() }
        assertNull(KeyAttestationParser.parseKeyDescription(garbage))
    }
}
