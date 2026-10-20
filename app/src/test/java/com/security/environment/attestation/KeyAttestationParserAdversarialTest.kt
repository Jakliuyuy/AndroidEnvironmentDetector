package com.security.environment.attestation

import com.security.environment.domain.attestation.AttestationSecurityLevel
import com.security.environment.domain.attestation.KeyAttestationParser
import com.security.environment.domain.attestation.VerifiedBootState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Random

/**
 * 最终经验挑战者 (Final Empirical Challenger) - 对抗性 ASN.1 DER 解析器压力测试套件
 * 
 * 专门针对 KeyAttestationParser 实施畸变数据、边界破坏、极端溢出与突变模糊测试 (Fuzzing)
 */
class KeyAttestationParserAdversarialTest {

    private fun getValidDer(): ByteArray {
        return KeyAttestationParser.DerBuilder.buildKeyDescription(
            attestationVersion = 3,
            attestationSecurityLevel = 1,
            keymasterVersion = 4,
            keymasterSecurityLevel = 1,
            challenge = byteArrayOf(0x11, 0x22, 0x33, 0x44),
            uniqueId = byteArrayOf(0x01, 0x02),
            verifiedBootKey = ByteArray(32) { 0x5A.toByte() },
            deviceLocked = true,
            verifiedBootState = 0,
            verifiedBootHash = ByteArray(32) { 0x6B.toByte() }
        )
    }

    @Test
    fun testProgressiveTruncationResilience() {
        // 对完整有效 DER 从 0 到 length-1 逐字节截断，测试所有截断前缀
        val valid = getValidDer()
        assertTrue("Valid DER should be non-empty", valid.isNotEmpty())

        for (cut in 0 until valid.size) {
            val truncated = valid.copyOfRange(0, cut)
            try {
                // Must gracefully return null or valid record, NEVER throw unhandled exception
                KeyAttestationParser.parseKeyDescription(truncated)
                KeyAttestationParser.parseFromExtension(truncated)
            } catch (t: Throwable) {
                fail("Truncated DER at length $cut threw unexpected exception: ${t.javaClass.name}: ${t.message}")
            }
        }
    }

    @Test
    fun testExtremeLengthFieldMutations() {
        val testCases = listOf(
            // Indefinite length 0x80 (forbidden in DER)
            byteArrayOf(0x30, 0x80.toByte(), 0x02, 0x01, 0x01),
            // Length requires 5 bytes (0x85), exceeding 4-byte max
            byteArrayOf(0x30, 0x85.toByte(), 0x01, 0x00, 0x00, 0x00, 0x01, 0x00),
            // Integer overflow: length = 0x7FFFFFFF (positive huge)
            byteArrayOf(0x30, 0x84.toByte(), 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x01),
            // Negative length: length = 0x80000000 (signed negative)
            byteArrayOf(0x30, 0x84.toByte(), 0x80.toByte(), 0x00, 0x00, 0x00),
            // All 0xFF: 0xFFFFFFFF (-1 signed)
            byteArrayOf(0x30, 0x84.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            // Multi-byte length prefix 0x80 with 0 length bytes
            byteArrayOf(0x30, 0x80.toByte())
        )

        for ((index, payload) in testCases.withIndex()) {
            try {
                val res1 = KeyAttestationParser.parseKeyDescription(payload)
                val res2 = KeyAttestationParser.parseFromExtension(payload)
                assertNull("Corrupted length payload #$index should return null", res1)
                assertNull("Corrupted length payload #$index in extension should return null", res2)
            } catch (t: Throwable) {
                fail("Payload #$index with corrupted length threw unhandled exception: ${t.javaClass.name}: ${t.message}")
            }
        }
    }

    @Test
    fun testInfiniteMultiByteTagBomb() {
        // Tag with 0x1F and 1000 high-bit 0xFF bytes never terminating
        val tagBomb = ByteArray(1000) { 0xFF.toByte() }
        tagBomb[0] = 0x1F // Multi-byte tag marker
        try {
            val res = KeyAttestationParser.parseKeyDescription(tagBomb)
            assertNull("Tag bomb should return null", res)
        } catch (t: Throwable) {
            fail("Infinite multi-byte tag bomb caused crash: ${t.javaClass.name}: ${t.message}")
        }
    }

    @Test
    fun testTag704DeepSearchBombResilience() {
        // Repeated Tag 704 headers (0xBF, 0x85, 0x40) to test deep scanner performance and safety
        val bomb = ByteArray(4096)
        for (i in 0 until bomb.size - 3 step 4) {
            bomb[i] = 0xBF.toByte()
            bomb[i + 1] = 0x85.toByte()
            bomb[i + 2] = 0x40.toByte()
            bomb[i + 3] = (i % 250).toByte() // random length
        }
        try {
            val res = KeyAttestationParser.parseKeyDescription(bomb)
            assertNull("Repeated Tag 704 header bomb should return null safely", res)
        } catch (t: Throwable) {
            fail("Tag 704 deep search bomb crashed: ${t.javaClass.name}: ${t.message}")
        }
    }

    @Test
    fun testDeepNestingRecursionBomb() {
        // 500 layers of nested SEQUENCE (0x30, 0x02, ...)
        val nested = ByteArray(1000)
        for (i in 0 until 500) {
            nested[i * 2] = 0x30.toByte()
            nested[i * 2 + 1] = (1000 - i * 2 - 2).coerceAtMost(127).toByte()
        }
        try {
            val res = KeyAttestationParser.parseKeyDescription(nested)
            assertNull("Deeply nested sequence bomb should return null", res)
        } catch (t: Throwable) {
            fail("Deeply nested SEQUENCE bomb threw exception: ${t.javaClass.name}: ${t.message}")
        }
    }

    @Test
    fun testTypeConfusionInRootOfTrust() {
        // RootOfTrust with INTEGER instead of OCTET STRING for verifiedBootKey
        val bogusRot = KeyAttestationParser.DerBuilder.encodeInteger(99999) +
                KeyAttestationParser.DerBuilder.encodeBoolean(true) +
                KeyAttestationParser.DerBuilder.encodeEnumerated(0)
        val seq = KeyAttestationParser.DerBuilder.encodeSequence(bogusRot)
        val tag704 = KeyAttestationParser.DerBuilder.encodeTag704(seq)
        val payload = KeyAttestationParser.DerBuilder.encodeSequence(
            KeyAttestationParser.DerBuilder.encodeInteger(3) +
            KeyAttestationParser.DerBuilder.encodeEnumerated(1) +
            KeyAttestationParser.DerBuilder.encodeInteger(4) +
            KeyAttestationParser.DerBuilder.encodeEnumerated(1) +
            KeyAttestationParser.DerBuilder.encodeOctetString(byteArrayOf(1, 2)) +
            KeyAttestationParser.DerBuilder.encodeOctetString(byteArrayOf()) +
            KeyAttestationParser.DerBuilder.encodeSequence(byteArrayOf()) +
            KeyAttestationParser.DerBuilder.encodeSequence(tag704)
        )

        try {
            val record = KeyAttestationParser.parseKeyDescription(payload)
            // Even if parsed, it shouldn't crash
            if (record != null) {
                // If parsed, rootOfTrust should handle missing key gracefully
                assertTrue(record.rootOfTrust?.deviceLocked == true)
            }
        } catch (t: Throwable) {
            fail("Type confusion in RootOfTrust threw exception: ${t.javaClass.name}: ${t.message}")
        }
    }

    @Test
    fun testFuzzingRandomBitFlipsAndMutations() {
        // 5,000 iterations of random bit flips, byte mutations, insertions, deletions
        val base = getValidDer()
        val rng = Random(42)

        var crashCount = 0
        val iterations = 5000

        for (i in 0 until iterations) {
            val mutated = base.clone()
            val mutationType = rng.nextInt(5)

            when (mutationType) {
                0 -> {
                    // Single bit flip
                    val byteIdx = rng.nextInt(mutated.size)
                    val bitIdx = rng.nextInt(8)
                    mutated[byteIdx] = (mutated[byteIdx].toInt() xor (1 shl bitIdx)).toByte()
                }
                1 -> {
                    // Multi-byte corruption
                    val start = rng.nextInt(mutated.size)
                    val len = rng.nextInt(mutated.size - start)
                    for (k in 0 until len) {
                        mutated[start + k] = rng.nextInt(256).toByte()
                    }
                }
                2 -> {
                    // Zero out a chunk
                    val start = rng.nextInt(mutated.size)
                    val len = rng.nextInt(mutated.size - start)
                    for (k in 0 until len) {
                        mutated[start + k] = 0
                    }
                }
                3 -> {
                    // Fill with 0xFF
                    val start = rng.nextInt(mutated.size)
                    val len = rng.nextInt(mutated.size - start)
                    for (k in 0 until len) {
                        mutated[start + k] = 0xFF.toByte()
                    }
                }
                4 -> {
                    // Invert all bytes in a window
                    val start = rng.nextInt(mutated.size)
                    val len = rng.nextInt(mutated.size - start)
                    for (k in 0 until len) {
                        mutated[start + k] = (mutated[start + k].toInt().inv()).toByte()
                    }
                }
            }

            try {
                KeyAttestationParser.parseKeyDescription(mutated)
                KeyAttestationParser.parseFromExtension(mutated)
            } catch (t: Throwable) {
                crashCount++
            }
        }

        assertEquals("Fuzzing encountered $crashCount crashes across $iterations adversarial mutations", 0, crashCount)
    }
}
