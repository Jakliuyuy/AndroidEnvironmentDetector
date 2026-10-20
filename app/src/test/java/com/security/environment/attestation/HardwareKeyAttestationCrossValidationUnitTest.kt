package com.security.environment.attestation

import com.security.environment.MockSystemEnvironment
import com.security.environment.data.model.DetectionStatus
import com.security.environment.domain.attestation.AttestationSecurityLevel
import com.security.environment.domain.attestation.KeyAttestationRecord
import com.security.environment.domain.attestation.KeyAttestationResult
import com.security.environment.domain.attestation.KeyStoreAttestationSource
import com.security.environment.domain.attestation.RootOfTrustRecord
import com.security.environment.domain.attestation.VerifiedBootState
import com.security.environment.domain.detectors.BootloaderDetector
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class HardwareKeyAttestationCrossValidationUnitTest {

    private lateinit var mockEnv: MockSystemEnvironment
    private lateinit var detector: BootloaderDetector

    @Before
    fun setUp() {
        mockEnv = MockSystemEnvironment()
        detector = BootloaderDetector(mockEnv)
    }

    private fun createMockSuccessAttestation(
        locked: Boolean,
        bootState: VerifiedBootState,
        isHardwareBacked: Boolean = true
    ): KeyAttestationResult.Success {
        val rootOfTrust = RootOfTrustRecord(
            verifiedBootKey = ByteArray(32) { 0x11 },
            deviceLocked = locked,
            verifiedBootState = bootState,
            verifiedBootHash = ByteArray(32) { 0x22 }
        )
        val record = KeyAttestationRecord(
            attestationVersion = 3,
            attestationSecurityLevel = if (isHardwareBacked) AttestationSecurityLevel.TRUSTED_ENVIRONMENT else AttestationSecurityLevel.SOFTWARE,
            keymasterVersion = 4,
            keymasterSecurityLevel = if (isHardwareBacked) AttestationSecurityLevel.TRUSTED_ENVIRONMENT else AttestationSecurityLevel.SOFTWARE,
            attestationChallenge = ByteArray(16),
            uniqueId = ByteArray(0),
            teeRootOfTrust = if (isHardwareBacked) rootOfTrust else null,
            softwareRootOfTrust = if (!isHardwareBacked) rootOfTrust else null
        )
        return KeyAttestationResult.Success(
            record = record,
            isHardwareBacked = isHardwareBacked
        )
    }

    @Test
    fun testMagiskResetpropBootloaderLockSpoofingDetected() {
        // Attack scenario: Magisk resetprop forces ro.boot.flash.locked = 1
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.locked"] = "1"
        mockEnv.properties["ro.secure"] = "1"

        // But hardware KeyStore attestation reveals deviceLocked = false (Unlocked!)
        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = false,
            bootState = VerifiedBootState.UNVERIFIED
        )

        val item = detector.checkBootloaderLock()

        // Must trigger DANGER and detect spoofing!
        assertEquals("SEC-R1-01", item.id)
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue("Evidence should report spoofing detection", item.evidence.contains("Spoofing Detected"))
        assertTrue("Evidence should reference hw_locked=false", item.evidence.contains("hw_locked=false"))
        assertTrue("Description should point out spoofing", item.description.contains("伪造"))
    }

    @Test
    fun testMagiskResetpropVerifiedBootStateSpoofingDetected() {
        // Attack scenario: Magisk resets ro.boot.verifiedbootstate to green
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"

        // But hardware attestation reveals verifiedBootState = UNVERIFIED (Orange state)
        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = true,
            bootState = VerifiedBootState.UNVERIFIED
        )

        val item = detector.checkVerifiedBootState()

        assertEquals("SEC-R1-02", item.id)
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue("Evidence should report AVB spoofing detection", item.evidence.contains("Spoofing Detected"))
        assertTrue("Evidence should note hw_state=UNVERIFIED", item.evidence.contains("hw_state=UNVERIFIED"))
        assertTrue("Description should highlight AVB spoofing", item.description.contains("伪造"))
    }

    @Test
    fun testSelfSignedFirmwareSpoofingGreenStateDetected() {
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"

        // Hardware attestation indicates custom user root of trust (Yellow / SelfSigned)
        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = true,
            bootState = VerifiedBootState.SELF_SIGNED
        )

        val item = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.evidence.contains("Spoofing Detected"))
        assertTrue(item.evidence.contains("SELF_SIGNED"))
    }

    @Test
    fun testGenuineDeviceWithConsistentLockedAndVerifiedStatusPasses() {
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"

        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = true,
            bootState = VerifiedBootState.VERIFIED
        )

        val lockItem = detector.checkBootloaderLock()
        assertEquals(DetectionStatus.PASS, lockItem.status)
        assertTrue(lockItem.evidence.contains("hw_locked=true (TEE)"))

        val avbItem = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.PASS, avbItem.status)
        assertTrue(avbItem.evidence.contains("hw_state=VERIFIED (TEE)"))
    }

    @Test
    fun testHardwareAttestationUnavailableGracefulFallback() {
        // On emulator or older phone without TEE KeyStore attestation support
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"
        mockEnv.mockAttestationResult = KeyAttestationResult.Unavailable("TEE missing in emulator")

        val lockItem = detector.checkBootloaderLock()
        assertEquals(DetectionStatus.PASS, lockItem.status)
        assertFalse(lockItem.evidence.contains("Spoofing Detected"))

        val avbItem = detector.checkVerifiedBootState()
        assertEquals(DetectionStatus.PASS, avbItem.status)
        assertFalse(avbItem.evidence.contains("Spoofing Detected"))
    }

    @Test
    fun testStandaloneHardwareAttestationCheckPassAndDanger() {
        // 1. Pass case
        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = true,
            bootState = VerifiedBootState.VERIFIED
        )
        var item = detector.checkHardwareKeyAttestation()
        assertEquals("SEC-R1-06", item.id)
        assertEquals(DetectionStatus.PASS, item.status)
        assertTrue(item.description.contains("通过"))

        // 2. Danger case
        mockEnv.mockAttestationResult = createMockSuccessAttestation(
            locked = false,
            bootState = VerifiedBootState.UNVERIFIED
        )
        item = detector.checkHardwareKeyAttestation()
        assertEquals(DetectionStatus.DANGER, item.status)
        assertTrue(item.description.contains("报警"))

        // 3. Unavailable case: graceful pass without false alarm
        mockEnv.mockAttestationResult = KeyAttestationResult.Unavailable()
        item = detector.checkHardwareKeyAttestation()
        assertEquals(DetectionStatus.PASS, item.status)
        assertTrue(item.evidence.contains("UNAVAILABLE"))
    }

    @Test
    fun testKeyStoreAttestationSourceGracefulHandlingInJvm() {
        // KeyStoreAttestationSource invoked on JVM should safely return Unavailable instead of crashing
        val source = KeyStoreAttestationSource()
        val result = source.getAttestationResult()
        assertTrue(
            "In headless JVM, should return Unavailable or Failed gracefully",
            result is KeyAttestationResult.Unavailable || result is KeyAttestationResult.Failed
        )
    }

    @Test
    fun testDetectMethodCompatibilityWithOptionalHardwareAttestation() {
        mockEnv.properties["ro.boot.flash.locked"] = "1"
        mockEnv.properties["ro.boot.verifiedbootstate"] = "green"
        mockEnv.properties["ro.boot.vbmeta.device_state"] = "locked"
        mockEnv.properties["ro.build.tags"] = "release-keys"
        mockEnv.properties["ro.build.type"] = "user"
        mockEnv.files["/sys/fs/selinux/enforce"] = "1"
        mockEnv.files["/proc/mounts"] = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0"
        mockEnv.files["/proc/self/attr/current"] = "u:r:untrusted_app:s0"

        // Default detect() returns exactly 5 items
        val defaultList = detector.detect()
        assertEquals(5, defaultList.size)

        // With includeHardwareAttestation = true returns 6 items
        val extendedList = detector.detect(includeHardwareAttestation = true)
        assertEquals(6, extendedList.size)
        assertEquals("SEC-R1-06", extendedList.last().id)
    }
}
