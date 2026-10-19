package com.security.environment

import com.security.environment.data.jni.SecurityEngineNative
import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.model.NativeDetectionItem
import org.junit.Assert.*
import org.junit.Test

class FoundationUnitTest {

    @Test
    fun testNativeDetectionItemMappingToDomain() {
        val nativeItem = NativeDetectionItem(
            id = "SEC-R1-01",
            name = "Bootloader 锁状态",
            category = 0,
            status = 0,
            evidence = "ro.boot.flash.locked=1",
            method = 2
        )

        val domainItem = nativeItem.toDomain()
        assertEquals("SEC-R1-01", domainItem.id)
        assertEquals("Bootloader 锁状态", domainItem.name)
        assertEquals(DetectionCategory.BOOTLOADER, domainItem.category)
        assertEquals(DetectionStatus.PASS, domainItem.status)
        assertEquals("ro.boot.flash.locked=1", domainItem.evidence)
        assertEquals(DetectionMethod.DIRECT_SYSCALL, domainItem.method)
    }

    @Test
    fun testDetectionStatusEnumsAndSeverities() {
        assertEquals(0, DetectionStatus.PASS.severity)
        assertEquals(1, DetectionStatus.WARN.severity)
        assertEquals(2, DetectionStatus.DANGER.severity)

        assertEquals(DetectionStatus.PASS, DetectionStatus.fromOrdinal(0))
        assertEquals(DetectionStatus.WARN, DetectionStatus.fromOrdinal(1))
        assertEquals(DetectionStatus.DANGER, DetectionStatus.fromOrdinal(2))
        // Out of bound fallback to PASS
        assertEquals(DetectionStatus.PASS, DetectionStatus.fromOrdinal(99))
    }

    @Test
    fun testDetectionCategoryEnums() {
        assertEquals(DetectionCategory.BOOTLOADER, DetectionCategory.fromOrdinal(0))
        assertEquals(DetectionCategory.ROOT, DetectionCategory.fromOrdinal(1))
        assertEquals(DetectionCategory.HOOK, DetectionCategory.fromOrdinal(2))
        assertEquals(DetectionCategory.VIRTUALIZATION, DetectionCategory.fromOrdinal(3))
        assertEquals(DetectionCategory.DEBUGGING, DetectionCategory.fromOrdinal(4))
        // Out of bound fallback to BOOTLOADER
        assertEquals(DetectionCategory.BOOTLOADER, DetectionCategory.fromOrdinal(-1))
    }

    @Test
    fun testDetectionMethodEnums() {
        assertEquals(DetectionMethod.JAVA, DetectionMethod.fromOrdinal(0))
        assertEquals(DetectionMethod.LIBC, DetectionMethod.fromOrdinal(1))
        assertEquals(DetectionMethod.DIRECT_SYSCALL, DetectionMethod.fromOrdinal(2))
        // Out of bound fallback to JAVA
        assertEquals(DetectionMethod.JAVA, DetectionMethod.fromOrdinal(10))
    }

    @Test
    fun testSecurityEngineNativeInstantiationWithoutCrashOnJvm() {
        val engine = SecurityEngineNative()
        assertNotNull(engine)
        // In pure JVM unit test without loaded Android NDK so, isNativeAvailable should be false or handled
        val available = SecurityEngineNative.isNativeAvailable()
        // Must be boolean, no uncaught exception thrown during static init
        assertTrue(available == true || available == false)
    }

    @Test
    fun testSecurityEngineNativeMethodsDeclared() {
        // Confirm all M2 native methods exist on the class via reflection
        val methods = SecurityEngineNative::class.java.declaredMethods.map { it.name }
        assertTrue(methods.contains("checkDirectSyscallAvailable"))
        assertTrue(methods.contains("checkMapsNative"))
        assertTrue(methods.contains("checkMountsNative"))
        assertTrue(methods.contains("checkStatusNative"))
        assertTrue(methods.contains("getTracerPidNative"))
        assertTrue(methods.contains("parseMapsBufferNative"))
        assertTrue(methods.contains("parseMountinfoBufferNative"))
        assertTrue(methods.contains("parseStatusBufferNative"))
        assertTrue(methods.contains("executeAllChecks"))
        assertTrue(methods.contains("executeCategoryChecks"))
        assertTrue(methods.contains("readSystemPropertyNative"))
    }
}
