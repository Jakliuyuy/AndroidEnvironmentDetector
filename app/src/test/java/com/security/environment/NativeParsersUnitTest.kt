package com.security.environment

import com.security.environment.data.model.DetectionCategory
import com.security.environment.data.model.DetectionMethod
import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.parser.NativeMapsParser
import com.security.environment.data.parser.NativeMountsParser
import com.security.environment.data.parser.NativeStatusParser
import org.junit.Assert.*
import org.junit.Test

class NativeParsersUnitTest {

    // =========================================================================
    // 1. /proc/self/maps Tests
    // =========================================================================

    @Test
    fun testCleanMapsReturnsPass() {
        val cleanMaps = """
            00400000-00452000 r-xp 00000000 08:02 173521 /system/bin/app_process64
            7f8a9b0000-7f8a9c0000 r-xp 00000000 08:01 123456 /system/lib64/libc.so
            7f8a9c0000-7f8a9d0000 r--p 00010000 08:01 123456 /system/lib64/libc.so
            7f8a9d0000-7f8a9e0000 rw-p 00020000 08:01 123456 /system/lib64/libc.so
            7f90000000-7f90040000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]
            7fff000000-7fff020000 rw-p 00000000 00:00 0 [stack]
        """.trimIndent()

        val result = NativeMapsParser.parse(cleanMaps)
        assertFalse(result.hasHookLibrary)
        assertFalse(result.hasAnonymousExecutable)
        assertEquals(0, result.suspiciousTotal)
        assertTrue(result.evidence.contains("maps_clean"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.PASS.ordinal, detectionItem.status)
        assertEquals("SEC-R3-04", detectionItem.id)
        assertEquals(DetectionCategory.HOOK.ordinal, detectionItem.category)
        assertEquals(DetectionMethod.DIRECT_SYSCALL.ordinal, detectionItem.method)
    }

    @Test
    fun testFridaAgentInMapsTriggersDanger() {
        val fridaMaps = """
            00400000-00452000 r-xp 00000000 08:02 173521 /system/bin/app_process64
            7f8a000000-7f8a100000 r-xp 00000000 08:01 999999 /data/local/tmp/frida-agent-64.so
            7f8a100000-7f8a110000 rw-p 00100000 08:01 999999 /data/local/tmp/frida-agent-64.so
        """.trimIndent()

        val result = NativeMapsParser.parse(fridaMaps)
        assertTrue(result.hasHookLibrary)
        assertTrue(result.hookLibraryNames.contains("frida-agent"))
        assertTrue(result.suspiciousTotal >= 1)

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
        assertTrue(detectionItem.evidence.contains("frida-agent"))
    }

    @Test
    fun testLSPosedAndXposedLibrariesTriggerDanger() {
        val lsposedMaps = """
            7f8b000000-7f8b050000 r-xp 00000000 08:01 888888 /data/adb/lspd/liblspd.so
            7f8b050000-7f8b060000 r--p 00000000 08:01 777777 /data/adb/lspd/XposedBridge.jar
        """.trimIndent()

        val result = NativeMapsParser.parse(lsposedMaps)
        assertTrue(result.hasHookLibrary)
        assertTrue(result.hookLibraryNames.contains("liblspd.so"))
        assertTrue(result.hookLibraryNames.contains("XposedBridge.jar"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
    }

    @Test
    fun testAnonymousExecutableMemoryTriggersDanger() {
        // Line with r-xp and completely empty pathname (not whitelisted)
        val anonMaps = """
            00400000-00452000 r-xp 00000000 08:02 173521 /system/bin/app_process64
            7f8a9c0000-7f8a9d0000 r-xp 00000000 00:00 0
        """.trimIndent()

        val result = NativeMapsParser.parse(anonMaps)
        assertTrue(result.hasAnonymousExecutable)
        assertEquals(1, result.anonymousExecutableCount)
        assertTrue(result.sampleAnonymousRegion.contains("7f8a9c0000-7f8a9d0000"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
        assertTrue(detectionItem.evidence.contains("anon_rx_count=1"))
    }

    @Test
    fun testWhitelistedAnonymousJitExecutablesDoNotTriggerDanger() {
        val jitMaps = """
            7f90000000-7f90040000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]
            7f90040000-7f90080000 r-xp 00000000 00:00 0 [anon:dalvik-data-code-cache]
            7f90080000-7f900c0000 r-xp 00000000 00:00 0 [anon:dalvik-zygote-jit-code-cache]
            7fff000000-7fff020000 r-xp 00000000 00:00 0 [vdso]
        """.trimIndent()

        val result = NativeMapsParser.parse(jitMaps)
        assertFalse(result.hasAnonymousExecutable)
        assertEquals(0, result.anonymousExecutableCount)

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.PASS.ordinal, detectionItem.status)
    }

    // =========================================================================
    // 2. /proc/self/mountinfo Tests
    // =========================================================================

    @Test
    fun testCleanMountinfoReturnsPass() {
        val cleanMountinfo = """
            36 21 0:31 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw,seclabel
            120 25 254:0 / /system ro,nodev,noatime shared:1 - erofs /dev/block/dm-0 ro
            121 25 254:1 / /vendor ro,nodev,noatime shared:2 - ext4 /dev/block/dm-1 ro
            122 25 254:2 / /product ro,nodev,noatime shared:3 - f2fs /dev/block/dm-2 ro
        """.trimIndent()

        val result = NativeMountsParser.parse(cleanMountinfo)
        assertFalse(result.hasMagicMount)
        assertFalse(result.hasKernelSuOrApatch)
        assertEquals(0, result.anomaliesCount)
        assertTrue(result.evidence.contains("mountinfo_clean"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.PASS.ordinal, detectionItem.status)
        assertEquals("SEC-R2-02", detectionItem.id)
        assertEquals(DetectionCategory.ROOT.ordinal, detectionItem.category)
        assertEquals(DetectionMethod.DIRECT_SYSCALL.ordinal, detectionItem.method)
    }

    @Test
    fun testMagiskMagicMountInversionDetected() {
        // Protected /system mounted as tmpfs or overlay
        val magiskMountinfo = """
            36 21 0:31 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw,seclabel
            120 25 0:45 / /system ro,relatime shared:1 - tmpfs tmpfs rw,seclabel
            121 25 0:46 / /vendor ro,relatime shared:2 - overlay overlay ro,lowerdir=/system
        """.trimIndent()

        val result = NativeMountsParser.parse(magiskMountinfo)
        assertTrue(result.hasMagicMount)
        assertTrue(result.magicMountPoints.contains("/system(tmpfs)"))
        assertTrue(result.magicMountPoints.contains("/vendor(overlay)"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
        assertTrue(detectionItem.evidence.contains("magic_mount_inversion"))
    }

    @Test
    fun testKernelSuAndApatchMountSignaturesDetected() {
        val ksuMountinfo = """
            130 25 0:50 / /data/adb/ksu/modules rw,relatime shared:1 - ext4 /dev/block/bootdevice rw
            131 25 0:51 / /system ro,relatime shared:2 - overlay overlay ro,lowerdir=/data/adb/ap/bin
        """.trimIndent()

        val result = NativeMountsParser.parse(ksuMountinfo)
        assertTrue(result.hasKernelSuOrApatch)
        assertTrue(result.rootSignatures.contains("/data/adb/ksu"))
        assertTrue(result.rootSignatures.contains("/data/adb/ap"))

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
        assertTrue(detectionItem.evidence.contains("root_signatures"))
    }

    @Test
    fun testProcMountsLegacyFormatParsing() {
        // Format: [src] [mount_point] [fstype] [flags] ...
        val procMounts = """
            rootfs / rootfs ro 0 0
            tmpfs /system tmpfs rw,seclabel 0 0
            /dev/block/dm-0 /vendor ext4 ro 0 0
        """.trimIndent()

        val result = NativeMountsParser.parse(procMounts)
        assertTrue(result.hasMagicMount)
        assertTrue(result.magicMountPoints.contains("/system(tmpfs)"))

        val item = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, item.status)
    }

    // =========================================================================
    // 3. /proc/self/status TracerPid Tests
    // =========================================================================

    @Test
    fun testCleanStatusReturnsTracerPidZeroAndPass() {
        val cleanStatus = """
            Name:	com.sec.app
            Umask:	0077
            State:	S (sleeping)
            Tgid:	12345
            Ngid:	0
            Pid:	12345
            PPid:	1000
            TracerPid:	0
            Uid:	10123	10123	10123	10123
        """.trimIndent()

        val result = NativeStatusParser.parse(cleanStatus)
        assertEquals(0, result.tracerPid)
        assertFalse(result.isTraced)
        assertEquals("S (sleeping)", result.state)

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.PASS.ordinal, detectionItem.status)
        assertEquals("SEC-R4-04", detectionItem.id)
        assertEquals(DetectionCategory.DEBUGGING.ordinal, detectionItem.category)
        assertEquals(DetectionMethod.DIRECT_SYSCALL.ordinal, detectionItem.method)
    }

    @Test
    fun testTracerPidGreaterThanZeroTriggersDanger() {
        val tracedStatus = """
            Name:	com.sec.app
            State:	t (tracing stop)
            Pid:	12345
            TracerPid:	9876
        """.trimIndent()

        val result = NativeStatusParser.parse(tracedStatus)
        assertEquals(9876, result.tracerPid)
        assertTrue(result.isTraced)
        assertEquals("t (tracing stop)", result.state)

        val detectionItem = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.DANGER.ordinal, detectionItem.status)
        assertTrue(detectionItem.evidence.contains("TracerPid=9876"))
    }

    // =========================================================================
    // 4. Boundary and Malformed Input Tests
    // =========================================================================

    @Test
    fun testEmptyInputHandling() {
        val mapsRes = NativeMapsParser.parse("")
        assertFalse(mapsRes.hasHookLibrary)
        assertFalse(mapsRes.hasAnonymousExecutable)
        assertEquals("empty_maps", mapsRes.evidence)

        val mountsRes = NativeMountsParser.parse("   \n\n  \t  ")
        assertFalse(mountsRes.hasMagicMount)
        assertFalse(mountsRes.hasKernelSuOrApatch)
        assertEquals("empty_mountinfo", mountsRes.evidence)

        val statusRes = NativeStatusParser.parse("")
        assertEquals(0, statusRes.tracerPid)
        assertFalse(statusRes.isTraced)
        assertEquals("no_status_data", statusRes.evidence)
    }

    @Test
    fun testCorruptAndMalformedLines() {
        val malformedMaps = """
            broken_line_without_spaces
            12345 only_two_tokens
            7f8a00-7f8a10 r-xp 0 0 0
            # Just a comment
            ---
        """.trimIndent()

        val mapsRes = NativeMapsParser.parse(malformedMaps)
        assertNotNull(mapsRes)

        val malformedMounts = """
            # comment only
            bad line with incomplete mountinfo tokens
            1 2 3
        """.trimIndent()

        val mountsRes = NativeMountsParser.parse(malformedMounts)
        assertNotNull(mountsRes)

        val malformedStatus = """
            TracerPid: not_a_number
            State:
        """.trimIndent()

        val statusRes = NativeStatusParser.parse(malformedStatus)
        assertEquals(-1, statusRes.tracerPid)
        assertFalse(statusRes.isTraced)
    }

    @Test
    fun testExtremelyLongLinesDoNotCrash() {
        val longPath = "/system/lib/" + "a".repeat(4000) + ".so"
        val longMapLine = "7f8a000000-7f8a100000 r-xp 00000000 08:01 1234 $longPath"
        val mapsRes = NativeMapsParser.parse(longMapLine)
        assertFalse(mapsRes.hasHookLibrary)

        val longMountLine = "120 25 254:0 / /system ro,nodev shared:1 - ext4 /dev/block/" + "b".repeat(4000)
        val mountsRes = NativeMountsParser.parse(longMountLine)
        assertFalse(mountsRes.hasMagicMount)
    }
}
