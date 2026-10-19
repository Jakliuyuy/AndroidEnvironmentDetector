package com.security.environment

import com.security.environment.data.model.DetectionStatus
import com.security.environment.data.parser.NativeMapsParser
import com.security.environment.data.parser.NativeMountsParser
import com.security.environment.data.parser.NativeStatusParser
import org.junit.Assert.*
import org.junit.Test

class ExtremeEdgeCasesUnitTest {

    // =========================================================================
    // 1. Extreme TracerPid Tests
    // =========================================================================

    @Test
    fun testTracerPidExtremeOverflow() {
        val hugeNumberStatus = """
            Name:	com.test.app
            State:	R (running)
            TracerPid:	99999999999999999999999999999999
        """.trimIndent()

        val result = NativeStatusParser.parse(hugeNumberStatus)
        // valStr.toIntOrNull() returns null -> tracerPid is -1
        assertEquals(-1, result.tracerPid)
        assertFalse(result.isTraced)
        val item = result.toNativeDetectionItem()
        assertEquals(DetectionStatus.PASS.ordinal, item.status)
    }

    @Test
    fun testTracerPidNegativeValue() {
        val negativeStatus = """
            Name:	com.test.app
            TracerPid:	-1
            State:	S
        """.trimIndent()

        val result = NativeStatusParser.parse(negativeStatus)
        assertEquals(-1, result.tracerPid)
        assertFalse(result.isTraced)
    }

    @Test
    fun testTracerPidMultipleDeclarations() {
        // Last one overrides
        val multiStatus = """
            TracerPid:	0
            TracerPid:	4567
        """.trimIndent()

        val result = NativeStatusParser.parse(multiStatus)
        assertEquals(4567, result.tracerPid)
        assertTrue(result.isTraced)
    }

    @Test
    fun testTracerPidTabAndWhitespaceHandling() {
        val tabStatus = "TracerPid:\t\t\t8888\t\r\nState:\t t (tracing stop)"
        val result = NativeStatusParser.parse(tabStatus)
        assertEquals(8888, result.tracerPid)
        assertTrue(result.isTraced)
    }

    // =========================================================================
    // 2. Extreme Maps Tests
    // =========================================================================

    @Test
    fun testMapsWithIncompleteTokensDoNotCrash() {
        val incompleteMaps = """
            7f8a00
            7f8a00-7f8a10 r-xp
            7f8a00-7f8a10 r-xp 00000000
            7f8a00-7f8a10 r-xp 00000000 08:01
            7f8a00-7f8a10 r-xp 00000000 08:01 1234
        """.trimIndent()

        val result = NativeMapsParser.parse(incompleteMaps)
        assertNotNull(result)
        // The last line has 5 tokens with 'x' permission and empty pathname -> anon executable
        assertTrue(result.hasAnonymousExecutable)
    }

    @Test
    fun testMapsWithMultipleSpacesInPath() {
        val spacesMaps = """
            7f8a000000-7f8a100000 r-xp 00000000 08:01 123456 /data/local/tmp/spaced directory/frida-agent-64.so
        """.trimIndent()

        val result = NativeMapsParser.parse(spacesMaps)
        assertTrue(result.hasHookLibrary)
        assertTrue(result.hookLibraryNames.contains("frida-agent"))
    }

    @Test
    fun testMapsWithNonWhitelistedAnonNameFlagged() {
        val customAnon = """
            7f8a000000-7f8a100000 r-xp 00000000 00:00 0 [anon:my_hook_shellcode]
        """.trimIndent()

        val result = NativeMapsParser.parse(customAnon)
        assertTrue(result.hasAnonymousExecutable)
        assertEquals(1, result.anonymousExecutableCount)
    }

    @Test
    fun testMapsWith10000LinesPerformance() {
        val sb = StringBuilder()
        for (i in 0 until 5000) {
            sb.append("7f${i.toString(16).padStart(8, '0')}-7f${(i+1).toString(16).padStart(8, '0')} r--p 00000000 08:01 1234 /system/framework/framework.jar\n")
        }
        sb.append("7fff000000-7fff100000 r-xp 00000000 08:01 9999 /data/adb/lspd/liblspd.so\n")

        val result = NativeMapsParser.parse(sb.toString())
        assertTrue(result.hasHookLibrary)
        assertTrue(result.hookLibraryNames.contains("liblspd.so"))
    }

    // =========================================================================
    // 3. Extreme Mountinfo Tests
    // =========================================================================

    @Test
    fun testMountinfoTruncatedAtHyphen() {
        val truncatedMountinfo = """
            120 25 254:0 / /system ro,nodev shared:1 -
            121 25 254:1 / /vendor ro,nodev shared:2
        """.trimIndent()

        val result = NativeMountsParser.parse(truncatedMountinfo)
        assertFalse(result.hasMagicMount)
        assertNotNull(result.evidence)
    }

    @Test
    fun testMountinfoAllProtectedPartitionsWithTmpfs() {
        val allPartitions = """
            101 1 0:1 / /system ro - tmpfs tmpfs rw
            102 1 0:2 / /system_ext/ ro - overlay overlay rw
            103 1 0:3 / /vendor ro - tmpfs tmpfs rw
            104 1 0:4 / /product/ ro - overlay overlay rw
            105 1 0:5 / /odm ro - tmpfs tmpfs rw
        """.trimIndent()

        val result = NativeMountsParser.parse(allPartitions)
        assertTrue(result.hasMagicMount)
        assertEquals(5, result.magicMountPoints.size)
    }

    @Test
    fun testMountinfoRootTracesInMountSourceOrOptions() {
        val rootTraces = """
            130 25 0:50 / /data/local/tmp rw - ext4 /dev/block/bootdevice options=kernelsu_active
            131 25 0:51 / /data rw - ext4 /data/adb/modules/test rw
        """.trimIndent()

        val result = NativeMountsParser.parse(rootTraces)
        assertTrue(result.hasKernelSuOrApatch)
        assertTrue(result.rootSignatures.contains("kernelsu"))
        assertTrue(result.rootSignatures.contains("/data/adb/modules"))
    }
}
