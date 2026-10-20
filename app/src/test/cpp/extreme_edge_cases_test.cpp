#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>

// Include C++ engine headers
#include "../../main/cpp/include/security_types.h"
#include "../../main/cpp/include/native_maps.h"
#include "../../main/cpp/include/native_mounts.h"
#include "../../main/cpp/include/native_status.h"
#include "../../main/cpp/include/obfuscate.h"
#include "../../main/cpp/include/native_kernel_probe.h"
#include "../../main/cpp/include/native_anti_hook.h"

using namespace security;

int main() {
    std::cout << "[INFO] Starting Native C++ Low-Level Engine Extreme Edge Cases Challenge..." << std::endl;

    // =========================================================================
    // 1. Extreme TracerPid Edge Cases
    // =========================================================================
    std::cout << "\n--- Testing Extreme TracerPid Edge Cases ---" << std::endl;
    {
        // Case S1: Normal clean TracerPid: 0
        const char* s1 = "Name:\ttest\nState:\tS (sleeping)\nTracerPid:\t0\n";
        auto res1 = ParseStatusBuffer(s1, strlen(s1));
        assert(res1.tracerPid == 0);
        assert(!res1.isTraced);
        assert(res1.state == "S (sleeping)");
        std::cout << "  [PASS] Case S1 (TracerPid 0): " << res1.evidence << std::endl;

        // Case S2: Normal traced TracerPid: 1337
        const char* s2 = "TracerPid:\t1337\nState:\tt (tracing stop)\n";
        auto res2 = ParseStatusBuffer(s2, strlen(s2));
        assert(res2.tracerPid == 1337);
        assert(res2.isTraced);
        std::cout << "  [PASS] Case S2 (TracerPid 1337): " << res2.evidence << std::endl;

        // Case S3: Extreme Integer Overflow (int64/out of range for int32)
        const char* s3 = "Name:\ttest\nTracerPid:\t99999999999999999999999999999999\nState:\tR\n";
        auto res3 = ParseStatusBuffer(s3, strlen(s3));
        assert(!res3.isTraced); // Overflow caught gracefully, does not crash
        assert(res3.tracerPid == -1);
        std::cout << "  [PASS] Case S3 (TracerPid 99999999999999999999999999999999 overflow handled): " << res3.evidence << std::endl;

        // Case S4: Negative TracerPid
        const char* s4 = "TracerPid:\t-1\nState:\tS\n";
        auto res4 = ParseStatusBuffer(s4, strlen(s4));
        assert(res4.tracerPid == -1);
        assert(!res4.isTraced);
        std::cout << "  [PASS] Case S4 (TracerPid -1): " << res4.evidence << std::endl;

        // Case S5: Non-numeric and malformed TracerPid
        const char* s5 = "TracerPid:\tnot_a_pid_123\nState:\tS\n";
        auto res5 = ParseStatusBuffer(s5, strlen(s5));
        assert(!res5.isTraced);
        std::cout << "  [PASS] Case S5 (TracerPid non-numeric): " << res5.evidence << std::endl;

        // Case S6: Multiple TracerPid lines (last one overrides)
        const char* s6 = "TracerPid:\t0\nState:\tS\nTracerPid:\t5555\n";
        auto res6 = ParseStatusBuffer(s6, strlen(s6));
        assert(res6.tracerPid == 5555);
        assert(res6.isTraced);
        std::cout << "  [PASS] Case S6 (Multiple TracerPid lines): " << res6.evidence << std::endl;

        // Case S7: Empty and blank status buffer
        auto res7 = ParseStatusBuffer("", 0);
        assert(!res7.isTraced);
        assert(res7.evidence == "no_status_data");
        std::cout << "  [PASS] Case S7 (Empty status buffer): " << res7.evidence << std::endl;
    }

    // =========================================================================
    // 2. Extreme Maps Edge Cases
    // =========================================================================
    std::cout << "\n--- Testing Extreme Maps Edge Cases ---" << std::endl;
    {
        // Case M1: Empty and whitespace maps
        auto res1 = ParseMapsBuffer("   \n\t  \n", 8);
        assert(!res1.hasHookLibrary);
        assert(!res1.hasAnonymousExecutable);
        std::cout << "  [PASS] Case M1 (Whitespace maps): " << res1.evidence << std::endl;

        // Case M2: Malformed tokens (1, 2, 3, 4 tokens without crash)
        const char* m2 = "broken_single_token\n"
                         "token1 token2\n"
                         "token1 token2 token3\n"
                         "token1 token2 token3 token4\n"
                         "00400000-00452000 r-xp 00000000 08:02 173521\n"; // 5 tokens (no pathname, but r-xp)
        auto res2 = ParseMapsBuffer(m2, strlen(m2));
        assert(res2.hasAnonymousExecutable); // 5 tokens with r-xp and empty path must be flagged as anon executable
        std::cout << "  [PASS] Case M2 (Malformed / incomplete lines handled): " << res2.evidence << std::endl;

        // Case M3: Non-whitelisted anonymous memory
        const char* m3 = "7f8a9c0000-7f8a9d0000 r-xp 00000000 00:00 0 [anon:unknown_injected_module]\n";
        auto res3 = ParseMapsBuffer(m3, strlen(m3));
        assert(res3.hasAnonymousExecutable);
        assert(!res3.hasHookLibrary);
        std::cout << "  [PASS] Case M3 (Non-whitelisted anon memory flagged): " << res3.evidence << std::endl;

        // Case M4: Whitelisted Dalvik JIT memory
        const char* m4 = "7f90000000-7f90040000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n"
                         "7f90040000-7f90080000 r-xp 00000000 00:00 0 [anon:dalvik-data-code-cache]\n"
                         "7fff000000-7fff020000 r-xp 00000000 00:00 0 [vdso]\n";
        auto res4 = ParseMapsBuffer(m4, strlen(m4));
        assert(!res4.hasAnonymousExecutable);
        assert(!res4.hasHookLibrary);
        std::cout << "  [PASS] Case M4 (Whitelisted JIT/vdso passes): " << res4.evidence << std::endl;

        // Case M5: Path with spaces containing suspicious library
        const char* m5 = "7f8b000000-7f8b050000 r-xp 00000000 08:01 1234 /data/local/tmp/my test dir/frida-agent.so\n";
        auto res5 = ParseMapsBuffer(m5, strlen(m5));
        assert(res5.hasHookLibrary);
        assert(res5.hookLibraryName == "frida-agent");
        std::cout << "  [PASS] Case M5 (Path with spaces and frida-agent): " << res5.evidence << std::endl;

        // Case M6: Extremely long map line (50,000 characters)
        std::string longLine = "00400000-00452000 rw-p 00000000 08:02 1234 /system/lib/";
        longLine.append(50000, 'x');
        longLine.append(".so\n");
        auto res6 = ParseMapsBuffer(longLine.data(), longLine.size());
        assert(!res6.hasHookLibrary);
        std::cout << "  [PASS] Case M6 (50,000 char line handled cleanly)" << std::endl;
    }

    // =========================================================================
    // 3. Extreme Mountinfo Edge Cases
    // =========================================================================
    std::cout << "\n--- Testing Extreme Mountinfo Edge Cases ---" << std::endl;
    {
        // Case T1: Truncated mountinfo before separator '-'
        const char* t1 = "120 25 254:0 / /system ro,nodev shared:1\n"
                         "121 25 254:1 / /vendor ro,nodev shared:2\n";
        auto res1 = ParseMountinfoBuffer(t1, strlen(t1));
        assert(!res1.hasMagicMount);
        std::cout << "  [PASS] Case T1 (Truncated before hyphen): " << res1.evidence << std::endl;

        // Case T2: Truncated mountinfo right after '-'
        const char* t2 = "120 25 254:0 / /system ro,nodev shared:1 -\n";
        auto res2 = ParseMountinfoBuffer(t2, strlen(t2));
        assert(!res2.hasMagicMount);
        std::cout << "  [PASS] Case T2 (Truncated right at hyphen): " << res2.evidence << std::endl;

        // Case T3: Mount point with trailing slash '/system/' tmpfs
        const char* t3 = "120 25 0:45 / /system/ ro,relatime shared:1 - tmpfs tmpfs rw,seclabel\n";
        auto res3 = ParseMountinfoBuffer(t3, strlen(t3));
        assert(res3.hasMagicMount);
        std::cout << "  [PASS] Case T3 (Trailing slash /system/ tmpfs detected): " << res3.evidence << std::endl;

        // Case T4: All protected mount points with overlay (standard 10-token mountinfo format)
        const char* t4 = "101 1 0:1 / /system ro,noatime shared:1 - overlay overlay rw\n"
                         "102 1 0:2 / /system_ext ro,noatime shared:2 - overlay overlay rw\n"
                         "103 1 0:3 / /vendor ro,noatime shared:3 - overlay overlay rw\n"
                         "104 1 0:4 / /product ro,noatime shared:4 - overlay overlay rw\n"
                         "105 1 0:5 / /odm ro,noatime shared:5 - overlay overlay rw\n";
        auto res4 = ParseMountinfoBuffer(t4, strlen(t4));
        assert(res4.hasMagicMount);
        assert(res4.anomaliesCount == 5);
        std::cout << "  [PASS] Case T4 (All 5 protected partitions detected with overlay): " << res4.evidence << std::endl;

        // Case T5: Root signatures everywhere in line
        const char* t5 = "120 25 0:45 / /storage rw,relatime - ext4 /data/adb/modules/my_mod rw\n"
                         "121 25 0:46 / /storage rw,relatime - ext4 /system/xbin/kernelsu rw\n";
        auto res5 = ParseMountinfoBuffer(t5, strlen(t5));
        assert(res5.hasKernelSuOrApatch);
        std::cout << "  [PASS] Case T5 (Root signatures detected): " << res5.evidence << std::endl;

        // Case T6: Extremely long mount line (50,000 characters)
        std::string longMount = "120 25 254:0 / /system ro,nodev shared:1 - ext4 /dev/block/";
        longMount.append(50000, 'm');
        longMount.append(" rw\n");
        auto res6 = ParseMountinfoBuffer(longMount.data(), longMount.size());
        assert(!res6.hasMagicMount);
        std::cout << "  [PASS] Case T6 (50,000 char mount line handled cleanly)" << std::endl;
    }

    // =========================================================================
    // 4. R4: Constexpr XOR Obfuscation & Volatile Zeroize Verification
    // =========================================================================
    std::cout << "\n--- Testing R4: Constexpr XOR Obfuscation ---" << std::endl;
    {
        auto obf1 = OBF_STR("/proc/self/maps");
        assert(obf1.str() == "/proc/self/maps");
        assert(strcmp(obf1.c_str(), "/proc/self/maps") == 0);

        auto obf2 = OBF_STR("frida-agent");
        assert(obf2.str() == "frida-agent");

        auto obf3 = OBF_STR("magisk");
        assert(obf3.str() == "magisk");

        std::cout << "  [PASS] R4 Obfuscation compiles and decrypts correctly on stack" << std::endl;
    }

    // =========================================================================
    // 5. R2: KernelSU & APatch Direct Syscall Probe Data Evaluation
    // =========================================================================
    std::cout << "\n--- Testing R2: KernelSU & APatch Probe Data Evaluation ---" << std::endl;
    {
        // Pure kernel response: ksuRet = -22 (-EINVAL), apatchRet = -14 (-EFAULT)
        auto cleanRes = ParseKernelProbeData(-22, 0, -14);
        assert(!cleanRes.kernelSuDetected);
        assert(!cleanRes.apatchDetected);
        auto itemKsuClean = EvaluateKernelSuDetection(cleanRes);
        auto itemApatchClean = EvaluateApatchDetection(cleanRes);
        assert(itemKsuClean.status == STATUS_PASS);
        assert(itemApatchClean.status == STATUS_PASS);
        std::cout << "  [PASS] Clean kernel response evaluated as STATUS_PASS" << std::endl;

        // KernelSU Active response: ksuRet = 0, version = 11000
        auto ksuActiveRes = ParseKernelProbeData(0, 11000, -14);
        assert(ksuActiveRes.kernelSuDetected);
        assert(ksuActiveRes.kernelSuVersion == 11000);
        auto itemKsuActive = EvaluateKernelSuDetection(ksuActiveRes);
        assert(itemKsuActive.status == STATUS_DANGER);
        std::cout << "  [PASS] KernelSU active handshake evaluated as STATUS_DANGER: " << itemKsuActive.evidence << std::endl;

        // APatch Active response: apatchRet = 0x11581158
        auto apatchActiveRes = ParseKernelProbeData(-22, 0, 0x11581158);
        assert(apatchActiveRes.apatchDetected);
        auto itemApatchActive = EvaluateApatchDetection(apatchActiveRes);
        assert(itemApatchActive.status == STATUS_DANGER);
        std::cout << "  [PASS] APatch active SuperCall evaluated as STATUS_DANGER: " << itemApatchActive.evidence << std::endl;
    }

    // =========================================================================
    // 6. R3: Anti-Inline Hook Trampoline Pattern Detection
    // =========================================================================
    std::cout << "\n--- Testing R3: Anti-Inline Hook Trampoline Pattern Detection ---" << std::endl;
    {
        // Case: Fake Dobby / Frida ARM64 trampoline (0x58000050, 0xd61f0200)
#if defined(__aarch64__)
        uint32_t fakeDobby[4] = {0x58000050, 0xd61f0200, 0xdeadbeef, 0xcafebabe};
        std::string reason;
        bool hooked = CheckFunctionTrampoline(fakeDobby, reason);
        assert(hooked);
        std::cout << "  [PASS] Dobby x16 hook identified: " << reason << std::endl;
#elif defined(__x86_64__)
        uint8_t fakeX64Jmp[8] = {0xE9, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00};
        std::string reason;
        bool hooked = CheckFunctionTrampoline(fakeX64Jmp, reason);
        assert(hooked);
        std::cout << "  [PASS] x86_64 JMP hook identified: " << reason << std::endl;
#endif
    }

    std::cout << "\n[SUCCESS] All Native C++ Extreme Edge Cases Passed Empirically!" << std::endl;
    return 0;
}
