#include "native_maps.h"
#include "syscall_helper.h"
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm>

namespace security {

static const char* const SUSPICIOUS_LIBS[] = {
    "frida-agent",
    "frida-gadget",
    "linjector",
    "gadget.so",
    "liblspd.so",
    "libxposed",
    "libsandhook",
    "libpine",
    "libwhale",
    "libepic",
    "XposedBridge.jar",
    "edxposed",
    "libsubstrate.so",
    "zygisk",
    "riru"
};

static const char* const ANON_EXEC_WHITELIST[] = {
    "[anon:dalvik-jit-code-cache]",
    "[anon:dalvik-data-code-cache]",
    "[anon:dalvik-zygote-jit-code-cache]",
    "[anon:dalvik-alloc-space]",
    "[stack]",
    "[vectors]",
    "[vdso]",
    "[vsyscall]"
};

static inline std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

static bool IsInWhitelist(const std::string& pathname) {
    for (const char* item : ANON_EXEC_WHITELIST) {
        if (pathname == item) {
            return true;
        }
    }
    return false;
}

MapsScanResult ParseMapsBuffer(const char* buffer, size_t length) {
    MapsScanResult result;
    result.hasHookLibrary = false;
    result.hasAnonymousExecutable = false;
    result.anonymousExecutableCount = 0;
    result.suspiciousTotal = 0;

    if (!buffer || length == 0) {
        result.evidence = "empty_maps";
        return result;
    }

    std::string content(buffer, length);
    std::istringstream stream(content);
    std::string line;

    std::vector<std::string> detectedLibs;

    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        // Line format:
        // address           perms offset  dev   inode   pathname
        // 00400000-00452000 r-xp  0000000 08:02 173521  /usr/bin/dbus-daemon
        std::istringstream lineStream(line);
        std::string address;
        std::string perms;
        std::string offset;
        std::string dev;
        std::string inode;
        std::string pathname;

        if (!(lineStream >> address >> perms >> offset >> dev >> inode)) {
            continue;
        }

        // Remainder of line is pathname
        std::getline(lineStream, pathname);
        pathname = Trim(pathname);

        // Check 1: Known Hook / Dynamic Instrumentation Libraries
        if (!pathname.empty()) {
            for (const char* keyword : SUSPICIOUS_LIBS) {
                if (pathname.find(keyword) != std::string::npos) {
                    result.hasHookLibrary = true;
                    if (result.hookLibraryName.empty()) {
                        result.hookLibraryName = keyword;
                    }
                    if (std::find(detectedLibs.begin(), detectedLibs.end(), keyword) == detectedLibs.end()) {
                        detectedLibs.push_back(keyword);
                    }
                    result.suspiciousTotal++;
                    break;
                }
            }
        }

        // Check 2: Anonymous Executable Memory (r-xp / rwxp without backing file or non-whitelisted anon)
        if (perms.find('x') != std::string::npos) {
            bool isAnon = pathname.empty() || pathname.rfind("[anon", 0) == 0;
            if (isAnon && !IsInWhitelist(pathname)) {
                result.hasAnonymousExecutable = true;
                result.anonymousExecutableCount++;
                if (result.sampleAnonymousRegion.empty()) {
                    result.sampleAnonymousRegion = address + " " + perms + " " + (pathname.empty() ? "[anon-unnamed]" : pathname);
                }
                result.suspiciousTotal++;
            }
        }
    }

    // Build evidence string
    std::string ev;
    if (result.hasHookLibrary) {
        ev += "hook_libs=[";
        for (size_t i = 0; i < detectedLibs.size(); ++i) {
            ev += detectedLibs[i];
            if (i + 1 < detectedLibs.size()) ev += ",";
        }
        ev += "] ";
    }
    if (result.hasAnonymousExecutable) {
        ev += "anon_rx_count=" + std::to_string(result.anonymousExecutableCount) + " sample=" + result.sampleAnonymousRegion;
    }
    if (ev.empty()) {
        ev = "maps_clean, no hook libs or anomalous executable pages detected";
    }
    result.evidence = Trim(ev);

    return result;
}

MapsScanResult ScanProcMapsDirect() {
    std::string mapsContent;
    bool ok = DirectSyscallReadFileToString("/proc/self/maps", mapsContent, 2 * 1024 * 1024);
    if (!ok || mapsContent.empty()) {
        MapsScanResult res;
        res.hasHookLibrary = false;
        res.hasAnonymousExecutable = false;
        res.anonymousExecutableCount = 0;
        res.suspiciousTotal = 0;
        res.evidence = "failed_to_read_proc_self_maps";
        return res;
    }
    return ParseMapsBuffer(mapsContent.data(), mapsContent.size());
}

NativeDetectionItem EvaluateMapsDetection(const MapsScanResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R3-04";
    item.name = "内存映射与动态插桩检测 (/proc/self/maps)";
    item.category = CAT_HOOK;
    item.method = METHOD_DIRECT_SYSCALL;

    if (result.hasHookLibrary) {
        item.status = STATUS_DANGER;
    } else if (result.hasAnonymousExecutable) {
        item.status = STATUS_DANGER;
    } else {
        item.status = STATUS_PASS;
    }

    item.evidence = result.evidence;
    return item;
}

} // namespace security
