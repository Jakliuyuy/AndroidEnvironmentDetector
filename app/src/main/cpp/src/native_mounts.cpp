#include "native_mounts.h"
#include "syscall_helper.h"
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm>

namespace security {

static const char* const ROOT_MOUNT_SIGNATURES[] = {
    "/data/adb/ksu",
    "/data/adb/ap",
    "/data/adb/modules",
    "magisk",
    "core/mirror",
    "core/img",
    "/sbin/.magisk",
    "mirror/system",
    "rootdir",
    "kernelsu",
    "apd"
};

static const char* const PROTECTED_SYSTEM_MOUNTS[] = {
    "/system",
    "/system_ext",
    "/vendor",
    "/product",
    "/odm"
};

static inline std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

static bool IsProtectedMountPoint(const std::string& mountPoint) {
    size_t last = mountPoint.find_last_not_of('/');
    std::string stripped = (last == std::string::npos) ? "/" : mountPoint.substr(0, last + 1);
    for (const char* p : PROTECTED_SYSTEM_MOUNTS) {
        if (stripped == p) {
            return true;
        }
    }
    return false;
}

MountsScanResult ParseMountinfoBuffer(const char* buffer, size_t length) {
    MountsScanResult result;
    result.hasMagicMount = false;
    result.hasKernelSuOrApatch = false;
    result.anomaliesCount = 0;

    if (!buffer || length == 0) {
        result.evidence = "empty_mountinfo";
        return result;
    }

    std::string content(buffer, length);
    std::istringstream stream(content);
    std::string line;

    std::vector<std::string> detectedSignatures;
    std::vector<std::string> magicMounts;

    while (std::getline(stream, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;

        // Check 1: Root / KSU / APatch / Magisk trace keywords anywhere in the mount line
        for (const char* sig : ROOT_MOUNT_SIGNATURES) {
            if (line.find(sig) != std::string::npos) {
                result.hasKernelSuOrApatch = true;
                if (std::find(detectedSignatures.begin(), detectedSignatures.end(), sig) == detectedSignatures.end()) {
                    detectedSignatures.push_back(sig);
                }
                result.anomaliesCount++;
            }
        }

        // Check 2: Parse mountinfo structure
        // /proc/self/mountinfo:
        // 36 35 98:0 / /mnt/rw rw,noatime master:1 - ext4 /dev/block/sda1 flags
        std::istringstream lineStream(line);
        std::vector<std::string> tokens;
        std::string token;
        while (lineStream >> token) {
            tokens.push_back(token);
        }

        if (tokens.size() >= 5) {
            std::string mountPoint = tokens[4];
            std::string fstype = "";
            std::string mountSource = "";

            // Find separator '-'
            auto hyphenIt = std::find(tokens.begin() + 4, tokens.end(), "-");
            if (hyphenIt != tokens.end() && (hyphenIt + 1) != tokens.end()) {
                fstype = *(hyphenIt + 1);
                if ((hyphenIt + 2) != tokens.end()) {
                    mountSource = *(hyphenIt + 2);
                }
            } else if (tokens.size() >= 3) {
                // Fallback for /proc/mounts format: [src] [mount_point] [fstype] ...
                mountPoint = tokens[1];
                fstype = tokens[2];
                mountSource = tokens[0];
            }

            // Check if protected partition is mounted as tmpfs or overlay (Magisk / KernelSU module inversion)
            if (IsProtectedMountPoint(mountPoint)) {
                if (fstype == "tmpfs" || fstype == "overlay") {
                    result.hasMagicMount = true;
                    std::string anomaly = mountPoint + "(" + fstype + ")";
                    if (std::find(magicMounts.begin(), magicMounts.end(), anomaly) == magicMounts.end()) {
                        magicMounts.push_back(anomaly);
                    }
                    result.anomaliesCount++;
                }
            }
        }
    }

    std::string ev;
    if (result.hasMagicMount) {
        ev += "magic_mount_inversion=[";
        for (size_t i = 0; i < magicMounts.size(); ++i) {
            ev += magicMounts[i];
            if (i + 1 < magicMounts.size()) ev += ",";
        }
        ev += "] ";
    }
    if (result.hasKernelSuOrApatch) {
        ev += "root_signatures=[";
        for (size_t i = 0; i < detectedSignatures.size(); ++i) {
            ev += detectedSignatures[i];
            if (i + 1 < detectedSignatures.size()) ev += ",";
        }
        ev += "] ";
    }

    if (ev.empty()) {
        ev = "mountinfo_clean, standard partition filesystems verified";
    }

    result.evidence = Trim(ev);
    return result;
}

MountsScanResult ScanProcMountinfoDirect() {
    std::string mountContent;
    bool ok = DirectSyscallReadFileToString("/proc/self/mountinfo", mountContent, 2 * 1024 * 1024);
    if (!ok || mountContent.empty()) {
        // Fallback to /proc/mounts
        ok = DirectSyscallReadFileToString("/proc/mounts", mountContent, 2 * 1024 * 1024);
    }

    if (!ok || mountContent.empty()) {
        MountsScanResult res;
        res.hasMagicMount = false;
        res.hasKernelSuOrApatch = false;
        res.anomaliesCount = 0;
        res.evidence = "failed_to_read_proc_mountinfo";
        return res;
    }

    return ParseMountinfoBuffer(mountContent.data(), mountContent.size());
}

NativeDetectionItem EvaluateMountsDetection(const MountsScanResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R2-02";
    item.name = "挂载点异常与新型Root特征 (/proc/self/mountinfo)";
    item.category = CAT_ROOT;
    item.method = METHOD_DIRECT_SYSCALL;

    if (result.hasMagicMount || result.hasKernelSuOrApatch) {
        item.status = STATUS_DANGER;
    } else {
        item.status = STATUS_PASS;
    }

    item.evidence = result.evidence;
    return item;
}

} // namespace security
