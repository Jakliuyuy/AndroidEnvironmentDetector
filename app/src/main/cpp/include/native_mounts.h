#pragma once

#include <string>
#include <vector>
#include "security_types.h"

namespace security {

struct MountsScanResult {
    bool hasMagicMount;
    std::string magicMountDetails;
    bool hasKernelSuOrApatch;
    std::string rootModuleDetails;
    int anomaliesCount;
    std::string evidence;
};

// Pure buffer parser for testability and JVM parity
MountsScanResult ParseMountinfoBuffer(const char* buffer, size_t length);

// Direct syscall scanner reading /proc/self/mountinfo
MountsScanResult ScanProcMountinfoDirect();

// Helper to convert scan result to NativeDetectionItem
NativeDetectionItem EvaluateMountsDetection(const MountsScanResult& result);

} // namespace security
