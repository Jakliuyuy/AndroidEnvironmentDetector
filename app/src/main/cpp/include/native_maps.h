#pragma once

#include <string>
#include <vector>
#include "security_types.h"

namespace security {

struct MapsScanResult {
    bool hasHookLibrary;
    std::string hookLibraryName;
    bool hasAnonymousExecutable;
    int anonymousExecutableCount;
    std::string sampleAnonymousRegion;
    int suspiciousTotal;
    std::string evidence;
};

// Pure buffer parser for testability and JVM parity
MapsScanResult ParseMapsBuffer(const char* buffer, size_t length);

// Direct syscall scanner reading /proc/self/maps without libc open/read
MapsScanResult ScanProcMapsDirect();

// Helper to convert scan result to NativeDetectionItem
NativeDetectionItem EvaluateMapsDetection(const MapsScanResult& result);

} // namespace security
