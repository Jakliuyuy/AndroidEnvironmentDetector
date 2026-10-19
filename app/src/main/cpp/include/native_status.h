#pragma once

#include <string>
#include "security_types.h"

namespace security {

struct StatusScanResult {
    int tracerPid;
    bool isTraced;
    std::string state;
    std::string evidence;
};

// Pure buffer parser for testability and JVM parity
StatusScanResult ParseStatusBuffer(const char* buffer, size_t length);

// Direct syscall scanner reading /proc/self/status
StatusScanResult ReadProcStatusDirect();

// Helper to convert scan result to NativeDetectionItem
NativeDetectionItem EvaluateStatusDetection(const StatusScanResult& result);

} // namespace security
