#pragma once

#include <string>
#include <vector>
#include "security_types.h"

namespace security {

struct AntiHookScanResult {
    bool hasInlineHook;
    std::string hookedFunctions;
    bool hasTextModification;
    std::string textDigestEvidence;
    std::string evidence;
};

// Anti-hook inspection: ELF .text integrity and inline trampoline detection
AntiHookScanResult ScanAntiHookIntegrityDirect();

// Helper to check whether a given function pointer has an inline hook trampoline
bool CheckFunctionTrampoline(const void* funcPtr, std::string& outReason);

// Evaluate scan result into NativeDetectionItem
NativeDetectionItem EvaluateAntiHookDetection(const AntiHookScanResult& result);

} // namespace security
