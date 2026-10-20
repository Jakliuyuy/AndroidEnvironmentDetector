#pragma once

#include <string>
#include "security_types.h"

namespace security {

struct KernelProbeResult {
    bool kernelSuDetected;
    int kernelSuVersion;
    std::string kernelSuEvidence;

    bool apatchDetected;
    long apatchResponseCode;
    std::string apatchEvidence;

    std::string summaryEvidence;
};

// Direct syscall kernel probes for KernelSU and APatch
KernelProbeResult ProbeKernelRootDirect();

// Pure functional parser for deterministic testability and JVM unit tests
KernelProbeResult ParseKernelProbeData(long ksuRet, unsigned int ksuVer, long apatchRet);

// Convert probe results to NativeDetectionItem
NativeDetectionItem EvaluateKernelSuDetection(const KernelProbeResult& result);
NativeDetectionItem EvaluateApatchDetection(const KernelProbeResult& result);

} // namespace security
