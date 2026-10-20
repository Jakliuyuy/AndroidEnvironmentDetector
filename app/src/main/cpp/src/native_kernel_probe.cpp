#include "native_kernel_probe.h"
#include "syscall_helper.h"
#include "obfuscate.h"
#include <chrono>

namespace security {

constexpr int KSU_OPTION = 0xDEADBEEF;
constexpr unsigned long APATCH_SUPERCALL_HELLO = 0x1000;
constexpr long APATCH_SUPERCALL_HELLO_MAGIC = 0x11581158;

KernelProbeResult ParseKernelProbeData(long ksuRet, unsigned int ksuVer, long apatchRet) {
    KernelProbeResult res;
    res.kernelSuDetected = false;
    res.kernelSuVersion = 0;
    res.apatchDetected = false;
    res.apatchResponseCode = apatchRet;

    // 1. Evaluate KernelSU response
    if (ksuRet == 0 && ksuVer >= 10000) {
        res.kernelSuDetected = true;
        res.kernelSuVersion = static_cast<int>(ksuVer);
        res.kernelSuEvidence = OBF_STR("ksu_handshake_active, version=").str() + std::to_string(ksuVer);
    } else if (ksuRet != -22 /* -EINVAL */ && ksuRet != -1) {
        res.kernelSuDetected = true;
        res.kernelSuEvidence = OBF_STR("ksu_prctl_anomaly, ret=").str() + std::to_string(ksuRet);
    } else {
        res.kernelSuEvidence = OBF_STR("prctl_clean (ret=-22, standard_latency)").str();
    }

    // 2. Evaluate APatch response
    if (apatchRet == APATCH_SUPERCALL_HELLO_MAGIC) {
        res.apatchDetected = true;
        res.apatchEvidence = OBF_STR("apatch_supercall_active (magic=0x11581158)").str();
    } else if (apatchRet != -14 /* -EFAULT */ && apatchRet != -2 /* -ENOENT */ && apatchRet != -1) {
        res.apatchDetected = true;
        res.apatchEvidence = OBF_STR("apatch_channel_anomaly (ret=").str() + std::to_string(apatchRet) + ")";
    } else {
        res.apatchEvidence = OBF_STR("truncate_clean (ret=-14/EFAULT)").str();
    }

    res.summaryEvidence = res.kernelSuEvidence + "; " + res.apatchEvidence;
    return res;
}

KernelProbeResult ProbeKernelRootDirect() {
    // 1. Direct KernelSU handshake probe (prctl 0xDEADBEEF)
    unsigned int ksuVersion = 0;
    long ksuRet = sys_prctl(KSU_OPTION, 0, reinterpret_cast<unsigned long>(&ksuVersion), 0, 0);

    // 2. Direct APatch SuperCall probe (truncate 0x1000)
    long apatchRet = sys_truncate(reinterpret_cast<const char*>(APATCH_SUPERCALL_HELLO), 0);

    KernelProbeResult res = ParseKernelProbeData(ksuRet, ksuVersion, apatchRet);

    // 3. Timing side-channel evaluation if direct ksuRet is standard EINVAL (-22)
    if (!res.kernelSuDetected && (ksuRet == -22 || ksuRet == -1)) {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 5; ++i) {
            sys_prctl(0x12345678, 0, 0, 0, 0);
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 5; ++i) {
            sys_prctl(KSU_OPTION, 0, 0, 0, 0);
        }
        auto t2 = std::chrono::high_resolution_clock::now();

        auto baselineNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        auto ksuNs = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();

        // If KSU hook handling time exceeds baseline by 20x and absolute time > 20,000ns
        if (ksuNs > baselineNs * 20 && ksuNs > 20000) {
            res.kernelSuDetected = true;
            res.kernelSuEvidence = OBF_STR("ksu_timing_side_channel, baseline=").str() +
                                  std::to_string(baselineNs) + "ns, ksu=" + std::to_string(ksuNs) + "ns";
            res.summaryEvidence = res.kernelSuEvidence + "; " + res.apatchEvidence;
        }
    }

    return res;
}

NativeDetectionItem EvaluateKernelSuDetection(const KernelProbeResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R2-03";
    item.name = OBF_STR("KernelSU 内核级特权调用探针 (Direct Syscall)").str();
    item.category = CAT_ROOT;
    item.method = METHOD_DIRECT_SYSCALL;
    item.status = result.kernelSuDetected ? STATUS_DANGER : STATUS_PASS;
    item.evidence = result.kernelSuEvidence;
    return item;
}

NativeDetectionItem EvaluateApatchDetection(const KernelProbeResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R2-04";
    item.name = OBF_STR("APatch SuperCall 内核通信通道探测").str();
    item.category = CAT_ROOT;
    item.method = METHOD_DIRECT_SYSCALL;
    item.status = result.apatchDetected ? STATUS_DANGER : STATUS_PASS;
    item.evidence = result.apatchEvidence;
    return item;
}

} // namespace security
