#include "native_status.h"
#include "syscall_helper.h"
#include "obfuscate.h"
#include <sstream>
#include <cstdlib>
#include <cstring>

namespace security {

static inline std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

StatusScanResult ParseStatusBuffer(const char* buffer, size_t length) {
    StatusScanResult result;
    result.tracerPid = 0;
    result.isTraced = false;
    result.state = "unknown";
    result.evidence = "no_status_data";

    if (!buffer || length == 0) {
        return result;
    }

    std::string content(buffer, length);
    std::istringstream stream(content);
    std::string line;

    bool foundTracerPid = false;

    while (std::getline(stream, line)) {
        line = Trim(line);
        std::string tracerKey = OBF_STR("TracerPid:").str();
        std::string stateKey = OBF_STR("State:").str();
        if (line.rfind(tracerKey, 0) == 0) {
            std::string valStr = line.substr(tracerKey.length());
            valStr = Trim(valStr);
            try {
                result.tracerPid = std::stoi(valStr);
                foundTracerPid = true;
            } catch (...) {
                result.tracerPid = -1;
            }
        } else if (line.rfind(stateKey, 0) == 0) {
            result.state = Trim(line.substr(stateKey.length()));
        }
    }

    if (foundTracerPid) {
        result.isTraced = (result.tracerPid > 0);
        result.evidence = "TracerPid=" + std::to_string(result.tracerPid) + ", State=" + result.state;
    } else {
        result.evidence = "TracerPid_not_found, State=" + result.state;
    }

    return result;
}

StatusScanResult ReadProcStatusDirect() {
    std::string statusContent;
    bool ok = DirectSyscallReadFileToString(OBF_STR("/proc/self/status").c_str(), statusContent, 128 * 1024);
    if (!ok || statusContent.empty()) {
        StatusScanResult res;
        res.tracerPid = -1;
        res.isTraced = false;
        res.state = "error";
        res.evidence = "failed_to_read_proc_self_status";
        return res;
    }

    return ParseStatusBuffer(statusContent.data(), statusContent.size());
}

NativeDetectionItem EvaluateStatusDetection(const StatusScanResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R4-04";
    item.name = OBF_STR("进程跟踪调试状态检测 (TracerPid)").str();
    item.category = CAT_DEBUG;
    item.method = METHOD_DIRECT_SYSCALL;

    if (result.isTraced) {
        item.status = STATUS_DANGER;
    } else {
        item.status = STATUS_PASS;
    }

    item.evidence = result.evidence;
    return item;
}

} // namespace security
