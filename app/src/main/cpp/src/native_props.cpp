#include "native_props.h"
#include <sys/system_properties.h>
#include <cstring>
#include <algorithm>
#include <cctype>
#include "syscall_helper.h"

namespace security {

static inline std::string TrimAndLower(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    std::string trimmed = str.substr(first, (last - first + 1));
    std::transform(trimmed.begin(), trimmed.end(), trimmed.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return trimmed;
}

std::string ReadSystemProperty(const char* key) {
    if (!key) return "";
    char valueBuf[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(key, valueBuf);
    if (len > 0) {
        return std::string(valueBuf, static_cast<size_t>(len));
    }
    return "";
}

PropsScanResult ScanSecurityProperties() {
    PropsScanResult res;
    res.flashLocked = ReadSystemProperty("ro.boot.flash.locked");
    res.verifiedBootState = ReadSystemProperty("ro.boot.verifiedbootstate");
    res.vbmetaState = ReadSystemProperty("ro.boot.vbmeta.device_state");
    res.secure = ReadSystemProperty("ro.secure");
    res.debuggable = ReadSystemProperty("ro.debuggable");
    res.buildTags = ReadSystemProperty("ro.build.tags");
    res.buildType = ReadSystemProperty("ro.build.type");
    res.hardware = ReadSystemProperty("ro.hardware");

    // Evaluate Bootloader unlocked state with whitespace and case hardening
    // Clean: locked="1", verifiedbootstate="green", vbmeta="locked"
    // Tainted: locked="0", verifiedbootstate="orange" / "yellow", vbmeta="unlocked"
    std::string flashLower = TrimAndLower(res.flashLocked);
    std::string verifiedBootLower = TrimAndLower(res.verifiedBootState);
    std::string vbmetaLower = TrimAndLower(res.vbmetaState);

    bool unlocked = false;
    if (flashLower == "0" ||
        verifiedBootLower == "orange" ||
        verifiedBootLower == "yellow" ||
        vbmetaLower == "unlocked") {
        unlocked = true;
    }
    res.isBootloaderUnlocked = unlocked;

    // Evaluate debuggable / test-keys
    bool debugOrTest = false;
    if (res.debuggable == "1" ||
        res.buildTags.find("test-keys") != std::string::npos ||
        res.buildTags.find("dev-keys") != std::string::npos ||
        res.buildType == "userdebug" ||
        res.buildType == "eng") {
        debugOrTest = true;
    }
    res.isDebuggableOrTestKeys = debugOrTest;

    std::string ev = "flash.locked=" + (res.flashLocked.empty() ? "unset" : res.flashLocked) +
                     ", verifiedbootstate=" + (res.verifiedBootState.empty() ? "unset" : res.verifiedBootState) +
                     ", vbmeta.device_state=" + (res.vbmetaState.empty() ? "unset" : res.vbmetaState) +
                     ", build.tags=" + (res.buildTags.empty() ? "unset" : res.buildTags);
    res.evidence = ev;

    return res;
}

NativeDetectionItem EvaluateBootloaderProps(const PropsScanResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R1-01";
    item.name = "Bootloader 锁状态深度检测";
    item.category = CAT_BOOTLOADER;
    item.method = METHOD_DIRECT_SYSCALL;

    if (result.isBootloaderUnlocked) {
        item.status = STATUS_DANGER;
    } else if (result.flashLocked.empty() && result.verifiedBootState.empty() && result.vbmetaState.empty()) {
        item.status = STATUS_WARN;
    } else {
        item.status = STATUS_PASS;
    }

    item.evidence = "flash.locked=" + result.flashLocked +
                    ", verifiedbootstate=" + result.verifiedBootState +
                    ", vbmeta=" + result.vbmetaState;
    return item;
}

NativeDetectionItem EvaluateBuildTagsProps(const PropsScanResult& result) {
    NativeDetectionItem item;
    item.id = "SEC-R1-05";
    item.name = "系统固件签名与构建标记";
    item.category = CAT_BOOTLOADER;
    item.method = METHOD_NATIVE_LIBC;

    if (result.isDebuggableOrTestKeys) {
        item.status = STATUS_DANGER;
    } else {
        item.status = STATUS_PASS;
    }

    item.evidence = "build.tags=" + result.buildTags +
                    ", build.type=" + result.buildType +
                    ", debuggable=" + result.debuggable;
    return item;
}

} // namespace security
