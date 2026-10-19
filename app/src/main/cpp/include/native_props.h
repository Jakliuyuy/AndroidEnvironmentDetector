#pragma once

#include <string>
#include <map>
#include "security_types.h"

namespace security {

struct PropsScanResult {
    std::string flashLocked;
    std::string verifiedBootState;
    std::string vbmetaState;
    std::string secure;
    std::string debuggable;
    std::string buildTags;
    std::string buildType;
    std::string hardware;
    bool isBootloaderUnlocked;
    bool isDebuggableOrTestKeys;
    std::string evidence;
};

// Reads a property using native libc __system_property_get
std::string ReadSystemProperty(const char* key);

// Scans core security properties
PropsScanResult ScanSecurityProperties();

// Evaluates Bootloader integrity item
NativeDetectionItem EvaluateBootloaderProps(const PropsScanResult& result);

// Evaluates Build Tags / Firmware signing item
NativeDetectionItem EvaluateBuildTagsProps(const PropsScanResult& result);

} // namespace security
