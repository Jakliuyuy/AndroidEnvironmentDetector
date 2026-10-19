#pragma once
#include <string>
#include <vector>

namespace security {

enum DetectionStatus : int {
    STATUS_PASS = 0,
    STATUS_WARN = 1,
    STATUS_DANGER = 2
};

enum DetectionCategory : int {
    CAT_BOOTLOADER = 0,
    CAT_ROOT = 1,
    CAT_HOOK = 2,
    CAT_VIRTUAL = 3,
    CAT_DEBUG = 4
};

enum DetectionMethod : int {
    METHOD_JAVA = 0,
    METHOD_LIBC = 1,
    METHOD_NATIVE_LIBC = 1,
    METHOD_DIRECT_SYSCALL = 2
};

struct NativeDetectionItem {
    std::string id;
    std::string name;
    int category;
    int status;
    std::string evidence;
    int method;
};

} // namespace security
