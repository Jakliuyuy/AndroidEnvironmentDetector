"""
Pytest configuration and shared fixtures for the E2E Test Suite.
"""
import sys
import os
import pytest

# Ensure tests and harness are in sys.path
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tests.harness.contracts import (
    DeviceInfo,
    SecurityAssessment,
    SecurityLevel,
    DiagnosticReport,
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    DetectionItem,
)
from tests.fixtures.clean_device_data import (
    CLEAN_PROPERTIES,
    CLEAN_MOUNTINFO,
    CLEAN_MAPS,
    CLEAN_STATUS,
    CLEAN_DATA_DIR,
    CLEAN_UID,
    CLEAN_PACKAGES,
)


@pytest.fixture
def clean_device_info():
    return DeviceInfo(
        fingerprint="google/husky/husky:14/UD1A.230803.041/10548174:user/release-keys",
        brand="google",
        model="Pixel 8 Pro",
        androidVersion="14",
        apiLevel=34,
        arch="arm64-v8a",
    )


@pytest.fixture
def clean_items_list():
    items = [
        DetectionItem("SEC-R1-01", "Bootloader Lock State", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "ro.boot.flash.locked=1", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R1-02", "SELinux Mode & Context", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "SELinux Enforcing (1)", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R1-03", "System Build Tags & Keys", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "ro.build.tags=release-keys", DetectionMethod.NATIVE_LIBC),
        DetectionItem("SEC-R2-01", "Conventional SU Binary Scan", DetectionCategory.ROOT, DetectionStatus.PASS, "No SU binary found", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R2-02", "KernelSU & APatch Detection", DetectionCategory.ROOT, DetectionStatus.PASS, "No KernelSU trace found", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R2-03", "Magisk & Zygisk Detection", DetectionCategory.ROOT, DetectionStatus.PASS, "No Magisk tmpfs inversion", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R2-04", "Root Manager Package Detection", DetectionCategory.ROOT, DetectionStatus.PASS, "No root manager packages", DetectionMethod.JAVA),
        DetectionItem("SEC-R3-01", "Xposed / LSPosed Framework Detection", DetectionCategory.HOOK, DetectionStatus.PASS, "No Xposed trace", DetectionMethod.JAVA),
        DetectionItem("SEC-R3-02", "Frida Dynamic Instrumentation Detection", DetectionCategory.HOOK, DetectionStatus.PASS, "No Frida port or thread", DetectionMethod.DIRECT_SYSCALL),
        DetectionItem("SEC-R4-01", "Emulator & Virtual Hardware Detection", DetectionCategory.VIRTUAL, DetectionStatus.PASS, "Physical hardware", DetectionMethod.NATIVE_LIBC),
        DetectionItem("SEC-R4-02", "Dual-App & Virtual Container Detection", DetectionCategory.VIRTUAL, DetectionStatus.PASS, "Standard user path", DetectionMethod.JAVA),
        DetectionItem("SEC-R4-03", "Debugger & Anti-Tracking Detection", DetectionCategory.DEBUG, DetectionStatus.PASS, "No debugger attached", DetectionMethod.DIRECT_SYSCALL),
    ]
    return items
