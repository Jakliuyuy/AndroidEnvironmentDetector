"""
Tier 1: Feature Coverage — F09 KernelSU & APatch Detection
5 Test Cases validating mountinfo overlayfs on system/vendor, upperdir in /data/adb, and kernel banner tags.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.magisk_ksu_data import KSU_MOUNTINFO
from tests.fixtures.clean_device_data import CLEAN_MOUNTINFO


class TestF09KernelSUAPatch:
    def test_f09_clean_mountinfo_returns_pass(self):
        """Clean standard mountinfo returns PASS"""
        item = DetectionEngine.check_kernelsu_apatch(CLEAN_MOUNTINFO, "Linux 6.1.0-android14")
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.ROOT

    def test_f09_overlayfs_on_system_detected_returns_danger(self):
        """OverlayFS mounted over /system triggers DANGER"""
        item = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER
        assert "OverlayFS on /system" in item.evidence

    def test_f09_overlayfs_on_vendor_detected_returns_danger(self):
        """OverlayFS mounted over /vendor triggers DANGER"""
        custom_mount = "30 20 0:43 / /vendor rw,relatime - overlay overlay rw,lowerdir=/vendor,upperdir=/data/adb"
        item = DetectionEngine.check_kernelsu_apatch(custom_mount, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER
        assert "OverlayFS on /vendor" in item.evidence

    def test_f09_data_adb_upperdir_detected_returns_danger(self):
        """Mount entry containing upperdir=/data/adb triggers DANGER"""
        item = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER
        assert "/data/adb" in item.evidence

    def test_f09_kernel_banner_kernelsu_tag_returns_danger(self):
        """Kernel version banner mentioning KernelSU or APatch triggers DANGER"""
        banner = "Linux version 6.1.25-KernelSU-v0.9.5 #1 SMP PREEMPT"
        item = DetectionEngine.check_kernelsu_apatch(CLEAN_MOUNTINFO, banner)
        assert item.status == DetectionStatus.DANGER
        assert "Kernel banner contains root tag" in item.evidence
