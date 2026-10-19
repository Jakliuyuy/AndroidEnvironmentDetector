"""
Tier 1: Feature Coverage — F10 Magisk & Zygisk Detection
5 Test Cases validating mountinfo filesystem inversion (tmpfs on /system), magisk mounts, and unix sockets.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.magisk_ksu_data import MAGISK_MOUNTINFO, ROOT_UNIX_SOCKETS
from tests.fixtures.clean_device_data import CLEAN_MOUNTINFO


class TestF10MagiskZygisk:
    def test_f10_clean_mounts_no_magisk_returns_pass(self):
        """Clean mountinfo without magisk or tmpfs inversion returns PASS"""
        item = DetectionEngine.check_magisk_zygisk(CLEAN_MOUNTINFO, [])
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.ROOT

    def test_f10_tmpfs_on_system_inversion_returns_danger(self):
        """Mounting tmpfs directly over /system or /system/bin triggers DANGER"""
        item = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, [])
        assert item.status == DetectionStatus.DANGER
        assert "Filesystem inversion tmpfs on /system" in item.evidence

    def test_f10_magisk_mount_source_detected_returns_danger(self):
        """Mount entry with source containing 'magisk' triggers DANGER"""
        item = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, [])
        assert item.status == DetectionStatus.DANGER
        assert "Magisk mount trace" in item.evidence

    def test_f10_magiskd_socket_detected_returns_danger(self):
        """Unix domain socket /dev/socket/magiskd triggers DANGER"""
        sockets = ["/dev/socket/magiskd"]
        item = DetectionEngine.check_magisk_zygisk(CLEAN_MOUNTINFO, sockets)
        assert item.status == DetectionStatus.DANGER
        assert "/dev/socket/magiskd" in item.evidence

    def test_f10_zygisk_socket_detected_returns_danger(self):
        """Unix domain socket matching Zygisk daemon triggers DANGER"""
        sockets = ["@zygisk_daemon_64"]
        item = DetectionEngine.check_magisk_zygisk(CLEAN_MOUNTINFO, sockets)
        assert item.status == DetectionStatus.DANGER
        assert "@zygisk_daemon_64" in item.evidence
