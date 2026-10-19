"""
Tier 1: Feature Coverage — F08 Conventional SU & PATH Scan
5 Test Cases validating static SU binaries, PATH scanning, and evidence formatting.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory


class TestF08SuPath:
    def test_f08_no_su_in_system_returns_pass(self):
        """When no SU binary exists, returns PASS"""
        existing = ["/system/bin/sh", "/system/bin/ls"]
        path_env = "/system/bin:/system/xbin"
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.ROOT
        assert "No SU binary found" in item.evidence

    def test_f08_system_bin_su_detected_returns_danger(self):
        """Presence of /system/bin/su triggers DANGER"""
        existing = ["/system/bin/su", "/system/bin/sh"]
        path_env = "/system/bin:/vendor/bin"
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert item.status == DetectionStatus.DANGER
        assert "/system/bin/su" in item.evidence

    def test_f08_system_xbin_su_detected_returns_danger(self):
        """Presence of /system/xbin/su triggers DANGER"""
        existing = ["/system/xbin/su"]
        path_env = "/sbin:/system/bin"
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert item.status == DetectionStatus.DANGER
        assert "/system/xbin/su" in item.evidence

    def test_f08_path_environment_traversal_detection(self):
        """SU binary located in dynamic PATH folder triggers DANGER"""
        existing = ["/data/local/bin/su"]
        path_env = "/sbin:/system/bin:/data/local/bin"
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert item.status == DetectionStatus.DANGER
        assert "/data/local/bin/su" in item.evidence

    def test_f08_su_evidence_contains_detected_paths(self):
        """Evidence string correctly lists all detected SU locations"""
        existing = ["/system/bin/su", "/sbin/su"]
        path_env = "/sbin:/system/bin"
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert "/system/bin/su" in item.evidence
        assert "/sbin/su" in item.evidence
