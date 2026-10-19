"""
Tier 1: Feature Coverage — F07 System Build Tags & Keys
5 Test Cases validating ro.build.tags (test-keys/release-keys) and ro.build.type (user/userdebug).
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory


class TestF07BuildTags:
    def test_f07_release_keys_user_build_returns_pass(self):
        """release-keys with user build type returns PASS"""
        item = DetectionEngine.check_build_tags("release-keys", "user")
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.BOOTLOADER
        assert "release-keys" in item.evidence

    def test_f07_test_keys_returns_warn(self):
        """test-keys build tags returns WARN"""
        item = DetectionEngine.check_build_tags("test-keys", "user")
        assert item.status == DetectionStatus.WARN
        assert "test-keys" in item.evidence

    def test_f07_userdebug_build_type_returns_warn(self):
        """userdebug build type returns WARN"""
        item = DetectionEngine.check_build_tags("release-keys", "userdebug")
        assert item.status == DetectionStatus.WARN
        assert "userdebug" in item.evidence

    def test_f07_eng_build_type_returns_warn(self):
        """eng (engineering) build type returns WARN"""
        item = DetectionEngine.check_build_tags("release-keys", "eng")
        assert item.status == DetectionStatus.WARN
        assert "eng" in item.evidence

    def test_f07_evidence_string_format(self):
        """Evidence string properly incorporates tags and type"""
        item = DetectionEngine.check_build_tags("release-keys", "user")
        assert "ro.build.tags=release-keys" in item.evidence
        assert "ro.build.type=user" in item.evidence
