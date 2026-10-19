"""
Tier 1: Feature Coverage — F11 Root Manager Package Detection
5 Test Cases validating presence of Magisk, KernelSU, APatch, SuperSU, and multiple manager packages.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.clean_device_data import CLEAN_PACKAGES
from tests.fixtures.magisk_ksu_data import ROOT_PACKAGES


class TestF11RootPackages:
    def test_f11_no_root_packages_returns_pass(self):
        """Clean package list without root managers returns PASS"""
        item = DetectionEngine.check_root_packages(CLEAN_PACKAGES)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.ROOT
        assert "No known root manager packages detected" in item.evidence

    def test_f11_magisk_app_detected_returns_danger(self):
        """Presence of com.topjohnwu.magisk triggers DANGER"""
        packages = CLEAN_PACKAGES + ["com.topjohnwu.magisk"]
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.DANGER
        assert "com.topjohnwu.magisk" in item.evidence

    def test_f11_kernelsu_app_detected_returns_danger(self):
        """Presence of me.weishu.kernelsu triggers DANGER"""
        packages = CLEAN_PACKAGES + ["me.weishu.kernelsu"]
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.DANGER
        assert "me.weishu.kernelsu" in item.evidence

    def test_f11_apatch_app_detected_returns_danger(self):
        """Presence of bmax.apatch triggers DANGER"""
        packages = CLEAN_PACKAGES + ["bmax.apatch"]
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.DANGER
        assert "bmax.apatch" in item.evidence

    def test_f11_multiple_root_packages_returns_danger(self):
        """Presence of multiple root managers lists all in evidence"""
        packages = CLEAN_PACKAGES + ROOT_PACKAGES
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.DANGER
        for pkg in ROOT_PACKAGES:
            assert pkg in item.evidence
