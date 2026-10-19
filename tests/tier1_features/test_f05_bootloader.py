"""
Tier 1: Feature Coverage — F05 Bootloader Status Detection
5 Test Cases validating ro.boot.flash.locked, verifiedbootstate, and vbmeta checks.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory


class TestF05Bootloader:
    def test_f05_locked_property_returns_pass(self):
        """ro.boot.flash.locked=1 and green state returns PASS"""
        props = {"ro.boot.flash.locked": "1", "ro.boot.verifiedbootstate": "green"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.BOOTLOADER
        assert "ro.boot.flash.locked=1" in item.evidence

    def test_f05_unlocked_zero_returns_danger(self):
        """ro.boot.flash.locked=0 returns DANGER"""
        props = {"ro.boot.flash.locked": "0", "ro.boot.verifiedbootstate": "green"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.DANGER
        assert "ro.boot.flash.locked=0" in item.evidence

    def test_f05_verified_boot_green_returns_pass(self):
        """ro.boot.verifiedbootstate=green returns PASS"""
        props = {"ro.boot.verifiedbootstate": "green"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.PASS

    def test_f05_verified_boot_orange_returns_danger(self):
        """ro.boot.verifiedbootstate=orange (unlocked custom ROM) returns DANGER"""
        props = {"ro.boot.flash.locked": "1", "ro.boot.verifiedbootstate": "orange"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.DANGER
        assert "orange" in item.evidence

    def test_f05_missing_properties_returns_warn(self):
        """When bootloader properties are completely missing, engine flags WARN"""
        props = {}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.WARN
        assert "no bootloader props found" in item.evidence
