"""
Tier 1: Feature Coverage — F16 Debugger & Anti-Tracking
5 Test Cases validating JDWP debugger, TracerPid, ADB enabled, and combinations.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory, DetectionMethod


class TestF16Debugger:
    def test_f16_unattached_no_adb_returns_pass(self):
        """No JDWP, TracerPid=0, and ADB disabled returns PASS"""
        item = DetectionEngine.check_debugger(False, False, 0)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.DEBUG
        assert "No debugger attached" in item.evidence

    def test_f16_jdwp_connected_returns_danger(self):
        """JDWP debugger connected triggers DANGER"""
        item = DetectionEngine.check_debugger(True, False, 0)
        assert item.status == DetectionStatus.DANGER
        assert "JDWP debugger connected" in item.evidence

    def test_f16_tracer_pid_nonzero_returns_danger(self):
        """TracerPid > 0 triggers DANGER"""
        item = DetectionEngine.check_debugger(False, False, 4321)
        assert item.status == DetectionStatus.DANGER
        assert "Process attached by TracerPid: 4321" in item.evidence

    def test_f16_adb_enabled_only_returns_warn(self):
        """ADB debugging enabled without active tracer returns WARN"""
        item = DetectionEngine.check_debugger(False, True, 0)
        assert item.status == DetectionStatus.WARN
        assert "ADB debugging is enabled" in item.evidence

    def test_f16_tracer_pid_and_adb_simultaneous_returns_danger(self):
        """Simultaneous TracerPid and ADB enabled escalates to DANGER"""
        item = DetectionEngine.check_debugger(False, True, 1234)
        assert item.status == DetectionStatus.DANGER
        assert "TracerPid: 1234" in item.evidence
        assert "ADB debugging" in item.evidence
