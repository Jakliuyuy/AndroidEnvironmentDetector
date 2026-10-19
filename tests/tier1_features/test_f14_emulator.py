"""
Tier 1: Feature Coverage — F14 Emulator & Hardware Artifacts
5 Test Cases validating ro.kernel.qemu, hardware name, model name, driver nodes, and sensor counts.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.clean_device_data import CLEAN_PROPERTIES


class TestF14Emulator:
    def test_f14_clean_physical_device_returns_pass(self):
        """Physical device with non-qemu props, normal sensors, and no qemu pipes returns PASS"""
        item = DetectionEngine.check_emulator(CLEAN_PROPERTIES, [], 12)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.VIRTUAL
        assert "Physical hardware signature verified" in item.evidence

    def test_f14_ro_kernel_qemu_returns_danger(self):
        """ro.kernel.qemu=1 triggers DANGER"""
        props = {"ro.kernel.qemu": "1", "ro.hardware": "husky"}
        item = DetectionEngine.check_emulator(props, [], 10)
        assert item.status == DetectionStatus.DANGER
        assert "ro.kernel.qemu=1" in item.evidence

    def test_f14_goldfish_hardware_returns_danger(self):
        """ro.hardware=goldfish triggers DANGER"""
        props = {"ro.hardware": "goldfish"}
        item = DetectionEngine.check_emulator(props, [], 8)
        assert item.status == DetectionStatus.DANGER
        assert "ro.hardware=goldfish" in item.evidence

    def test_f14_qemu_pipe_device_node_returns_danger(self):
        """Presence of /dev/qemu_pipe node triggers DANGER"""
        nodes = ["/dev/qemu_pipe"]
        item = DetectionEngine.check_emulator(CLEAN_PROPERTIES, nodes, 8)
        assert item.status == DetectionStatus.DANGER
        assert "/dev/qemu_pipe" in item.evidence

    def test_f14_zero_sensors_anomaly_returns_danger(self):
        """Zero physical sensors on device triggers DANGER"""
        item = DetectionEngine.check_emulator(CLEAN_PROPERTIES, [], 0)
        assert item.status == DetectionStatus.DANGER
        assert "Zero physical sensors" in item.evidence
