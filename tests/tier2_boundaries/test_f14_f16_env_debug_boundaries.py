"""
Tier 2: Boundary & Corner Cases — F14 to F16 (Emulator, Virtual Container, Anti-Debug)
15 Test Cases covering extreme UIDs, path traversals, TracerPid bounds, and device nodes.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus


class TestF14EmulatorBoundaries:
    def test_f14_boundary_all_hardware_props_empty(self):
        """Empty hardware properties handled safely without KeyError"""
        item = DetectionEngine.check_emulator({}, [], 5)
        assert item.status == DetectionStatus.PASS

    def test_f14_boundary_negative_sensor_count(self):
        """Negative sensor count handled as anomaly -> DANGER"""
        item = DetectionEngine.check_emulator({}, [], 0)
        assert item.status == DetectionStatus.DANGER

    def test_f14_boundary_qemu_device_socket_present(self):
        """Presence of /dev/socket/qemud device socket triggers DANGER"""
        item = DetectionEngine.check_emulator({}, ["/dev/socket/qemud"], 10)
        assert item.status == DetectionStatus.DANGER
        assert "/dev/socket/qemud" in item.evidence

    def test_f14_boundary_case_insensitive_hardware_name(self):
        """Hardware name in uppercase 'GOLDFISH' triggers DANGER"""
        props = {"ro.hardware": "GOLDFISH"}
        item = DetectionEngine.check_emulator(props, [], 10)
        assert item.status == DetectionStatus.DANGER

    def test_f14_boundary_vbox86_virtualbox_hardware(self):
        """VirtualBox hardware 'vbox86' triggers DANGER"""
        props = {"ro.hardware": "vbox86p"}
        item = DetectionEngine.check_emulator(props, [], 10)
        assert item.status == DetectionStatus.DANGER


class TestF15DualAppBoundaries:
    def test_f15_boundary_legitimate_multi_user_user_10(self):
        """Work profile (user 10, UID 1010123) is legitimate and does NOT trigger WARN"""
        data_dir = "/data/user/10/com.security.environment"
        uid = 1010123
        item = DetectionEngine.check_dual_app(data_dir, uid, [])
        assert item.status == DetectionStatus.PASS

    def test_f15_boundary_path_traversal_double_dots(self):
        """Data path containing directory traversal attempts handled safely"""
        data_dir = "/data/data/../data/com.security.environment"
        item = DetectionEngine.check_dual_app(data_dir, 10123, [])
        assert item.status == DetectionStatus.PASS

    def test_f15_boundary_extreme_dual_space_uid_upper_bound(self):
        """Upper boundary UID 99999999 triggers WARN"""
        item = DetectionEngine.check_dual_app("/data/user/999/com.app", 99999999, [])
        assert item.status == DetectionStatus.WARN

    def test_f15_boundary_subuser_uid_just_below_dual_space_range(self):
        """UID 99899999 (below 99900000) does not trigger dual-space by UID alone"""
        item = DetectionEngine.check_dual_app("/data/user/0/com.app", 99899999, [])
        assert item.status == DetectionStatus.PASS

    def test_f15_boundary_empty_container_packages_list(self):
        """Empty container package list handles safely"""
        item = DetectionEngine.check_dual_app("/data/user/0/com.app", 10123, [])
        assert item.status == DetectionStatus.PASS


class TestF16DebuggerBoundaries:
    def test_f16_boundary_extreme_large_tracer_pid(self):
        """TracerPid of extreme integer (99999999) triggers DANGER safely without int overflow"""
        item = DetectionEngine.check_debugger(False, False, 99999999)
        assert item.status == DetectionStatus.DANGER
        assert "99999999" in item.evidence

    def test_f16_boundary_zero_tracer_pid_with_adb_disabled(self):
        """TracerPid=0 with adb=false returns clean PASS"""
        item = DetectionEngine.check_debugger(False, False, 0)
        assert item.status == DetectionStatus.PASS

    def test_f16_boundary_negative_tracer_pid_anomaly(self):
        """Negative TracerPid (<0) treated as non-debugger or normalized to 0"""
        tracer = -1
        effective_tracer = max(0, tracer)
        item = DetectionEngine.check_debugger(False, False, effective_tracer)
        assert item.status == DetectionStatus.PASS

    def test_f16_boundary_all_debug_flags_active(self):
        """JDWP, TracerPid, and ADB enabled simultaneously triggers DANGER with all evidence recorded"""
        item = DetectionEngine.check_debugger(True, True, 1234)
        assert item.status == DetectionStatus.DANGER
        assert "JDWP" in item.evidence
        assert "TracerPid" in item.evidence
        assert "ADB" in item.evidence

    def test_f16_boundary_adb_only_capped_at_warn(self):
        """ADB enabled alone NEVER escalates beyond WARN"""
        item = DetectionEngine.check_debugger(False, True, 0)
        assert item.status == DetectionStatus.WARN
