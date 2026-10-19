"""
Tier 1: Feature Coverage — F06 SELinux Mode & Context Check
5 Test Cases validating /sys/fs/selinux/enforce, permissive mode, disabled, and context.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory, DetectionMethod


class TestF06SELinux:
    def test_f06_enforce_value_one_returns_pass(self):
        """enforce=1 indicates SELinux Enforcing mode, returning PASS"""
        item = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0:c123,c456")
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.BOOTLOADER
        assert "SELinux Enforcing (1)" in item.evidence

    def test_f06_enforce_value_zero_returns_danger(self):
        """enforce=0 indicates SELinux Permissive mode, returning DANGER"""
        item = DetectionEngine.check_selinux("0", "u:r:untrusted_app:s0")
        assert item.status == DetectionStatus.DANGER
        assert "SELinux Permissive (0)" in item.evidence

    def test_f06_missing_enforce_node_returns_danger(self):
        """None value indicates SELinux Disabled or missing, returning DANGER"""
        item = DetectionEngine.check_selinux(None, "u:r:kernel:s0")
        assert item.status == DetectionStatus.DANGER
        assert "SELinux Disabled" in item.evidence

    def test_f06_valid_app_context_reported(self):
        """Evidence string includes the active SELinux process context"""
        ctx = "u:r:untrusted_app:s0:c512,c768"
        item = DetectionEngine.check_selinux("1", ctx)
        assert ctx in item.evidence

    def test_f06_direct_syscall_method_contract(self):
        """SELinux check is performed via DIRECT_SYSCALL method"""
        item = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")
        assert item.method == DetectionMethod.DIRECT_SYSCALL
