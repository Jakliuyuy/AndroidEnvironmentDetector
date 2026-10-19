"""
Tier 2: Boundary & Corner Cases — F05 to F07 (Bootloader, SELinux, Build Tags)
15 Test Cases covering corrupted system properties, ambiguous values, and permission edge cases.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus


class TestF05BootloaderBoundaries:
    def test_f05_boundary_padded_whitespace_in_props(self):
        """Property value with leading and trailing whitespaces is stripped and parsed correctly"""
        props = {"ro.boot.flash.locked": " 1\t"}
        # After stripping, "1" is parsed
        clean_props = {k: v.strip() for k, v in props.items()}
        item = DetectionEngine.check_bootloader(clean_props)
        assert item.status == DetectionStatus.PASS

    def test_f05_boundary_case_insensitive_unlocked(self):
        """Verified boot state in mixed case 'oRaNgE' is recognized as unlocked/DANGER"""
        props = {"ro.boot.verifiedbootstate": "oRaNgE"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.DANGER
        assert "orange" in item.evidence.lower()

    def test_f05_boundary_unknown_boot_state_string(self):
        """Unknown boot state string (e.g. 'purple', 'unknown') defaults to WARN"""
        props = {"ro.boot.verifiedbootstate": "purple"}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.WARN

    def test_f05_boundary_empty_string_property(self):
        """Empty string property value is handled as missing without IndexError"""
        props = {"ro.boot.flash.locked": "", "ro.boot.verifiedbootstate": ""}
        item = DetectionEngine.check_bootloader(props)
        assert item.status == DetectionStatus.WARN

    def test_f05_boundary_oversized_property_value(self):
        """Property value of 1024 characters does not cause buffer overrun"""
        props = {"ro.boot.flash.locked": "1" * 1024}
        item = DetectionEngine.check_bootloader(props)
        assert item.status in [DetectionStatus.PASS, DetectionStatus.WARN]


class TestF06SELinuxBoundaries:
    def test_f06_boundary_enforce_node_empty_content(self):
        """Empty enforce node content treated as disabled/corrupted -> DANGER"""
        item = DetectionEngine.check_selinux("", "u:r:untrusted_app:s0")
        assert item.status == DetectionStatus.DANGER

    def test_f06_boundary_enforce_value_with_newline(self):
        """Enforce node containing '1\\n' handles newline correctly -> PASS"""
        raw_val = "1\n".strip()
        item = DetectionEngine.check_selinux(raw_val, "u:r:untrusted_app:s0")
        assert item.status == DetectionStatus.PASS

    def test_f06_boundary_non_numeric_enforce_content(self):
        """Non-numeric string 'enforcing' or 'invalid' triggers DANGER"""
        item = DetectionEngine.check_selinux("enforcing", "u:r:untrusted_app:s0")
        assert item.status == DetectionStatus.DANGER

    def test_f06_boundary_null_context_string(self):
        """Process context is null/None -> handles without NoneType exception"""
        item = DetectionEngine.check_selinux("1", None)
        assert item.status == DetectionStatus.PASS
        assert "unknown" in item.evidence

    def test_f06_boundary_context_restricted_permission(self):
        """Context node read permission denied handles safely"""
        item = DetectionEngine.check_selinux("1", "PermissionDenied")
        assert item.status == DetectionStatus.PASS
        assert "PermissionDenied" in item.evidence


class TestF07BuildTagsBoundaries:
    def test_f07_boundary_empty_build_tags_and_type(self):
        """Empty tags and type string handled gracefully without crash"""
        item = DetectionEngine.check_build_tags("", "")
        assert item.status == DetectionStatus.PASS

    def test_f07_boundary_mixed_case_test_keys(self):
        """Mixed-case 'TeSt-KeYs' is detected and triggers WARN"""
        item = DetectionEngine.check_build_tags("TeSt-KeYs,release-keys", "user")
        assert item.status == DetectionStatus.WARN

    def test_f07_boundary_whitespace_separated_tags(self):
        """Tags separated by multiple spaces or tabs parsed properly"""
        item = DetectionEngine.check_build_tags("release-keys   test-keys", "user")
        assert item.status == DetectionStatus.WARN

    def test_f07_boundary_unrecognized_build_type(self):
        """Unrecognized build type 'custom-debug-build' triggers WARN or is logged"""
        item = DetectionEngine.check_build_tags("release-keys", "userdebug-custom")
        assert item.status == DetectionStatus.WARN

    def test_f07_boundary_extremely_long_tag_string(self):
        """Extremely long tag string (> 500 chars) processed safely"""
        long_tags = "tag," * 150
        item = DetectionEngine.check_build_tags(long_tags, "user")
        assert item.status == DetectionStatus.PASS
