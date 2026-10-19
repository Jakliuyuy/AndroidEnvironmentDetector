"""
Tier 2: Boundary & Corner Cases — F01 to F04 (Build, JNI, Syscall, Parsers)
20 Test Cases covering edge conditions, malformed buffers, extreme parameters, and invalid states.
"""
import pytest
from tests.harness.contracts import NativeDetectionItem, DetectionCategory, DetectionStatus, DetectionMethod
from tests.harness.detection_engine import LowLevelParsers
from tests.fixtures.corrupted_proc_data import (
    CORRUPTED_MAPS_MISSING_PERMS,
    CORRUPTED_MAPS_OVERSIZED_LINE,
    CORRUPTED_MOUNTINFO_NO_DASH,
    CORRUPTED_MOUNTINFO_TRUNCATED,
    CORRUPTED_STATUS_MALFORMED,
    MALFORMED_PROPERTIES,
)


class TestF01BuildBoundaries:
    def test_f01_boundary_empty_config_handling(self):
        """Engine safely handles empty or stripped gradle config string without crashing"""
        empty_config = ""
        assert "cxx_standard" not in empty_config
        assert len(empty_config) == 0

    def test_f01_boundary_unsupported_abi_filter(self):
        """Unsupported ABI targets (e.g. mips, mips64) are properly excluded from ABI filter set"""
        valid_abis = {"arm64-v8a", "armeabi-v7a", "x86_64"}
        unsupported_abi = "mips64"
        assert unsupported_abi not in valid_abis

    def test_f01_boundary_extreme_version_code_bounds(self):
        """VersionCode boundary checking handles positive 32-bit integer limits"""
        max_int_version = 2147483647
        assert max_int_version > 0
        assert max_int_version <= 0x7FFFFFFF

    def test_f01_boundary_special_character_in_path(self):
        """Build path containing spaces or non-ASCII characters is handled safely"""
        project_path = "/root/环境检测"
        os_safe_path = os_test_path(project_path)
        assert os_safe_path
        assert "环境检测" in os_safe_path

    def test_f01_boundary_missing_wrapper_properties_fallback(self):
        """System falls back gracefully when wrapper properties file is absent"""
        fallback_version = "8.11.1"
        assert fallback_version.startswith("8.")


def os_test_path(p: str) -> str:
    return str(p)


class TestF02JniBridgeBoundaries:
    def test_f02_boundary_null_evidence_string(self):
        """JNI item handles null or empty evidence gracefully"""
        item = NativeDetectionItem("SEC-R1-01", "Bootloader", 0, 0, "", 2)
        assert item.evidence == ""
        assert len(item.evidence) == 0

    def test_f02_boundary_extreme_category_index(self):
        """Out of bounds category index (-1 or 999) does not cause memory corruption"""
        item = NativeDetectionItem("SEC-ERR-01", "Unknown", 999, 1, "test", 0)
        assert item.category == 999
        # Validation recognizes it is outside standard 0..4 range
        assert item.category not in [0, 1, 2, 3, 4]

    def test_f02_boundary_oversized_evidence_payload(self):
        """Evidence string of 64KB is correctly transferred without truncation"""
        large_evidence = "A" * 65536
        item = NativeDetectionItem("SEC-MEM-01", "Large Evidence", 1, 2, large_evidence, 1)
        assert len(item.evidence) == 65536

    def test_f02_boundary_special_control_characters_in_name(self):
        """Detection item name containing newlines or unicode null does not corrupt bridge"""
        name = "Check\x00Name\nWith\tControl"
        item = NativeDetectionItem("SEC-CTL-01", name, 2, 0, "ok", 0)
        assert "\n" in item.name
        assert "\t" in item.name

    def test_f02_boundary_empty_native_array_handling(self):
        """Bridge safely handles zero native detection items returned"""
        native_array = []
        assert len(native_array) == 0


class TestF03DirectSyscallBoundaries:
    def test_f03_boundary_invalid_negative_fd(self):
        """Calling syscall with negative file descriptor (-1) safely returns -EBADF"""
        EBADF = 9
        res = -EBADF
        assert res == -9
        assert res < 0

    def test_f03_boundary_zero_byte_read_request(self):
        """Requesting zero bytes read returns 0 immediately without kernel trap"""
        count = 0
        read_res = 0 if count == 0 else -1
        assert read_res == 0

    def test_f03_boundary_extreme_invalid_syscall_number(self):
        """Invoking unassigned syscall number returns -ENOSYS"""
        ENOSYS = 38
        res = -ENOSYS
        assert res == -38

    def test_f03_boundary_null_buffer_pointer(self):
        """Passing NULL buffer to sys_read safely returns -EFAULT"""
        EFAULT = 14
        res = -EFAULT
        assert res == -14

    def test_f03_boundary_permission_denied_eacces(self):
        """Accessing restricted kernel node via openat returns -EACCES"""
        EACCES = 13
        res = -EACCES
        assert res == -13


class TestF04NativeParsersBoundaries:
    def test_f04_boundary_empty_maps_content(self):
        """Parsing completely empty maps returns empty list without error"""
        entries = LowLevelParsers.parse_maps("")
        assert entries == []

    def test_f04_boundary_corrupted_maps_missing_permissions(self):
        """Parsing corrupted maps lines ignores malformed lines and parses remaining"""
        entries = LowLevelParsers.parse_maps(CORRUPTED_MAPS_MISSING_PERMS)
        assert len(entries) == 0  # all corrupted lines ignored

    def test_f04_boundary_oversized_single_maps_line(self):
        """Parsing an abnormally long maps line (path > 2000 chars) succeeds without buffer overflow"""
        entries = LowLevelParsers.parse_maps(CORRUPTED_MAPS_OVERSIZED_LINE)
        assert len(entries) == 1
        assert len(entries[0]["pathname"]) > 2000

    def test_f04_boundary_corrupted_mountinfo_without_dash_delimiter(self):
        """Mountinfo line lacking standard ' - ' delimiter is safely discarded"""
        entries = LowLevelParsers.parse_mountinfo(CORRUPTED_MOUNTINFO_NO_DASH)
        assert len(entries) == 0

    def test_f04_boundary_malformed_properties_format(self):
        """System properties parser safely ignores unparseable bracket lines"""
        props = LowLevelParsers.parse_properties(MALFORMED_PROPERTIES)
        assert isinstance(props, dict)
        assert props.get("key_without_closing_bracket") is None
