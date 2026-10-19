"""
Tier 1: Feature Coverage — F04 Native Low-Level Parsers
5 Test Cases validating C++ parsers for maps, mountinfo, status, and system properties.
"""
import pytest
from tests.harness.detection_engine import LowLevelParsers
from tests.fixtures.clean_device_data import CLEAN_MAPS, CLEAN_MOUNTINFO, CLEAN_STATUS


class TestF04NativeParsers:
    def test_f04_maps_parser_standard_entries(self):
        """Parses standard Linux /proc/self/maps lines extracting address and permissions"""
        entries = LowLevelParsers.parse_maps(CLEAN_MAPS)
        assert len(entries) >= 5
        first = entries[0]
        assert first["start"] == "78c2e000"
        assert first["end"] == "78c2f000"
        assert first["perms"] == "r--p"
        libc_entry = next((e for e in entries if "libc.so" in e["pathname"]), None)
        assert libc_entry is not None
        assert libc_entry["perms"] == "r-xp"

    def test_f04_mountinfo_parser_standard_entries(self):
        """Parses /proc/self/mountinfo extracting mount ID, mount point, fs type, and source"""
        entries = LowLevelParsers.parse_mountinfo(CLEAN_MOUNTINFO)
        assert len(entries) >= 5
        system_mount = next((e for e in entries if e["mount_point"] == "/system"), None)
        assert system_mount is not None
        assert system_mount["fs_type"] == "ext4"
        assert "/dev/block/dm-1" in system_mount["mount_source"]

    def test_f04_status_parser_key_value(self):
        """Parses /proc/self/status extracting TracerPid, Pid, PPid, and Uid"""
        status_map = LowLevelParsers.parse_status(CLEAN_STATUS)
        assert "TracerPid" in status_map
        assert status_map["TracerPid"] == "0"
        assert status_map["Pid"] == "12345"
        assert "Uid" in status_map

    def test_f04_properties_bracket_parser(self):
        """Parses getprop output in [key]: [value] bracketed format"""
        bracket_output = """
[ro.boot.flash.locked]: [1]
[ro.boot.verifiedbootstate]: [green]
[ro.build.tags]: [release-keys]
"""
        props = LowLevelParsers.parse_properties(bracket_output)
        assert props.get("ro.boot.flash.locked") == "1"
        assert props.get("ro.boot.verifiedbootstate") == "green"
        assert props.get("ro.build.tags") == "release-keys"

    def test_f04_properties_key_value_parser(self):
        """Parses system properties in key=value format"""
        kv_output = """
ro.boot.flash.locked=1
ro.build.type=user
ro.product.brand=google
"""
        props = LowLevelParsers.parse_properties(kv_output)
        assert props.get("ro.boot.flash.locked") == "1"
        assert props.get("ro.build.type") == "user"
        assert props.get("ro.product.brand") == "google"
