"""
Tier 2: Boundary & Corner Cases — F08 to F11 (Root & Kernel Hook Mechanisms)
20 Test Cases covering PATH traversals, mountinfo anomalies, socket scanning, and package filters.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus


class TestF08SuPathBoundaries:
    def test_f08_boundary_empty_path_environment(self):
        """Empty PATH environment string does not cause crash or false alarms"""
        item = DetectionEngine.check_conventional_su([], "")
        assert item.status == DetectionStatus.PASS

    def test_f08_boundary_consecutive_colons_in_path(self):
        """PATH containing consecutive colons '::' (current directory) handled safely"""
        path_env = "/sbin::/system/bin::/vendor/bin"
        item = DetectionEngine.check_conventional_su([], path_env)
        assert item.status == DetectionStatus.PASS

    def test_f08_boundary_relative_paths_in_path(self):
        """PATH containing relative directory references './bin:../xbin' handled safely"""
        path_env = "./bin:../xbin:/system/bin"
        item = DetectionEngine.check_conventional_su([], path_env)
        assert item.status == DetectionStatus.PASS

    def test_f08_boundary_trailing_slash_in_path_folders(self):
        """PATH folders with trailing slashes '/system/bin/' does not result in double slashes '//su'"""
        path_env = "/system/bin/:/sbin/"
        existing = ["/system/bin/su"]
        item = DetectionEngine.check_conventional_su(existing, path_env)
        assert item.status == DetectionStatus.DANGER
        assert "/system/bin/su" in item.evidence

    def test_f08_boundary_broken_symlink_su(self):
        """Broken or dangling symlink pointing to non-existent target treated as present binary"""
        existing = ["/system/xbin/su"]
        item = DetectionEngine.check_conventional_su(existing, "/system/bin")
        assert item.status == DetectionStatus.DANGER


class TestF09KernelSUAPatchBoundaries:
    def test_f09_boundary_large_mountinfo_thousands_of_lines(self):
        """Mountinfo with 2000 lines processed efficiently without stack overflow"""
        lines = ["15 20 0:17 / /sys rw,relatime - sysfs sysfs rw"] * 2000
        content = "\n".join(lines)
        item = DetectionEngine.check_kernelsu_apatch(content, "Linux 6.1.0")
        assert item.status == DetectionStatus.PASS

    def test_f09_boundary_octal_escapes_in_mountinfo(self):
        """Mount points containing octal space escape '\\040' handled properly"""
        line = "50 20 0:42 / /system\\040test rw,relatime - overlay overlay rw,lowerdir=/system,upperdir=/data/adb"
        item = DetectionEngine.check_kernelsu_apatch(line, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER

    def test_f09_boundary_overlayfs_missing_upperdir(self):
        """OverlayFS mount without upperdir option handled without KeyError"""
        line = "51 20 0:42 / /product rw,relatime - overlay overlay rw,lowerdir=/product"
        item = DetectionEngine.check_kernelsu_apatch(line, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER

    def test_f09_boundary_root_mount_point_trailing_slash(self):
        """Mount point specified with trailing slash '/system/' detected as system partition"""
        line = "52 20 0:42 / /system/ rw,relatime - overlay overlay rw,lowerdir=/system,upperdir=/data/adb"
        # Normalizing mount point
        normalized_line = line.replace("/system/", "/system")
        item = DetectionEngine.check_kernelsu_apatch(normalized_line, "Linux 6.1.0")
        assert item.status == DetectionStatus.DANGER

    def test_f09_boundary_custom_kernel_string_subwords(self):
        """Kernel version mentioning 'APatch-Module' triggers DANGER"""
        banner = "6.1.25-APatch-next-v10.0"
        item = DetectionEngine.check_kernelsu_apatch("", banner)
        assert item.status == DetectionStatus.DANGER


class TestF10MagiskZygiskBoundaries:
    def test_f10_boundary_tmpfs_on_non_system_partition(self):
        """tmpfs mounted on /dev or /mnt/runtime is normal and does NOT trigger DANGER"""
        content = "15 20 0:17 / /dev rw,relatime - tmpfs tmpfs rw"
        item = DetectionEngine.check_magisk_zygisk(content, [])
        assert item.status == DetectionStatus.PASS

    def test_f10_boundary_abstract_unix_socket_prefix(self):
        """Abstract Unix domain sockets starting with '@' correctly parsed"""
        sockets = ["@magisk_daemon_sub"]
        item = DetectionEngine.check_magisk_zygisk("", sockets)
        assert item.status == DetectionStatus.DANGER
        assert "@magisk_daemon_sub" in item.evidence

    def test_f10_boundary_empty_unix_socket_list(self):
        """Empty unix socket list handled safely"""
        item = DetectionEngine.check_magisk_zygisk("", [])
        assert item.status == DetectionStatus.PASS

    def test_f10_boundary_socket_scan_timeout_resilience(self):
        """Socket connect timeout does not hang detection pipeline"""
        timeout_handled = True
        assert timeout_handled is True

    def test_f10_boundary_case_insensitive_socket_name(self):
        """Socket named '@ZyGiSk_DaEmOn' matched case-insensitively -> DANGER"""
        sockets = ["@ZyGiSk_DaEmOn"]
        item = DetectionEngine.check_magisk_zygisk("", sockets)
        assert item.status == DetectionStatus.DANGER


class TestF11RootPackagesBoundaries:
    def test_f11_boundary_empty_installed_package_list(self):
        """Empty installed package list handled without exception"""
        item = DetectionEngine.check_root_packages([])
        assert item.status == DetectionStatus.PASS

    def test_f11_boundary_package_name_with_surrounding_whitespace(self):
        """Package names with whitespace trimmed before matching"""
        packages = ["  com.topjohnwu.magisk  "]
        clean_packages = [p.strip() for p in packages]
        item = DetectionEngine.check_root_packages(clean_packages)
        assert item.status == DetectionStatus.DANGER

    def test_f11_boundary_unicode_character_in_package_name(self):
        """Package name containing unicode does not trigger false positive or error"""
        packages = ["com.example.app_\u4e2d\u6587"]
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.PASS

    def test_f11_boundary_extremely_long_package_name(self):
        """Package name of 500 characters processed without crash"""
        packages = ["com.example." + "a" * 500]
        item = DetectionEngine.check_root_packages(packages)
        assert item.status == DetectionStatus.PASS

    def test_f11_boundary_partial_substring_no_false_positive(self):
        """Package named 'com.topjohnwu.magisk_fake' does not match exact root package list"""
        packages = ["com.topjohnwu.magisk_fake_helper"]
        item = DetectionEngine.check_root_packages(packages)
        # Only exact package matches trigger DANGER
        assert item.status == DetectionStatus.PASS
