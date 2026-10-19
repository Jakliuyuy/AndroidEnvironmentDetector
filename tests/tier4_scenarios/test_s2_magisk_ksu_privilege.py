"""
Tier 4: Scenario 2 — High-Privilege Magisk/KernelSU Device (S2)
Exercises Features: F08-F11, F17, F18, F20
Threat Model & Validation Target:
Validates mountinfo overlayfs/tmpfs anomaly detection triggering instant DANGER score cap <= 40.
"""
import json
import pytest
from tests.harness.contracts import (
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    SecurityLevel,
    SecurityAssessment,
    DiagnosticReport,
    DeviceInfo,
)
from tests.harness.detection_engine import DetectionEngine
from tests.harness.scorer import SecurityScorer
from tests.harness.report_serializer import ReportSerializer
from tests.fixtures.clean_device_data import (
    CLEAN_PROPERTIES,
    CLEAN_MAPS,
    CLEAN_DATA_DIR,
    CLEAN_UID,
)
from tests.fixtures.magisk_ksu_data import (
    MAGISK_MOUNTINFO,
    KSU_MOUNTINFO,
    ROOT_EXISTING_FILES,
    ROOT_UNIX_SOCKETS,
    ROOT_PACKAGES,
)


class TestScenario2MagiskKSUPrivilege:
    def test_s2_magisk_and_kernelsu_compromised_device(self, clean_device_info):
        """
        Executes security evaluation against a device compromised by Magisk and KernelSU.
        Verifies that deep kernel mount inspection and socket tracing triggers DANGER,
        scores strictly <= 40, and formats forensic evidence in the export report.
        """
        # Baseline system props
        item_bl = DetectionEngine.check_bootloader(CLEAN_PROPERTIES)
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")
        item_tags = DetectionEngine.check_build_tags(CLEAN_PROPERTIES.get("ro.build.tags"), CLEAN_PROPERTIES.get("ro.build.type"))

        # Root Vector Probing (F08, F09, F10, F11)
        item_su = DetectionEngine.check_conventional_su(ROOT_EXISTING_FILES, "/sbin:/system/bin")
        item_ksu = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.25-KernelSU-v0.9.5")
        item_magisk = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, ROOT_UNIX_SOCKETS)
        item_pkg = DetectionEngine.check_root_packages(ROOT_PACKAGES)

        assert item_su.status == DetectionStatus.DANGER
        assert item_ksu.status == DetectionStatus.DANGER
        assert item_magisk.status == DetectionStatus.DANGER
        assert item_pkg.status == DetectionStatus.DANGER

        # Evidence forensic checks
        assert "SU binaries detected" in item_su.evidence
        assert "OverlayFS on /system" in item_ksu.evidence
        assert "Kernel banner contains root tag" in item_ksu.evidence
        assert "Filesystem inversion tmpfs on /system" in item_magisk.evidence
        assert "com.topjohnwu.magisk" in item_pkg.evidence

        all_items = [item_bl, item_se, item_tags, item_su, item_ksu, item_magisk, item_pkg]

        # Scoring verification
        assessment = SecurityScorer.calculate_score(all_items)
        assert assessment.level == SecurityLevel.DANGEROUS
        assert 0 <= assessment.score <= 40
        assert assessment.dangerCount >= 4
        assert "High security risk detected" in assessment.summary

        # Diagnostic Report Export
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, all_items)
        data = json.loads(ReportSerializer.serialize_to_json(report))
        is_valid, msg = ReportSerializer.validate_schema(data)
        assert is_valid is True
        assert data["assessment"]["level"] == "DANGEROUS"
        assert data["assessment"]["score"] <= 40
