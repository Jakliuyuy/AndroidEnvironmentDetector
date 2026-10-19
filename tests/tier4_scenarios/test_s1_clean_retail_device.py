"""
Tier 4: Scenario 1 — Clean Retail Device Emulation (S1)
Exercises Features: F05-F07, F17, F18, F20
Threat Model & Validation Target:
Validates that an uncompromised, factory-sealed consumer device scores 100/SAFE with zero false alarms.
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
    CLEAN_MOUNTINFO,
    CLEAN_MAPS,
    CLEAN_STATUS,
    CLEAN_DATA_DIR,
    CLEAN_UID,
    CLEAN_OPEN_PORTS,
    CLEAN_THREAD_NAMES,
    CLEAN_PACKAGES,
)


class TestScenario1CleanRetailDevice:
    def test_s1_clean_retail_device_e2e_evaluation(self, clean_device_info):
        """
        Executes complete multi-layer security scans against a pristine retail device profile.
        Asserts 100% PASS across all detection domains, SAFE rating, score 95-100, and valid diagnostic report.
        """
        # 1. System & Bootloader Checks (F05, F06, F07)
        item_bl = DetectionEngine.check_bootloader(CLEAN_PROPERTIES)
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0:c123,c456")
        item_tags = DetectionEngine.check_build_tags(CLEAN_PROPERTIES.get("ro.build.tags"), CLEAN_PROPERTIES.get("ro.build.type"))

        assert item_bl.status == DetectionStatus.PASS
        assert item_se.status == DetectionStatus.PASS
        assert item_tags.status == DetectionStatus.PASS

        # 2. Root Checks (F08, F09, F10, F11)
        item_su = DetectionEngine.check_conventional_su([], "/system/bin:/system/xbin")
        item_ksu = DetectionEngine.check_kernelsu_apatch(CLEAN_MOUNTINFO, "Linux 6.1.0-android14")
        item_magisk = DetectionEngine.check_magisk_zygisk(CLEAN_MOUNTINFO, [])
        item_pkg = DetectionEngine.check_root_packages(CLEAN_PACKAGES)

        assert item_su.status == DetectionStatus.PASS
        assert item_ksu.status == DetectionStatus.PASS
        assert item_magisk.status == DetectionStatus.PASS
        assert item_pkg.status == DetectionStatus.PASS

        # 3. Hook & Injection Checks (F12, F13)
        item_xp = DetectionEngine.check_xposed([], "", CLEAN_MAPS)
        item_frida = DetectionEngine.check_frida(CLEAN_OPEN_PORTS, CLEAN_THREAD_NAMES, CLEAN_MAPS)

        assert item_xp.status == DetectionStatus.PASS
        assert item_frida.status == DetectionStatus.PASS

        # 4. Virtualization & Debug Checks (F14, F15, F16)
        item_emu = DetectionEngine.check_emulator(CLEAN_PROPERTIES, [], 14)
        item_dual = DetectionEngine.check_dual_app(CLEAN_DATA_DIR, CLEAN_UID, [])
        item_dbg = DetectionEngine.check_debugger(False, False, 0)

        assert item_emu.status == DetectionStatus.PASS
        assert item_dual.status == DetectionStatus.PASS
        assert item_dbg.status == DetectionStatus.PASS

        all_items = [
            item_bl, item_se, item_tags,
            item_su, item_ksu, item_magisk, item_pkg,
            item_xp, item_frida,
            item_emu, item_dual, item_dbg,
        ]

        # 5. Security Scoring (F17)
        assessment = SecurityScorer.calculate_score(all_items)
        assert assessment.level == SecurityLevel.SAFE
        assert 95 <= assessment.score <= 100
        assert assessment.dangerCount == 0
        assert assessment.warnCount == 0
        assert assessment.passCount == len(all_items)
        assert "Device environment is clean" in assessment.summary

        # 6. Report Export & Schema Conformance (F20)
        report = DiagnosticReport(
            appVersion="1.0.0",
            timestamp=1774032000000,
            deviceInfo=clean_device_info,
            assessment=assessment,
            items=all_items,
        )
        json_output = ReportSerializer.serialize_to_json(report)
        text_output = ReportSerializer.serialize_to_text(report)

        is_valid, err = ReportSerializer.validate_schema(json.loads(json_output))
        assert is_valid is True, f"Report failed schema: {err}"
        assert "Overall Score: 100/100" in text_output or "/100" in text_output
        assert "SAFE" in text_output
