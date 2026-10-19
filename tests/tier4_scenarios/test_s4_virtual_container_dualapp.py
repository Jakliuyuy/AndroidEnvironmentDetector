"""
Tier 4: Scenario 4 — VirtualApp / Parallel Space Dual Container (S4)
Exercises Features: F14-F15, F17, F20
Threat Model & Validation Target:
Validates private storage path redirection and package mismatch identification.
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
from tests.fixtures.clean_device_data import CLEAN_PROPERTIES
from tests.fixtures.virtual_container_data import (
    VIRTUAL_APP_PATH,
    DUAL_SPACE_UID,
    VIRTUAL_CONTAINER_PACKAGES,
)


class TestScenario4VirtualContainerDualApp:
    def test_s4_virtual_app_container_sandbox_detection(self, clean_device_info):
        """
        Executes security evaluation against an application running inside an isolation container
        such as VirtualApp, Parallel Space, or sub-user dual-app workspace.
        Verifies detection of redirected /data/data paths, abnormal sub-user UIDs, and container APKs.
        """
        # Baseline checks
        item_bl = DetectionEngine.check_bootloader(CLEAN_PROPERTIES)
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")

        # Virtualization & Container checks (F14, F15)
        item_emu = DetectionEngine.check_emulator(CLEAN_PROPERTIES, [], 10)
        item_dual = DetectionEngine.check_dual_app(VIRTUAL_APP_PATH, DUAL_SPACE_UID, VIRTUAL_CONTAINER_PACKAGES)

        assert item_emu.status == DetectionStatus.PASS
        assert item_dual.status == DetectionStatus.WARN
        assert item_dual.category == DetectionCategory.VIRTUAL
        assert "io.va.exposed" in item_dual.evidence
        assert "Dual-space multi-user ID" in item_dual.evidence
        assert "Container package detected" in item_dual.evidence

        all_items = [item_bl, item_se, item_emu, item_dual]

        # Scoring verification (WARN caps score at 75)
        assessment = SecurityScorer.calculate_score(all_items)
        assert assessment.level == SecurityLevel.WARNING
        assert 41 <= assessment.score <= 75
        assert assessment.warnCount == 1
        assert assessment.dangerCount == 0

        # Export report verification
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, all_items)
        data = json.loads(ReportSerializer.serialize_to_json(report))
        is_valid, err = ReportSerializer.validate_schema(data)
        assert is_valid is True
        assert data["assessment"]["level"] == "WARNING"
        assert data["assessment"]["score"] <= 75
