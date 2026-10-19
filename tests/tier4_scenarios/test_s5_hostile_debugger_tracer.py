"""
Tier 4: Scenario 5 — Hostile Debugger & TracerPid Attachment (S5)
Exercises Features: F16, F03, F17, F20
Threat Model & Validation Target:
Validates JDWP connection detection and /proc/self/status TracerPid non-zero alerting.
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
from tests.fixtures.hostile_debug_data import (
    DEBUGGER_CONNECTED,
    ADB_ENABLED,
    ATTACHED_TRACER_PID,
)


class TestScenario5HostileDebuggerTracer:
    def test_s5_hostile_tracer_and_jdwp_attachment(self, clean_device_info):
        """
        Executes security evaluation against a process under active debugging
        via TracerPid attachment (e.g. gdbserver, IDA Pro, Frida stalker ptrace)
        and active JDWP debugger connection.
        Verifies direct kernel status polling, TracerPid alerting, and score cap <= 40.
        """
        # Baseline checks
        item_bl = DetectionEngine.check_bootloader(CLEAN_PROPERTIES)
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")

        # Debugger and anti-tracking check (F16 via F03 Direct Syscall)
        item_dbg = DetectionEngine.check_debugger(DEBUGGER_CONNECTED, ADB_ENABLED, ATTACHED_TRACER_PID)

        assert item_dbg.status == DetectionStatus.DANGER
        assert item_dbg.category == DetectionCategory.DEBUG
        assert item_dbg.method == DetectionMethod.DIRECT_SYSCALL
        assert "JDWP debugger connected" in item_dbg.evidence
        assert f"TracerPid: {ATTACHED_TRACER_PID}" in item_dbg.evidence
        assert "ADB debugging is enabled" in item_dbg.evidence

        all_items = [item_bl, item_se, item_dbg]

        # Scoring verification
        assessment = SecurityScorer.calculate_score(all_items)
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.score <= 40
        assert assessment.dangerCount == 1

        # Diagnostic report export
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, all_items)
        data = json.loads(ReportSerializer.serialize_to_json(report))
        is_valid, err = ReportSerializer.validate_schema(data)
        assert is_valid is True
        assert data["assessment"]["level"] == "DANGEROUS"
        assert data["assessment"]["score"] <= 40
        assert any("TracerPid" in it["evidence"] for it in data["items"])
