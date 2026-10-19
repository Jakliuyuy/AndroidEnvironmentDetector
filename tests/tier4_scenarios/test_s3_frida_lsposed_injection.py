"""
Tier 4: Scenario 3 — Active Frida/LSPosed Dynamic Injection (S3)
Exercises Features: F12-F13, F03, F04, F17
Threat Model & Validation Target:
Validates detection of anonymous r-xp memory, Frida ports/threads, and Xposed classes overriding normal state.
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
from tests.fixtures.frida_hook_data import (
    FRIDA_OPEN_PORTS,
    HOOK_THREAD_NAMES,
    XPOSED_LOADED_CLASSES,
    XPOSED_STACKTRACE,
    INJECTED_MAPS,
)


class TestScenario3FridaLSPosedInjection:
    def test_s3_active_dynamic_hook_and_injection(self, clean_device_info):
        """
        Executes security evaluation against a process undergoing dynamic instrumentation
        by Frida and LSPosed.
        Verifies detection of injected shared libraries, anonymous executable memory,
        background instrumentation threads, and active TCP ports.
        """
        # Hook & Injection checks (F12, F13)
        item_xp = DetectionEngine.check_xposed(XPOSED_LOADED_CLASSES, XPOSED_STACKTRACE, INJECTED_MAPS)
        item_frida = DetectionEngine.check_frida(FRIDA_OPEN_PORTS, HOOK_THREAD_NAMES, INJECTED_MAPS)

        # Baseline checks
        item_bl = DetectionEngine.check_bootloader(CLEAN_PROPERTIES)
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")

        assert item_xp.status == DetectionStatus.DANGER
        assert item_frida.status == DetectionStatus.DANGER
        assert item_xp.category == DetectionCategory.HOOK
        assert item_frida.category == DetectionCategory.HOOK

        # Forensic details
        assert "XposedBridge" in item_xp.evidence
        assert "liblsp.so" in item_xp.evidence
        assert "Frida default port 27042 active" in item_frida.evidence
        assert "gum-js-loop" in item_frida.evidence
        assert "frida-agent-64.so" in item_frida.evidence
        assert "Suspicious anonymous executable memory regions" in item_frida.evidence

        all_items = [item_bl, item_se, item_xp, item_frida]

        # Scoring verification
        assessment = SecurityScorer.calculate_score(all_items)
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.score <= 40
        assert assessment.dangerCount == 2

        # Export Report validation
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, all_items)
        data = json.loads(ReportSerializer.serialize_to_json(report))
        is_valid, err = ReportSerializer.validate_schema(data)
        assert is_valid is True
        assert data["assessment"]["level"] == "DANGEROUS"
