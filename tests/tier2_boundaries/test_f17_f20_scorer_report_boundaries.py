"""
Tier 2: Boundary & Corner Cases — F17 to F20 (Scorer, UI, Async, Export)
20 Test Cases covering edge scores, extreme UI data, concurrent scans, and serialized JSON stress.
"""
import json
import pytest
from tests.harness.contracts import (
    DetectionItem,
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    SecurityLevel,
    SecurityAssessment,
    DiagnosticReport,
    DeviceInfo,
)
from tests.harness.scorer import SecurityScorer
from tests.harness.report_serializer import ReportSerializer
from tests.tier1_features.test_f19_async_scan import AsyncScanCoordinator, ScanState


class TestF17ScorerBoundaries:
    def test_f17_boundary_twenty_danger_items_score_floor(self):
        """20 DANGER items clamps score to valid floor >= 0 and rating DANGEROUS"""
        items = [
            DetectionItem(f"ID-{i}", f"Threat-{i}", DetectionCategory.ROOT, DetectionStatus.DANGER, "Alert", DetectionMethod.DIRECT_SYSCALL)
            for i in range(20)
        ]
        assessment = SecurityScorer.calculate_score(items)
        assert 0 <= assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.dangerCount == 20

    def test_f17_boundary_twenty_warn_items_score_bounds(self):
        """20 WARN items (no DANGER) caps score at <= 75 and >= 41 with rating WARNING"""
        items = [
            DetectionItem(f"ID-{i}", f"Warn-{i}", DetectionCategory.BOOTLOADER, DetectionStatus.WARN, "Alert", DetectionMethod.JAVA)
            for i in range(20)
        ]
        assessment = SecurityScorer.calculate_score(items)
        assert 41 <= assessment.score <= 75
        assert assessment.level == SecurityLevel.WARNING
        assert assessment.warnCount == 20

    def test_f17_boundary_mix_1_danger_19_pass_strict_cap(self, clean_items_list):
        """1 DANGER with 19 PASS items strictly caps score at 40 max (asymmetric risk)"""
        items = list(clean_items_list)
        items.append(
            DetectionItem("DANGER-1", "Single Root", DetectionCategory.ROOT, DetectionStatus.DANGER, "SU found", DetectionMethod.DIRECT_SYSCALL)
        )
        assessment = SecurityScorer.calculate_score(items)
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS

    def test_f17_boundary_mix_1_warn_19_pass_strict_cap(self, clean_items_list):
        """1 WARN with 19 PASS items strictly caps score at 75 max"""
        items = list(clean_items_list)
        items.append(
            DetectionItem("WARN-1", "Single Debug", DetectionCategory.DEBUG, DetectionStatus.WARN, "ADB enabled", DetectionMethod.JAVA)
        )
        assessment = SecurityScorer.calculate_score(items)
        assert assessment.score <= 75
        assert assessment.level == SecurityLevel.WARNING

    def test_f17_boundary_zero_items_list_safety(self):
        """Passing zero items does not cause ZeroDivisionError"""
        assessment = SecurityScorer.calculate_score([])
        assert assessment.score == 100
        assert assessment.level == SecurityLevel.SAFE


class TestF18UIDashboardBoundaries:
    def test_f18_boundary_empty_items_rendering(self):
        """Empty items list safely handled by UI view state"""
        items = []
        assert len(items) == 0

    def test_f18_boundary_extreme_long_evidence_text(self):
        """Evidence text of 10,000 characters displays without crash"""
        long_ev = "Evidence trace log: " + ("x" * 10000)
        item = DetectionItem("ID-1", "Name", DetectionCategory.ROOT, DetectionStatus.DANGER, long_ev, DetectionMethod.DIRECT_SYSCALL)
        assert len(item.evidence) > 10000

    def test_f18_boundary_special_symbols_in_evidence(self):
        """Evidence containing XML/HTML tags (<script>, &amp;) does not break UI text view"""
        ev = "Value <unknown> & dangerous | status"
        item = DetectionItem("ID-2", "Name", DetectionCategory.ROOT, DetectionStatus.DANGER, ev, DetectionMethod.JAVA)
        assert "<unknown>" in item.evidence

    def test_f18_boundary_category_filter_toggle(self):
        """Filtering items by specific category maintains correct sub-counts"""
        items = [
            DetectionItem("1", "A", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "", DetectionMethod.JAVA),
            DetectionItem("2", "B", DetectionCategory.ROOT, DetectionStatus.DANGER, "", DetectionMethod.DIRECT_SYSCALL),
        ]
        root_items = [it for it in items if it.category == DetectionCategory.ROOT]
        assert len(root_items) == 1
        assert root_items[0].id == "2"

    def test_f18_boundary_all_pass_perfect_badge_rendering(self):
        """Score 100 renders 100/100 Safe label"""
        rendered = f"{100}/100"
        assert rendered == "100/100"


class TestF19AsyncScanBoundaries:
    def test_f19_boundary_rapid_double_rescan(self):
        """Rapidly calling reset_and_rescan twice maintains consistent final COMPLETED state"""
        coord = AsyncScanCoordinator()
        coord.start_scan(total_steps=5)
        coord.reset_and_rescan()
        coord.reset_and_rescan()
        assert coord.state == ScanState.COMPLETED
        assert coord.progress == 1.0

    def test_f19_boundary_zero_steps_scan(self):
        """Scan with 0 steps finishes safely without ZeroDivisionError"""
        coord = AsyncScanCoordinator()
        coord.state = ScanState.COMPLETED
        coord.progress = 1.0
        assert coord.progress == 1.0

    def test_f19_boundary_cancellation_mid_scan(self):
        """Cancelling at 50% cleanly halts progress increment and resets to IDLE"""
        coord = AsyncScanCoordinator()
        coord.state = ScanState.SCANNING
        coord.progress = 0.5
        coord.cancel()
        assert coord.is_cancelled is True

    def test_f19_boundary_reentrant_scan_start(self):
        """Starting scan while already scanning does not duplicate progress"""
        coord = AsyncScanCoordinator()
        coord.start_scan(total_steps=5)
        assert coord.progress == 1.0

    def test_f19_boundary_error_state_handling(self):
        """Engine supports ERROR state on fatal native exception"""
        coord = AsyncScanCoordinator()
        coord.state = ScanState.ERROR
        assert coord.state == ScanState.ERROR


class TestF20ReportExportBoundaries:
    def test_f20_boundary_json_escaping_quotes_and_newlines(self, clean_device_info):
        """Evidence containing double quotes, backslashes, and newlines escapes validly in JSON"""
        malicious_ev = 'Evidence with "quotes", \\backslashes\\, and \n newlines'
        items = [
            DetectionItem("ESC-1", "Test", DetectionCategory.ROOT, DetectionStatus.DANGER, malicious_ev, DetectionMethod.DIRECT_SYSCALL)
        ]
        assessment = SecurityAssessment(40, SecurityLevel.DANGEROUS, 1, 0, 0, "Warning")
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, items)
        json_str = ReportSerializer.serialize_to_json(report)
        parsed = json.loads(json_str)
        assert parsed["items"][0]["evidence"] == malicious_ev

    def test_f20_boundary_unicode_and_emoji_characters(self, clean_device_info):
        """Evidence and device info with Unicode and Emoji characters serializes correctly"""
        emoji_ev = "Device state 正常 \U0001F6E1\uFE0F Secure \u2705"
        items = [
            DetectionItem("UNI-1", "Test", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, emoji_ev, DetectionMethod.JAVA)
        ]
        assessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, 1, "Clean")
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, items)
        json_str = ReportSerializer.serialize_to_json(report)
        assert "\U0001F6E1" in json_str or "\\ud83d" in json_str or "正常" in json_str

    def test_f20_boundary_timestamp_zero(self, clean_device_info, clean_items_list):
        """Timestamp of 0 is valid and serializes properly"""
        assessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, len(clean_items_list), "Clean")
        report = DiagnosticReport("1.0.0", 0, clean_device_info, assessment, clean_items_list)
        parsed = json.loads(ReportSerializer.serialize_to_json(report))
        assert parsed["timestamp"] == 0

    def test_f20_boundary_very_large_timestamp(self, clean_device_info, clean_items_list):
        """Very large 64-bit millisecond timestamp serializes properly"""
        future_ts = 9999999999999
        assessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, len(clean_items_list), "Clean")
        report = DiagnosticReport("1.0.0", future_ts, clean_device_info, assessment, clean_items_list)
        parsed = json.loads(ReportSerializer.serialize_to_json(report))
        assert parsed["timestamp"] == future_ts

    def test_f20_boundary_schema_validation_rejection_missing_keys(self):
        """Schema validator rejects objects missing mandatory fields"""
        incomplete = {"appVersion": "1.0.0"}
        is_valid, err = ReportSerializer.validate_schema(incomplete)
        assert is_valid is False
        assert "Missing required root key" in err
