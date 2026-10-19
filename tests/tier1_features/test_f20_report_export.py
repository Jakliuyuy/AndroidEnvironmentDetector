"""
Tier 1: Feature Coverage — F20 Diagnostic Report Export
5 Test Cases validating structured JSON export, schema conformance, device info, assessment summary, and plain text.
"""
import json
import pytest
from tests.harness.contracts import (
    DiagnosticReport,
    DeviceInfo,
    SecurityAssessment,
    SecurityLevel,
)
from tests.harness.report_serializer import ReportSerializer


class TestF20ReportExport:
    def test_f20_json_export_schema_valid(self, clean_device_info, clean_items_list):
        """JSON diagnostic report strictly conforms to PROJECT.md Export Contract schema"""
        assessment = SecurityAssessment(
            score=100,
            level=SecurityLevel.SAFE,
            dangerCount=0,
            warnCount=0,
            passCount=len(clean_items_list),
            summary="All clean",
        )
        report = DiagnosticReport(
            appVersion="1.0.0",
            timestamp=1774032000000,
            deviceInfo=clean_device_info,
            assessment=assessment,
            items=clean_items_list,
        )
        json_str = ReportSerializer.serialize_to_json(report)
        data = json.loads(json_str)

        is_valid, err = ReportSerializer.validate_schema(data)
        assert is_valid is True, f"Schema validation error: {err}"

    def test_f20_plaintext_export_contains_all_fields(self, clean_device_info, clean_items_list):
        """Plaintext diagnostic report contains human-readable summaries and divider lines"""
        assessment = SecurityAssessment(
            score=100,
            level=SecurityLevel.SAFE,
            dangerCount=0,
            warnCount=0,
            passCount=len(clean_items_list),
            summary="Clean retail device",
        )
        report = DiagnosticReport(
            appVersion="1.0.0",
            timestamp=1774032000000,
            deviceInfo=clean_device_info,
            assessment=assessment,
            items=clean_items_list,
        )
        txt = ReportSerializer.serialize_to_text(report)
        assert "ANDROID ENVIRONMENT SECURITY DETECTION REPORT" in txt
        assert "Pixel 8 Pro" in txt
        assert "Overall Score: 100/100" in txt
        assert "SEC-R1-01" in txt

    def test_f20_device_info_in_exported_report(self, clean_device_info, clean_items_list):
        """Device metadata (fingerprint, brand, model, apiLevel, arch) matches in export"""
        assessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, len(clean_items_list), "Clean")
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, clean_items_list)
        d = report.to_dict()
        assert d["deviceInfo"]["brand"] == "google"
        assert d["deviceInfo"]["model"] == "Pixel 8 Pro"
        assert d["deviceInfo"]["apiLevel"] == 34
        assert d["deviceInfo"]["arch"] == "arm64-v8a"

    def test_f20_assessment_metrics_in_exported_report(self, clean_device_info, clean_items_list):
        """Assessment object correctly exports dangerCount, warnCount, passCount, score, and level"""
        assessment = SecurityAssessment(35, SecurityLevel.DANGEROUS, 2, 1, 9, "Danger detected")
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, clean_items_list)
        d = report.to_dict()
        ass = d["assessment"]
        assert ass["score"] == 35
        assert ass["level"] == "DANGEROUS"
        assert ass["dangerCount"] == 2
        assert ass["warnCount"] == 1
        assert ass["passCount"] == 9

    def test_f20_item_details_and_evidence_in_exported_report(self, clean_device_info, clean_items_list):
        """Item array in JSON export contains exact evidence string and method string for each item"""
        assessment = SecurityAssessment(100, SecurityLevel.SAFE, 0, 0, len(clean_items_list), "Clean")
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, clean_items_list)
        d = report.to_dict()
        items = d["items"]
        assert len(items) == len(clean_items_list)
        assert items[0]["evidence"] == "ro.boot.flash.locked=1"
        assert items[0]["method"] == "DIRECT_SYSCALL"
        assert items[0]["status"] == "PASS"
