"""
Report serializer and JSON schema validator for Android Environment Security Detection.
Conforms strictly to PROJECT.md § Export Contract: ReportSerializer.
"""
import json
from typing import Dict, Any, Tuple
from tests.harness.contracts import DiagnosticReport, DeviceInfo, SecurityAssessment, DetectionItem, DetectionCategory, DetectionStatus, DetectionMethod, SecurityLevel


class ReportSerializer:
    @classmethod
    def serialize_to_json(cls, report: DiagnosticReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def serialize_to_text(cls, report: DiagnosticReport) -> str:
        lines = [
            "=" * 60,
            "ANDROID ENVIRONMENT SECURITY DETECTION REPORT",
            "=" * 60,
            f"App Version: {report.appVersion}",
            f"Timestamp:   {report.timestamp}",
            "-" * 60,
            "DEVICE INFORMATION:",
            f"  Brand / Model: {report.deviceInfo.brand} {report.deviceInfo.model}",
            f"  Fingerprint:   {report.deviceInfo.fingerprint}",
            f"  Android Ver:   {report.deviceInfo.androidVersion} (API {report.deviceInfo.apiLevel})",
            f"  Architecture:  {report.deviceInfo.arch}",
            "-" * 60,
            "SECURITY ASSESSMENT:",
            f"  Overall Score: {report.assessment.score}/100",
            f"  Risk Level:    {report.assessment.level.value if hasattr(report.assessment.level, 'value') else report.assessment.level}",
            f"  Passed Checks: {report.assessment.passCount}",
            f"  Warnings:      {report.assessment.warnCount}",
            f"  Dangers:       {report.assessment.dangerCount}",
            f"  Summary:       {report.assessment.summary}",
            "-" * 60,
            "DETECTION DETAILS:",
        ]

        for item in report.items:
            cat_name = item.category.name if hasattr(item.category, "name") else str(item.category)
            status_name = item.status.name if hasattr(item.status, "name") else str(item.status)
            method_name = item.method.name if hasattr(item.method, "name") else str(item.method)
            lines.append(f"[{status_name}] [{cat_name}] {item.id}: {item.name}")
            lines.append(f"     Method:   {method_name}")
            lines.append(f"     Evidence: {item.evidence}")

        lines.append("=" * 60)
        return "\n".join(lines)

    @classmethod
    def validate_schema(cls, data: Any) -> Tuple[bool, str]:
        """
        Validates JSON structure according to PROJECT.md § Export Contract.
        Returns (is_valid, error_message).
        """
        if not isinstance(data, dict):
            return False, "Root element must be a JSON object"

        # Check root fields
        required_root_keys = ["appVersion", "timestamp", "deviceInfo", "assessment", "items"]
        for key in required_root_keys:
            if key not in data:
                return False, f"Missing required root key: {key}"

        if not isinstance(data["appVersion"], str) or not data["appVersion"].strip():
            return False, "appVersion must be a non-empty string"
        if not isinstance(data["timestamp"], (int, float)) or data["timestamp"] < 0:
            return False, "timestamp must be a non-negative number"

        # Validate deviceInfo
        dev = data["deviceInfo"]
        if not isinstance(dev, dict):
            return False, "deviceInfo must be an object"
        for dev_key in ["fingerprint", "brand", "model", "androidVersion", "apiLevel", "arch"]:
            if dev_key not in dev:
                return False, f"deviceInfo missing required key: {dev_key}"
        if not isinstance(dev["apiLevel"], int) or dev["apiLevel"] <= 0:
            return False, "apiLevel must be a positive integer"

        # Validate assessment
        ass = data["assessment"]
        if not isinstance(ass, dict):
            return False, "assessment must be an object"
        for ass_key in ["score", "level", "dangerCount", "warnCount", "passCount"]:
            if ass_key not in ass:
                return False, f"assessment missing required key: {ass_key}"
        if not (0 <= ass["score"] <= 100):
            return False, f"score must be between 0 and 100, got {ass['score']}"
        if ass["level"] not in ["SAFE", "WARNING", "DANGEROUS"]:
            return False, f"invalid risk level: {ass['level']}"

        # Validate items
        items = data["items"]
        if not isinstance(items, list):
            return False, "items must be a list"

        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                return False, f"items[{idx}] must be an object"
            for item_key in ["id", "name", "category", "status", "evidence", "method"]:
                if item_key not in item:
                    return False, f"items[{idx}] missing key: {item_key}"
            if item["category"] not in ["BOOTLOADER", "ROOT", "HOOK", "VIRTUAL", "DEBUG"]:
                return False, f"items[{idx}] invalid category: {item['category']}"
            if item["status"] not in ["PASS", "WARN", "DANGER"]:
                return False, f"items[{idx}] invalid status: {item['status']}"
            if item["method"] not in ["JAVA", "NATIVE_LIBC", "DIRECT_SYSCALL"]:
                return False, f"items[{idx}] invalid method: {item['method']}"

        return True, "Valid"
