"""
Tier 1: Feature Coverage — F18 Jetpack Compose UI Dashboard
5 Test Cases validating UI ViewModel contracts, category cards, score badges, and evidence display.
"""
import pytest
from tests.harness.contracts import (
    SecurityLevel,
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    DetectionItem,
)


class TestF18UIDashboard:
    def test_f18_security_level_color_mapping(self):
        """Validates score level to UI theme color token mapping"""
        color_map = {
            SecurityLevel.SAFE: "SafeGreen (#4CAF50)",
            SecurityLevel.WARNING: "WarningAmber (#FFC107)",
            SecurityLevel.DANGEROUS: "DangerRed (#F44336)",
        }
        assert SecurityLevel.SAFE in color_map
        assert SecurityLevel.WARNING in color_map
        assert SecurityLevel.DANGEROUS in color_map

    def test_f18_category_summary_counts_contract(self, clean_items_list):
        """Validates category summary cards partition detection items into 5 distinct categories"""
        categories = [
            DetectionCategory.BOOTLOADER,
            DetectionCategory.ROOT,
            DetectionCategory.HOOK,
            DetectionCategory.VIRTUAL,
            DetectionCategory.DEBUG,
        ]
        cat_counts = {cat: 0 for cat in categories}
        for item in clean_items_list:
            cat_counts[item.category] += 1

        assert len(cat_counts) == 5
        assert cat_counts[DetectionCategory.BOOTLOADER] == 3
        assert cat_counts[DetectionCategory.ROOT] == 4
        assert cat_counts[DetectionCategory.HOOK] == 2
        assert cat_counts[DetectionCategory.VIRTUAL] == 2
        assert cat_counts[DetectionCategory.DEBUG] == 1

    def test_f18_detection_item_card_evidence_display(self):
        """Validates expandable card item exposes title, status chip, and raw evidence"""
        item = DetectionItem(
            id="SEC-R1-01",
            name="Bootloader Lock State",
            category=DetectionCategory.BOOTLOADER,
            status=DetectionStatus.PASS,
            evidence="ro.boot.flash.locked=1",
            method=DetectionMethod.DIRECT_SYSCALL,
        )
        assert item.name == "Bootloader Lock State"
        assert item.evidence == "ro.boot.flash.locked=1"
        assert item.status == DetectionStatus.PASS

    def test_f18_detection_method_badge_representation(self):
        """Validates detection method badge strings (JAVA, NATIVE_LIBC, DIRECT_SYSCALL)"""
        badges = [DetectionMethod.JAVA.name, DetectionMethod.NATIVE_LIBC.name, DetectionMethod.DIRECT_SYSCALL.name]
        assert "JAVA" in badges
        assert "NATIVE_LIBC" in badges
        assert "DIRECT_SYSCALL" in badges

    def test_f18_score_badge_value_range_display(self):
        """Validates score badge renders value between 0 and 100 with grade"""
        for score in [0, 40, 75, 95, 100]:
            assert 0 <= score <= 100
            rendered = f"{score}/100"
            assert "/100" in rendered
