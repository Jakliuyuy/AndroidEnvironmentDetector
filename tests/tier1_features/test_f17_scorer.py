"""
Tier 1: Feature Coverage — F17 Asymmetric Security Scorer
5 Test Cases validating asymmetric risk override model, thresholds, penalty logic, and ratings.
"""
import pytest
from tests.harness.contracts import (
    DetectionItem,
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    SecurityLevel,
)
from tests.harness.scorer import SecurityScorer


class TestF17Scorer:
    def test_f17_all_pass_yields_score_95_to_100_safe(self, clean_items_list):
        """When all detection items pass, overall score must be 95-100 and SAFE"""
        assessment = SecurityScorer.calculate_score(clean_items_list)
        assert 95 <= assessment.score <= 100
        assert assessment.level == SecurityLevel.SAFE
        assert assessment.dangerCount == 0
        assert assessment.warnCount == 0
        assert assessment.passCount == len(clean_items_list)

    def test_f17_single_danger_caps_score_at_40_dangerous(self, clean_items_list):
        """A single DANGER item caps score at <= 40 with DANGEROUS level"""
        corrupted_items = list(clean_items_list)
        corrupted_items[0] = DetectionItem(
            "SEC-R1-01", "Bootloader", DetectionCategory.BOOTLOADER,
            DetectionStatus.DANGER, "ro.boot.flash.locked=0", DetectionMethod.DIRECT_SYSCALL
        )
        assessment = SecurityScorer.calculate_score(corrupted_items)
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.dangerCount == 1

    def test_f17_single_warn_caps_score_at_75_warning(self, clean_items_list):
        """A single WARN item (no DANGER) caps score at <= 75 with WARNING level"""
        warn_items = list(clean_items_list)
        warn_items[2] = DetectionItem(
            "SEC-R1-03", "Build Tags", DetectionCategory.BOOTLOADER,
            DetectionStatus.WARN, "ro.build.tags=test-keys", DetectionMethod.NATIVE_LIBC
        )
        assessment = SecurityScorer.calculate_score(warn_items)
        assert assessment.score <= 75
        assert assessment.score >= 41
        assert assessment.level == SecurityLevel.WARNING
        assert assessment.warnCount == 1
        assert assessment.dangerCount == 0

    def test_f17_multiple_danger_capped_at_40_dangerous(self, clean_items_list):
        """Multiple DANGER items still result in DANGEROUS rating and non-negative score"""
        dangerous_items = list(clean_items_list)
        for i in range(5):
            dangerous_items[i] = DetectionItem(
                f"SEC-DNG-{i}", f"Threat {i}", DetectionCategory.ROOT,
                DetectionStatus.DANGER, "Compromised", DetectionMethod.DIRECT_SYSCALL
            )
        assessment = SecurityScorer.calculate_score(dangerous_items)
        assert 0 <= assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.dangerCount == 5

    def test_f17_empty_items_yields_safe_base_score(self):
        """Empty detection items list yields default SAFE assessment"""
        assessment = SecurityScorer.calculate_score([])
        assert assessment.score == 100
        assert assessment.level == SecurityLevel.SAFE
        assert assessment.dangerCount == 0
