"""
Asymmetric Security Scorer implementation conforming to PROJECT.md specifications:
- Any DANGER status item caps the score at <= 40, rating DANGEROUS.
- Any WARN status item (with no DANGER) caps the score at <= 75, rating WARNING.
- All PASS status items yields score in 95..100, rating SAFE.
"""
from typing import List
from tests.harness.contracts import (
    DetectionItem,
    DetectionStatus,
    SecurityAssessment,
    SecurityLevel,
)


class SecurityScorer:
    BASE_SCORE = 100
    DANGER_PENALTY = 25
    WARN_PENALTY = 10

    @classmethod
    def calculate_score(cls, items: List[DetectionItem]) -> SecurityAssessment:
        if not items:
            return SecurityAssessment(
                score=100,
                level=SecurityLevel.SAFE,
                dangerCount=0,
                warnCount=0,
                passCount=0,
                summary="No detection items evaluated.",
            )

        danger_count = sum(1 for item in items if item.status == DetectionStatus.DANGER)
        warn_count = sum(1 for item in items if item.status == DetectionStatus.WARN)
        pass_count = sum(1 for item in items if item.status == DetectionStatus.PASS)

        # Raw penalty calculation
        raw_score = cls.BASE_SCORE - (danger_count * cls.DANGER_PENALTY) - (warn_count * cls.WARN_PENALTY)
        raw_score = max(0, min(cls.BASE_SCORE, raw_score))

        # Asymmetric Override Logic
        if danger_count > 0:
            level = SecurityLevel.DANGEROUS
            score = min(raw_score, 40)
            summary = f"High security risk detected: {danger_count} dangerous condition(s) found."
        elif warn_count > 0:
            level = SecurityLevel.WARNING
            score = max(41, min(raw_score, 75))
            summary = f"Potential security risks detected: {warn_count} warning(s) found."
        else:
            level = SecurityLevel.SAFE
            score = max(95, min(cls.BASE_SCORE, raw_score))
            summary = f"Device environment is clean: all {pass_count} checks passed."

        return SecurityAssessment(
            score=score,
            level=level,
            dangerCount=danger_count,
            warnCount=warn_count,
            passCount=pass_count,
            summary=summary,
        )
