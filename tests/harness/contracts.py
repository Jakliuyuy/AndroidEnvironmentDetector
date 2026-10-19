"""
Data contracts and schema definitions for Android Environment Security Detection.
Matches specifications in PROJECT.md and TEST_INFRA.md.
"""
from enum import IntEnum, Enum
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any


class DetectionCategory(IntEnum):
    BOOTLOADER = 0
    ROOT = 1
    HOOK = 2
    VIRTUAL = 3
    DEBUG = 4

    @classmethod
    def from_name(cls, name: str) -> "DetectionCategory":
        return cls[name.upper()]


class DetectionStatus(IntEnum):
    PASS = 0
    WARN = 1
    DANGER = 2

    @classmethod
    def from_name(cls, name: str) -> "DetectionStatus":
        return cls[name.upper()]


class DetectionMethod(IntEnum):
    JAVA = 0
    NATIVE_LIBC = 1
    DIRECT_SYSCALL = 2

    @classmethod
    def from_name(cls, name: str) -> "DetectionMethod":
        return cls[name.upper()]


class SecurityLevel(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    DANGEROUS = "DANGEROUS"


@dataclass
class NativeDetectionItem:
    id: str
    name: str
    category: int
    status: int
    evidence: str
    method: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "evidence": self.evidence,
            "method": self.method,
        }


@dataclass
class DetectionItem:
    id: str
    name: str
    category: DetectionCategory
    status: DetectionStatus
    evidence: str
    method: DetectionMethod

    @classmethod
    def from_native(cls, native_item: NativeDetectionItem) -> "DetectionItem":
        return cls(
            id=native_item.id,
            name=native_item.name,
            category=DetectionCategory(native_item.category),
            status=DetectionStatus(native_item.status),
            evidence=native_item.evidence,
            method=DetectionMethod(native_item.method),
        )

    def to_export_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.name,
            "status": self.status.name,
            "evidence": self.evidence,
            "method": self.method.name,
        }


@dataclass
class DeviceInfo:
    fingerprint: str
    brand: str
    model: str
    androidVersion: str
    apiLevel: int
    arch: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAssessment:
    score: int
    level: SecurityLevel
    dangerCount: IntEnum
    warnCount: IntEnum
    passCount: IntEnum
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level.value if isinstance(self.level, SecurityLevel) else str(self.level),
            "dangerCount": int(self.dangerCount),
            "warnCount": int(self.warnCount),
            "passCount": int(self.passCount),
            "summary": self.summary,
        }


@dataclass
class DiagnosticReport:
    appVersion: str
    timestamp: int
    deviceInfo: DeviceInfo
    assessment: SecurityAssessment
    items: List[DetectionItem]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "appVersion": self.appVersion,
            "timestamp": self.timestamp,
            "deviceInfo": self.deviceInfo.to_dict(),
            "assessment": self.assessment.to_dict(),
            "items": [item.to_export_dict() for item in self.items],
        }
