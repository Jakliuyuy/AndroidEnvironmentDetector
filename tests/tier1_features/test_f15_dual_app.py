"""
Tier 1: Feature Coverage — F15 Dual-App & Virtual Container
5 Test Cases validating storage redirection, user 999 sub-user, container packages, and normal UID path.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.clean_device_data import CLEAN_DATA_DIR, CLEAN_UID
from tests.fixtures.virtual_container_data import (
    VIRTUAL_APP_PATH,
    DUAL_SPACE_UID,
    DUAL_SPACE_PATH,
    VIRTUAL_CONTAINER_PACKAGES,
)


class TestF15DualApp:
    def test_f15_standard_data_path_returns_pass(self):
        """Standard private data path (/data/user/0/<pkg>) and UID returns PASS"""
        item = DetectionEngine.check_dual_app(CLEAN_DATA_DIR, CLEAN_UID, [])
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.VIRTUAL
        assert "Normal private storage path" in item.evidence

    def test_f15_virtualapp_exposed_path_returns_warn(self):
        """Redirected path containing io.va.exposed triggers WARN"""
        item = DetectionEngine.check_dual_app(VIRTUAL_APP_PATH, CLEAN_UID, [])
        assert item.status == DetectionStatus.WARN
        assert "Redirected private path" in item.evidence
        assert "io.va.exposed" in item.evidence

    def test_f15_dual_space_uid_999_returns_warn(self):
        """Sub-user UID in 99900000..99999999 range triggers WARN"""
        item = DetectionEngine.check_dual_app(DUAL_SPACE_PATH, DUAL_SPACE_UID, [])
        assert item.status == DetectionStatus.WARN
        assert "Dual-space multi-user ID" in item.evidence

    def test_f15_parallel_space_path_returns_warn(self):
        """Path containing com.lbe.parallel triggers WARN"""
        parallel_path = "/data/data/com.lbe.parallel/virtual/data/user/0/com.security.app"
        item = DetectionEngine.check_dual_app(parallel_path, CLEAN_UID, [])
        assert item.status == DetectionStatus.WARN
        assert "Redirected private path" in item.evidence

    def test_f15_container_package_detected_returns_warn(self):
        """Installed virtual container packages trigger WARN"""
        item = DetectionEngine.check_dual_app(CLEAN_DATA_DIR, CLEAN_UID, VIRTUAL_CONTAINER_PACKAGES)
        assert item.status == DetectionStatus.WARN
        assert "Container package detected" in item.evidence
