"""
Tier 1: Feature Coverage — F12 Xposed / LSPosed Detection
5 Test Cases validating ClassLoader inspection, stack trace frames, and memory maps hooking.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.clean_device_data import CLEAN_MAPS
from tests.fixtures.frida_hook_data import XPOSED_LOADED_CLASSES, XPOSED_STACKTRACE, INJECTED_MAPS


class TestF12XposedLSPosed:
    def test_f12_clean_classloader_returns_pass(self):
        """Clean runtime without Xposed classes, stackframes, or maps returns PASS"""
        item = DetectionEngine.check_xposed([], "", CLEAN_MAPS)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.HOOK
        assert "No Xposed/LSPosed class or memory mapping found" in item.evidence

    def test_f12_xposed_bridge_class_returns_danger(self):
        """Loaded de.robv.android.xposed.XposedBridge class triggers DANGER"""
        classes = ["de.robv.android.xposed.XposedBridge"]
        item = DetectionEngine.check_xposed(classes, "", CLEAN_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "Xposed class loaded" in item.evidence
        assert "XposedBridge" in item.evidence

    def test_f12_lsposed_class_returns_danger(self):
        """Loaded org.lsposed.lspd.core.Main class triggers DANGER"""
        classes = ["org.lsposed.lspd.core.Main"]
        item = DetectionEngine.check_xposed(classes, "", CLEAN_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "org.lsposed.lspd" in item.evidence

    def test_f12_xposed_stackframe_detected_returns_danger(self):
        """Stack trace containing XposedBridge frame triggers DANGER"""
        item = DetectionEngine.check_xposed([], XPOSED_STACKTRACE, CLEAN_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "Xposed stack trace frame detected" in item.evidence

    def test_f12_liblsp_in_maps_detected_returns_danger(self):
        """Memory map containing /data/adb/lspd/liblsp.so triggers DANGER"""
        item = DetectionEngine.check_xposed([], "", INJECTED_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "liblsp.so" in item.evidence
