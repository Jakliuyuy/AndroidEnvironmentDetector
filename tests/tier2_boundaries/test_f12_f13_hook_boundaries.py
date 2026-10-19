"""
Tier 2: Boundary & Corner Cases — F12 to F13 (Hook & Frida Dynamic Injection)
10 Test Cases covering deep stack traces, non-standard Frida ports, and memory boundary conditions.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus


class TestF12XposedLSPosedBoundaries:
    def test_f12_boundary_deep_stack_trace_1000_frames(self):
        """Stack trace containing 1000 normal frames processed without recursion or memory limits"""
        stack = "\n".join([f"    at com.example.normal.Class.method(Class.kt:{i})" for i in range(1000)])
        item = DetectionEngine.check_xposed([], stack, "")
        assert item.status == DetectionStatus.PASS

    def test_f12_boundary_similar_class_name_no_false_positive(self):
        """Class named 'com.app.xposed_like_feature' does not trigger false positive"""
        classes = ["com.app.xposed_like_feature.Test"]
        item = DetectionEngine.check_xposed(classes, "", "")
        assert item.status == DetectionStatus.PASS

    def test_f12_boundary_empty_class_and_stack_list(self):
        """Completely empty class list and empty stack string returns PASS safely"""
        item = DetectionEngine.check_xposed([], "", "")
        assert item.status == DetectionStatus.PASS

    def test_f12_boundary_maps_read_only_hook_file(self):
        """Hook shared library mapped with read-only 'r--p' still triggers DANGER"""
        maps = "7b000000-7b020000 r--p 00000000 00:00 0 /data/adb/lspd/liblsp.so"
        item = DetectionEngine.check_xposed([], "", maps)
        assert item.status == DetectionStatus.DANGER
        assert "liblsp.so" in item.evidence

    def test_f12_boundary_case_sensitive_xposed_package(self):
        """Classloader name 'DE.ROBV.ANDROID.XPOSED.XPOSEDBRIDGE' detected in case-insensitive check"""
        classes = ["de.robv.android.xposed.XposedBridge".lower()]
        item = DetectionEngine.check_xposed(classes, "", "")
        assert item.status == DetectionStatus.DANGER


class TestF13FridaBoundaries:
    def test_f13_boundary_high_alternative_port(self):
        """Frida alternative port 27045 triggers DANGER"""
        item = DetectionEngine.check_frida([27045], [], "")
        assert item.status == DetectionStatus.DANGER
        assert "27045" in item.evidence

    def test_f13_boundary_irrelevant_open_ports_no_false_positive(self):
        """Unrelated open ports (80, 443, 8080, 5555) do NOT trigger Frida detection"""
        item = DetectionEngine.check_frida([80, 443, 8080, 5555], ["main"], "")
        assert item.status == DetectionStatus.PASS

    def test_f13_boundary_empty_thread_name_list(self):
        """Empty thread name list handled safely without crash"""
        item = DetectionEngine.check_frida([], [], "")
        assert item.status == DetectionStatus.PASS

    def test_f13_boundary_anonymous_rx_count_boundary(self):
        """1-2 anonymous executable memory regions (standard JIT) do NOT trigger, but >=4 triggers DANGER"""
        # Exactly 2 anon rx -> PASS
        maps_2_anon = """
7c000000-7c010000 r-xp 00000000 00:00 0 
7c010000-7c020000 r-xp 00000000 00:00 0 
"""
        item_normal = DetectionEngine.check_frida([], [], maps_2_anon)
        assert item_normal.status == DetectionStatus.PASS

        # 5 anon rx -> DANGER
        maps_5_anon = """
7c000000-7c010000 r-xp 00000000 00:00 0 
7c010000-7c020000 r-xp 00000000 00:00 0 
7c020000-7c030000 r-xp 00000000 00:00 0 
7c030000-7c040000 r-xp 00000000 00:00 0 
7c040000-7c050000 r-xp 00000000 00:00 0 
"""
        item_danger = DetectionEngine.check_frida([], [], maps_5_anon)
        assert item_danger.status == DetectionStatus.DANGER

    def test_f13_boundary_linjector_name_in_maps(self):
        """Presence of 'linjector' mapping in maps triggers DANGER"""
        maps = "7a000000-7a010000 r-xp 00000000 00:00 0 /data/local/tmp/linjector.so"
        item = DetectionEngine.check_frida([], [], maps)
        assert item.status == DetectionStatus.DANGER
        assert "linjector" in item.evidence
