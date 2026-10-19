"""
Tier 1: Feature Coverage — F13 Frida Dynamic Instrumentation
5 Test Cases validating Frida default port 27042, alternative ports, threads, agent library, and anon r-xp memory.
"""
import pytest
from tests.harness.detection_engine import DetectionEngine
from tests.harness.contracts import DetectionStatus, DetectionCategory
from tests.fixtures.clean_device_data import CLEAN_MAPS
from tests.fixtures.frida_hook_data import FRIDA_OPEN_PORTS, HOOK_THREAD_NAMES, INJECTED_MAPS


class TestF13Frida:
    def test_f13_clean_runtime_returns_pass(self):
        """Clean runtime with no open Frida ports, standard threads, and no agent in maps returns PASS"""
        item = DetectionEngine.check_frida([], ["main", "RenderThread"], CLEAN_MAPS)
        assert item.status == DetectionStatus.PASS
        assert item.category == DetectionCategory.HOOK
        assert "No Frida port, thread, or anonymous executable mapping" in item.evidence

    def test_f13_default_port_27042_returns_danger(self):
        """Active listening port 27042 triggers DANGER"""
        item = DetectionEngine.check_frida([27042], ["main"], CLEAN_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "Frida default port 27042 active" in item.evidence

    def test_f13_gum_js_loop_thread_returns_danger(self):
        """Presence of thread named gum-js-loop triggers DANGER"""
        item = DetectionEngine.check_frida([], ["main", "gum-js-loop"], CLEAN_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "Frida thread detected: gum-js-loop" in item.evidence

    def test_f13_frida_agent_so_in_maps_returns_danger(self):
        """Presence of frida-agent-64.so in /proc/self/maps triggers DANGER"""
        item = DetectionEngine.check_frida([], ["main"], INJECTED_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "frida-agent-64.so" in item.evidence

    def test_f13_multiple_anon_rx_memory_regions_returns_danger(self):
        """Multiple anonymous r-xp memory regions trigger DANGER"""
        item = DetectionEngine.check_frida([], ["main"], INJECTED_MAPS)
        assert item.status == DetectionStatus.DANGER
        assert "Suspicious anonymous executable memory regions" in item.evidence
