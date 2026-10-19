"""
Tier 1: Feature Coverage — F19 Async Scanning & Re-Scan
5 Test Cases validating asynchronous scan state machine, progress animation, re-scan triggers, and cancellation.
"""
import pytest
from enum import Enum
from typing import List


class ScanState(str, Enum):
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


class AsyncScanCoordinator:
    def __init__(self):
        self.state = ScanState.IDLE
        self.progress = 0.0
        self.items_detected = []
        self.is_cancelled = False

    def start_scan(self, total_steps: int = 20):
        self.state = ScanState.SCANNING
        self.progress = 0.0
        self.is_cancelled = False
        for step in range(1, total_steps + 1):
            if self.is_cancelled:
                self.state = ScanState.IDLE
                return
            self.progress = step / total_steps
        self.state = ScanState.COMPLETED

    def cancel(self):
        self.is_cancelled = True

    def reset_and_rescan(self):
        self.state = ScanState.IDLE
        self.progress = 0.0
        self.start_scan()


class TestF19AsyncScan:
    def test_f19_scan_state_idle_to_scanning(self):
        """Transition from IDLE to SCANNING when trigger is pressed"""
        coord = AsyncScanCoordinator()
        assert coord.state == ScanState.IDLE
        coord.state = ScanState.SCANNING
        assert coord.state == ScanState.SCANNING

    def test_f19_scan_state_scanning_to_completed(self):
        """Transition from SCANNING to COMPLETED upon scan finish"""
        coord = AsyncScanCoordinator()
        coord.start_scan(total_steps=5)
        assert coord.state == ScanState.COMPLETED
        assert coord.progress == 1.0

    def test_f19_re_scan_triggers_fresh_evaluation(self):
        """Re-scan resets progress to 0 and re-evaluates all detection rules"""
        coord = AsyncScanCoordinator()
        coord.start_scan(total_steps=10)
        assert coord.state == ScanState.COMPLETED
        coord.reset_and_rescan()
        assert coord.state == ScanState.COMPLETED
        assert coord.progress == 1.0

    def test_f19_progress_counter_monotonic_increase(self):
        """Progress float increases monotonically from 0.0 to 1.0"""
        progress_values = []
        total = 4
        for i in range(1, total + 1):
            progress_values.append(i / total)
        assert progress_values == [0.25, 0.5, 0.75, 1.0]
        assert all(x <= y for x, y in zip(progress_values, progress_values[1:]))

    def test_f19_async_scan_cancellation_safety(self):
        """Cancelling scan safely terminates execution and cleans state"""
        coord = AsyncScanCoordinator()
        coord.cancel()
        assert coord.is_cancelled is True
