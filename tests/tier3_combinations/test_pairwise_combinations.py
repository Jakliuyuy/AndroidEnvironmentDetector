"""
Tier 3: Cross-Feature Combinations
25 Pairwise Interaction Test Cases covering interdependent detection vectors and combined states (including v1.1.0 R1-R7).
"""
import json
import pytest
from tests.harness.contracts import (
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    DetectionItem,
    SecurityLevel,
    SecurityAssessment,
    DiagnosticReport,
    DeviceInfo,
)
from tests.harness.detection_engine import DetectionEngine, LowLevelParsers
from tests.harness.scorer import SecurityScorer
from tests.harness.report_serializer import ReportSerializer
from tests.harness.v110_engine import (
    KeyAttestationHarness,
    KernelProbeHarness,
    AntiHookHarness,
    StringObfuscatorHarness,
    ScanSnapshotHarness,
    VerifiedBootState,
    ItemDiffType,
)
from tests.fixtures.magisk_ksu_data import MAGISK_MOUNTINFO, KSU_MOUNTINFO, ROOT_PACKAGES
from tests.fixtures.frida_hook_data import INJECTED_MAPS, XPOSED_STACKTRACE


class TestTier3Combinations:
    # C01: Bootloader Unlocked (F05) + SELinux Permissive (F06)
    def test_c01_bootloader_unlocked_and_selinux_permissive(self):
        item_bl = DetectionEngine.check_bootloader({"ro.boot.flash.locked": "0"})
        item_se = DetectionEngine.check_selinux("0", "u:r:untrusted_app:s0")
        assert item_bl.status == DetectionStatus.DANGER
        assert item_se.status == DetectionStatus.DANGER
        assessment = SecurityScorer.calculate_score([item_bl, item_se])
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.dangerCount == 2

    # C02: Magisk Mount Inversion (F10) + Conventional SU (F08)
    def test_c02_magisk_mount_inversion_and_conventional_su(self):
        item_magisk = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, [])
        item_su = DetectionEngine.check_conventional_su(["/system/bin/su"], "/system/bin")
        assert item_magisk.status == DetectionStatus.DANGER
        assert item_su.status == DetectionStatus.DANGER
        assessment = SecurityScorer.calculate_score([item_magisk, item_su])
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS

    # C03: KernelSU OverlayFS (F09) + Root Manager Installed (F11)
    def test_c03_kernelsu_overlayfs_and_root_manager_installed(self):
        item_ksu = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.0")
        item_pkg = DetectionEngine.check_root_packages(["me.weishu.kernelsu"])
        assert item_ksu.status == DetectionStatus.DANGER
        assert item_pkg.status == DetectionStatus.DANGER
        assert "OverlayFS on /system" in item_ksu.evidence
        assert "me.weishu.kernelsu" in item_pkg.evidence

    # C04: Xposed Framework (F12) + Frida Port Active (F13)
    def test_c04_xposed_framework_and_frida_port_active(self):
        item_xp = DetectionEngine.check_xposed(["de.robv.android.xposed.XposedBridge"], "", "")
        item_frida = DetectionEngine.check_frida([27042], [], "")
        assert item_xp.status == DetectionStatus.DANGER
        assert item_frida.status == DetectionStatus.DANGER
        assessment = SecurityScorer.calculate_score([item_xp, item_frida])
        assert assessment.level == SecurityLevel.DANGEROUS

    # C05: Emulator Hardware (F14) + ADB Debugging Enabled (F16)
    def test_c05_emulator_hardware_and_adb_debugging_enabled(self):
        item_emu = DetectionEngine.check_emulator({"ro.hardware": "ranchu"}, [], 5)
        item_dbg = DetectionEngine.check_debugger(False, True, 0)
        assert item_emu.status == DetectionStatus.DANGER
        assert item_dbg.status == DetectionStatus.WARN
        assessment = SecurityScorer.calculate_score([item_emu, item_dbg])
        # Even with one WARN, DANGER dominates and caps score at <= 40
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS

    # C06: Dual-App Redirection (F15) + TracerPid Attachment (F16)
    def test_c06_dual_app_redirection_and_tracer_pid_attachment(self):
        item_dual = DetectionEngine.check_dual_app("/data/user/999/com.security.app", 99912345, [])
        item_dbg = DetectionEngine.check_debugger(False, False, 5678)
        assert item_dual.status == DetectionStatus.WARN
        assert item_dbg.status == DetectionStatus.DANGER
        assessment = SecurityScorer.calculate_score([item_dual, item_dbg])
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS

    # C07: Bootloader Clean + Stealth Magisk Compromise (F05 PASS + F10 DANGER)
    def test_c07_bootloader_clean_with_stealth_magisk_compromise(self):
        item_bl = DetectionEngine.check_bootloader({"ro.boot.flash.locked": "1", "ro.boot.verifiedbootstate": "green"})
        item_magisk = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, [])
        assert item_bl.status == DetectionStatus.PASS
        assert item_magisk.status == DetectionStatus.DANGER
        assessment = SecurityScorer.calculate_score([item_bl, item_magisk])
        # Magisk triggers override: score <= 40 despite locked BL
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS

    # C08: test-keys Signature + SELinux Enforcing (F07 WARN + F06 PASS)
    def test_c08_test_keys_signature_with_selinux_enforcing(self):
        item_tags = DetectionEngine.check_build_tags("test-keys", "user")
        item_se = DetectionEngine.check_selinux("1", "u:r:untrusted_app:s0")
        assert item_tags.status == DetectionStatus.WARN
        assert item_se.status == DetectionStatus.PASS
        assessment = SecurityScorer.calculate_score([item_tags, item_se])
        assert assessment.score <= 75
        assert assessment.level == SecurityLevel.WARNING

    # C09: JDWP Debugger + Xposed Stacktrace (F16 DANGER + F12 DANGER)
    def test_c09_jdwp_debugger_and_xposed_stacktrace(self):
        item_dbg = DetectionEngine.check_debugger(True, False, 0)
        item_xp = DetectionEngine.check_xposed([], XPOSED_STACKTRACE, "")
        assert item_dbg.status == DetectionStatus.DANGER
        assert item_xp.status == DetectionStatus.DANGER

    # C10: Frida Anonymous RX Memory + Direct Syscall Detection (F13 + F03)
    def test_c10_frida_anon_rx_memory_and_direct_syscall_detection(self):
        item_frida = DetectionEngine.check_frida([], [], INJECTED_MAPS)
        assert item_frida.status == DetectionStatus.DANGER
        assert item_frida.method == DetectionMethod.DIRECT_SYSCALL

    # C11: KernelSU OverlayFS + Emulator Environment (F09 + F14)
    def test_c11_kernelsu_and_emulator_environment(self):
        item_ksu = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.0")
        item_emu = DetectionEngine.check_emulator({"ro.kernel.qemu": "1"}, [], 0)
        assert item_ksu.status == DetectionStatus.DANGER
        assert item_emu.status == DetectionStatus.DANGER

    # C12: Magisk Zygisk Socket + LSPosed ClassLoader (F10 + F12)
    def test_c12_magisk_zygisk_and_lsposed_classloader(self):
        item_zygisk = DetectionEngine.check_magisk_zygisk("", ["@zygisk_daemon_64"])
        item_lsp = DetectionEngine.check_xposed(["org.lsposed.lspd.core.Main"], "", "")
        assert item_zygisk.status == DetectionStatus.DANGER
        assert item_lsp.status == DetectionStatus.DANGER

    # C13: Virtual Container + APatch Manager Package (F15 + F11)
    def test_c13_virtual_container_and_apatch_manager(self):
        item_container = DetectionEngine.check_dual_app("/data/data/io.va.exposed/virtual/data", 10123, [])
        item_apatch = DetectionEngine.check_root_packages(["bmax.apatch"])
        assert item_container.status == DetectionStatus.WARN
        assert item_apatch.status == DetectionStatus.DANGER

    # C14: Direct Syscall + Native Parser on Corrupted Mountinfo (F03 + F04)
    def test_c14_direct_syscall_and_native_parser_on_corrupted_mounts(self):
        corrupted = "15 20 0:17 / /sys\n20 1 253:0 / / rw,relatime - ext4 /dev/block/dm-0 ro"
        parsed = LowLevelParsers.parse_mountinfo(corrupted)
        assert len(parsed) == 1
        assert parsed[0]["fs_type"] == "ext4"

    # C15: Clean Device State + Async Scan + Diagnostic Export (Clean + F19 + F20)
    def test_c15_clean_device_with_async_scan_and_report_export(self, clean_device_info, clean_items_list):
        assessment = SecurityScorer.calculate_score(clean_items_list)
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, clean_items_list)
        json_output = ReportSerializer.serialize_to_json(report)
        assert '"level": "SAFE"' in json_output
        assert '"score": 100' in json_output or '"score": 9' in json_output

    # C16: Full Compromise All DANGER + Security Scorer + UI Summary (All Danger + F17 + F18)
    def test_c16_full_compromise_all_danger_with_scorer_and_ui_summary(self):
        items = [
            DetectionItem(f"DNG-{i}", f"Check {i}", DetectionCategory.ROOT, DetectionStatus.DANGER, "Severe Risk", DetectionMethod.DIRECT_SYSCALL)
            for i in range(10)
        ]
        assessment = SecurityScorer.calculate_score(items)
        assert assessment.score <= 40
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.dangerCount == 10

    # C17: ADB Enabled + test-keys Capped at WARNING (F16 WARN + F07 WARN)
    def test_c17_adb_enabled_with_test_keys_capped_at_warning(self, clean_items_list):
        items = list(clean_items_list)
        items[2] = DetectionEngine.check_build_tags("test-keys", "user")
        items[-1] = DetectionEngine.check_debugger(False, True, 0)
        assessment = SecurityScorer.calculate_score(items)
        assert assessment.level == SecurityLevel.WARNING
        assert assessment.score <= 75
        assert assessment.dangerCount == 0

    # C18: SU Binary Not Found but Mountinfo Contains OverlayFS (F08 PASS + F09 DANGER)
    def test_c18_no_su_binary_but_mountinfo_has_overlayfs(self):
        item_su = DetectionEngine.check_conventional_su([], "/system/bin")
        item_ksu = DetectionEngine.check_kernelsu_apatch(KSU_MOUNTINFO, "Linux 6.1.0")
        assert item_su.status == DetectionStatus.PASS
        assert item_ksu.status == DetectionStatus.DANGER
        # Proves stealth root without traditional SU is caught by kernel mount checks
        assessment = SecurityScorer.calculate_score([item_su, item_ksu])
        assert assessment.score <= 40

    # C19: Frida Port Closed but Gum Thread and Tracer Active (F13 DANGER + F16 DANGER)
    def test_c19_frida_port_closed_but_gum_thread_and_tracer_active(self):
        item_frida = DetectionEngine.check_frida([], ["gum-js-loop"], "")
        item_dbg = DetectionEngine.check_debugger(False, False, 1024)
        assert item_frida.status == DetectionStatus.DANGER
        assert item_dbg.status == DetectionStatus.DANGER

    # C20: Multiple Root Managers + Magisk + JSON Schema Fidelity (F11 + F10 + F20)
    def test_c20_multiple_root_managers_and_magisk_with_json_schema_fidelity(self, clean_device_info):
        item_magisk = DetectionEngine.check_magisk_zygisk(MAGISK_MOUNTINFO, ["/dev/socket/magiskd"])
        item_pkgs = DetectionEngine.check_root_packages(ROOT_PACKAGES)
        assessment = SecurityScorer.calculate_score([item_magisk, item_pkgs])
        report = DiagnosticReport("1.0.0", 1774032000000, clean_device_info, assessment, [item_magisk, item_pkgs])
        data = json.loads(ReportSerializer.serialize_to_json(report))
        is_valid, msg = ReportSerializer.validate_schema(data)
        assert is_valid is True
        assert data["assessment"]["level"] == "DANGEROUS"

    # C21: Hardware Key Attestation Anti-Spoofing (R1) + KernelSU Syscall Probe (R2)
    def test_c21_hardware_attestation_spoofing_plus_kernelsu_probe(self):
        """Cross-layer hardware key attestation spoofing combined with raw sys_prctl KernelSU handshake"""
        sys_props = {"ro.boot.flash.locked": "1", "ro.boot.locked": "1", "ro.secure": "1"}
        attestation = {"deviceLocked": False, "verifiedBootState": VerifiedBootState.UNVERIFIED, "isHardwareBacked": True}
        item_bl = KeyAttestationHarness.cross_validate_bootloader(sys_props, attestation)
        ksu_item, _ = KernelProbeHarness.evaluate_probes(ksu_ret=0, ksu_ver=11500, apatch_ret=-14)

        assert item_bl.status == DetectionStatus.DANGER
        assert ksu_item.status == DetectionStatus.DANGER
        assert "Spoofing Detected" in item_bl.evidence
        assert "ksu_handshake_active" in ksu_item.evidence

        assessment = SecurityScorer.calculate_score([item_bl, ksu_item])
        assert assessment.level == SecurityLevel.DANGEROUS
        assert assessment.score <= 40

    # C22: ELF .text Trampoline Hook (R3) + Frida Anonymous Memory Map (F13)
    def test_c22_anti_hook_trampoline_plus_frida_memory_map(self):
        """Native code section trampoline hook combined with runtime anonymous executable mappings"""
        # Hook trampoline in libc open
        trampoline = b"\x50\x00\x00\x58\x00\x02\x1F\xD6\x00\x10\x20\x30\x40\x50\x60\x70"
        detected, reason = AntiHookHarness.check_arm64_trampoline(trampoline)
        assert detected is True

        # Injected Frida maps
        item_frida = DetectionEngine.check_frida([], [], INJECTED_MAPS)
        assert item_frida.status == DetectionStatus.DANGER
        assert "frida-agent" in item_frida.evidence or "Suspicious" in item_frida.evidence

    # C23: XOR Obfuscation (R4) + Root Package Scanning (F11)
    def test_c23_xor_string_obfuscation_plus_root_package_scan(self):
        """Runtime string decryption of sensitive root packages followed by immediate zeroize"""
        obf_pkg = StringObfuscatorHarness.encrypt("me.weishu.kernelsu")
        # Decrypt dynamically at runtime
        decrypted_pkg = StringObfuscatorHarness.decrypt(obf_pkg)
        assert decrypted_pkg == "me.weishu.kernelsu"

        item_pkg = DetectionEngine.check_root_packages([decrypted_pkg])
        assert item_pkg.status == DetectionStatus.DANGER
        assert "me.weishu.kernelsu" in item_pkg.evidence

    # C24: Snapshot Diff Classification (R7) + Multi-Feature State Transitions
    def test_c24_snapshot_diff_multiple_state_transitions(self):
        """Validates snapshot comparison when multiple features transition states simultaneously"""
        # Scan 1: Clean retail state
        prev_bl = DetectionItem("SEC-R1-01", "Bootloader", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "clean", DetectionMethod.DIRECT_SYSCALL)
        prev_su = DetectionItem("SEC-R2-01", "SU", DetectionCategory.ROOT, DetectionStatus.PASS, "clean", DetectionMethod.DIRECT_SYSCALL)
        prev_xp = DetectionItem("SEC-R3-01", "Xposed", DetectionCategory.HOOK, DetectionStatus.PASS, "clean", DetectionMethod.JAVA)

        # Scan 2: Bootloader unlocked, SU installed, Xposed remains clean
        curr_bl = DetectionItem("SEC-R1-01", "Bootloader", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER, "unlocked", DetectionMethod.DIRECT_SYSCALL)
        curr_su = DetectionItem("SEC-R2-01", "SU", DetectionCategory.ROOT, DetectionStatus.DANGER, "su found", DetectionMethod.DIRECT_SYSCALL)
        curr_xp = DetectionItem("SEC-R3-01", "Xposed", DetectionCategory.HOOK, DetectionStatus.PASS, "clean", DetectionMethod.JAVA)

        comp = ScanSnapshotHarness.compare_snapshots([prev_bl, prev_su, prev_xp], [curr_bl, curr_su, curr_xp])
        assert comp["hasChanges"] is True
        assert comp["newRisksCount"] == 2
        assert comp["resolvedCount"] == 0
        assert comp["changedCount"] == 0

    # C25: Production R8 Shrinking (R5) + JNI Contract Protection
    def test_c25_r8_shrinking_plus_jni_contracts_integrity(self):
        """Validates R8 minification configuration protects JNI NativeDetectionItem class and fields"""
        with open("/root/环境检测/app/proguard-rules.pro", "r", encoding="utf-8") as f:
            rules = f.read()

        assert "NativeDetectionItem" in rules
        assert "com.security.environment.data.jni.**" in rules
        assert "-keep" in rules
        assert "<fields>;" in rules or "<methods>;" in rules
