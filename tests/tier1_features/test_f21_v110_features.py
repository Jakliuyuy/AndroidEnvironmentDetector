"""
Tier 1: Feature Coverage — F21 v1.1.0 Core Hardening & Security Features (R1 - R7)
14 Test Cases validating:
- R1: Hardware KeyStore Key Attestation ASN.1 DER parsing & anti-spoofing cross-validation
- R2: KernelSU (sys_prctl) & APatch (sys_truncate) direct syscall probes
- R3: ELF .text section FNV1a hash integrity & anti-trampoline opcode detection
- R4: C++17 constexpr XOR string obfuscation & 0 sensitive plain strings in compiled .so
- R5: Production R8 code shrinking, proguard-rules, release signing & <= 5.5MB APK size
- R6: GitHub Actions CI/CD workflows (.github/workflows/ci.yml & release.yml)
- R7: Scan snapshot JSON persistence & 4-way diff classification engine
"""
import os
import json
import subprocess
import pytest
from tests.harness.contracts import (
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    DetectionItem,
)
from tests.harness.v110_engine import (
    KeyAttestationHarness,
    KernelProbeHarness,
    AntiHookHarness,
    StringObfuscatorHarness,
    ScanSnapshotHarness,
    VerifiedBootState,
    ItemDiffType,
)


class TestF21V110Features:

    # --------------------------------------------------------------------------
    # R1: Hardware Key Attestation
    # --------------------------------------------------------------------------
    def test_f21_r1_key_attestation_der_asn1_structure(self):
        """Verifies parsing of ASN.1 DER encoded KeyDescription with RootOfTrust"""
        der_bytes = KeyAttestationHarness.build_test_key_description_der(
            attestation_version=3,
            attestation_security_level=1,  # TEE
            keymaster_version=4,
            keymaster_security_level=1,
            device_locked=True,
            verified_boot_state=0,  # Verified
        )
        record = KeyAttestationHarness.parse_key_description(der_bytes)
        assert record["deviceLocked"] is True
        assert record["verifiedBootState"] == VerifiedBootState.VERIFIED
        assert record["isHardwareBacked"] is True

    def test_f21_r1_hardware_cross_validation_spoofing_detected(self):
        """Verifies detection of Magisk resetprop property spoofing when TEE proves unlocked"""
        # Attacker spoofs ro.boot.flash.locked = 1
        sys_props = {
            "ro.boot.flash.locked": "1",
            "ro.boot.locked": "1",
            "ro.secure": "1",
        }
        # Hardware KeyStore attestation proves bootloader is actually unlocked
        attestation = {
            "deviceLocked": False,
            "verifiedBootState": VerifiedBootState.UNVERIFIED,
            "isHardwareBacked": True,
        }
        item = KeyAttestationHarness.cross_validate_bootloader(sys_props, attestation)
        assert item.status == DetectionStatus.DANGER
        assert "Spoofing Detected: ro.boot.flash.locked overridden by hardware attestation" in item.evidence

    def test_f21_r1_hardware_verifiedbootstate_cross_validation_spoofing(self):
        """Verifies detection of verifiedbootstate=green spoofing when hardware state is UNVERIFIED"""
        sys_props = {
            "ro.boot.flash.locked": "1",
            "ro.boot.verifiedbootstate": "green",
            "ro.secure": "1",
        }
        attestation = {
            "deviceLocked": True,
            "verifiedBootState": VerifiedBootState.UNVERIFIED,
            "isHardwareBacked": True,
        }
        item = KeyAttestationHarness.cross_validate_bootloader(sys_props, attestation)
        assert item.status == DetectionStatus.DANGER
        assert "verifiedbootstate green spoofed" in item.evidence

    # --------------------------------------------------------------------------
    # R2: KernelSU & APatch Direct Syscall Probes
    # --------------------------------------------------------------------------
    def test_f21_r2_kernelsu_direct_prctl_handshake_positive(self):
        """Verifies direct sys_prctl KernelSU handshake returns DANGER when active"""
        ksu_item, apatch_item = KernelProbeHarness.evaluate_probes(
            ksu_ret=0,
            ksu_ver=11500,
            apatch_ret=-14,  # EFAULT (clean)
        )
        assert ksu_item.status == DetectionStatus.DANGER
        assert "ksu_handshake_active, version=11500" in ksu_item.evidence
        assert apatch_item.status == DetectionStatus.PASS

    def test_f21_r2_apatch_supercall_truncate_positive(self):
        """Verifies direct sys_truncate APatch SuperCall probe detects magic response"""
        ksu_item, apatch_item = KernelProbeHarness.evaluate_probes(
            ksu_ret=-22,  # EINVAL (clean)
            ksu_ver=0,
            apatch_ret=0x11581158,  # APATCH_SUPERCALL_HELLO_MAGIC
        )
        assert apatch_item.status == DetectionStatus.DANGER
        assert "apatch_supercall_active (magic=0x11581158)" in apatch_item.evidence
        assert ksu_item.status == DetectionStatus.PASS

    def test_f21_r2_clean_kernel_probes_returns_pass(self):
        """Verifies clean standard kernel returns PASS for both KernelSU and APatch probes"""
        ksu_item, apatch_item = KernelProbeHarness.evaluate_probes(
            ksu_ret=-22,
            ksu_ver=0,
            apatch_ret=-14,
        )
        assert ksu_item.status == DetectionStatus.PASS
        assert apatch_item.status == DetectionStatus.PASS

    # --------------------------------------------------------------------------
    # R3: ELF .text Section Hash Integrity & Anti-Trampoline
    # --------------------------------------------------------------------------
    def test_f21_r3_anti_trampoline_arm64_instructions_detected(self):
        """Verifies detection of Dobby/Frida x16 inline hook trampoline (ldr x16, #8; br x16)"""
        # AArch64: 0x58000050 (ldr x16, #8), 0xD61F0200 (br x16), target: 0x00007F1234567800
        trampoline_bytes = (
            b"\x50\x00\x00\x58"
            b"\x00\x02\x1F\xD6"
            b"\x00\x78\x56\x34\x12\x7F\x00\x00"
        )
        detected, reason = AntiHookHarness.check_arm64_trampoline(trampoline_bytes)
        assert detected is True
        assert "Dobby/Frida x16 br trampoline" in reason

    def test_f21_r3_text_section_hash_integrity_mismatch_detected(self):
        """Verifies FNV1a hash mismatch between memory .text and disk ELF generates DANGER"""
        disk_text = b"\x1F\x20\x03\xD5" * 128  # clean nop sled
        mem_text = disk_text[:64] + b"\x50\x00\x00\x58\x00\x02\x1F\xD6" + disk_text[72:]  # injected hook
        item = AntiHookHarness.evaluate_text_integrity(mem_text, disk_text)
        assert item.status == DetectionStatus.DANGER
        assert "Memory .text hash mismatch with disk ELF" in item.evidence

    # --------------------------------------------------------------------------
    # R4: XOR String Obfuscator
    # --------------------------------------------------------------------------
    def test_f21_r4_constexpr_xor_obfuscation_logic(self):
        """Verifies XOR string obfuscation encryption, reversible decryption and volatile wiping"""
        secret = "me.weishu.kernelsu"
        encrypted = StringObfuscatorHarness.encrypt(secret, key=0xA7)
        assert secret.encode("utf-8") not in encrypted, "Plaintext must not be visible in ciphertext"
        decrypted = StringObfuscatorHarness.decrypt(encrypted, key=0xA7)
        assert decrypted == secret

    def test_f21_r4_zero_plain_sensitive_strings_in_so_and_src(self):
        """Verifies zero plaintext sensitive keywords exist in compiled libsecurity_engine.so"""
        sensitive_keywords = [
            b"de.robv.android.xposed",
            b"frida-agent",
            b"/proc/self/mountinfo",
            b"me.weishu.kernelsu",
        ]
        # Inspect compiled release .so
        so_paths = []
        for root, _, files in os.walk("/root/环境检测/app/build"):
            for f in files:
                if f == "libsecurity_engine.so":
                    so_paths.append(os.path.join(root, f))

        assert len(so_paths) > 0, "libsecurity_engine.so must be compiled"
        for so_file in so_paths:
            with open(so_file, "rb") as fp:
                content = fp.read()
                for kw in sensitive_keywords:
                    assert kw not in content, f"Sensitive plaintext '{kw.decode()}' leaked in {so_file}"

    # --------------------------------------------------------------------------
    # R5: Production R8 Shrinking & Release Signing
    # --------------------------------------------------------------------------
    def test_f21_r5_r8_shrinking_and_resource_minification(self):
        """Verifies R8 shrinking and resource minification enabled in build configuration"""
        build_gradle_path = "/root/环境检测/app/build.gradle.kts"
        proguard_rules_path = "/root/环境检测/app/proguard-rules.pro"
        with open(build_gradle_path, "r", encoding="utf-8") as f:
            gradle_content = f.read()

        assert "isMinifyEnabled = true" in gradle_content
        assert "isShrinkResources = true" in gradle_content
        assert os.path.exists(proguard_rules_path)

        with open(proguard_rules_path, "r", encoding="utf-8") as f:
            pg_content = f.read()
        assert "NativeDetectionItem" in pg_content
        assert "-keepclassmembers" in pg_content or "-keep" in pg_content

    def test_f21_r5_release_signing_and_apk_size_bounds(self):
        """Verifies official release APK exists, passes apksigner, and size <= 5.5MB"""
        apk_path = "/root/环境检测/release/AndroidEnvironmentDetector-v1.1.0.apk"
        assert os.path.exists(apk_path), "Release APK must exist at release/AndroidEnvironmentDetector-v1.1.0.apk"

        size = os.path.getsize(apk_path)
        # Size must be <= 5.5MB (5,767,168 bytes) and >= 3MB
        assert 3 * 1024 * 1024 <= size <= int(5.5 * 1024 * 1024), f"APK size {size} out of bounds"

        # Verify signature with apksigner
        cmd = ["apksigner", "verify", "--verbose", apk_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode == 0, f"apksigner verification failed: {result.stderr}"
        assert "Verifies" in result.stdout
        assert "Verified using v2 scheme (APK Signature Scheme v2): true" in result.stdout
        assert "Verified using v3 scheme (APK Signature Scheme v3): true" in result.stdout

    # --------------------------------------------------------------------------
    # R6: CI/CD Workflows
    # --------------------------------------------------------------------------
    def test_f21_r6_cicd_workflow_ci_and_release_pipeline_specs(self):
        """Verifies CI/CD workflow YAML syntax and required job stages"""
        ci_path = "/root/环境检测/.github/workflows/ci.yml"
        release_path = "/root/环境检测/.github/workflows/release.yml"
        assert os.path.exists(ci_path), "ci.yml must exist"
        assert os.path.exists(release_path), "release.yml must exist"

        with open(ci_path, "r", encoding="utf-8") as f:
            ci_content = f.read()
        assert "testDebugUnitTest" in ci_content
        assert "run_e2e_tests.sh" in ci_content
        assert "assembleRelease" in ci_content

        with open(release_path, "r", encoding="utf-8") as f:
            release_content = f.read()
        assert "tags:" in release_content
        assert "v*" in release_content
        assert "AndroidEnvironmentDetector" in release_content

    # --------------------------------------------------------------------------
    # R7: Scan Snapshot Persistence & Diff Engine
    # --------------------------------------------------------------------------
    def test_f21_r7_scan_diff_classification_and_snapshot_persistence(self):
        """Verifies ScanSnapshotManager JSON persistence and 4-way diff classification"""
        item_pass = DetectionItem("SEC-01", "Bootloader", DetectionCategory.BOOTLOADER, DetectionStatus.PASS, "clean", DetectionMethod.DIRECT_SYSCALL)
        item_warn = DetectionItem("SEC-01", "Bootloader", DetectionCategory.BOOTLOADER, DetectionStatus.WARN, "tampered", DetectionMethod.DIRECT_SYSCALL)
        item_danger = DetectionItem("SEC-01", "Bootloader", DetectionCategory.BOOTLOADER, DetectionStatus.DANGER, "unlocked", DetectionMethod.DIRECT_SYSCALL)

        # 1. PASS -> DANGER (NEW_ABNORMAL)
        assert ScanSnapshotHarness.classify_diff(DetectionStatus.PASS, DetectionStatus.DANGER) == ItemDiffType.NEW_ABNORMAL
        # 2. WARN -> DANGER (STATUS_CHANGED)
        assert ScanSnapshotHarness.classify_diff(DetectionStatus.WARN, DetectionStatus.DANGER) == ItemDiffType.STATUS_CHANGED
        # 3. DANGER -> PASS (RESOLVED)
        assert ScanSnapshotHarness.classify_diff(DetectionStatus.DANGER, DetectionStatus.PASS) == ItemDiffType.RESOLVED
        # 4. PASS -> PASS (UNCHANGED)
        assert ScanSnapshotHarness.classify_diff(DetectionStatus.PASS, DetectionStatus.PASS) == ItemDiffType.UNCHANGED

        # Verify JSON serialization
        json_str = ScanSnapshotHarness.serialize_snapshot_json([item_pass, item_danger], 1700000000000)
        parsed = json.loads(json_str)
        assert parsed["version"] == 1
        assert len(parsed["items"]) == 2
        assert parsed["items"][0]["id"] == "SEC-01"
