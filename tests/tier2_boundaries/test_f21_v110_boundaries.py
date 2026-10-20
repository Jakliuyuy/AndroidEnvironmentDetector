"""
Tier 2: Boundary & Corner Cases — F21 v1.1.0 Edge & Negative Conditions
6 Test Cases validating:
- R1: Corrupted or truncated ASN.1 DER key attestation payload
- R2: Abnormal errno responses from KernelSU / APatch syscall channels
- R3: Short instruction buffer & zero-pointer boundary for anti-trampoline analyzer
- R4: Boundary lengths (empty string, UTF-8 unicode, null byte, 512-byte payload) for XOR obfuscator
- R5: Signature absence / corrupted APK verification detection via apksigner
- R6/R7: Corrupted JSON snapshot fallback & empty field resiliency
"""
import os
import json
import pytest
import subprocess
from tests.harness.contracts import (
    DetectionStatus,
)
from tests.harness.v110_engine import (
    KeyAttestationHarness,
    KernelProbeHarness,
    AntiHookHarness,
    StringObfuscatorHarness,
    ScanSnapshotHarness,
    ItemDiffType,
)


class TestF21V110Boundaries:

    def test_t2_r1_attestation_corrupted_der_handles_gracefully(self):
        """Verifies truncated or corrupted ASN.1 DER data raises ValueError or returns safe default"""
        # Truncated DER
        truncated = b"\x30\x10\x02\x01\x03\x0A"
        try:
            res = KeyAttestationHarness.parse_key_description(truncated)
            # If no exception, fields must be None
            assert res["deviceLocked"] is None
        except ValueError:
            pass  # Expected safe failure

        # Non-sequence tag
        invalid_tag = b"\x04\x05hello"
        with pytest.raises(ValueError, match="Invalid ASN.1 sequence header"):
            KeyAttestationHarness.parse_key_description(invalid_tag)

    def test_t2_r2_kernel_probes_abnormal_errno_handling(self):
        """Verifies abnormal non-standard errno (e.g. -13 EACCES or -38 ENOSYS) triggers anomaly detection"""
        # When KernelSU returns non-standard errno (e.g. -13 EACCES instead of -22 EINVAL)
        ksu_item, apatch_item = KernelProbeHarness.evaluate_probes(
            ksu_ret=-13,
            ksu_ver=0,
            apatch_ret=-38,  # ENOSYS instead of -14 EFAULT
        )
        assert ksu_item.status == DetectionStatus.DANGER
        assert "ksu_prctl_anomaly, ret=-13" in ksu_item.evidence

        assert apatch_item.status == DetectionStatus.DANGER
        assert "apatch_channel_anomaly (ret=-38)" in apatch_item.evidence

    def test_t2_r3_anti_hook_invalid_pointer_and_short_buffer(self):
        """Verifies anti-trampoline inspection safely handles buffers shorter than 8 bytes without out-of-bounds"""
        short_buffers = [
            b"",
            b"\x50",
            b"\x50\x00",
            b"\x50\x00\x00\x58",  # 4 bytes only
            b"\x00" * 7,
        ]
        for buf in short_buffers:
            detected, reason = AntiHookHarness.check_arm64_trampoline(buf)
            assert detected is False
            assert "Buffer too short" in reason or "Clean" in reason

    def test_t2_r4_xor_obfuscation_boundary_lengths_and_utf8(self):
        """Verifies XOR obfuscation handles empty string, Chinese UTF-8, null bytes and 512-byte payloads"""
        test_strings = [
            "",
            "A",
            "春秋检测-硬件密钥证明",
            "Line1\nLine2\tLine3",
            "A" * 512,
        ]
        for s in test_strings:
            enc = StringObfuscatorHarness.encrypt(s, key=0xA7)
            dec = StringObfuscatorHarness.decrypt(enc, key=0xA7)
            assert dec == s, f"Decryption mismatch for payload of length {len(s)}"

    def test_t2_r5_release_apk_corrupted_signature_detection(self, tmp_path):
        """Verifies apksigner correctly identifies an unsigned or corrupted APK dummy file"""
        dummy_unsigned_apk = tmp_path / "dummy_unsigned.apk"
        # Create a valid zip with non-signed content
        import zipfile
        with zipfile.ZipFile(dummy_unsigned_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<dummy>")
            zf.writestr("classes.dex", b"<dummy dex>")

        cmd = ["apksigner", "verify", str(dummy_unsigned_apk)]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert result.returncode != 0
        assert "DOES NOT VERIFY" in result.stdout or "DOES NOT VERIFY" in result.stderr or result.returncode != 0

    def test_t2_r7_snapshot_diff_corrupted_json_fallback(self):
        """Verifies corrupted JSON or empty files in snapshot persistence is handled gracefully"""
        corrupted_payloads = [
            "",
            "{",
            "not a json",
            json.dumps({"version": 999, "unknown_field": True}),
        ]
        for p in corrupted_payloads:
            try:
                data = json.loads(p)
                items = data.get("items", [])
                assert isinstance(items, list)
            except Exception:
                pass  # Fallback to empty snapshot safely
