"""
Reference Detection Engine & Low-Level Parsers for E2E Verification.
Implements the exact logic and rule contracts defined in ORIGINAL_REQUEST.md & PROJECT.md.
"""
import re
from typing import Dict, List, Optional, Any
from tests.harness.contracts import (
    DetectionCategory,
    DetectionStatus,
    DetectionMethod,
    DetectionItem,
)


class LowLevelParsers:
    """Simulates/verifies C++ low-level parsers (maps, mountinfo, status, props)"""

    @staticmethod
    def parse_maps(content: str) -> List[Dict[str, Any]]:
        """
        Parses /proc/self/maps lines.
        Format: address perms offset dev inode pathname
        """
        entries = []
        if not content:
            return entries

        # e.g.: 7f8a9000-7f8aa000 r-xp 00000000 00:00 0 [anon:...] or /lib/...
        pattern = re.compile(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxsp\-]{4})\s+([0-9a-fA-F]+)\s+([0-9a-fA-F:]+)\s+(\d+)\s*(.*)$")
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if m:
                entries.append({
                    "start": m.group(1),
                    "end": m.group(2),
                    "perms": m.group(3),
                    "offset": m.group(4),
                    "dev": m.group(5),
                    "inode": int(m.group(6)),
                    "pathname": m.group(7).strip(),
                })
        return entries

    @staticmethod
    def parse_mountinfo(content: str) -> List[Dict[str, Any]]:
        """
        Parses /proc/self/mountinfo lines.
        Format: id parent_id major:minor root mount_point mount_options [optional_fields] - fs_type mount_source super_options
        """
        entries = []
        if not content:
            return entries

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(" - ")
            if len(parts) != 2:
                continue
            prefix = parts[0].split()
            suffix = parts[1].split()
            if len(prefix) < 5 or len(suffix) < 2:
                continue
            entries.append({
                "mount_id": prefix[0],
                "parent_id": prefix[1],
                "root": prefix[3],
                "mount_point": prefix[4],
                "fs_type": suffix[0],
                "mount_source": suffix[1],
                "super_options": suffix[2] if len(suffix) > 2 else "",
                "raw_line": line,
            })
        return entries

    @staticmethod
    def parse_status(content: str) -> Dict[str, str]:
        """Parses /proc/self/status key-value lines"""
        status_dict = {}
        if not content:
            return status_dict
        for line in content.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                status_dict[k.strip()] = v.strip()
        return status_dict

    @staticmethod
    def parse_properties(content: str) -> Dict[str, str]:
        """Parses property output like [key]: [value] or key=value"""
        props = {}
        if not content:
            return props
        bracket_pattern = re.compile(r"^\[(.*?)\]:\s*\[(.*?)\]$")
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            bm = bracket_pattern.match(line)
            if bm:
                props[bm.group(1)] = bm.group(2)
            elif "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
        return props


class DetectionEngine:
    """Reference implementation of the 20 Security Features"""

    KNOWN_SU_PATHS = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sbin/su",
        "/usr/bin/su",
        "/vendor/bin/su",
        "/cache/su",
    ]

    ROOT_PACKAGES = [
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "bmax.apatch",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.thirdparty.superuser",
    ]

    EMULATOR_PROPS = {
        "ro.kernel.qemu": "1",
        "ro.hardware": ["goldfish", "ranchu", "vbox86"],
        "ro.product.model": ["sdk", "google_sdk", "Emulator", "Android SDK built for x86"],
    }

    # F05: Bootloader Status Detection
    @staticmethod
    def check_bootloader(props: Dict[str, str]) -> DetectionItem:
        locked = props.get("ro.boot.flash.locked")
        state = props.get("ro.boot.verifiedbootstate")
        vbmeta = props.get("ro.boot.vbmeta.device_state")

        is_unlocked = False
        evidence_list = []

        if locked is not None:
            evidence_list.append(f"ro.boot.flash.locked={locked}")
            if locked in ["0", "unlocked"]:
                is_unlocked = True

        if state is not None:
            evidence_list.append(f"ro.boot.verifiedbootstate={state}")
            if state.lower() in ["orange", "red", "yellow"]:
                is_unlocked = True

        if vbmeta is not None:
            evidence_list.append(f"ro.boot.vbmeta.device_state={vbmeta}")
            if vbmeta.lower() == "unlocked":
                is_unlocked = True

        evidence_str = "; ".join(evidence_list) if evidence_list else "no bootloader props found"
        if is_unlocked:
            status = DetectionStatus.DANGER
        elif locked == "1" or state == "green":
            status = DetectionStatus.PASS
        else:
            status = DetectionStatus.WARN

        return DetectionItem(
            id="SEC-R1-01",
            name="Bootloader Lock State",
            category=DetectionCategory.BOOTLOADER,
            status=status,
            evidence=evidence_str,
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F06: SELinux Mode & Context Check
    @staticmethod
    def check_selinux(enforce_val: Optional[str], context_str: Optional[str]) -> DetectionItem:
        if enforce_val == "1":
            status = DetectionStatus.PASS
            ev = f"SELinux Enforcing (1); Context={context_str or 'unknown'}"
        elif enforce_val == "0":
            status = DetectionStatus.DANGER
            ev = f"SELinux Permissive (0); Context={context_str or 'unknown'}"
        else:
            status = DetectionStatus.DANGER
            ev = f"SELinux Disabled or missing enforce node; Context={context_str or 'unknown'}"

        return DetectionItem(
            id="SEC-R1-02",
            name="SELinux Mode & Context",
            category=DetectionCategory.BOOTLOADER,
            status=status,
            evidence=ev,
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F07: System Build Tags & Keys
    @staticmethod
    def check_build_tags(build_tags: Optional[str], build_type: Optional[str]) -> DetectionItem:
        ev = f"ro.build.tags={build_tags or 'none'}, ro.build.type={build_type or 'none'}"
        if build_tags and "test-keys" in build_tags.lower():
            status = DetectionStatus.WARN
        elif build_type and any(t in build_type.lower() for t in ["userdebug", "eng"]):
            status = DetectionStatus.WARN
        else:
            status = DetectionStatus.PASS

        return DetectionItem(
            id="SEC-R1-03",
            name="System Build Tags & Keys",
            category=DetectionCategory.BOOTLOADER,
            status=status,
            evidence=ev,
            method=DetectionMethod.NATIVE_LIBC,
        )

    # F08: Conventional SU & PATH Scan
    @classmethod
    def check_conventional_su(cls, existing_files: List[str], path_env: str) -> DetectionItem:
        found_su = []
        for p in cls.KNOWN_SU_PATHS:
            if p in existing_files:
                found_su.append(p)

        # dynamic PATH scan
        if path_env:
            for d in path_env.split(":"):
                candidate = f"{d.rstrip('/')}/su"
                if candidate in existing_files and candidate not in found_su:
                    found_su.append(candidate)

        if found_su:
            return DetectionItem(
                id="SEC-R2-01",
                name="Conventional SU Binary Scan",
                category=DetectionCategory.ROOT,
                status=DetectionStatus.DANGER,
                evidence=f"SU binaries detected: {', '.join(found_su)}",
                method=DetectionMethod.DIRECT_SYSCALL,
            )
        return DetectionItem(
            id="SEC-R2-01",
            name="Conventional SU Binary Scan",
            category=DetectionCategory.ROOT,
            status=DetectionStatus.PASS,
            evidence="No SU binary found in system or PATH",
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F09: KernelSU & APatch Detection
    @staticmethod
    def check_kernelsu_apatch(mountinfo_content: str, kernel_version: str) -> DetectionItem:
        anomalies = []
        parsed = LowLevelParsers.parse_mountinfo(mountinfo_content)
        for m in parsed:
            # KernelSU / APatch mounts overlay on /system or /vendor
            if m["fs_type"] == "overlay" and m["mount_point"] in ["/system", "/vendor", "/product"]:
                anomalies.append(f"OverlayFS on {m['mount_point']} ({m['mount_source']})")
            if "upperdir=/data/adb" in m.get("super_options", "") or "upperdir=/data/adb" in m.get("raw_line", ""):
                anomalies.append("APatch/KernelSU upperdir in /data/adb")

        if "KernelSU" in kernel_version or "APatch" in kernel_version:
            anomalies.append(f"Kernel banner contains root tag: {kernel_version}")

        if anomalies:
            return DetectionItem(
                id="SEC-R2-02",
                name="KernelSU & APatch Detection",
                category=DetectionCategory.ROOT,
                status=DetectionStatus.DANGER,
                evidence="; ".join(anomalies),
                method=DetectionMethod.DIRECT_SYSCALL,
            )
        return DetectionItem(
            id="SEC-R2-02",
            name="KernelSU & APatch Detection",
            category=DetectionCategory.ROOT,
            status=DetectionStatus.PASS,
            evidence="No KernelSU / APatch mount or kernel banner traces found",
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F10: Magisk & Zygisk Detection
    @staticmethod
    def check_magisk_zygisk(mountinfo_content: str, unix_sockets: List[str]) -> DetectionItem:
        anomalies = []
        parsed = LowLevelParsers.parse_mountinfo(mountinfo_content)
        for m in parsed:
            if "magisk" in m.get("mount_source", "").lower() or "magisk" in m.get("mount_point", "").lower():
                anomalies.append(f"Magisk mount trace: {m['mount_point']}")
            # Filesystem inversion: tmpfs mounted directly over /system
            if m["fs_type"] == "tmpfs" and m["mount_point"] in ["/system", "/system/bin", "/system/xbin"]:
                anomalies.append(f"Filesystem inversion tmpfs on {m['mount_point']}")

        for s in unix_sockets:
            if "magisk" in s.lower() or "zygisk" in s.lower():
                anomalies.append(f"Suspicious daemon socket: {s}")

        if anomalies:
            return DetectionItem(
                id="SEC-R2-03",
                name="Magisk & Zygisk Detection",
                category=DetectionCategory.ROOT,
                status=DetectionStatus.DANGER,
                evidence="; ".join(anomalies),
                method=DetectionMethod.DIRECT_SYSCALL,
            )
        return DetectionItem(
            id="SEC-R2-03",
            name="Magisk & Zygisk Detection",
            category=DetectionCategory.ROOT,
            status=DetectionStatus.PASS,
            evidence="No Magisk tmpfs inversion or Zygisk sockets identified",
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F11: Root Manager Package Detection
    @classmethod
    def check_root_packages(cls, installed_packages: List[str]) -> DetectionItem:
        detected = [pkg for pkg in installed_packages if pkg in cls.ROOT_PACKAGES]
        if detected:
            return DetectionItem(
                id="SEC-R2-04",
                name="Root Manager Package Detection",
                category=DetectionCategory.ROOT,
                status=DetectionStatus.DANGER,
                evidence=f"Root manager packages installed: {', '.join(detected)}",
                method=DetectionMethod.JAVA,
            )
        return DetectionItem(
            id="SEC-R2-04",
            name="Root Manager Package Detection",
            category=DetectionCategory.ROOT,
            status=DetectionStatus.PASS,
            evidence="No known root manager packages detected",
            method=DetectionMethod.JAVA,
        )

    # F12: Xposed / LSPosed Detection
    @staticmethod
    def check_xposed(loaded_classes: List[str], stack_traces: str, maps_content: str) -> DetectionItem:
        traces = []
        for cls_name in loaded_classes:
            if "de.robv.android.xposed" in cls_name or "org.lsposed.lspd" in cls_name:
                traces.append(f"Xposed class loaded: {cls_name}")

        if "de.robv.android.xposed" in stack_traces:
            traces.append("Xposed stack trace frame detected")

        maps_entries = LowLevelParsers.parse_maps(maps_content)
        for m in maps_entries:
            path = m.get("pathname", "")
            if any(k in path.lower() for k in ["xposed", "edxp", "lspd", "liblsp.so"]):
                traces.append(f"Hook library in memory: {path}")

        if traces:
            return DetectionItem(
                id="SEC-R3-01",
                name="Xposed / LSPosed Framework Detection",
                category=DetectionCategory.HOOK,
                status=DetectionStatus.DANGER,
                evidence="; ".join(traces),
                method=DetectionMethod.JAVA,
            )
        return DetectionItem(
            id="SEC-R3-01",
            name="Xposed / LSPosed Framework Detection",
            category=DetectionCategory.HOOK,
            status=DetectionStatus.PASS,
            evidence="No Xposed/LSPosed class or memory mapping found",
            method=DetectionMethod.JAVA,
        )

    # F13: Frida Dynamic Instrumentation
    @staticmethod
    def check_frida(open_ports: List[int], thread_names: List[str], maps_content: str) -> DetectionItem:
        traces = []
        if 27042 in open_ports:
            traces.append("Frida default port 27042 active")
        for p in open_ports:
            if p != 27042 and p in [27043, 27044, 27045]:
                traces.append(f"Frida alternative port {p} active")

        for th in thread_names:
            if th in ["gum-js-loop", "gmain", "gdbus"]:
                traces.append(f"Frida thread detected: {th}")

        maps_entries = LowLevelParsers.parse_maps(maps_content)
        anon_rx_count = 0
        for m in maps_entries:
            path = m.get("pathname", "")
            perms = m.get("perms", "")
            if "frida" in path.lower() or "linjector" in path.lower():
                traces.append(f"Frida binary mapped: {path}")
            if perms == "r-xp" and not path:
                anon_rx_count += 1

        if anon_rx_count > 3:
            traces.append(f"Suspicious anonymous executable memory regions: {anon_rx_count}")

        if traces:
            return DetectionItem(
                id="SEC-R3-02",
                name="Frida Dynamic Instrumentation Detection",
                category=DetectionCategory.HOOK,
                status=DetectionStatus.DANGER,
                evidence="; ".join(traces),
                method=DetectionMethod.DIRECT_SYSCALL,
            )
        return DetectionItem(
            id="SEC-R3-02",
            name="Frida Dynamic Instrumentation Detection",
            category=DetectionCategory.HOOK,
            status=DetectionStatus.PASS,
            evidence="No Frida port, thread, or anonymous executable mapping detected",
            method=DetectionMethod.DIRECT_SYSCALL,
        )

    # F14: Emulator & Hardware Artifacts
    @classmethod
    def check_emulator(cls, props: Dict[str, str], device_nodes: List[str], sensor_count: int) -> DetectionItem:
        traces = []
        if props.get("ro.kernel.qemu") == "1":
            traces.append("ro.kernel.qemu=1")
        hw = props.get("ro.hardware", "").lower()
        if any(g in hw for g in ["goldfish", "ranchu", "vbox86"]):
            traces.append(f"ro.hardware={hw}")
        model = props.get("ro.product.model", "").lower()
        if "sdk" in model or "emulator" in model:
            traces.append(f"ro.product.model={model}")

        for node in ["/dev/socket/qemud", "/dev/qemu_pipe"]:
            if node in device_nodes:
                traces.append(f"QEMU device node present: {node}")

        if sensor_count == 0:
            traces.append("Zero physical sensors reported")

        if traces:
            return DetectionItem(
                id="SEC-R4-01",
                name="Emulator & Virtual Hardware Detection",
                category=DetectionCategory.VIRTUAL,
                status=DetectionStatus.DANGER,
                evidence="; ".join(traces),
                method=DetectionMethod.NATIVE_LIBC,
            )
        return DetectionItem(
            id="SEC-R4-01",
            name="Emulator & Virtual Hardware Detection",
            category=DetectionCategory.VIRTUAL,
            status=DetectionStatus.PASS,
            evidence="Physical hardware signature verified",
            method=DetectionMethod.NATIVE_LIBC,
        )

    # F15: Dual-App & Virtual Container
    @staticmethod
    def check_dual_app(data_dir: str, uid: int, installed_container_pkgs: List[str]) -> DetectionItem:
        traces = []
        suspicious_paths = ["io.va.exposed", "com.lbe.parallel", "com.excelliance.dualaid", "virtual/data"]
        for sp in suspicious_paths:
            if sp in data_dir:
                traces.append(f"Redirected private path: {data_dir}")

        # Sub-user / dual space often uses UID range >= 999000
        if 99900000 <= uid <= 99999999 or "/999/" in data_dir:
            traces.append(f"Dual-space multi-user ID: {uid} (path: {data_dir})")

        if installed_container_pkgs:
            traces.append(f"Container package detected: {', '.join(installed_container_pkgs)}")

        if traces:
            return DetectionItem(
                id="SEC-R4-02",
                name="Dual-App & Virtual Container Detection",
                category=DetectionCategory.VIRTUAL,
                status=DetectionStatus.WARN,
                evidence="; ".join(traces),
                method=DetectionMethod.JAVA,
            )
        return DetectionItem(
            id="SEC-R4-02",
            name="Dual-App & Virtual Container Detection",
            category=DetectionCategory.VIRTUAL,
            status=DetectionStatus.PASS,
            evidence=f"Normal private storage path ({data_dir}), standard UID {uid}",
            method=DetectionMethod.JAVA,
        )

    # F16: Debugger & Anti-Tracking
    @staticmethod
    def check_debugger(jdwp_connected: bool, adb_enabled: bool, tracer_pid: int) -> DetectionItem:
        traces = []
        if jdwp_connected:
            traces.append("JDWP debugger connected")
        if tracer_pid > 0:
            traces.append(f"Process attached by TracerPid: {tracer_pid}")
        if adb_enabled:
            traces.append("ADB debugging is enabled in Developer Options")

        if jdwp_connected or tracer_pid > 0:
            status = DetectionStatus.DANGER
        elif adb_enabled:
            status = DetectionStatus.WARN
        else:
            status = DetectionStatus.PASS

        ev = "; ".join(traces) if traces else f"No debugger attached (TracerPid={tracer_pid}, ADB={adb_enabled})"
        return DetectionItem(
            id="SEC-R4-03",
            name="Debugger & Anti-Tracking Detection",
            category=DetectionCategory.DEBUG,
            status=status,
            evidence=ev,
            method=DetectionMethod.DIRECT_SYSCALL,
        )
