"""
System Inspector for Build Systems, NDK Config, APK Artifacts, and ADB Environment.
"""
import os
import shutil
import glob
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional


class SystemInspector:
    PROJECT_ROOT = str(Path(__file__).resolve().parents[2])

    @classmethod
    def find_apksigner(cls) -> Optional[str]:
        """Dynamically locates apksigner executable via PATH, ANDROID_HOME build-tools, or fallbacks."""
        which_path = shutil.which("apksigner")
        if which_path:
            return which_path

        for env_var in ["ANDROID_HOME", "ANDROID_SDK_ROOT"]:
            sdk_root = os.environ.get(env_var)
            if sdk_root and os.path.exists(sdk_root):
                matches = glob.glob(os.path.join(sdk_root, "build-tools", "*", "apksigner"))
                if matches:
                    matches.sort()
                    return matches[-1]

        fallbacks = [
            "/usr/bin/apksigner",
            "/usr/local/bin/apksigner",
        ]
        for fb in fallbacks:
            if os.path.exists(fb) and os.access(fb, os.X_OK):
                return fb
        return None

    @classmethod
    def check_gradle_wrapper(cls) -> Dict[str, Any]:
        props_path = os.path.join(cls.PROJECT_ROOT, "gradle/wrapper/gradle-wrapper.properties")
        exists = os.path.exists(props_path)
        content = ""
        if exists:
            with open(props_path, "r", encoding="utf-8") as f:
                content = f.read()
        return {
            "exists": exists,
            "has_8_11_1": "gradle-8.11.1" in content,
            "content": content,
        }

    @classmethod
    def check_cmake_config(cls) -> Dict[str, Any]:
        cmake_path = os.path.join(cls.PROJECT_ROOT, "app/src/main/cpp/CMakeLists.txt")
        exists = os.path.exists(cmake_path)
        content = ""
        if exists:
            with open(cmake_path, "r", encoding="utf-8") as f:
                content = f.read()
        return {
            "exists": exists,
            "has_cxx17": "c++17" in content.lower() or "cxx_standard 17" in content.lower(),
            "target_so": "security_engine" in content,
            "content": content,
        }

    @classmethod
    def check_jni_skeleton(cls) -> Dict[str, Any]:
        jni_cpp = os.path.join(cls.PROJECT_ROOT, "app/src/main/cpp/src/security_engine_jni.cpp")
        kt_jni = os.path.join(cls.PROJECT_ROOT, "app/src/main/java/com/security/environment/data/jni/SecurityEngineNative.kt")
        
        has_cpp = os.path.exists(jni_cpp)
        has_kt = os.path.exists(kt_jni)
        cpp_content = ""
        kt_content = ""
        if has_cpp:
            with open(jni_cpp, "r", encoding="utf-8") as f:
                cpp_content = f.read()
        if has_kt:
            with open(kt_jni, "r", encoding="utf-8") as f:
                kt_content = f.read()

        return {
            "has_cpp": has_cpp,
            "has_kt": has_kt,
            "cpp_exports_all": "executeAllChecks" in cpp_content,
            "kt_exports_all": "executeAllChecks" in kt_content,
            "has_native_item": "NativeDetectionItem" in kt_content or "NativeDetectionItem" in cpp_content,
        }

    @classmethod
    def check_apk_artifact(cls) -> Dict[str, Any]:
        apk_path = os.path.join(cls.PROJECT_ROOT, "app/build/outputs/apk/debug/app-debug.apk")
        exists = os.path.exists(apk_path)
        size = os.path.getsize(apk_path) if exists else 0
        return {
            "exists": exists,
            "path": apk_path,
            "size": size,
        }

    @classmethod
    def inspect_adb_device(cls) -> Dict[str, Any]:
        try:
            res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
            lines = res.stdout.strip().splitlines()
            devices = [line.split()[0] for line in lines[1:] if line.strip() and "device" in line]
            return {
                "available": len(devices) > 0,
                "devices": devices,
            }
        except Exception as e:
            return {
                "available": False,
                "error": str(e),
                "devices": [],
            }
