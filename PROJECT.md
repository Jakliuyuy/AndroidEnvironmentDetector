# Project: Android Environment Security Detection App

## Architecture
The application adopts a hardened, layered defense-in-depth architecture:
1. **Presentation Layer (Kotlin / Jetpack Compose)**:
   - UI State Flow (UDF / MVVM) with Coroutines on `Dispatchers.IO` / `Dispatchers.Default`.
   - Security Dashboard: Overall Risk Score Badge (0-100, Safe / Warning / Dangerous), Category Summary Cards, Expandable Detection Detail Cards with Raw System Evidence.
   - Non-blocking async scanning with animated progress.
   - Export Manager: JSON & Plaintext Diagnostic Report serialization and Android Share / Clipboard copy.
2. **Domain & Scoring Layer (Kotlin)**:
   - `DetectionCoordinator`: orchestrates detectors across Java API, libc, and native direct syscall channels.
   - `SecurityScorer`: Asymmetric Risk Override Model (any DANGER caps score at 40; any WARN caps score at 75; all PASS yields 95-100).
   - `SecurityDataSource` abstraction: decouples data acquisition to support 100% JVM headless testing (`MockSecurityDataSource`) and native production (`NativeSecurityDataSource`).
3. **Detection Modules Layer (Kotlin & JNI)**:
   - R1: `BootloaderDetector` (Properties cross-validation, SELinux enforcing/permissive, build-tags).
   - R2: `RootDetector` (SU binary paths, PATH scan, execution probe, KernelSU, APatch, Magisk mountinfo overlayfs/tmpfs anomalies, Zygisk, Root packages).
   - R3: `HookDetector` (Xposed/LSPosed classloader & stacktrace, Frida ports, D-Bus AUTH, threads, maps anonymous r-xp memory).
   - R4: `VirtualEnvDetector` & `DebugDetector` (Emulator props/drivers/sensors, dual-app private dir redirection, JDWP, ADB, TracerPid, anti-ptrace).
4. **Native C/C++ Engine (NDK / Direct Syscall)**:
   - `libsecurity_engine.so` compiled with C++17, `-fvisibility=hidden`.
   - Direct inline assembly syscalls (`sys_openat`, `sys_read`, `sys_close`, `sys_readlinkat`, `sys_faccessat`, `sys_ptrace`) for ARM64 (`svc #0`), ARM32 (`svc #0`), and x86_64 (`syscall`).
   - Raw `/proc/self/maps` scanner, `/proc/self/mountinfo` parser, `/proc/self/status` parser, and `/dev/__properties__` reader bypassing libc inline hooks.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F01 | Gradle & NDK Build System | Gradle 8.11.1, AGP 8.7.3, Kotlin 2.0.21, CMake C++17 config, APK `./gradlew assembleDebug` | M1 | ORIGINAL_REQUEST §Acceptance |
| F02 | JNI Bridge Skeleton | JNI interface and data struct mappings between Kotlin and C++ | M1 | ORIGINAL_REQUEST §R5 |
| F03 | Direct Syscall Inline Engine | Raw inline assembly syscalls (`openat`, `read`, `readlinkat`, etc.) for ARM64, ARM32, x86_64 | M2 | ORIGINAL_REQUEST §R5 |
| F04 | Native Low-Level Parsers | High-speed, hook-resistant C++ parsers for maps, mountinfo, status, properties | M2 | ORIGINAL_REQUEST §R5 |
| F05 | Bootloader Status Detection | `ro.boot.flash.locked`, `ro.boot.verifiedbootstate`, `ro.boot.vbmeta.device_state` cross-layer checks | M3 | ORIGINAL_REQUEST §R1 |
| F06 | SELinux Mode & Context Check | `/sys/fs/selinux/enforce`, mount check, `/proc/self/attr/current` context check | M3 | ORIGINAL_REQUEST §R1 |
| F07 | System Build Tags & Keys | `ro.build.tags` test-keys, dev-keys, userdebug build type verification | M3 | ORIGINAL_REQUEST §R1 |
| F08 | Conventional SU & PATH Scan | 16 static SU binary paths, dynamic PATH traversal, timeout-protected `su -v` execution | M3 | ORIGINAL_REQUEST §R2 |
| F09 | KernelSU & APatch Detection | OverlayFS inspection on system partitions in `/proc/self/mountinfo`, kernel version string matching | M3 | ORIGINAL_REQUEST §R2 |
| F10 | Magisk & Zygisk Detection | Mountinfo filesystem inversion (tmpfs/overlayfs on /system), Zygisk traces, Unix socket scans | M3 | ORIGINAL_REQUEST §R2 |
| F11 | Root Manager Package Detection | Known Root Manager APK package detection with Android 11+ permission/syscall side-channels | M3 | ORIGINAL_REQUEST §R2 |
| F12 | Xposed / LSPosed Detection | ClassLoader checks, stacktrace inspection (`de.robv.android.xposed`), maps inspection | M3 | ORIGINAL_REQUEST §R3 |
| F13 | Frida Dynamic Instrumentation | Port 27042 + TCP scan with D-Bus AUTH, thread scan (`gmain`, `gum-js-loop`), anonymous r-xp memory scan | M3 | ORIGINAL_REQUEST §R3 |
| F14 | Emulator & Hardware Artifacts | Build props (fingerprint, hardware, product), QEMU drivers/pipes, battery & sensor presence | M3 | ORIGINAL_REQUEST §R4 |
| F15 | Dual-App & Virtual Container | Private data path redirection check (`virtual/`, `io.va.exposed/`, 999 user), container signatures | M3 | ORIGINAL_REQUEST §R4 |
| F16 | Debugger & Anti-Tracking | JDWP `isDebuggerConnected()`, ADB setting, TracerPid in status, defensive `ptrace(PTRACE_TRACEME)` | M3 | ORIGINAL_REQUEST §R4 |
| F17 | Asymmetric Security Scorer | Weighted risk scoring (DANGER caps at 40, WARN caps at 75, SAFE 95-100) | M3 | ORIGINAL_REQUEST §R6 |
| F18 | Jetpack Compose UI Dashboard | Material3 UI with risk score badge, 5 category summary cards, expandable detection detail cards | M4 | ORIGINAL_REQUEST §R6 |
| F19 | Async Scanning & Re-Scan | Kotlin Coroutines asynchronous execution without UI thread blocking, scan progress animation | M4 | ORIGINAL_REQUEST §R6 |
| F20 | Diagnostic Report Export | Structured JSON / Plaintext export, device metadata, timestamp, clipboard copy and file share | M4 | ORIGINAL_REQUEST §R6 |
| F21 | E2E Test Suite & Test Runner | Complete 4-tier E2E test suite (Feature, Boundary, Combinatorial, Workload) and runner script | M-TEST | Dual Track Plan |
| F22 | Full Verification & Hardening | 100% E2E test pass (Tiers 1-4) + Tier 5 adversarial coverage hardening | M5 | ORIGINAL_REQUEST §Acceptance |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M-TEST | E2E Testing Suite | Requirements-driven opaque-box test runner and Tiers 1-4 test suite, publish TEST_READY.md | none | DONE |
| M1 | Project Foundation & Build System | Gradle 8.11.1, AGP 8.7.3, Compose 2.0.21, CMake C++17 build setup, JNI skeleton, assembleDebug passes | none | DONE |
| M2 | Native Syscall & Low-Level Engine | Direct inline syscalls (ARM64/ARM32/x86_64), hook-free maps, mountinfo, properties parsers | M1 | DONE |
| M3 | Core Security Detectors & Scorer | R1 (Bootloader), R2 (Root/KSU/Magisk), R3 (Xposed/Frida), R4 (Emulator/Virtual/Debug), SecurityScorer | M2 | DONE |
| M4 | Compose UI & Report Export | Material3 UI, risk badges, category filter cards, item detail cards, async scan, JSON report export | M3 | DONE |
| M5 | E2E Validation & Adversarial Hardening | Pass 100% E2E tests (Tiers 1-4), Tier 5 adversarial challenge hardening, Forensic Audit clean | M4, M-TEST | DONE |

---

## Interface Contracts

### JNI Contract: `SecurityEngineNative` ↔ `libsecurity_engine.so`
- **Class**: `com.security.environment.data.jni.SecurityEngineNative`
- **Methods**:
  ```kotlin
  external fun executeAllChecks(): Array<NativeDetectionItem>
  external fun executeCategoryChecks(categoryIndex: Int): Array<NativeDetectionItem>
  external fun readSystemPropertyNative(key: String): String?
  external fun checkDirectSyscallAvailable(): Boolean
  ```
- **Data Transfer Object**:
  ```kotlin
  data class NativeDetectionItem(
      val id: String,              // e.g. "SEC-R1-01"
      val name: String,            // e.g. "Bootloader Lock State"
      val category: Int,          // 0:BOOTLOADER, 1:ROOT, 2:HOOK, 3:VIRTUAL, 4:DEBUG
      val status: Int,            // 0:PASS, 1:WARN, 2:DANGER
      val evidence: String,        // e.g. "ro.boot.flash.locked=0"
      val method: Int              // 0:JAVA, 1:NATIVE_LIBC, 2:DIRECT_SYSCALL
  )
  ```

### Domain Contract: `DetectionCoordinator` ↔ `SecurityScorer`
- **Function**:
  ```kotlin
  fun calculateScore(items: List<DetectionItem>): SecurityAssessment
  
  data class SecurityAssessment(
      val score: Int,              // 0 to 100
      val level: SecurityLevel,    // SAFE, WARNING, DANGEROUS
      val dangerCount: Int,
      val warnCount: Int,
      val passCount: Int,
      val summary: String
  )
  ```

### Export Contract: `ReportSerializer`
- **Output JSON Schema**:
  ```json
  {
    "appVersion": "1.0.0",
    "timestamp": 1774032000000,
    "deviceInfo": {
      "fingerprint": "...",
      "brand": "...",
      "model": "...",
      "androidVersion": "...",
      "apiLevel": 35,
      "arch": "arm64-v8a"
    },
    "assessment": {
      "score": 85,
      "level": "SAFE",
      "dangerCount": 0,
      "warnCount": 1,
      "passCount": 19
    },
    "items": [
      {
        "id": "SEC-R1-01",
        "name": "Bootloader Lock State",
        "category": "BOOTLOADER",
        "status": "PASS",
        "evidence": "ro.boot.flash.locked=1",
        "method": "DIRECT_SYSCALL"
      }
    ]
  }
  ```

---

## Code Layout
```
/root/环境检测/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── local.properties
├── gradlew
├── gradle/wrapper/
│   ├── gradle-wrapper.jar
│   └── gradle-wrapper.properties
└── app/
    ├── build.gradle.kts
    ├── proguard-rules.pro
    └── src/
        ├── main/
        │   ├── AndroidManifest.xml
        │   ├── cpp/
        │   │   ├── CMakeLists.txt
        │   │   ├── include/
        │   │   │   ├── security_types.h
        │   │   │   ├── syscall_helper.h
        │   │   │   ├── native_bootloader.h
        │   │   │   ├── native_root.h
        │   │   │   ├── native_hook.h
        │   │   │   ├── native_maps.h
        │   │   │   └── native_debug.h
        │   │   └── src/
        │   │       ├── security_engine_jni.cpp
        │   │       ├── syscall_helper.cpp
        │   │       ├── native_bootloader.cpp
        │   │       ├── native_root.cpp
        │   │       ├── native_hook.cpp
        │   │       ├── native_maps.cpp
        │   │       └── native_debug.cpp
        │   ├── java/com/security/environment/
        │   │   ├── MainActivity.kt
        │   │   ├── SecurityApp.kt
        │   │   ├── data/
        │   │   │   ├── model/
        │   │   │   ├── jni/
        │   │   │   ├── source/
        │   │   │   └── export/
        │   │   ├── domain/
        │   │   │   ├── DetectionCoordinator.kt
        │   │   │   ├── SecurityScorer.kt
        │   │   │   └── detectors/
        │   │   └── ui/
        │   │       ├── theme/
        │   │       ├── state/
        │   │       ├── viewmodel/
        │   │       └── screens/
        │   └── res/
        └── test/
            └── java/com/security/environment/
                ├── domain/
                ├── data/
                └── ui/
```
