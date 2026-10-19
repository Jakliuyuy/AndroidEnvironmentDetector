# E2E Test Infra: Android Environment Security Detection App

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Derived directly from `ORIGINAL_REQUEST.md` user requirements and acceptance criteria, treating the application and detection engine as an opaque-box system under test.
- **Progressive Testability**: Verification mechanisms do not require features more complex than what they verify. Early tiers (JVM testDebugUnitTest, headless mocked engines, APK build check) give high-confidence pass/fail signals independently of physical hardware.
- **Methodology**: Systematic 4-Tier verification combining Category-Partition, Boundary Value Analysis (BVA), Pairwise Combinatorial Testing, and Realistic Threat Emulation Scenarios.

---

## Feature Inventory Coverage Matrix
| # | Feature | Category | Source Requirement | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---|---------|----------|--------------------|:------:|:------:|:------:|:------:|
| F01 | Gradle & NDK Build System | Build / Packaging | ORIGINAL_REQUEST §Acceptance | 5 | 5 | ✓ | ✓ |
| F02 | JNI Bridge Skeleton | Interop / Native | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F03 | Direct Syscall Inline Engine | Native Kernel | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F04 | Native Low-Level Parsers | Native Engine | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F05 | Bootloader Status Detection | System Integrity | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F06 | SELinux Mode & Context Check | System Integrity | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F07 | System Build Tags & Keys | System Integrity | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F08 | Conventional SU & PATH Scan | Root Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F09 | KernelSU & APatch Detection | Root Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F10 | Magisk & Zygisk Detection | Root Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F11 | Root Manager Package Detection | Root Detection | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F12 | Xposed / LSPosed Detection | Hook / Injection | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| F13 | Frida Dynamic Instrumentation | Hook / Injection | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| F14 | Emulator & Hardware Artifacts | Virtualization | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| F15 | Dual-App & Virtual Container | Virtualization | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| F16 | Debugger & Anti-Tracking | Anti-Debugging | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| F17 | Asymmetric Security Scorer | Scoring Engine | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |
| F18 | Jetpack Compose UI Dashboard | UI / UX | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |
| F19 | Async Scanning & Re-Scan | Async Engine | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |
| F20 | Diagnostic Report Export | Report / Export | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |

---

## Test Architecture

### 1. Test Execution Channels
1. **JVM Unit Tests (`./gradlew testDebugUnitTest`)**:
   - Comprehensive headless unit tests verifying all detection parsers (maps, mountinfo, status, properties), detection scoring logic, report JSON serialization, and simulated vector state machines.
   - Run independently on JVM 17 without physical hardware dependencies.
2. **APK Build & Packaging Verification (`./gradlew assembleDebug`)**:
   - Verifies complete compilation of Kotlin + Compose + CMake Native C++ NDK library (`libsecurity_engine.so`) for all ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
   - Asserts zero linking, JNI mismatch, or unresolved symbol errors.
3. **Redroid Emulated Device Execution & Dynamic Verification**:
   - Deploys built APK to `127.0.0.1:55555` (Redroid Android 11 container) via ADB.
   - Exercises real detection scan on real Android kernel and verifies accurate risk detection (e.g. Redroid emulated environment, test-keys, adb enabled, TracerPid).
   - Extracts exported diagnostic report JSON via ADB pull or logcat broadcast.

---

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Threat Model & Validation Target | Complexity |
|---|----------|--------------------|----------------------------------|------------|
| S1 | Clean Retail Device Emulation | F05-F07, F17, F18, F20 | Validates that an uncompromised system scores 100/SAFE with zero false alarms. | Medium |
| S2 | High-Privilege Magisk/KernelSU Device | F08-F11, F17, F18, F20 | Validates mountinfo overlayfs/tmpfs anomaly detection triggering instant DANGER score cap <= 40. | High |
| S3 | Active Frida/LSPosed Dynamic Injection | F12-F13, F03, F04, F17 | Validates detection of anonymous r-xp memory, Frida ports, and Xposed classes overriding normal state. | High |
| S4 | VirtualApp / Parallel Space Dual Container | F14-F15, F17, F20 | Validates private storage path redirection and package mismatch identification. | Medium |
| S5 | Hostile Debugger & TracerPid Attachment | F16, F03, F17, F20 | Validates JDWP connection detection and `/proc/self/status` TracerPid non-zero alerting. | Medium |

---

## Coverage Thresholds
- **Tier 1 (Feature Coverage)**: ≥ 100 tests (20 features × 5 tests each) covering baseline happy-path evaluations.
- **Tier 2 (Boundary & Corner Cases)**: ≥ 100 tests covering edge-cases (corrupted `/proc` files, truncated maps, empty properties, extreme PID values, malformed JSON).
- **Tier 3 (Cross-Feature Combinations)**: ≥ 20 pairwise combination tests (e.g., Magisk + Frida simultaneously, Bootloader unlocked + SELinux Permissive, Virtual Container + ADB Debugging).
- **Tier 4 (Real-World Application Scenarios)**: 5 comprehensive end-to-end scenario evaluations (S1–S5).
- **Total Minimum Target**: ≥ 225 test cases across the test suite.
