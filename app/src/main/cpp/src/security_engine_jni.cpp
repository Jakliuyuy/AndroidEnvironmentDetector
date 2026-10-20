#include <jni.h>
#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <vector>

#include "security_types.h"
#include "syscall_helper.h"
#include "native_maps.h"
#include "native_mounts.h"
#include "native_status.h"
#include "native_props.h"
#include "obfuscate.h"
#include "native_kernel_probe.h"
#include "native_anti_hook.h"

#define LOG_TAG "SecurityEngineNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static jclass g_nativeItemClass = nullptr;
static jmethodID g_nativeItemConstructor = nullptr;

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }

    jclass localClass = env->FindClass("com/security/environment/data/model/NativeDetectionItem");
    if (!localClass) {
        LOGE("JNI_OnLoad: NativeDetectionItem class not found");
        return JNI_ERR;
    }

    g_nativeItemClass = reinterpret_cast<jclass>(env->NewGlobalRef(localClass));
    g_nativeItemConstructor = env->GetMethodID(
        g_nativeItemClass,
        "<init>",
        "(Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;I)V"
    );

    if (!g_nativeItemConstructor) {
        LOGE("JNI_OnLoad: NativeDetectionItem constructor not found");
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: Initialized successfully with low-level syscall engine");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && g_nativeItemClass) {
        env->DeleteGlobalRef(g_nativeItemClass);
        g_nativeItemClass = nullptr;
    }
}

static jobject CreateNativeDetectionItemObject(
    JNIEnv* env,
    const security::NativeDetectionItem& item) {
    if (!g_nativeItemClass || !g_nativeItemConstructor) {
        return nullptr;
    }

    jstring jId = env->NewStringUTF(item.id.c_str());
    jstring jName = env->NewStringUTF(item.name.c_str());
    jstring jEvidence = env->NewStringUTF(item.evidence.c_str());

    jobject obj = env->NewObject(
        g_nativeItemClass,
        g_nativeItemConstructor,
        jId,
        jName,
        static_cast<jint>(item.category),
        static_cast<jint>(item.status),
        jEvidence,
        static_cast<jint>(item.method)
    );

    if (jId) env->DeleteLocalRef(jId);
    if (jName) env->DeleteLocalRef(jName);
    if (jEvidence) env->DeleteLocalRef(jEvidence);

    return obj;
}

static jobjectArray CreateNativeDetectionItemArray(
    JNIEnv* env,
    const std::vector<security::NativeDetectionItem>& items) {
    if (!g_nativeItemClass) {
        return nullptr;
    }

    jobjectArray arr = env->NewObjectArray(
        static_cast<jsize>(items.size()),
        g_nativeItemClass,
        nullptr
    );

    for (size_t i = 0; i < items.size(); ++i) {
        jobject itemObj = CreateNativeDetectionItemObject(env, items[i]);
        if (itemObj) {
            env->SetObjectArrayElement(arr, static_cast<jsize>(i), itemObj);
            env->DeleteLocalRef(itemObj);
        }
    }

    return arr;
}

// Generate genuine detection results using native syscall engine
static std::vector<security::NativeDetectionItem> PerformNativeSecurityChecks(int categoryFilter) {
    std::vector<security::NativeDetectionItem> results;

    // Category 0: Bootloader & System Integrity
    if (categoryFilter == -1 || categoryFilter == security::CAT_BOOTLOADER) {
        auto props = security::ScanSecurityProperties();
        results.push_back(security::EvaluateBootloaderProps(props));
        results.push_back(security::EvaluateBuildTagsProps(props));
    }

    // Category 1: Root & Concealment (SU paths + mountinfo inspection)
    if (categoryFilter == -1 || categoryFilter == security::CAT_ROOT) {
        // Probe static SU paths with direct faccessat syscall
        static const auto suPaths = {
            OBF_STR("/system/bin/su").str(),
            OBF_STR("/system/xbin/su").str(),
            OBF_STR("/sbin/su").str(),
            OBF_STR("/vendor/bin/su").str(),
            OBF_STR("/data/local/xbin/su").str(),
            OBF_STR("/data/local/bin/su").str(),
            OBF_STR("/data/local/su").str(),
            OBF_STR("/data/local/tmp/su").str()
        };
        bool suFound = false;
        std::string foundPath = "None";
        for (const auto& path : suPaths) {
            long ret = security::sys_faccessat(-100 /* AT_FDCWD */, path.c_str(), F_OK, 0);
            if (ret == 0) {
                suFound = true;
                foundPath = path;
                break;
            }
        }

        results.push_back({
            "SEC-R2-01",
            OBF_STR("基础 SU 二进制底层探测 (Direct Syscall)").str(),
            security::CAT_ROOT,
            suFound ? security::STATUS_DANGER : security::STATUS_PASS,
            "faccessat_path=" + foundPath,
            security::METHOD_DIRECT_SYSCALL
        });

        // Scan mountinfo for Magisk Magic Mount inversion & KernelSU / APatch mounts
        auto mountRes = security::ScanProcMountinfoDirect();
        results.push_back(security::EvaluateMountsDetection(mountRes));

        // R2: KernelSU prctl handshake & APatch SuperCall probe
        auto kernelRootRes = security::ProbeKernelRootDirect();
        results.push_back(security::EvaluateKernelSuDetection(kernelRootRes));
        results.push_back(security::EvaluateApatchDetection(kernelRootRes));
    }

    // Category 2: Dynamic Hook & Instrumentation (/proc/self/maps)
    if (categoryFilter == -1 || categoryFilter == security::CAT_HOOK) {
        // Frida & Xposed & anonymous executable memory scan via direct syscall
        auto mapsRes = security::ScanProcMapsDirect();
        results.push_back(security::EvaluateMapsDetection(mapsRes));

        // R3: ELF .text integrity & Anti-Inline Hook trampoline probe
        auto antiHookRes = security::ScanAntiHookIntegrityDirect();
        results.push_back(security::EvaluateAntiHookDetection(antiHookRes));
    }

    // Category 3: Virtualization & Emulator
    if (categoryFilter == -1 || categoryFilter == security::CAT_VIRTUAL) {
        std::string hardware = security::ReadSystemProperty(OBF_STR("ro.hardware").c_str());
        bool isQemu = (hardware.find(OBF_STR("qemu").str()) != std::string::npos ||
                       hardware.find(OBF_STR("goldfish").str()) != std::string::npos);

        results.push_back({
            "SEC-R4-01",
            "QEMU/模拟器硬件特征探测",
            security::CAT_VIRTUAL,
            isQemu ? security::STATUS_WARN : security::STATUS_PASS,
            "ro.hardware=" + (hardware.empty() ? "unknown" : hardware),
            security::METHOD_NATIVE_LIBC
        });
    }

    // Category 4: Debug & Anti-Tracking (/proc/self/status TracerPid)
    if (categoryFilter == -1 || categoryFilter == security::CAT_DEBUG) {
        auto statusRes = security::ReadProcStatusDirect();
        results.push_back(security::EvaluateStatusDetection(statusRes));

        std::string adbProp = security::ReadSystemProperty(OBF_STR("init.svc.adbd").c_str());
        int adbStatus = (adbProp == OBF_STR("running").str()) ? security::STATUS_WARN : security::STATUS_PASS;
        results.push_back({
            "SEC-R4-02",
            "ADB 调试守护进程状态",
            security::CAT_DEBUG,
            adbStatus,
            "init.svc.adbd=" + adbProp,
            security::METHOD_NATIVE_LIBC
        });
    }

    return results;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_executeAllChecks(
    JNIEnv* env, jobject /*thiz*/) {
    auto items = PerformNativeSecurityChecks(-1);
    return CreateNativeDetectionItemArray(env, items);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_executeCategoryChecks(
    JNIEnv* env, jobject /*thiz*/, jint categoryIndex) {
    auto items = PerformNativeSecurityChecks(categoryIndex);
    return CreateNativeDetectionItemArray(env, items);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_readSystemPropertyNative(
    JNIEnv* env, jobject /*thiz*/, jstring jKey) {
    if (!jKey) return nullptr;
    const char* keyChars = env->GetStringUTFChars(jKey, nullptr);
    if (!keyChars) return nullptr;

    std::string val = security::ReadSystemProperty(keyChars);
    env->ReleaseStringUTFChars(jKey, keyChars);

    if (!val.empty()) {
        return env->NewStringUTF(val.c_str());
    }
    return nullptr;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkDirectSyscallAvailable(
    JNIEnv* /*env*/, jobject /*thiz*/) {
    pid_t libcPid = ::getpid();
    pid_t directSyscallPid = static_cast<pid_t>(security::sys_getpid());

    if (directSyscallPid > 0 && directSyscallPid == libcPid) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

// -----------------------------------------------------------------------------
// Direct Low-Level JNI Query Endpoints
// -----------------------------------------------------------------------------

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkMapsNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ScanProcMapsDirect();
    auto item = security::EvaluateMapsDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkMountsNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ScanProcMountinfoDirect();
    auto item = security::EvaluateMountsDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkStatusNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ReadProcStatusDirect();
    auto item = security::EvaluateStatusDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_getTracerPidNative(
    JNIEnv* /*env*/, jobject /*thiz*/) {
    auto res = security::ReadProcStatusDirect();
    return static_cast<jint>(res.tracerPid);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_parseMapsBufferNative(
    JNIEnv* env, jobject /*thiz*/, jstring jBuffer) {
    if (!jBuffer) return nullptr;
    const char* str = env->GetStringUTFChars(jBuffer, nullptr);
    jsize len = env->GetStringUTFLength(jBuffer);

    auto res = security::ParseMapsBuffer(str, static_cast<size_t>(len));
    env->ReleaseStringUTFChars(jBuffer, str);

    auto item = security::EvaluateMapsDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_parseMountinfoBufferNative(
    JNIEnv* env, jobject /*thiz*/, jstring jBuffer) {
    if (!jBuffer) return nullptr;
    const char* str = env->GetStringUTFChars(jBuffer, nullptr);
    jsize len = env->GetStringUTFLength(jBuffer);

    auto res = security::ParseMountinfoBuffer(str, static_cast<size_t>(len));
    env->ReleaseStringUTFChars(jBuffer, str);

    auto item = security::EvaluateMountsDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_parseStatusBufferNative(
    JNIEnv* env, jobject /*thiz*/, jstring jBuffer) {
    if (!jBuffer) return nullptr;
    const char* str = env->GetStringUTFChars(jBuffer, nullptr);
    jsize len = env->GetStringUTFLength(jBuffer);

    auto res = security::ParseStatusBuffer(str, static_cast<size_t>(len));
    env->ReleaseStringUTFChars(jBuffer, str);

    auto item = security::EvaluateStatusDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkKernelSuNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ProbeKernelRootDirect();
    auto item = security::EvaluateKernelSuDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkApatchNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ProbeKernelRootDirect();
    auto item = security::EvaluateApatchDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkKernelRootNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ProbeKernelRootDirect();
    auto item = security::EvaluateKernelSuDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_security_environment_data_jni_SecurityEngineNative_checkAntiHookNative(
    JNIEnv* env, jobject /*thiz*/) {
    auto res = security::ScanAntiHookIntegrityDirect();
    auto item = security::EvaluateAntiHookDetection(res);
    return CreateNativeDetectionItemObject(env, item);
}
