# ==============================================================================
# Production-Grade ProGuard & R8 Hardening Rules for Android Environment Detector
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. JNI Bridge & Native Data Transfer Objects (Critical for NDK Linkage)
# ------------------------------------------------------------------------------
-keep class com.security.environment.data.jni.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep NativeDetectionItem strictly intact (class name, fields, and 6-arg constructor)
# for C++ JNI reflection via FindClass and GetMethodID in security_engine_jni.cpp
-keep class com.security.environment.data.model.NativeDetectionItem {
    public <init>(java.lang.String, java.lang.String, int, int, java.lang.String, int);
    *;
}
-keepclassmembers class com.security.environment.data.model.NativeDetectionItem {
    <fields>;
    <methods>;
}

# ------------------------------------------------------------------------------
# 2. Domain Models & Enums
# ------------------------------------------------------------------------------
-keep class com.security.environment.data.model.** { *; }
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ------------------------------------------------------------------------------
# 3. Serialization Rules (Kotlinx Serialization / Gson / org.json)
# ------------------------------------------------------------------------------
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature

# Kotlinx Serialization
-keepclassmembers class * {
    @kotlinx.serialization.SerialName <fields>;
    @kotlinx.serialization.Serializable <fields>;
    *** Companion;
}
-dontwarn kotlinx.serialization.**

# Gson
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
    @com.google.gson.annotations.Expose <fields>;
}

# ------------------------------------------------------------------------------
# 4. Jetpack Compose Runtime & UI
# ------------------------------------------------------------------------------
-keep class androidx.compose.runtime.** { *; }
-keep class androidx.compose.ui.** { *; }
-keep class androidx.compose.material3.** { *; }
-keep class androidx.compose.animation.** { *; }
-dontwarn androidx.compose.**

# ------------------------------------------------------------------------------
# 5. AndroidX Lifecycle & ViewModel
# ------------------------------------------------------------------------------
-keep class * extends androidx.lifecycle.ViewModel {
    public <init>();
    public <init>(...);
}
-keep class * extends androidx.lifecycle.AndroidViewModel {
    public <init>(android.app.Application);
}
-keep class androidx.lifecycle.ViewModelProvider$Factory { *; }

# ------------------------------------------------------------------------------
# 6. Coroutines Internal Hooks
# ------------------------------------------------------------------------------
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ------------------------------------------------------------------------------
# 7. General Optimization & Safety Directives
# ------------------------------------------------------------------------------
-repackageclasses 'com.security.environment.s'
-allowaccessmodification
-dontusemixedcaseclassnames
-verbose
