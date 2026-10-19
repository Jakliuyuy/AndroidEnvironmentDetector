# ProGuard rules for Environment Security Detector
-keep class com.security.environment.data.jni.** { *; }
-keep class com.security.environment.data.model.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
