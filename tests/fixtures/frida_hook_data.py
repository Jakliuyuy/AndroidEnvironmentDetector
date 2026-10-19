"""
Frida Dynamic Instrumentation and Xposed/LSPosed Hook Fixtures (S3).
"""

FRIDA_OPEN_PORTS = [27042, 27043]

HOOK_THREAD_NAMES = [
    "main",
    "gum-js-loop",
    "gmain",
    "gdbus",
]

XPOSED_LOADED_CLASSES = [
    "de.robv.android.xposed.XposedBridge",
    "de.robv.android.xposed.XposedHelpers",
    "org.lsposed.lspd.core.Main",
]

XPOSED_STACKTRACE = """
java.lang.Exception: Stack trace probe
    at com.security.environment.domain.detectors.HookDetector.probe(HookDetector.kt:42)
    at de.robv.android.xposed.XposedBridge.invokeOriginalMethodNative(Native Method)
    at de.robv.android.xposed.XposedBridge.handleHookedMethod(XposedBridge.java:374)
    at com.security.environment.MainActivity.onCreate(MainActivity.kt:18)
"""

INJECTED_MAPS = """
78c2e000-78c2f000 r--p 00000000 00:00 0 [anon:linker_alloc]
78c30000-78df3000 r-xp 00000000 07:40 1205 /apex/com.android.runtime/bin/linker64
7a100000-7a250000 r-xp 00000000 00:00 0 /data/local/tmp/re.frida.server/frida-agent-64.so
7a250000-7a260000 rw-p 00150000 00:00 0 /data/local/tmp/re.frida.server/frida-agent-64.so
7b000000-7b020000 r-xp 00000000 00:00 0 /data/adb/lspd/liblsp.so
7c000000-7c010000 r-xp 00000000 00:00 0 
7c010000-7c020000 r-xp 00000000 00:00 0 
7c020000-7c030000 r-xp 00000000 00:00 0 
7c030000-7c040000 r-xp 00000000 00:00 0 
7fff1000-7fff2000 rw-p 00000000 00:00 0 [stack]
"""
