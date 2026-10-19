"""
Magisk, KernelSU, and APatch Compromised Device Fixtures (S2).
"""

MAGISK_MOUNTINFO = """
15 20 0:17 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
16 20 0:18 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
20 1 253:0 / / rw,relatime - ext4 /dev/block/dm-0 ro
21 20 0:35 / /system rw,relatime - tmpfs tmpfs rw,seclabel
22 20 0:36 / /system/bin rw,relatime - tmpfs magisk rw
23 20 0:37 / /debug_ramdisk rw,relatime - tmpfs magisk rw
24 20 253:4 /data /data rw,nosuid,nodev,noatime - f2fs /dev/block/dm-4 rw
"""

KSU_MOUNTINFO = """
15 20 0:17 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
16 20 0:18 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
20 1 253:0 / / rw,relatime - ext4 /dev/block/dm-0 ro
21 20 0:42 / /system rw,relatime - overlay overlay rw,lowerdir=/system,upperdir=/data/adb/modules/system
22 20 0:43 / /vendor rw,relatime - overlay overlay rw,lowerdir=/vendor,upperdir=/data/adb/modules/vendor
24 20 253:4 /data /data rw,nosuid,nodev,noatime - f2fs /dev/block/dm-4 rw
"""

ROOT_EXISTING_FILES = [
    "/system/bin/su",
    "/data/local/tmp/su",
    "/sbin/su",
]

ROOT_UNIX_SOCKETS = [
    "/dev/socket/magiskd",
    "@zygisk_daemon_64",
]

ROOT_PACKAGES = [
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
    "bmax.apatch",
]
