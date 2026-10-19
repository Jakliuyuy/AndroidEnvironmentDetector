"""
Clean Retail Device Fixture (S1 baseline).
Represents a genuine, locked, unrooted, retail physical device running Android 14/15.
"""

CLEAN_PROPERTIES = {
    "ro.boot.flash.locked": "1",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.vbmeta.device_state": "locked",
    "ro.build.tags": "release-keys",
    "ro.build.type": "user",
    "ro.product.brand": "google",
    "ro.product.model": "Pixel 8 Pro",
    "ro.hardware": "husky",
    "ro.kernel.qemu": "0",
}

CLEAN_MOUNTINFO = """
15 20 0:17 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
16 20 0:18 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
20 1 253:0 / / rw,relatime - ext4 /dev/block/dm-0 ro
21 20 253:1 /system /system ro,relatime - ext4 /dev/block/dm-1 ro
22 20 253:2 /vendor /vendor ro,relatime - ext4 /dev/block/dm-2 ro
23 20 253:3 /product /product ro,relatime - ext4 /dev/block/dm-3 ro
24 20 253:4 /data /data rw,nosuid,nodev,noatime - f2fs /dev/block/dm-4 rw
"""

CLEAN_MAPS = """
78c2e000-78c2f000 r--p 00000000 00:00 0 [anon:linker_alloc]
78c2f000-78c30000 rw-p 00000000 00:00 0 [anon:linker_alloc]
78c30000-78df3000 r-xp 00000000 07:40 1205 /apex/com.android.runtime/bin/linker64
78df3000-78df5000 r--p 001c2000 07:40 1205 /apex/com.android.runtime/bin/linker64
78df5000-78df6000 rw-p 001c4000 07:40 1205 /apex/com.android.runtime/bin/linker64
7b3c0000-7b440000 r-xp 00000000 fe:00 4812 /system/lib64/libc.so
7b440000-7b445000 r--p 0007f000 fe:00 4812 /system/lib64/libc.so
7b445000-7b447000 rw-p 00084000 fe:00 4812 /system/lib64/libc.so
7fff1000-7fff2000 rw-p 00000000 00:00 0 [stack]
"""

CLEAN_STATUS = """
Name:   com.sec.app
Umask:  0077
State:  R (running)
Tgid:   12345
Ngid:   0
Pid:    12345
PPid:   678
TracerPid:      0
Uid:    10123   10123   10123   10123
Gid:    10123   10123   10123   10123
FDSize: 64
Groups: 10123 
"""

CLEAN_DATA_DIR = "/data/user/0/com.security.environment"
CLEAN_UID = 10123
CLEAN_OPEN_PORTS = []
CLEAN_THREAD_NAMES = ["main", "RenderThread", "hwuiTask1"]
CLEAN_PACKAGES = [
    "com.google.android.gms",
    "com.google.android.youtube",
    "com.android.chrome",
    "com.security.environment",
]
