"""
Corrupted, Truncated, and Malformed Fixtures for Tier 2 Boundary Testing.
"""

CORRUPTED_MAPS_MISSING_PERMS = """
78c2e000-78c2f000
78c30000-78df3000 r-xp 00000000
INVALID_LINE_NO_ADDRESS_RANGE
"""

CORRUPTED_MAPS_OVERSIZED_LINE = (
    "78c2e000-78c2f000 r-xp 00000000 00:00 0 " + ("/very_long_path" * 2000)
)

CORRUPTED_MOUNTINFO_NO_DASH = """
15 20 0:17 / /sys rw,nosuid,nodev,noexec,relatime sysfs sysfs rw
INVALID MOUNTINFO CONTENT WITHOUT DELIMITER
"""

CORRUPTED_MOUNTINFO_TRUNCATED = """
15 20 0:17
"""

CORRUPTED_STATUS_MALFORMED = """
Name
TracerPid: not_a_number
Uid: negative -1
Gid
"""

MALFORMED_PROPERTIES = """
[key_without_closing_bracket: [val]
[key_with_unmatched]: val_no_brackets
===
invalid line
"""
