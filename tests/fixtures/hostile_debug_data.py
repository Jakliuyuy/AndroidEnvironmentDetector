"""
Hostile Debugger & TracerPid Attachment Fixtures (S5).
"""

HOSTILE_STATUS = """
Name:   com.sec.app
Umask:  0077
State:  t (tracing stop)
Tgid:   12345
Ngid:   0
Pid:    12345
PPid:   678
TracerPid:      4321
Uid:    10123   10123   10123   10123
Gid:    10123   10123   10123   10123
FDSize: 64
Groups: 10123 
"""

DEBUGGER_CONNECTED = True
ADB_ENABLED = True
ATTACHED_TRACER_PID = 4321
