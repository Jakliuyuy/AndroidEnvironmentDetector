#include "syscall_helper.h"
#include <sys/syscall.h>
#include <cerrno>

namespace security {

// -----------------------------------------------------------------------------
// ARM64 (aarch64) Implementation
// -----------------------------------------------------------------------------
#if defined(__aarch64__)

long sys_openat(int dfd, const char *filename, int flags, mode_t mode) {
    register long x0 __asm__("x0") = static_cast<long>(dfd);
    register long x1 __asm__("x1") = reinterpret_cast<long>(filename);
    register long x2 __asm__("x2") = static_cast<long>(flags);
    register long x3 __asm__("x3") = static_cast<long>(mode);
    register long x8 __asm__("x8") = 56; // __NR_openat
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_read(int fd, void *buf, size_t count) {
    register long x0 __asm__("x0") = static_cast<long>(fd);
    register long x1 __asm__("x1") = reinterpret_cast<long>(buf);
    register long x2 __asm__("x2") = static_cast<long>(count);
    register long x8 __asm__("x8") = 63; // __NR_read
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_close(int fd) {
    register long x0 __asm__("x0") = static_cast<long>(fd);
    register long x8 __asm__("x8") = 57; // __NR_close
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_readlinkat(int dfd, const char *path, char *buf, size_t bufsiz) {
    register long x0 __asm__("x0") = static_cast<long>(dfd);
    register long x1 __asm__("x1") = reinterpret_cast<long>(path);
    register long x2 __asm__("x2") = reinterpret_cast<long>(buf);
    register long x3 __asm__("x3") = static_cast<long>(bufsiz);
    register long x8 __asm__("x8") = 78; // __NR_readlinkat
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_faccessat(int dfd, const char *filename, int mode, int flags) {
    register long x0 __asm__("x0") = static_cast<long>(dfd);
    register long x1 __asm__("x1") = reinterpret_cast<long>(filename);
    register long x2 __asm__("x2") = static_cast<long>(mode);
    register long x3 __asm__("x3") = static_cast<long>(flags);
    register long x8 __asm__("x8") = 48; // __NR_faccessat
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_getpid() {
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = 172; // __NR_getpid
    __asm__ volatile (
        "svc #0\n\t"
        : "=r"(x0)
        : "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    register long x0 __asm__("x0") = static_cast<long>(option);
    register long x1 __asm__("x1") = static_cast<long>(arg2);
    register long x2 __asm__("x2") = static_cast<long>(arg3);
    register long x3 __asm__("x3") = static_cast<long>(arg4);
    register long x4 __asm__("x4") = static_cast<long>(arg5);
    register long x8 __asm__("x8") = 167; // __NR_prctl
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

long sys_truncate(const char *path, off_t length) {
    register long x0 __asm__("x0") = reinterpret_cast<long>(path);
    register long x1 __asm__("x1") = static_cast<long>(length);
    register long x8 __asm__("x8") = 45; // __NR_truncate
    __asm__ volatile (
        "svc #0\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x8)
        : "memory", "cc"
    );
    return x0;
}

// -----------------------------------------------------------------------------
// ARM32 (armeabi-v7a) Implementation with Thumb r7 protection
// -----------------------------------------------------------------------------
#elif defined(__arm__)

long sys_openat(int dfd, const char *filename, int flags, mode_t mode) {
    register long r0 __asm__("r0") = static_cast<long>(dfd);
    register long r1 __asm__("r1") = reinterpret_cast<long>(filename);
    register long r2 __asm__("r2") = static_cast<long>(flags);
    register long r3 __asm__("r3") = static_cast<long>(mode);
    long nr = 322; // __NR_openat
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1), "r"(r2), "r"(r3)
        : "memory", "cc"
    );
    return r0;
}

long sys_read(int fd, void *buf, size_t count) {
    register long r0 __asm__("r0") = static_cast<long>(fd);
    register long r1 __asm__("r1") = reinterpret_cast<long>(buf);
    register long r2 __asm__("r2") = static_cast<long>(count);
    long nr = 3; // __NR_read
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1), "r"(r2)
        : "memory", "cc"
    );
    return r0;
}

long sys_close(int fd) {
    register long r0 __asm__("r0") = static_cast<long>(fd);
    long nr = 6; // __NR_close
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr)
        : "memory", "cc"
    );
    return r0;
}

long sys_readlinkat(int dfd, const char *path, char *buf, size_t bufsiz) {
    register long r0 __asm__("r0") = static_cast<long>(dfd);
    register long r1 __asm__("r1") = reinterpret_cast<long>(path);
    register long r2 __asm__("r2") = reinterpret_cast<long>(buf);
    register long r3 __asm__("r3") = static_cast<long>(bufsiz);
    long nr = 332; // __NR_readlinkat
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1), "r"(r2), "r"(r3)
        : "memory", "cc"
    );
    return r0;
}

long sys_faccessat(int dfd, const char *filename, int mode, int flags) {
    register long r0 __asm__("r0") = static_cast<long>(dfd);
    register long r1 __asm__("r1") = reinterpret_cast<long>(filename);
    register long r2 __asm__("r2") = static_cast<long>(mode);
    register long r3 __asm__("r3") = static_cast<long>(flags);
    long nr = 334; // __NR_faccessat
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1), "r"(r2), "r"(r3)
        : "memory", "cc"
    );
    return r0;
}

long sys_getpid() {
    register long r0 __asm__("r0");
    long nr = 20; // __NR_getpid
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "=r"(r0)
        : "r"(nr)
        : "memory", "cc"
    );
    return r0;
}

long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long /*arg5*/) {
    register long r0 __asm__("r0") = static_cast<long>(option);
    register long r1 __asm__("r1") = static_cast<long>(arg2);
    register long r2 __asm__("r2") = static_cast<long>(arg3);
    register long r3 __asm__("r3") = static_cast<long>(arg4);
    long nr = 172; // __NR_prctl
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1), "r"(r2), "r"(r3)
        : "memory", "cc"
    );
    return r0;
}

long sys_truncate(const char *path, off_t length) {
    register long r0 __asm__("r0") = reinterpret_cast<long>(path);
    register long r1 __asm__("r1") = static_cast<long>(length);
    long nr = 92; // __NR_truncate
    __asm__ volatile (
        "push {r7}\n\t"
        "mov r7, %1\n\t"
        "svc #0\n\t"
        "pop {r7}\n\t"
        : "+r"(r0)
        : "r"(nr), "r"(r1)
        : "memory", "cc"
    );
    return r0;
}

// -----------------------------------------------------------------------------
// x86_64 Implementation
// -----------------------------------------------------------------------------
#elif defined(__x86_64__)

long sys_openat(int dfd, const char *filename, int flags, mode_t mode) {
    long ret;
    register long r10 __asm__("r10") = static_cast<long>(mode);
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(257L), "D"(static_cast<long>(dfd)), "S"(reinterpret_cast<long>(filename)), "d"(static_cast<long>(flags)), "r"(r10)
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_read(int fd, void *buf, size_t count) {
    long ret;
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(0L), "D"(static_cast<long>(fd)), "S"(reinterpret_cast<long>(buf)), "d"(static_cast<long>(count))
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_close(int fd) {
    long ret;
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(3L), "D"(static_cast<long>(fd))
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_readlinkat(int dfd, const char *path, char *buf, size_t bufsiz) {
    long ret;
    register long r10 __asm__("r10") = static_cast<long>(bufsiz);
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(267L), "D"(static_cast<long>(dfd)), "S"(reinterpret_cast<long>(path)), "d"(reinterpret_cast<long>(buf)), "r"(r10)
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_faccessat(int dfd, const char *filename, int mode, int flags) {
    long ret;
    register long r10 __asm__("r10") = static_cast<long>(flags);
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(269L), "D"(static_cast<long>(dfd)), "S"(reinterpret_cast<long>(filename)), "d"(static_cast<long>(mode)), "r"(r10)
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_getpid() {
    long ret;
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(39L)
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    long ret;
    register long r10 __asm__("r10") = static_cast<long>(arg4);
    register long r8  __asm__("r8")  = static_cast<long>(arg5);
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(157L), "D"(static_cast<long>(option)), "S"(static_cast<long>(arg2)),
          "d"(static_cast<long>(arg3)), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

long sys_truncate(const char *path, off_t length) {
    long ret;
    __asm__ volatile (
        "syscall\n\t"
        : "=a"(ret)
        : "a"(76L), "D"(reinterpret_cast<long>(path)), "S"(static_cast<long>(length))
        : "rcx", "r11", "memory", "cc"
    );
    return ret;
}

#else

// Fallback for unsupported architectures
long sys_openat(int dfd, const char *filename, int flags, mode_t mode) {
    return ::syscall(__NR_openat, dfd, filename, flags, mode);
}

long sys_read(int fd, void *buf, size_t count) {
    return ::syscall(__NR_read, fd, buf, count);
}

long sys_close(int fd) {
    return ::syscall(__NR_close, fd);
}

long sys_readlinkat(int dfd, const char *path, char *buf, size_t bufsiz) {
    return ::syscall(__NR_readlinkat, dfd, path, buf, bufsiz);
}

long sys_faccessat(int dfd, const char *filename, int mode, int flags) {
    return ::syscall(__NR_faccessat, dfd, filename, mode, flags);
}

long sys_getpid() {
    return ::getpid();
}

long sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
#if defined(__NR_prctl)
    return ::syscall(__NR_prctl, option, arg2, arg3, arg4, arg5);
#else
    return -1;
#endif
}

long sys_truncate(const char *path, off_t length) {
#if defined(__NR_truncate)
    return ::syscall(__NR_truncate, path, length);
#else
    return -1;
#endif
}

#endif

// -----------------------------------------------------------------------------
// Direct Syscall Buffer Reading Functions
// -----------------------------------------------------------------------------

ssize_t DirectSyscallReadFile(const char* path, char* buffer, size_t max_bytes) {
    if (!path || !buffer || max_bytes == 0) {
        return -1;
    }

    long fd = sys_openat(-100 /* AT_FDCWD */, path, O_RDONLY, 0);
    if (fd < 0) {
        return -1;
    }

    size_t total_read = 0;
    while (total_read < max_bytes - 1) {
        size_t chunk_size = max_bytes - 1 - total_read;
        long n = sys_read(static_cast<int>(fd), buffer + total_read, chunk_size);
        if (n <= 0) {
            break;
        }
        total_read += static_cast<size_t>(n);
    }

    sys_close(static_cast<int>(fd));
    buffer[total_read] = '\0';
    return static_cast<ssize_t>(total_read);
}

bool DirectSyscallReadFileToString(const char* path, std::string& out_content, size_t max_bytes) {
    out_content.clear();
    long fd = sys_openat(-100 /* AT_FDCWD */, path, O_RDONLY, 0);
    if (fd < 0) {
        return false;
    }

    char chunk[4096];
    size_t total = 0;
    while (total < max_bytes) {
        size_t to_read = sizeof(chunk);
        if (total + to_read > max_bytes) {
            to_read = max_bytes - total;
        }

        long n = sys_read(static_cast<int>(fd), chunk, to_read);
        if (n <= 0) {
            break;
        }
        out_content.append(chunk, static_cast<size_t>(n));
        total += static_cast<size_t>(n);
    }

    sys_close(static_cast<int>(fd));
    return true;
}

} // namespace security
