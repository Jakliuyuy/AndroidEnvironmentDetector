#pragma once

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>

namespace security {

// Direct raw system calls implemented via inline assembly
long sys_openat(int dfd, const char *filename, int flags, mode_t mode = 0);
long sys_read(int fd, void *buf, size_t count);
long sys_close(int fd);
long sys_readlinkat(int dfd, const char *path, char *buf, size_t bufsiz);
long sys_faccessat(int dfd, const char *filename, int mode, int flags = 0);
long sys_getpid();
long sys_prctl(int option, unsigned long arg2 = 0, unsigned long arg3 = 0, unsigned long arg4 = 0, unsigned long arg5 = 0);
long sys_truncate(const char *path, off_t length);

// Direct syscall memory/buffer utilities for procfs interrogation
// Reads entire file into buffer using raw syscalls without calling libc open/read/close
ssize_t DirectSyscallReadFile(const char* path, char* buffer, size_t max_bytes);
bool DirectSyscallReadFileToString(const char* path, std::string& out_content, size_t max_bytes = 1024 * 1024);

} // namespace security
