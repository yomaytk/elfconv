#pragma once

#include <runtime/Runtime.h>

#define _LINUX_EPERM 1 /* Operation not permitted */
#define _LINUX_ENOENT 2 /* No such file or directory */
#define _LINUX_ESRCH 3 /* No such process */
#define _LINUX_EINTR 4 /* Interrupted system call */
#define _LINUX_EIO 5 /* I/O error */
#define _LINUX_ENXIO 6 /* No such device or address */
#define _LINUX_E2BIG 7 /* Argument list too long */
#define _LINUX_ENOEXEC 8 /* Exec format error */
#define _LINUX_EBADF 9 /* Bad file number */
#define _LINUX_ECHILD 10 /* No child processes */
#define _LINUX_EAGAIN 11 /* Try again */
#define _LINUX_ENOMEM 12 /* Out of memory */
#define _LINUX_EACCES 13 /* Permission denied */
#define _LINUX_EFAULT 14 /* Bad address */
#define _LINUX_ENOTBLK 15 /* Block device required */
#define _LINUX_EBUSY 16 /* Device or resource busy */
#define _LINUX_EEXIST 17 /* File exists */
#define _LINUX_EXDEV 18 /* Cross-device link */
#define _LINUX_ENODEV 19 /* No such device */
#define _LINUX_ENOTDIR 20 /* Not a directory */
#define _LINUX_EISDIR 21 /* Is a directory */
#define _LINUX_EINVAL 22 /* Invalid argument */
#define _LINUX_ENFILE 23 /* File table overflow */
#define _LINUX_EMFILE 24 /* Too many open files */
#define _LINUX_ENOTTY 25 /* Not a typewriter */
#define _LINUX_ETXTBSY 26 /* Text file busy */
#define _LINUX_EFBIG 27 /* File too large */
#define _LINUX_ENOSPC 28 /* No space left on device */
#define _LINUX_ESPIPE 29 /* Illegal seek */
#define _LINUX_EROFS 30 /* Read-only file system */
#define _LINUX_EMLINK 31 /* Too many links */
#define _LINUX_EPIPE 32 /* Broken pipe */
#define _LINUX_EDOM 33 /* Math argument out of domain of func */
#define _LINUX_ERANGE 34 /* Math result not representable */

#define _LINUX_ENOSYS 38

#define _LINUX_TCGETS 0x5401
#define _LINUX_TCSETS 0x5402
#define _LINUX_TIOCGWINSZ 0x5413
#define _LINUX_NCCS 19

#define _LINUX_AT_EACCESS 0x200
#define _LINUX_AT_SYMLINK_NOFOLLOW 0x100

#define _LINUX_AT_EMPTY_PATH 0x1000
#define _LINUX_STATX_BASIC_STATS 0x000007ffU

#if defined(NOSYS_EXIT)
#  define NOSYS_CODE(sysnum) elfconv_runtime_error("Unimplemented syscall number: %ld\n", sysnum)
#else
#  define NOSYS_CODE(sysnum) X0_Q = -_ECV_ENOSYS
#endif

#if defined(ELF_IS_AARCH64)

// prctl
#  define ECV_PR_GET_NAME 16
// fcntl
#  define ECV_F_DUPFD 0
#  define ECV_F_GETFD 1
#  define ECV_F_SETFD 2
#  define ECV_F_GETFL 3
#  define ECV_F_SETFL 4

#  include <remill/Arch/AArch64/Runtime/State.h>
#  define PCREG CPUState.gpr.pc.qword
#  define SYSNUMREG CPUState.gpr.x8.qword
#  define X0_D CPUState.gpr.x0.dword
#  define X1_D CPUState.gpr.x1.dword
#  define X2_D CPUState.gpr.x2.dword
#  define X3_D CPUState.gpr.x3.dword
#  define X4_D CPUState.gpr.x4.dword
#  define X5_D CPUState.gpr.x5.dword
#  define X0_Q CPUState.gpr.x0.qword
#  define X1_Q CPUState.gpr.x1.qword
#  define X2_Q CPUState.gpr.x2.qword
#  define X3_Q CPUState.gpr.x3.qword
#  define X4_Q CPUState.gpr.x4.qword
#  define X5_Q CPUState.gpr.x5.qword

#  define ECV_SYS_GETCWD 17
#  define ECV_SYS_DUP 23
#  define ECV_SYS_DUP3 24
#  define ECV_SYS_FCNTL 25
#  define ECV_SYS_IOCTL 29
#  define ECV_SYS_MKDIRAT 34
#  define ECV_SYS_UNLINKAT 35
#  define ECV_SYS_STATFS 43
#  define ECV_SYS_TRUNCATE 45
#  define ECV_SYS_FTRUNCATE 46
#  define ECV_SYS_FACCESSAT 48
#  define ECV_SYS_CHDIR 49
#  define ECV_SYS_OPENAT 56
#  define ECV_SYS_CLOSE 57
#  define ECV_SYS_GETDENTS64 61
#  define ECV_SYS_LSEEK 62
#  define ECV_SYS_READ 63
#  define ECV_SYS_WRITE 64
#  define ECV_SYS_WRITEV 66
#  define ECV_SYS_SENDFILE 71
#  define ECV_SYS_PPOLL 73
#  define ECV_SYS_READLINKAT 78
#  define ECV_SYS_NEWFSTATAT 79
#  define ECV_SYS_FSYNC 82
#  define ECV_SYS_UTIMENSAT 88
#  define ECV_SYS_EXIT 93
#  define ECV_SYS_EXITGROUP 94
#  define ECV_SYS_SET_TID_ADDRESS 96
#  define ECV_SYS_FUTEX 98
#  define ECV_SYS_SET_ROBUST_LIST 99
#  define ECV_SYS_CLOCK_GETTIME 113
#  define ECV_SYS_TGKILL 131
#  define ECV_SYS_RT_SIGACTION 134
#  define ECV_SYS_RT_SIGPROCMASK 135
#  define ECV_SYS_SETREGID 143
#  define ECV_SYS_SETGID 144
#  define ECV_SYS_SETREUID 145
#  define ECV_SYS_SETUID 146
#  define ECV_SYS_SETRESUID 147
#  define ECV_SYS_UNAME 160
#  define ECV_SYS_GETRUSAGE 165
#  define ECV_SYS_PRCTL 167
#  define ECV_SYS_GETTIMEOFDAY 169
#  define ECV_SYS_GETPID 172
#  define ECV_SYS_GETPPID 173
#  define ECV_SYS_GETUID 174
#  define ECV_SYS_GETEUID 175
#  define ECV_SYS_GETGID 176
#  define ECV_SYS_GETEGID 177
#  define ECV_SYS_GETTID 178
#  define ECV_SYS_BRK 214
#  define ECV_SYS_MUNMAP 215
#  define ECV_SYS_MMAP 222
#  define ECV_SYS_MPROTECT 226
#  define ECV_SYS_WAIT4 260
#  define ECV_SYS_PRLIMIT64 261
#  define ECV_SYS_GETRANDOM 278
#  define ECV_SYS_STATX 291
#  define ECV_SYS_RSEQ 293

#elif defined(ELF_IS_AMD64)
#  include <remill/Arch/X86/Runtime/State.h>
#  define PCREG CPUState.gpr.rip.qword
#  define SYSNUMREG CPUState.gpr.rax.qword
#  define X0_D CPUState.gpr.rdi.dword
#  define X1_D CPUState.gpr.rsi.dword
#  define X2_D CPUState.gpr.rdx.dword
#  define X3_D CPUState.gpr.r10.dword
#  define X4_D CPUState.gpr.r8.dword
#  define X5_D CPUState.gpr.r9.dword
#  define X0_Q CPUState.gpr.rdi.qword
#  define X1_Q CPUState.gpr.rsi.qword
#  define X2_Q CPUState.gpr.rdx.qword
#  define X3_Q CPUState.gpr.r10.qword
#  define X4_Q CPUState.gpr.r8.qword
#  define X5_Q CPUState.gpr.r9.qword

#  define ECV_SYS_DUP 32
#  define ECV_SYS_IOCTL 16
#  define ECV_SYS_MKDIRAT 258
#  define ECV_SYS_UNLINKAT 263
#  define ECV_SYS_STATFS 137
#  define ECV_SYS_TRUNCATE 76
#  define ECV_SYS_FTRUNCATE 77
#  define ECV_SYS_FACCESSAT 269
#  define ECV_SYS_OPENAT 257
#  define ECV_SYS_CLOSE 3
#  define ECV_SYS_LSEEK 8
#  define ECV_SYS_READ 0
#  define ECV_SYS_WRITE 1
#  define ECV_SYS_WRITEV 20
#  define ECV_SYS_READLINKAT 267
#  define ECV_SYS_NEWFSTATAT 262
#  define ECV_SYS_FSYNC 74
#  define ECV_SYS_EXIT 60
#  define ECV_SYS_EXITGROUP 231
#  define ECV_SYS_SET_TID_ADDRESS 218
#  define ECV_SYS_FUTEX 202
#  define ECV_SYS_SET_ROBUST_LIST 273
#  define ECV_SYS_CLOCK_GETTIME 228
#  define ECV_SYS_TGKILL 234
#  define ECV_SYS_RT_SIGACTION 13
#  define ECV_SYS_RT_SIGPROCMASK 14
#  define ECV_SYS_UNAME 63
#  define ECV_SYS_GETRUSAGE 98
#  define ECV_SYS_GETTIMEOFDAY 96
#  define ECV_SYS_GETPID 39
#  define ECV_SYS_GETPPID 110
#  define ECV_SYS_GETUID 102
#  define ECV_SYS_GETEUID 107
#  define ECV_SYS_GETGID 104
#  define ECV_SYS_GETEGID 108
#  define ECV_SYS_GETTID 186
#  define ECV_SYS_BRK 12
#  define ECV_SYS_MUNMAP 11
#  define ECV_SYS_MMAP 9
#  define ECV_SYS_MPROTECT 10
#  define ECV_SYS_WAIT4 61
#  define ECV_SYS_PRLIMIT64 302
#  define ECV_SYS_GETRANDOM 318
#  define ECV_SYS_STATX 332
#  define ECV_SYS_RSEQ 334

#endif
