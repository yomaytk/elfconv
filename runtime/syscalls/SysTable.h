#pragma once

#define _ECV_EACCESS 13
#define _ECV_ENOSYS 38
/*
    syscall number table
*/
#define AARCH64_SYS_DUP 23
#define AARCH64_SYS_IOCTL 29
#define AARCH64_SYS_MKDIRAT 34
#define AARCH64_SYS_UNLINKAT 35
#define AARCH64_SYS_STATFS 43
#define AARCH64_SYS_TRUNCATE 45
#define AARCH64_SYS_FTRUNCATE 46
#define AARCH64_SYS_FACCESSAT 48
#define AARCH64_SYS_OPENAT 56
#define AARCH64_SYS_CLOSE 57
#define AARCH64_SYS_LSEEK 62
#define AARCH64_SYS_READ 63
#define AARCH64_SYS_WRITE 64
#define AARCH64_SYS_WRITEV 66
#define AARCH64_SYS_READLINKAT 78
#define AARCH64_SYS_NEWFSTATAT 79
#define AARCH64_SYS_FSYNC 82
#define AARCH64_SYS_EXIT 93
#define AARCH64_SYS_EXITGROUP 94
#define AARCH64_SYS_SET_TID_ADDRESS 96
#define AARCH64_SYS_FUTEX 98
#define AARCH64_SYS_SET_ROBUST_LIST 99
#define AARCH64_SYS_CLOCK_GETTIME 113
#define AARCH64_SYS_TGKILL 131
#define AARCH64_SYS_RT_SIGACTION 134
#define AARCH64_SYS_RT_SIGPROCMASK 135
#define AARCH64_SYS_UNAME 160
#define AARCH64_SYS_GETRUSAGE 165
#define AARCH64_SYS_GETTIMEOFDAY 169
#define AARCH64_SYS_GETPID 172
#define AARCH64_SYS_GETPPID 173
#define AARCH64_SYS_GETTUID 174
#define AARCH64_SYS_GETEUID 175
#define AARCH64_SYS_GETGID 176
#define AARCH64_SYS_GETEGID 177
#define AARCH64_SYS_GETTID 178
#define AARCH64_SYS_BRK 214
#define AARCH64_SYS_MUNMAP 215
#define AARCH64_SYS_MMAP 222
#define AARCH64_SYS_MPROTECT 226
#define AARCH64_SYS_WAIT4 260
#define AARCH64_SYS_PRLIMIT64 261
#define AARCH64_SYS_GETRANDOM 278
#define AARCH64_SYS_STATX 291
#define AARCH64_SYS_RSEQ 293

#include "runtime/Runtime.h"

#if defined(ELF_IS_AARCH64)
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

#  define ECV_SYS_WRITE 64
#  define ECV_SYS_EXIT 93
#  define ECV_SYS_CLOCK_GETTIME AARCH64_SYS_CLOCK_GETTIME
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

#  define ECV_SYS_WRITE 1
#  define ECV_SYS_EXIT 60
#  define ECV_SYS_CLOCK_GETTIME 228
#endif