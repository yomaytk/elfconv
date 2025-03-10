#pragma once

#include <runtime/Runtime.h>

#define _ECV_EACCESS 13
#define _ECV_ENOSYS 38

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

#  define ECV_SYS_DUP 23
#  define ECV_SYS_IOCTL 29
#  define ECV_SYS_MKDIRAT 34
#  define ECV_SYS_UNLINKAT 35
#  define ECV_SYS_STATFS 43
#  define ECV_SYS_TRUNCATE 45
#  define ECV_SYS_FTRUNCATE 46
#  define ECV_SYS_FACCESSAT 48
#  define ECV_SYS_OPENAT 56
#  define ECV_SYS_CLOSE 57
#  define ECV_SYS_LSEEK 62
#  define ECV_SYS_READ 63
#  define ECV_SYS_WRITE 64
#  define ECV_SYS_WRITEV 66
#  define ECV_SYS_READLINKAT 78
#  define ECV_SYS_NEWFSTATAT 79
#  define ECV_SYS_FSYNC 82
#  define ECV_SYS_EXIT 93
#  define ECV_SYS_EXITGROUP 94
#  define ECV_SYS_SET_TID_ADDRESS 96
#  define ECV_SYS_FUTEX 98
#  define ECV_SYS_SET_ROBUST_LIST 99
#  define ECV_SYS_CLOCK_GETTIME 113
#  define ECV_SYS_TGKILL 131
#  define ECV_SYS_RT_SIGACTION 134
#  define ECV_SYS_RT_SIGPROCMASK 135
#  define ECV_SYS_UNAME 160
#  define ECV_SYS_GETRUSAGE 165
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

#else
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

#  define ECV_SYS_DUP 23
#  define ECV_SYS_IOCTL 29
#  define ECV_SYS_MKDIRAT 34
#  define ECV_SYS_UNLINKAT 35
#  define ECV_SYS_STATFS 43
#  define ECV_SYS_TRUNCATE 45
#  define ECV_SYS_FTRUNCATE 46
#  define ECV_SYS_FACCESSAT 48
#  define ECV_SYS_OPENAT 56
#  define ECV_SYS_CLOSE 57
#  define ECV_SYS_LSEEK 62
#  define ECV_SYS_READ 63
#  define ECV_SYS_WRITE 64
#  define ECV_SYS_WRITEV 66
#  define ECV_SYS_READLINKAT 78
#  define ECV_SYS_NEWFSTATAT 79
#  define ECV_SYS_FSYNC 82
#  define ECV_SYS_EXIT 93
#  define ECV_SYS_EXITGROUP 94
#  define ECV_SYS_SET_TID_ADDRESS 96
#  define ECV_SYS_FUTEX 98
#  define ECV_SYS_SET_ROBUST_LIST 99
#  define ECV_SYS_CLOCK_GETTIME 113
#  define ECV_SYS_TGKILL 131
#  define ECV_SYS_RT_SIGACTION 134
#  define ECV_SYS_RT_SIGPROCMASK 135
#  define ECV_SYS_UNAME 160
#  define ECV_SYS_GETRUSAGE 165
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
#endif