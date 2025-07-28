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

#define UNIMPLEMENTED_SYSCALL \
  do { \
    X0_Q = -1; \
    errno = -_LINUX_ENOSYS; \
  } while (0)

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

#  define ECV_IO_SETUP 0
#  define ECV_IO_DESTROY 1
#  define ECV_IO_SUBMIT 2
#  define ECV_IO_CANCEL 3
#  define ECV_IO_GETEVENTS 4
#  define ECV_SETXATTR 5
#  define ECV_LSETXATTR 6
#  define ECV_FSETXATTR 7
#  define ECV_GETXATTR 8
#  define ECV_LGETXATTR 9
#  define ECV_FGETXATTR 10
#  define ECV_LISTXATTR 11
#  define ECV_LLISTXATTR 12
#  define ECV_FLISTXATTR 13
#  define ECV_REMOVEXATTR 14
#  define ECV_LREMOVEXATTR 15
#  define ECV_FREMOVEXATTR 16
#  define ECV_GETCWD 17
#  define ECV_LOOKUP_DCOOKIE 18
#  define ECV_EVENTFD2 19
#  define ECV_EPOLL_CREATE1 20
#  define ECV_EPOLL_CTL 21
#  define ECV_EPOLL_PWAIT 22
#  define ECV_DUP 23
#  define ECV_DUP3 24
#  define ECV_FCNTL 25
#  define ECV_INOTIFY_INIT1 26
#  define ECV_INOTIFY_ADD_WATCH 27
#  define ECV_INOTIFY_RM_WATCH 28
#  define ECV_IOCTL 29
#  define ECV_IOPRIO_SET 30
#  define ECV_IOPRIO_GET 31
#  define ECV_FLOCK 32
#  define ECV_MKNODAT 33
#  define ECV_MKDIRAT 34
#  define ECV_UNLINKAT 35
#  define ECV_SYMLINKAT 36
#  define ECV_LINKAT 37
#  define ECV_RENAMEAT 38
#  define ECV_UMOUNT2 39
#  define ECV_MOUNT 40
#  define ECV_PIVOT_ROOT 41
#  define ECV_NFSSERVCTL 42
#  define ECV_STATFS 43
#  define ECV_FSTATFS 44
#  define ECV_TRUNCATE 45
#  define ECV_FTRUNCATE 46
#  define ECV_FALLOCATE 47
#  define ECV_FACCESSAT 48
#  define ECV_CHDIR 49
#  define ECV_FCHDIR 50
#  define ECV_CHROOT 51
#  define ECV_FCHMOD 52
#  define ECV_FCHMODAT 53
#  define ECV_FCHOWNAT 54
#  define ECV_FCHOWN 55
#  define ECV_OPENAT 56
#  define ECV_CLOSE 57
#  define ECV_VHANGUP 58
#  define ECV_PIPE2 59
#  define ECV_QUOTACTL 60
#  define ECV_GETDENTS 61
#  define ECV_LSEEK 62
#  define ECV_READ 63
#  define ECV_WRITE 64
#  define ECV_READV 65
#  define ECV_WRITEV 66
#  define ECV_PREAD 67
#  define ECV_PWRITE 68
#  define ECV_PREADV 69
#  define ECV_PWRITEV 70
#  define ECV_SENDFILE 71
#  define ECV_PSELECT6 72
#  define ECV_PPOLL 73
#  define ECV_SIGNALFD4 74
#  define ECV_VMSPLICE 75
#  define ECV_SPLICE 76
#  define ECV_TEE 77
#  define ECV_READLINKAT 78
#  define ECV_NEWFSTATAT 79
#  define ECV_NEWFSTAT 80
#  define ECV_SYNC 81
#  define ECV_FSYNC 82
#  define ECV_FDATASYNC 83
#  define ECV_SYNC_FILE_RANGE 84
#  define ECV_TIMERFD_CREATE 85
#  define ECV_TIMERFD_SETTIME 86
#  define ECV_TIMERFD_GETTIME 87
#  define ECV_UTIMENSAT 88
#  define ECV_ACCT 89
#  define ECV_CAPGET 90
#  define ECV_CAPSET 91
#  define ECV_PERSONALITY 92
#  define ECV_EXIT 93
#  define ECV_EXIT_GROUP 94
#  define ECV_WAITID 95
#  define ECV_SET_TID_ADDRESS 96
#  define ECV_UNSHARE 97
#  define ECV_FUTEX 98
#  define ECV_SET_ROBUST_LIST 99
#  define ECV_GET_ROBUST_LIST 100
#  define ECV_NANOSLEEP 101
#  define ECV_GETITIMER 102
#  define ECV_SETITIMER 103
#  define ECV_KEXEC_LOAD 104
#  define ECV_INIT_MODULE 105
#  define ECV_DELETE_MODULE 106
#  define ECV_TIMER_CREATE 107
#  define ECV_TIMER_GETTIME 108
#  define ECV_TIMER_GETOVERRUN 109
#  define ECV_TIMER_SETTIME 110
#  define ECV_TIMER_DELETE 111
#  define ECV_CLOCK_SETTIME 112
#  define ECV_CLOCK_GETTIME 113
#  define ECV_CLOCK_GETRES 114
#  define ECV_CLOCK_NANOSLEEP 115
#  define ECV_SYSLOG 116
#  define ECV_PTRACE 117
#  define ECV_SCHED_SETPARAM 118
#  define ECV_SCHED_SETSCHEDULER 119
#  define ECV_SCHED_GETSCHEDULER 120
#  define ECV_SCHED_GETPARAM 121
#  define ECV_SCHED_SETAFFINITY 122
#  define ECV_SCHED_GETAFFINITY 123
#  define ECV_SCHED_YIELD 124
#  define ECV_SCHED_GET_PRIORITY_MAX 125
#  define ECV_SCHED_GET_PRIORITY_MIN 126
#  define ECV_SCHED_RR_GET_INTERVAL 127
#  define ECV_RESTART_SYSCALL 128
#  define ECV_KILL 129
#  define ECV_TKILL 130
#  define ECV_TGKILL 131
#  define ECV_SIGALTSTACK 132
#  define ECV_RT_SIGSUSPEND 133
#  define ECV_RT_SIGACTION 134
#  define ECV_RT_SIGPROCMASK 135
#  define ECV_RT_SIGPENDING 136
#  define ECV_RT_SIGTIMEDWAIT 137
#  define ECV_RT_SIGQUEUEINFO 138
#  define ECV_RT_SIGRETURN 139
#  define ECV_SETPRIORITY 140
#  define ECV_GETPRIORITY 141
#  define ECV_REBOOT 142
#  define ECV_SETREGID 143
#  define ECV_SETGID 144
#  define ECV_SETREUID 145
#  define ECV_SETUID 146
#  define ECV_SETRESUID 147
#  define ECV_GETRESUID 148
#  define ECV_SETRESGID 149
#  define ECV_GETRESGID 150
#  define ECV_SETFSUID 151
#  define ECV_SETFSGID 152
#  define ECV_TIMES 153
#  define ECV_SETPGID 154
#  define ECV_GETPGID 155
#  define ECV_GETSID 156
#  define ECV_SETSID 157
#  define ECV_GETGROUPS 158
#  define ECV_SETGROUPS 159
#  define ECV_UNAME 160
#  define ECV_SETHOSTNAME 161
#  define ECV_SETDOMAINNAME 162
#  define ECV_GETRLIMIT 163
#  define ECV_SETRLIMIT 164
#  define ECV_GETRUSAGE 165
#  define ECV_UMASK 166
#  define ECV_PRCTL 167
#  define ECV_GETCPU 168
#  define ECV_GETTIMEOFDAY 169
#  define ECV_SETTIMEOFDAY 170
#  define ECV_ADJTIMEX 171
#  define ECV_GETPID 172
#  define ECV_GETPPID 173
#  define ECV_GETUID 174
#  define ECV_GETEUID 175
#  define ECV_GETGID 176
#  define ECV_GETEGID 177
#  define ECV_GETTID 178
#  define ECV_SYSINFO 179
#  define ECV_MQ_OPEN 180
#  define ECV_MQ_UNLINK 181
#  define ECV_MQ_TIMEDSEND 182
#  define ECV_MQ_TIMEDRECEIVE 183
#  define ECV_MQ_NOTIFY 184
#  define ECV_MQ_GETSETATTR 185
#  define ECV_MSGGET 186
#  define ECV_MSGCTL 187
#  define ECV_MSGRCV 188
#  define ECV_MSGSND 189
#  define ECV_SEMGET 190
#  define ECV_SEMCTL 191
#  define ECV_SEMTIMEDOP 192
#  define ECV_SEMOP 193
#  define ECV_SHMGET 194
#  define ECV_SHMCTL 195
#  define ECV_SHMAT 196
#  define ECV_SHMDT 197
#  define ECV_SOCKET 198
#  define ECV_SOCKETPAIR 199
#  define ECV_BIND 200
#  define ECV_LISTEN 201
#  define ECV_ACCEPT 202
#  define ECV_CONNECT 203
#  define ECV_GETSOCKNAME 204
#  define ECV_GETPEERNAME 205
#  define ECV_SENDTO 206
#  define ECV_RECVFROM 207
#  define ECV_SETSOCKOPT 208
#  define ECV_GETSOCKOPT 209
#  define ECV_SHUTDOWN 210
#  define ECV_SENDMSG 211
#  define ECV_RECVMSG 212
#  define ECV_READAHEAD 213
#  define ECV_BRK 214
#  define ECV_MUNMAP 215
#  define ECV_MREMAP 216
#  define ECV_ADD_KEY 217
#  define ECV_REQUEST_KEY 218
#  define ECV_KEYCTL 219
#  define ECV_CLONE 220
#  define ECV_EXECVE 221
#  define ECV_MMAP 222
#  define ECV_FADVISE64 223
#  define ECV_SWAPON 224
#  define ECV_SWAPOFF 225
#  define ECV_MPROTECT 226
#  define ECV_MSYNC 227
#  define ECV_MLOCK 228
#  define ECV_MUNLOCK 229
#  define ECV_MLOCKALL 230
#  define ECV_MUNLOCKALL 231
#  define ECV_MINCORE 232
#  define ECV_MADVISE 233
#  define ECV_REMAP_FILE_PAGES 234
#  define ECV_MBIND 235
#  define ECV_GET_MEMPOLICY 236
#  define ECV_SET_MEMPOLICY 237
#  define ECV_MIGRATE_PAGES 238
#  define ECV_MOVE_PAGES 239
#  define ECV_RT_TGSIGQUEUEINFO 240
#  define ECV_PERF_EVENT_OPEN 241
#  define ECV_ACCEPT4 242
#  define ECV_RECVMMSG 243
#  define ECV_WAIT4 260
#  define ECV_PRLIMIT64 261
#  define ECV_FANOTIFY_INIT 262
#  define ECV_FANOTIFY_MARK 263
#  define ECV_NAME_TO_HANDLE_AT 264
#  define ECV_OPEN_BY_HANDLE_AT 265
#  define ECV_CLOCK_ADJTIME 266
#  define ECV_SYNCFS 267
#  define ECV_SETNS 268
#  define ECV_SENDMMSG 269
#  define ECV_PROCESS_VM_READV 270
#  define ECV_PROCESS_VM_WRITEV 271
#  define ECV_KCMP 272
#  define ECV_FINIT_MODULE 273
#  define ECV_SCHED_SETATTR 274
#  define ECV_SCHED_GETATTR 275
#  define ECV_RENAMEAT2 276
#  define ECV_SECCOMP 277
#  define ECV_GETRANDOM 278
#  define ECV_MEMFD_CREATE 279
#  define ECV_BPF 280
#  define ECV_EXECVEAT 281
#  define ECV_USERFAULTFD 282
#  define ECV_MEMBARRIER 283
#  define ECV_MLOCK2 284
#  define ECV_COPY_FILE_RANGE 285
#  define ECV_PREADV2 286
#  define ECV_PWRITEV2 287
#  define ECV_PKEY_MPROTECT 288
#  define ECV_PKEY_ALLOC 289
#  define ECV_PKEY_FREE 290
#  define ECV_STATX 291
#  define ECV_IO_PGETEVENTS 292
#  define ECV_RSEQ 293
#  define ECV_KEXEC_FILE_LOAD 294
#  define ECV_PIDFD_SEND_SIGNAL 424
#  define ECV_IO_URING_SETUP 425
#  define ECV_IO_URING_ENTER 426
#  define ECV_IO_URING_REGISTER 427
#  define ECV_OPEN_TREE 428
#  define ECV_MOVE_MOUNT 429
#  define ECV_FSOPEN 430
#  define ECV_FSCONFIG 431
#  define ECV_FSMOUNT 432
#  define ECV_FSPICK 433
#  define ECV_PIDFD_OPEN 434
#  define ECV_CLONE3 435
#  define ECV_CLOSE_RANGE 436
#  define ECV_OPENAT2 437
#  define ECV_PIDFD_GETFD 438
#  define ECV_FACCESSAT2 439
#  define ECV_PROCESS_MADVISE 440
#  define ECV_EPOLL_PWAIT2 441
#  define ECV_MOUNT_SETATTR 442
#  define ECV_QUOTACTL_FD 443
#  define ECV_LANDLOCK_CREATE_RULESET 444
#  define ECV_LANDLOCK_ADD_RULE 445
#  define ECV_LANDLOCK_RESTRICT_SELF 446
#  define ECV_MEMFD_SECRET 447
#  define ECV_PROCESS_MRELEASE 448
#  define ECV_FUTEX_WAITV 449

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
