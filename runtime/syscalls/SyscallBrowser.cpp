#include "SysTable.h"

#if defined(ELF_IS_AARCH64)
#  include "remill/Arch/Runtime/Types.h"
#else
#  include "remill/Arch/Runtime/RemillTypes.h"
#endif
#include "runtime/Memory.h"
#include "runtime/Runtime.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <emscripten.h>
#include <emscripten/threading.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <remill/BC/HelperMacro.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
#  define EMPTY_SYSCALL(sysnum) printf("[WARNING] syscall \"" #  sysnum "\" is empty now.\n");
#  define NOP_SYSCALL(sysnum) \
    printf("[INFO] syscall \"" #sysnum "\" is nop (but maybe allowd) now.\n");
#else
#  define EMPTY_SYSCALL(sysnum) ;
#  define NOP_SYSCALL(sysnum) ;
#endif

#if defined(__wasm32__)
typedef uint32_t _ecv_long;
#elif defined(__wasm64__)
typedef uint64_t _ecv_long;
#else
typedef uint64_t _ecv_long;
#endif

extern _ecv_reg64_t TASK_STRUCT_VMA;
extern void *TranslateVMA(uint8_t *arena_ptr, addr_t vma_addr);

/*
  for ioctl syscall
*/
typedef uint32_t _ecv_tcflag_t;
typedef uint8_t _ecv_cc_t;

struct _elfarm64_termios {
  tcflag_t c_iflag; /* input mode flags */
  tcflag_t c_oflag; /* output mode flags */
  tcflag_t c_cflag; /* control mode flags */
  tcflag_t c_lflag; /* local mode flags */
  cc_t c_line; /* line discipline */
  cc_t c_cc[_LINUX_NCCS]; /* control characters */
  //   speed_t c_ispeed; /* input speed */
  //   speed_t c_ospeed; /* output speed */
  // #define _HAVE_STRUCT_TERMIOS_C_ISPEED 1
  // #define _HAVE_STRUCT_TERMIOS_C_OSPEED 1
};

struct _elfarm64_winsize {
  uint16_t ws_row;
  uint16_t ws_col;
  uint16_t ws_xpixel;
  uint16_t ws_ypixel;
};

/* for stat */
struct _elfarm64_timespec {
  int64_t tv_sec;
  uint32_t tv_nsec;  // ??? #define __SLONGWORD_TYPE	long int
};

struct _elfarm64df_stat {
  uint64_t st_dev;
  uint64_t st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint64_t st_rdev;
  uint64_t __pad1;
  uint64_t st_size;
  int st_blksize;  // ??? #define __SLONGWORD_TYPE	long int
  int __pad2;
  uint64_t st_blocks;
  struct _elfarm64_timespec st_atim;
  struct _elfarm64_timespec st_mtim;
  struct _elfarm64_timespec st_ctim;
// #ifdef __USE_XOPEN2K8
/* __USE_XOPEN2K8 is defined. */
#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
  // #else
  // __time_t st_atime;			/* Time of last access.  */
  // unsigned long int st_atimensec;	/* Nscecs of last access.  */
  // __time_t st_mtime;			/* Time of last modification.  */
  // unsigned long int st_mtimensec;	/* Nsecs of last modification.  */
  // __time_t st_ctime;			/* Time of last status change.  */
  // unsigned long int st_ctimensec;	/* Nsecs of last status change.  */
  // #endif
  int __glibc_reserved[2];
};

/* timeval */
struct _linux_timeval {
  int64_t tv_sec;
  int64_t tv_usec;
};

/* 
  for statx 
*/
struct _ecv_statx_timestamp {
  int64_t tv_sec;
  uint32_t tv_nsec;
};

struct _linux_statx {
  uint32_t stx_mask;
  uint32_t stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink;
  uint32_t stx_uid;
  uint32_t stx_gid;
  uint16_t stx_mode;
  uint64_t stx_ino;
  uint64_t stx_size;
  uint64_t stx_blocks;
  uint64_t stx_attributes_mask;
  struct _ecv_statx_timestamp stx_atime;
  struct _ecv_statx_timestamp stx_btime;
  struct _ecv_statx_timestamp stx_ctime;
  struct _ecv_statx_timestamp stx_mtime;
  uint32_t stx_rdev_major;
  uint32_t stx_rdev_minor;
  uint32_t stx_dev_major;
  uint32_t stx_dev_minor;
  uint64_t stx_mnt_id;
  uint32_t stx_dio_mem_align;
  uint32_t stx_dio_offset_align;
  uint64_t __spare3[12];
};

/*
  for rusage
*/
struct _linux_rusage {
  struct _linux_timeval ru_utime;
  struct _linux_timeval ru_stime;
  long ru_maxrss;
  long ru_ixrss;
  long ru_idrss;
  long ru_isrss;
  long ru_minflt;
  long ru_majflt;
  long ru_nswap;
  long ru_inblock;
  long ru_oublock;
  long ru_msgsnd;
  long ru_msgrcv;
  long ru_nsignals;
  long ru_nvcsw;
  long ru_nivcsw;
};

#ifndef WASI_ERRNO_MAX_VALUE
#  define WASI_ERRNO_MAX_VALUE 76  // __WASI_ERRNO_NOTCAPABLE
#endif

#define W2L(wasi, linuxv) [wasi] = (int16_t) (linuxv)

// WASI errno to Linux errno conversion table
static const int16_t wasi2linux_errno[WASI_ERRNO_MAX_VALUE + 1] = {
    /*  0 __WASI_ERRNO_SUCCESS      */ 0,
    /*  1 __WASI_ERRNO_2BIG         */ _LINUX_E2BIG,
    /*  2 __WASI_ERRNO_ACCES        */ _LINUX_EACCES,
    /*  3 __WASI_ERRNO_ADDRINUSE    */ _LINUX_EADDRINUSE,
    /*  4 __WASI_ERRNO_ADDRNOTAVAIL */ _LINUX_EADDRNOTAVAIL,
    /*  5 __WASI_ERRNO_AFNOSUPPORT  */ _LINUX_EAFNOSUPPORT,
    /*  6 __WASI_ERRNO_AGAIN        */ _LINUX_EAGAIN,
    /*  7 __WASI_ERRNO_ALREADY      */ _LINUX_EALREADY,
    /*  8 __WASI_ERRNO_BADF         */ _LINUX_EBADF,
    /*  9 __WASI_ERRNO_BADMSG       */ _LINUX_EBADMSG,
    /* 10 __WASI_ERRNO_BUSY         */ _LINUX_EBUSY,
    /* 11 __WASI_ERRNO_CANCELED     */ _LINUX_ECANCELED,
    /* 12 __WASI_ERRNO_CHILD        */ _LINUX_ECHILD,
    /* 13 __WASI_ERRNO_CONNABORTED  */ _LINUX_ECONNABORTED,
    /* 14 __WASI_ERRNO_CONNREFUSED  */ _LINUX_ECONNREFUSED,
    /* 15 __WASI_ERRNO_CONNRESET    */ _LINUX_ECONNRESET,
    /* 16 __WASI_ERRNO_DEADLK       */ _LINUX_EDEADLK,
    /* 17 __WASI_ERRNO_DESTADDRREQ  */ _LINUX_EDESTADDRREQ,
    /* 18 __WASI_ERRNO_DOM          */ _LINUX_EDOM,
    /* 19 __WASI_ERRNO_DQUOT        */ _LINUX_EDQUOT,
    /* 20 __WASI_ERRNO_EXIST        */ _LINUX_EEXIST,
    /* 21 __WASI_ERRNO_FAULT        */ _LINUX_EFAULT,
    /* 22 __WASI_ERRNO_FBIG         */ _LINUX_EFBIG,
    /* 23 __WASI_ERRNO_HOSTUNREACH  */ _LINUX_EHOSTUNREACH,
    /* 24 __WASI_ERRNO_IDRM         */ _LINUX_EIDRM,
    /* 25 __WASI_ERRNO_ILSEQ        */ _LINUX_EILSEQ,
    /* 26 __WASI_ERRNO_INPROGRESS   */ _LINUX_EINPROGRESS,
    /* 27 __WASI_ERRNO_INTR         */ _LINUX_EINTR,
    /* 28 __WASI_ERRNO_INVAL        */ _LINUX_EINVAL,
    /* 29 __WASI_ERRNO_IO           */ _LINUX_EIO,
    /* 30 __WASI_ERRNO_ISCONN       */ _LINUX_EISCONN,
    /* 31 __WASI_ERRNO_ISDIR        */ _LINUX_EISDIR,
    /* 32 __WASI_ERRNO_LOOP         */ _LINUX_ELOOP,
    /* 33 __WASI_ERRNO_MFILE        */ _LINUX_EMFILE,
    /* 34 __WASI_ERRNO_MLINK        */ _LINUX_EMLINK,
    /* 35 __WASI_ERRNO_MSGSIZE      */ _LINUX_EMSGSIZE,
    /* 36 __WASI_ERRNO_MULTIHOP     */ _LINUX_EMULTIHOP,
    /* 37 __WASI_ERRNO_NAMETOOLONG  */ _LINUX_ENAMETOOLONG,
    /* 38 __WASI_ERRNO_NETDOWN      */ _LINUX_ENETDOWN,
    /* 39 __WASI_ERRNO_NETRESET     */ _LINUX_ENETRESET,
    /* 40 __WASI_ERRNO_NETUNREACH   */ _LINUX_ENETUNREACH,
    /* 41 __WASI_ERRNO_NFILE        */ _LINUX_ENFILE,
    /* 42 __WASI_ERRNO_NOBUFS       */ _LINUX_ENOBUFS,
    /* 43 __WASI_ERRNO_NODEV        */ _LINUX_ENODEV,
    /* 44 __WASI_ERRNO_NOENT        */ _LINUX_ENOENT,
    /* 45 __WASI_ERRNO_NOEXEC       */ _LINUX_ENOEXEC,
    /* 46 __WASI_ERRNO_NOLCK        */ _LINUX_ENOLCK,
    /* 47 __WASI_ERRNO_NOLINK       */ _LINUX_ENOLINK,
    /* 48 __WASI_ERRNO_NOMEM        */ _LINUX_ENOMEM,
    /* 49 __WASI_ERRNO_NOMSG        */ _LINUX_ENOMSG,
    /* 50 __WASI_ERRNO_NOPROTOOPT   */ _LINUX_ENOPROTOOPT,
    /* 51 __WASI_ERRNO_NOSPC        */ _LINUX_ENOSPC,
    /* 52 __WASI_ERRNO_NOSYS        */ _LINUX_ENOSYS,
    /* 53 __WASI_ERRNO_NOTCONN      */ _LINUX_ENOTCONN,
    /* 54 __WASI_ERRNO_NOTDIR       */ _LINUX_ENOTDIR,
    /* 55 __WASI_ERRNO_NOTEMPTY     */ _LINUX_ENOTEMPTY,
    /* 56 __WASI_ERRNO_NOTRECOVERABLE */ _LINUX_ENOTRECOVERABLE,
    /* 57 __WASI_ERRNO_NOTSOCK      */ _LINUX_ENOTSOCK,
    /* 58 __WASI_ERRNO_NOTSUP       */ _LINUX_EOPNOTSUPP,
    /* 59 __WASI_ERRNO_NOTTY        */ _LINUX_ENOTTY,
    /* 60 __WASI_ERRNO_NXIO         */ _LINUX_ENXIO,
    /* 61 __WASI_ERRNO_OVERFLOW     */ _LINUX_EOVERFLOW,
    /* 62 __WASI_ERRNO_OWNERDEAD    */ _LINUX_EOWNERDEAD,
    /* 63 __WASI_ERRNO_PERM         */ _LINUX_EPERM,
    /* 64 __WASI_ERRNO_PIPE         */ _LINUX_EPIPE,
    /* 65 __WASI_ERRNO_PROTO        */ _LINUX_EPROTO,
    /* 66 __WASI_ERRNO_PROTONOSUPPORT */ _LINUX_EPROTONOSUPPORT,
    /* 67 __WASI_ERRNO_PROTOTYPE    */ _LINUX_EPROTOTYPE,
    /* 68 __WASI_ERRNO_RANGE        */ _LINUX_ERANGE,
    /* 69 __WASI_ERRNO_ROFS         */ _LINUX_EROFS,
    /* 70 __WASI_ERRNO_SPIPE        */ _LINUX_ESPIPE,
    /* 71 __WASI_ERRNO_SRCH         */ _LINUX_ESRCH,
    /* 72 __WASI_ERRNO_STALE        */ _LINUX_ESTALE,
    /* 73 __WASI_ERRNO_TIMEDOUT     */ _LINUX_ETIMEDOUT,
    /* 74 __WASI_ERRNO_TXTBSY       */ _LINUX_ETXTBSY,
    /* 75 __WASI_ERRNO_XDEV         */ _LINUX_EXDEV,
    /* 76 __WASI_ERRNO_NOTCAPABLE   */ _LINUX_EPERM,
};

template<typename T>
inline typename std::enable_if<std::is_integral<T>::value, uint64_t>::type
SetSyscallRes(T result, int error_value = -1) {
  if (result == error_value) {
    return static_cast<uint64_t>(-wasi2linux_errno[errno]);
  }
  return static_cast<uint64_t>(result);
}

template<typename T>
inline uint64_t SetSyscallRes(T* result) {
  if (result == nullptr) {
    return static_cast<uint64_t>(-wasi2linux_errno[errno]);
  }
  return reinterpret_cast<uint64_t>(result);
}

template<typename T>
inline uint64_t SetSyscallResAndErrno(T res) {
  if (res < 0) {
    errno = wasi2linux_errno[-res];
    return -(errno);
  } else {
    return res;
  }
}

/*
  List of unimplemented syscalls for efficient lookup
*/
constexpr uint32_t UNIMPLEMENTED_SYSCALLS[] = {
  // I/O operations
  ECV_IO_SETUP, ECV_IO_DESTROY, ECV_IO_SUBMIT, ECV_IO_CANCEL, ECV_IO_GETEVENTS,
  ECV_IO_PGETEVENTS, ECV_IO_URING_SETUP, ECV_IO_URING_ENTER, ECV_IO_URING_REGISTER,

  // Extended attributes
  ECV_SETXATTR, ECV_LSETXATTR, ECV_FSETXATTR,
  ECV_GETXATTR, ECV_LGETXATTR, ECV_FGETXATTR,
  ECV_LISTXATTR, ECV_LLISTXATTR, ECV_FLISTXATTR,
  ECV_REMOVEXATTR, ECV_LREMOVEXATTR, ECV_FREMOVEXATTR,

  // File operations
  ECV_LOOKUP_DCOOKIE, ECV_FLOCK, ECV_MKNODAT, ECV_SYMLINKAT, ECV_LINKAT,
  ECV_RENAMEAT, ECV_RENAMEAT2, ECV_UMOUNT2, ECV_MOUNT, ECV_PIVOT_ROOT,
  ECV_NFSSERVCTL, ECV_FSTATFS, ECV_FALLOCATE, ECV_FCHDIR, ECV_CHROOT,
  ECV_FCHMOD, ECV_FCHMODAT, ECV_FCHOWNAT, ECV_FCHOWN, ECV_VHANGUP,
  ECV_QUOTACTL, ECV_QUOTACTL_FD, ECV_NEWFSTAT, ECV_FDATASYNC, ECV_SYNC,
  ECV_SYNC_FILE_RANGE, ECV_SYNCFS, ECV_ACCT,
  ECV_READV, ECV_PREAD, ECV_PWRITE, ECV_PREADV, ECV_PWRITEV,
  ECV_PREADV2, ECV_PWRITEV2, ECV_COPY_FILE_RANGE, ECV_READAHEAD,
  ECV_FADVISE64, ECV_SPLICE, ECV_VMSPLICE, ECV_TEE,

  // Epoll/event operations
  ECV_EVENTFD2, ECV_EPOLL_CREATE1, ECV_EPOLL_CTL, ECV_EPOLL_PWAIT,
  ECV_EPOLL_PWAIT2, ECV_SIGNALFD4,

  // Inotify operations
  ECV_INOTIFY_INIT1, ECV_INOTIFY_ADD_WATCH, ECV_INOTIFY_RM_WATCH,

  // I/O priority operations
  ECV_IOPRIO_SET, ECV_IOPRIO_GET,

  // Timer operations
  ECV_TIMERFD_CREATE, ECV_TIMERFD_SETTIME, ECV_TIMERFD_GETTIME,
  ECV_TIMER_CREATE, ECV_TIMER_GETTIME, ECV_TIMER_GETOVERRUN,
  ECV_TIMER_SETTIME, ECV_TIMER_DELETE, ECV_CLOCK_SETTIME,
  ECV_CLOCK_GETRES, ECV_CLOCK_ADJTIME,
  ECV_NANOSLEEP, ECV_GETITIMER, ECV_SETITIMER,

  // Process/thread operations
  ECV_CAPGET, ECV_CAPSET, ECV_PERSONALITY, ECV_WAITID, ECV_UNSHARE,
  ECV_SET_ROBUST_LIST, ECV_GET_ROBUST_LIST, ECV_KEXEC_LOAD, ECV_KEXEC_FILE_LOAD,
  ECV_INIT_MODULE, ECV_DELETE_MODULE, ECV_PRLIMIT64, ECV_FINIT_MODULE,

  // System logging
  ECV_SYSLOG, ECV_PTRACE,

  // Scheduling
  ECV_SCHED_SETPARAM, ECV_SCHED_SETSCHEDULER, ECV_SCHED_GETSCHEDULER,
  ECV_SCHED_GETPARAM, ECV_SCHED_SETAFFINITY, ECV_SCHED_GETAFFINITY,
  ECV_SCHED_YIELD, ECV_SCHED_GET_PRIORITY_MAX, ECV_SCHED_GET_PRIORITY_MIN,
  ECV_SCHED_RR_GET_INTERVAL, ECV_SCHED_SETATTR, ECV_SCHED_GETATTR,

  // Signals
  ECV_RESTART_SYSCALL, ECV_KILL, ECV_TKILL, ECV_SIGALTSTACK,
  ECV_RT_SIGSUSPEND, ECV_RT_SIGPROCMASK, ECV_RT_SIGPENDING,
  ECV_RT_SIGTIMEDWAIT, ECV_RT_SIGQUEUEINFO, ECV_RT_SIGRETURN,
  ECV_RT_TGSIGQUEUEINFO,

  // Priority
  ECV_SETPRIORITY, ECV_GETPRIORITY,

  // System operations
  ECV_REBOOT, ECV_SETHOSTNAME, ECV_SETDOMAINNAME,
  ECV_GETRLIMIT, ECV_SETRLIMIT, ECV_UMASK, ECV_GETCPU,
  ECV_SETTIMEOFDAY, ECV_ADJTIMEX, ECV_SYSINFO,

  // User/group ID operations
  ECV_SETREGID, ECV_SETGID, ECV_SETREUID, ECV_SETUID,
  ECV_SETRESUID, ECV_GETRESUID, ECV_SETRESGID, ECV_GETRESGID,
  ECV_SETFSUID, ECV_SETFSGID, ECV_TIMES, ECV_GETSID, ECV_SETSID,
  ECV_GETGROUPS, ECV_SETGROUPS,

  // IPC operations
  ECV_MQ_OPEN, ECV_MQ_UNLINK, ECV_MQ_TIMEDSEND, ECV_MQ_TIMEDRECEIVE,
  ECV_MQ_NOTIFY, ECV_MQ_GETSETATTR,
  ECV_MSGGET, ECV_MSGCTL, ECV_MSGRCV, ECV_MSGSND,
  ECV_SEMGET, ECV_SEMCTL, ECV_SEMTIMEDOP, ECV_SEMOP,
  ECV_SHMGET, ECV_SHMCTL, ECV_SHMAT, ECV_SHMDT,

  // Socket operations
  ECV_SOCKET, ECV_SOCKETPAIR, ECV_BIND, ECV_LISTEN, ECV_ACCEPT, ECV_ACCEPT4,
  ECV_CONNECT, ECV_GETSOCKNAME, ECV_GETPEERNAME, ECV_SENDTO, ECV_RECVFROM,
  ECV_SETSOCKOPT, ECV_GETSOCKOPT, ECV_SHUTDOWN, ECV_SENDMSG, ECV_RECVMSG,
  ECV_SENDMMSG, ECV_RECVMMSG,

  // Memory operations
  ECV_MUNMAP, ECV_MREMAP, ECV_MSYNC, ECV_MLOCK, ECV_MUNLOCK,
  ECV_MLOCKALL, ECV_MUNLOCKALL, ECV_MINCORE, ECV_MADVISE,
  ECV_REMAP_FILE_PAGES, ECV_MBIND, ECV_GET_MEMPOLICY, ECV_SET_MEMPOLICY,
  ECV_MIGRATE_PAGES, ECV_MOVE_PAGES, ECV_MLOCK2,
  ECV_PKEY_MPROTECT, ECV_PKEY_ALLOC, ECV_PKEY_FREE,
  ECV_SWAPON, ECV_SWAPOFF, ECV_MEMFD_CREATE, ECV_MEMFD_SECRET,
  ECV_PROCESS_MADVISE, ECV_PROCESS_MRELEASE,

  // Key operations
  ECV_ADD_KEY, ECV_REQUEST_KEY, ECV_KEYCTL,

  // Futex operations
  ECV_FUTEX_WAITV,

  // Performance monitoring
  ECV_PERF_EVENT_OPEN,

  // Filesystem operations
  ECV_FANOTIFY_INIT, ECV_FANOTIFY_MARK,
  ECV_NAME_TO_HANDLE_AT, ECV_OPEN_BY_HANDLE_AT,
  ECV_SETNS, ECV_PROCESS_VM_READV, ECV_PROCESS_VM_WRITEV,
  ECV_KCMP, ECV_SECCOMP, ECV_BPF, ECV_EXECVEAT, ECV_USERFAULTFD,
  ECV_MEMBARRIER, ECV_RSEQ,
  ECV_PIDFD_SEND_SIGNAL, ECV_PIDFD_OPEN, ECV_PIDFD_GETFD,
  ECV_OPEN_TREE, ECV_MOVE_MOUNT, ECV_FSOPEN, ECV_FSCONFIG,
  ECV_FSMOUNT, ECV_FSPICK, ECV_MOUNT_SETATTR,
  ECV_CLONE3, ECV_CLOSE_RANGE, ECV_OPENAT2, ECV_FACCESSAT2,
  ECV_LANDLOCK_CREATE_RULESET, ECV_LANDLOCK_ADD_RULE, ECV_LANDLOCK_RESTRICT_SELF,
};

constexpr bool IsSyscallUnimplemented(uint32_t syscall_num) {
  for (size_t i = 0; i < std::size(UNIMPLEMENTED_SYSCALLS); ++i) {
    if (UNIMPLEMENTED_SYSCALLS[i] == syscall_num) return true;
  }
  return false;
}

EM_JS(uint32_t, ___syscall_clone,
      (uint32_t ecvPid, uint32_t sData, uint32_t sDataLen, uint32_t mBytes, uint32_t mBytesLen), {
        let bellView = new Int32Array(copyFinBell);
        Atomics.store(bellView, 0, 0);

        // clone syscall entry.
        let sysRes = ecvProxySyscallJs(ECV_CLONE, sData, sDataLen, mBytes, mBytesLen);

        // waiting until process state copy has been finished.
        Atomics.wait(bellView, 0, 0);

        let copyFinBellRes = Atomics.load(bellView, 0);
        if (copyFinBellRes != 1) {
          throw new Error(`copyFinBellRes(${copyFinBellRes}) is strange.`);
        }

        return sysRes;
      });

EM_JS(uint32_t, ___syscall_wait4, (uint32_t ecvPid), {
  let childMonitorView = new Int32Array(childMonitor);

  // if no child exited process is on the ring buffer, the parent should wait.
  Atomics.wait(childMonitorView, 1, 1);

  // waked up. Atomics.load(childMonitorView, 1) is `0`.

  // should wait during the other process is operating the ring buffer. (FIXME?)
  Atomics.wait(childMonitorView, 0, 1);

  // waked up. Atomics.load(childMonitorView, 0) is `0`.

  // Lock ringBufferLock.
  Atomics.store(childMonitorView, 0, 1);

  let sysRes = ecvProxySyscallJs(ECV_WAIT4, ecvPid);

  // Free ringBufferLock.
  Atomics.store(childMonitorView, 0, 0);
  Atomics.notify(childMonitorView, 0, 1);

  return sysRes;
});

EM_JS(void, ___syscall_exit, (uint32_t ecvPid, uint32_t code), {
  if (parMonitor) {
    // has parent
    let parMonitorView = new Int32Array(parMonitor);

    // should wait during the other process is operating the ring buffer. (FIXME?)
    Atomics.wait(parMonitorView, 0, 1);

    // waked up. Atomics.load(parMonitorView, 0) is `0`

    // Lock ringBufferLock.
    Atomics.store(parMonitorView, 0, 1);

    ecvProxySyscallJs(ECV_EXIT, ecvPid, code);

    // Free ringBufferLock.
    Atomics.store(parMonitorView, 0, 0);
    Atomics.notify(parMonitorView, 0, 1);
  } else {
    // init process.
    ecvProxySyscallJs(ECV_EXIT, ecvPid, code);
  }

  throw new Error(`exit process(${ecvPid})`);
});

EM_JS(int, ___syscall_execve, (uint32_t fileNameP, uint32_t argvP, uint32_t envpP), {
  let execveBellView = new Int32Array(execveBell);
  Atomics.store(execveBellView, 0, 0);

  ecvProxySyscallJs(ECV_EXECVE, ecvPid, fileNameP, argvP, envpP);

  // waiting until this worker is noted whether or not `execve` succeeds.
  Atomics.wait(execveBellView, 0, 0);

  if (Atomics.load(execveBellView, 0) == 1) {
    // `execve` failed.
    Atomics.store(execveBellView, 0, 0);
  } else {
    throw new Error(`execveBell is strange at ___syscall_execve.`);
  }

  // this worker being waked up shows that `execve` has failed.
  // (FIXME) should set valid error code.
  return -1;
});

EM_JS(int, ___syscall_setpgid, (uint32_t tEcvPid, uint32_t ecvPgid),
      { return ecvProxySyscallJs(ECV_SETPGID, tEcvPid, ecvPgid, ecvPid); });

EM_JS(int, ___syscall_getpgid, (uint32_t tEcvPid),
      { return ecvProxySyscallJs(ECV_GETPGID, tEcvPid, ecvPid); });

EM_JS(int, ___ecv_syscall_ioctl, (uint32_t fd, uint32_t cmd, uint32_t arg),
      { return ecvProxySyscallJs(ECV_IOCTL, fd, cmd, arg); });

EM_JS(int, ___syscall_poll, (uint32_t fd, uint32_t nfds, int tmSec, uint32_t tmNsec),
      { return ecvProxySyscallJs(ECV_POLL_SCAN, fd, nfds, tmSec, tmNsec); });  // dummy body

EM_JS(int, ___syscall_pselect6,
      (uint32_t nfds, uint32_t readfdsP, uint32_t writefdsP, uint32_t exceptfdsP, int tmSec, uint32_t tmNsec,
       uint32_t sigmaskP),
      {
        return ecvProxySyscallJs(ECV_PSELECT6_SCAN, nfds, readfdsP, writefdsP, exceptfdsP, timeout,
                                 sigmaskP);
      });  // dummy body

EM_JS(int, ___syscall_pipe2, (uint32_t pipefd, uint32_t flags), {
  return ecvProxySyscallJs(ECV_PIPE2, pipefd, flags);
});

EM_JS(uint32_t, ___syscall_sendfile, (uint32_t out_fd, uint32_t in_fd, uint32_t offsetP, uint32_t count), {
  return ecvProxySyscallJs(ECV_SENDFILE, out_fd, in_fd, offsetP, count);
});

/*
  Syscall emulation function for Browser/Emscripten environment

  This function handles Linux system calls in a WebAssembly environment using Emscripten.
  It provides Linux syscall emulation with errno conversion from WASI to Linux format.

  Calling Conventions:
  - ARM64: syscall NR: x8, return: x0, args: x0-x5
    ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/

  - x86-64: syscall NR: rax, return: rax, args: rdi, rsi, rdx, r10, r8, r9
    ref: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
*/
void RuntimeManager::SVCBrowserCall(uint8_t *arena_ptr) {
  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] SVCBrowserCall: syscall=%u, PC=0x%016llx\n", SYSNUMREG, PCREG);
#endif
    // printf("[pid %u] syscall number: %llu, X0_Q: 0x%llx, X1_Q: 0x%llx, X2_Q: 0x%llx\n",
    //        main_ecv_pr->ecv_pid, SYSNUMREG, X0_Q, X1_Q, X2_Q);
  switch (SYSNUMREG) {
    case ECV_GETCWD: /* getcwd (char *buf, unsigned long size) */
    {
      char *res = getcwd((char *) TranslateVMA(arena_ptr, X0_Q), X1_Q);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_DUP: /* dup (unsigned int fildes) */
    {
      int res = dup(X0_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_DUP3: /* int dup3(int oldfd, int newfd, int flags) */
    {
      int res = dup3(X0_D, X1_D, X2_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_FCNTL: /* int fcntl(int fd, int cmd, ... arg ); */
    {
      int res;
      // Commands that take an argument
      if (X1_D == ECV_F_DUPFD || X1_D == ECV_F_SETFD || X1_D == ECV_F_SETFL) {
        res = fcntl(X0_D, X1_D, X2_D);
        X0_Q = SetSyscallRes(res);
      }
      // Commands that don't take an argument
      else if (X1_D == ECV_F_GETFD || X1_D == ECV_F_GETFL) {
        res = fcntl(X0_D, X1_D);
        X0_Q = SetSyscallRes(res);
      }
      // Unsupported command
      else {
        errno = _LINUX_EINVAL;
        X0_Q = -errno;
      }
      break;
    }
    case ECV_IOCTL: /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
    {
      unsigned int fd = X0_D;
      unsigned int cmd = X1_D;
      unsigned long arg = X2_Q;
      switch (cmd) {
        case _LINUX_TCGETS: {
          struct termios t_host;
          int rc = tcgetattr(fd, &t_host);
          if (rc == 0) {
            struct _elfarm64_termios t;
            memset(&t, 0, sizeof(_elfarm64_termios));
            t.c_iflag = t_host.c_iflag;
            t.c_oflag = t_host.c_oflag;
            t.c_cflag = t_host.c_cflag;
            t.c_lflag = t_host.c_lflag;
            t.c_line = t_host.c_line;
            memcpy(t.c_cc, t_host.c_cc, std::min(NCCS, _LINUX_NCCS));
            memcpy(TranslateVMA(arena_ptr, arg), &t, sizeof(_elfarm64_termios));
            X0_Q = 0;
          } else {
            X0_Q = -wasi2linux_errno[errno];
          }
          break;
        }
        case _LINUX_TCSETS: {
          struct termios t_wasm;
          auto t_host = *(_elfarm64_termios *) TranslateVMA(arena_ptr, arg);
          t_wasm.c_iflag = t_host.c_iflag;
          t_wasm.c_oflag = t_host.c_oflag;
          t_wasm.c_cflag = t_host.c_cflag;
          t_wasm.c_lflag = t_host.c_lflag;
          t_wasm.c_line = t_host.c_line;
          memcpy(t_wasm.c_cc, t_host.c_cc, std::min(NCCS, _LINUX_NCCS));
          int res = tcsetattr(fd, 0 /* TCSANOW */, &t_wasm);
          if (res == 0) {
            X0_Q = 0;
          } else {
            X0_Q = -wasi2linux_errno[errno];
          }
          break;
        }
        case _LINUX_TIOCGPGRP: {
          auto arg_p = TranslateVMA(arena_ptr, arg);
          int res = ___ecv_syscall_ioctl(X0_D, _EMCC_TIOCGPGRP, (uint32_t) &arg_p);
          X0_Q = SetSyscallResAndErrno(res);
          break;
        }
        case _LINUX_TIOCGWINSZ: {
          auto arg_p = TranslateVMA(arena_ptr, arg);
          int res = ___ecv_syscall_ioctl(X0_D, _EMCC_TIOCGWINSZ, (uint32_t) &arg_p);
          X0_Q = SetSyscallResAndErrno(res);
          break;
        }
        default: 
          errno = _LINUX_EINVAL; X0_Q = -errno; break;
      }
      break;
    }
    case ECV_MKDIRAT: /* int mkdirat (int dfd, const char *pathname, umode_t mode) */
    {
      int res = mkdirat(X0_D, (char *) TranslateVMA(arena_ptr, X1_Q), X2_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_UNLINKAT: /* int unlinkat (int dfd, const char *pathname, int flag) */
    {
      int res = unlinkat(X0_D, (char *) TranslateVMA(arena_ptr, X1_Q), X2_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_STATFS: /* int statfs(const char *path, struct statfs *buf) */
    {
      int res = statfs((char *) TranslateVMA(arena_ptr, X0_Q),
                       (struct statfs *) TranslateVMA(arena_ptr, X1_Q));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_TRUNCATE: /* int truncate(const char *path, off_t length) */
    {
      int res = truncate((char *) TranslateVMA(arena_ptr, X0_Q), (_ecv_long) X1_Q);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_FTRUNCATE: /* int ftruncate(int fd, off_t length) */
    {
      int res = ftruncate(X0_Q, (_ecv_long) X1_Q);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
    {
      int res = faccessat(X0_D, (const char *) TranslateVMA(arena_ptr, X1_Q), X2_D, X3_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_CHDIR: /* int chdir (const char * path) */
    {
      int res = chdir((const char *) TranslateVMA(arena_ptr, X0_Q));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
    {
      int res = openat(X0_D, (char *) TranslateVMA(arena_ptr, X1_Q), X2_D, X3_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_CLOSE: /* int close (unsigned int fd) */
    {
      int res = close(X0_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_PIPE2: /* int pipe2(int pipefd[2], int flags) */
    {
      int pipefd[2];
      int res = ___syscall_pipe2((uint32_t) pipefd, X1_D);
      int *_res_pipefd = (int *)TranslateVMA(arena_ptr, X0_Q);
      _res_pipefd[0] = pipefd[0];
      _res_pipefd[1] = pipefd[1];
      X0_Q = SetSyscallResAndErrno(X0_D);
      break;
    }
    case ECV_GETDENTS: /* long getdents64 (int fd, void *dirp, size_t count) */
    {
      long res = getdents(X0_D, (struct dirent *) TranslateVMA(arena_ptr, X1_Q), X2_Q);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_LSEEK: /* int lseek(unsigned int fd, off_t offset, unsigned int whence) */
    {
      off_t res = lseek(X0_D, (_ecv_long) X1_Q, X2_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_READ: /* read (unsigned int fd, char *buf, size_t count) */
    {
      ssize_t res = read(X0_D, (char *) TranslateVMA(arena_ptr, X1_Q), static_cast<size_t>(X2_Q));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
    {
      ssize_t res = write(X0_D, TranslateVMA(arena_ptr, X1_Q), static_cast<size_t>(X2_Q));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_WRITEV: /* writev (unsigned long fd, const struct iovec *vec, unsigned long vlen) */
    {
      unsigned long fd = X0_Q;
      unsigned long vlen = X2_Q;
      auto tr_vec = reinterpret_cast<iovec *>(TranslateVMA(arena_ptr, X1_Q));
      auto cache_vec = reinterpret_cast<iovec *>(malloc(sizeof(iovec) * vlen));
      for (unsigned long i = 0; i < vlen; i++) {
        cache_vec[i].iov_base =
            TranslateVMA(arena_ptr, reinterpret_cast<addr_t>(tr_vec[i].iov_base));
        cache_vec[i].iov_len = tr_vec[i].iov_len;
      }
      uint64_t res = writev(fd, cache_vec, vlen);
      X0_Q = SetSyscallRes(res);
      free(cache_vec);
      break;
    }
    case ECV_SENDFILE: /* sendfile (int out_fd, int in_fd, off_t *offset, size_t count) */
    {
      int res;
      if (X2_Q == NULL) {
        res = ___syscall_sendfile(X0_D, X1_D, NULL, X3_Q);
      } else {
        res = ___syscall_sendfile(X0_D, X1_D, (uint32_t)TranslateVMA(arena_ptr, X2_Q), X3_Q);
      }
      X0_Q = SetSyscallResAndErrno(res);
      break;
    }
    case ECV_PSELECT6: /* pselect6 (int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t* sigmask) */
    {
      int res;
      if (X4_Q == NULL) {
        res = ___syscall_pselect6(X0_D, X1_Q, X2_Q, X3_Q, -1, 0, X5_Q);
      } else {
        auto tm = (_elfarm64_timespec *)TranslateVMA(arena_ptr, X4_Q);
        res = ___syscall_pselect6(X0_D, X1_Q, X2_Q, X3_Q, (int) tm->tv_sec, tm->tv_nsec, X5_Q);
      }
      X0_Q = SetSyscallResAndErrno(res);
      break;
    }
    case ECV_PPOLL: /* ppoll (struct pollfd*, unsigned int, const struct timespec *, const unsigned long int) */
    {
      int res;
      if (X2_Q == NULL) {
        res = ___syscall_poll((uint32_t)TranslateVMA(arena_ptr, X0_Q), X1_D, -1, 0);
      } else {
        auto tm = (_elfarm64_timespec *)TranslateVMA(arena_ptr, X2_Q);
        res = ___syscall_poll((uint32_t)TranslateVMA(arena_ptr, X0_Q), X1_D, (int) tm->tv_sec, tm->tv_nsec);
      }
      X0_Q = SetSyscallResAndErrno(res);
      break;
    }
    case ECV_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
    {
      ssize_t res = readlinkat(X0_D, (const char *) TranslateVMA(arena_ptr, X1_Q),
                                (char *) TranslateVMA(arena_ptr, X2_Q), X3_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
    {
      struct stat _tmp_wasm_stat;
      int res = fstatat(X0_D, (const char *) TranslateVMA(arena_ptr, X1_Q), &_tmp_wasm_stat, X3_D);
      if (res == 0) {
        struct _elfarm64df_stat _elf_stat;
        memset(&_elf_stat, 0, sizeof(_elf_stat));
        _elf_stat.st_dev = _tmp_wasm_stat.st_dev;
        _elf_stat.st_ino = _tmp_wasm_stat.st_ino;
        _elf_stat.st_mode = _tmp_wasm_stat.st_mode;
        _elf_stat.st_nlink = _tmp_wasm_stat.st_nlink;
        _elf_stat.st_uid = _tmp_wasm_stat.st_uid;
        _elf_stat.st_gid = _tmp_wasm_stat.st_gid;
        _elf_stat.st_rdev = _tmp_wasm_stat.st_rdev;
        _elf_stat.st_size = _tmp_wasm_stat.st_size;
        _elf_stat.st_blksize = _tmp_wasm_stat.st_blksize;
        _elf_stat.st_blocks = _tmp_wasm_stat.st_blocks;
        _elf_stat.st_atime = _tmp_wasm_stat.st_atim.tv_sec;
        _elf_stat.st_mtime = _tmp_wasm_stat.st_mtim.tv_sec;
        _elf_stat.st_ctime = _tmp_wasm_stat.st_ctim.tv_sec;
        memcpy((struct _elfarm64df_stat *) TranslateVMA(arena_ptr, X2_Q), &_elf_stat,
               sizeof(_elf_stat));
        X0_D = 0;
      } else {
        X0_Q = -wasi2linux_errno[errno];
      }
      break;
    }
    case ECV_FSYNC: /* fsync (unsigned int fd) */
    {
      int res = fsync(X0_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_UTIMENSAT: /* int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) */
    {
      const struct timespec *times_ptr = nullptr;
      struct timespec emu_tp[2];

      if (X2_Q != 0) {
        auto x2_time = (const struct _elfarm64_timespec *) TranslateVMA(arena_ptr, X2_Q);
        for (int i = 0; i < 2; i++) {
          emu_tp[i].tv_sec = (time_t) x2_time[i].tv_sec;
          emu_tp[i].tv_nsec = (long) x2_time[i].tv_nsec;
        }
        times_ptr = &emu_tp[0];
      }

      int res = utimensat(X0_D, (char *) TranslateVMA(arena_ptr, X1_Q), times_ptr, X3_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_EXIT: /* exit (int error_code) */
    case ECV_EXIT_GROUP: /* exit_group (int error_code) */
    {
      ___syscall_exit(main_ecv_pr->ecv_pid, X0_D);
      break;
    }
    case ECV_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = gettid();
      *reinterpret_cast<int *>(TranslateVMA(arena_ptr, X0_Q)) = tid;
      X0_Q = tid;
      break;
    }
    case ECV_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u23 val3) */
    /* (FIXME) */
    {
      if ((X1_D & 0x7F) == 0) {
        /* FUTEX_WAIT */
        X0_Q = 0;
      } else {
        errno = _LINUX_ENOSYS;
        X0_Q = -errno;
      }
      break;
    }
    case ECV_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
    {
      struct timespec emu_tp;
      int res = clock_gettime(CLOCK_REALTIME, &emu_tp);
      if (res != -1) {
        // int res = clock_gettime(X0_D, &emu_tp); throw error.
        struct {
          uint64_t tv_sec; /* time_t */
          uint64_t tv_nsec; /* long (assume that the from target architecture is 64bit) */
        } tp = {
            .tv_sec = (uint64_t) emu_tp.tv_sec,
            .tv_nsec = (uint64_t) (_ecv_long) emu_tp.tv_nsec,
        };
        memcpy(TranslateVMA(arena_ptr, X1_Q), &tp, sizeof(tp));
        X0_Q = (_ecv_reg64_t) res;
      } else {
        X0_Q = -wasi2linux_errno[errno];
      }
      break;
    }
    case ECV_CLOCK_NANOSLEEP: /* clock_nanosleep (clockid_t which_clock, int flags, const struct __kernel_timespec *rqtp, struct __kernel_timespce *rmtp) */
    {
      struct timespec _wasm_rqtp, _wasm_rmtp;
      struct _elfarm64_timespec _elf_rmtp;

      auto _elf_rqtp = (const struct _elfarm64_timespec *) TranslateVMA(arena_ptr, X2_Q);
      _wasm_rqtp.tv_nsec = _elf_rqtp->tv_nsec;
      _wasm_rqtp.tv_sec = _elf_rqtp->tv_sec;
      int res = clock_nanosleep(CLOCK_REALTIME, X1_D, &_wasm_rqtp, &_wasm_rmtp);
      _elf_rmtp.tv_nsec = _wasm_rmtp.tv_nsec;
      _elf_rmtp.tv_sec = _wasm_rmtp.tv_sec;
      memcpy((struct _elfarm64_timespec *) TranslateVMA(arena_ptr, X3_Q), &_elf_rmtp,
             sizeof(_elf_rmtp));
      X0_Q = -res;
      break;
    }
    case ECV_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */
    {
      int res = kill(X0_D, X1_D);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
    {
      int res = sigaction(X0_D, (const struct sigaction *) TranslateVMA(arena_ptr, X1_Q),
                          (struct sigaction *) TranslateVMA(arena_ptr, X2_Q));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_SETPGID: /* int setpgid(pid_t pid, pid_t pgid) */
    {
      X0_Q = ___syscall_setpgid(X0_D, X1_D);
      break;
    }
    case ECV_GETPGID: /* void getpgid(pid_t pid) */
    {
      X0_Q = ___syscall_getpgid(X0_D);
      break;
    }
    case ECV_UNAME: /* uname (struct old_utsname* buf) */
    {
      struct __elfarm64_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
      } new_utsname = {"Linux", "wasm-host-01",
                       "6.0.0-00-generic", /* cause error if the kernel version is too old. */
                       "#4 SMP PREEMPT Tue May 15 12:34:56 UTC 2025", "wasm32"};
      memcpy(TranslateVMA(arena_ptr, X0_Q), &new_utsname, sizeof(new_utsname));
      X0_D = 0;
      break;
    }
    case ECV_GETTIMEOFDAY: /* gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) */
    {
      int res = gettimeofday((struct timeval *) TranslateVMA(arena_ptr, X0_Q),
                             nullptr); /* Second argument (timezone) is deprecated and unused */
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_GETRUSAGE: /* getrusage (int who, struct rusage *ru) */
    {
      struct rusage tmp_rusage;
      int res = getrusage(X0_D, &tmp_rusage);
      _linux_rusage _ecv_usage;
      _ecv_usage.ru_utime.tv_sec = tmp_rusage.ru_utime.tv_sec;
      _ecv_usage.ru_utime.tv_usec = tmp_rusage.ru_utime.tv_usec;
      _ecv_usage.ru_stime.tv_sec = tmp_rusage.ru_stime.tv_sec;
      _ecv_usage.ru_stime.tv_usec = tmp_rusage.ru_stime.tv_usec;
      memcpy(TranslateVMA(arena_ptr, X1_Q), &_ecv_usage, sizeof(_linux_rusage));
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_PRCTL: /* prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */
    {
      uint32_t option = X0_D;
      switch (option) {
        case ECV_PR_GET_NAME:
          memcpy(TranslateVMA(arena_ptr, X1_Q), TranslateVMA(arena_ptr, TASK_STRUCT_VMA),
                 /* TASK_COMM_LEN */ 16);
          X0_Q = 0;
          break;
        default: 
          errno = _LINUX_EINVAL;
          X0_Q = -errno; 
          break;
      }
      break;
    }
    case ECV_GETPID: /* getpid () */ X0_D = main_ecv_pr->ecv_pid; break;
    case ECV_GETPPID: /* getppid () */ X0_D = main_ecv_pr->par_ecv_pid; break;
    case ECV_GETUID: /* getuid () */ X0_D = main_ecv_pr->ecv_uid; break;
    case ECV_GETEUID: /* geteuid () */ X0_D = main_ecv_pr->ecv_euid; break;
    case ECV_GETGID: /* getgid () */ X0_D = main_ecv_pr->ecv_gid; break;
    case ECV_GETEGID: /* getegid () */ X0_D = main_ecv_pr->ecv_egid; break;
    case ECV_GETTID: /* getttid () */ X0_D = main_ecv_pr->ecv_ttid; break;
    case ECV_BRK: /* brk (unsigned long brk) */
    {
      MemoryArena *memory_arena;
      memory_arena = main_ecv_pr->memory_arena;
      if (X0_Q == 0) {
        /* init program break (FIXME) */
        X0_Q = memory_arena->heap_cur;
      } else if (HEAPS_START_VMA <= X0_Q && X0_Q < HEAPS_START_VMA + HEAP_UNIT_SIZE) {
        /* change program break */
        memory_arena->heap_cur = X0_Q;
      } else {
        errno = _LINUX_ENOMEM;
        X0_Q = -errno;
      }
      break;
    }
    case ECV_CLONE: /* clone (unsigned long, unsigned long, int *, int *, unsigned long) */
    {
      State *cur_state, *new_state;
      uint64_t t_func_addr, t_next_pc;

      cur_state = CPUState;
      new_state = new State();
      memcpy(new_state, cur_state, sizeof(State));

      new_state->func_depth = 0;
      new_state->gpr.x0.qword = 0;  // child side

      // assumes that generated LLVM IR save these two values before calling syscall.
      t_func_addr = CPUState->fork_entry_fun_addr;
      t_next_pc = CPUState->gpr.pc.qword;

      /// copy shared data to give the new process worker through js-kernel.
      /// memory content:
      /// [ CPUState (sizeof(CPUState) byte); memory_arena_type: (4 byte); vma (4 byte); len (4 byte);
      ///   heap_cur (4 byte); t_func_addr (4 byte); t_next_pc (4 byte);
      ///   call_history_len (4 byte); [ t_func_addr_1, t_func_next_pc_1, ..., t_func_addr_n, t_func_next_pc_n ] (8 * call_history_len byte); ]

      uint32_t shared_data_len = sizeof(State) +
                                 4 /* memory_area_type */
                                 // + 4 /* name<ptr> */
                                 + 4 /* vma */
                                 + 4 /* len */
                                 //  + 4 /* bytes<ptr>*/
                                 + 4 /* heap_cur */
                                 + 4 /* t_func_addr */
                                 + 4 /* t_next_pc */
                                 + 4 /* call_history_len */
                                 +
                                 4 * main_ecv_pr->call_history.size() * 2 /* parent_call_history */
                                 + 4 /* child pid (written by js-kernel) */
                                 + 4 /* parent pid (written by js-kernel) */
                                 + 4; /* pgid (written by js-kernel) */
      uint8_t *shared_data = (uint8_t *) malloc(shared_data_len);

      // CPUState
      memcpy(shared_data, new_state, sizeof(State));
      // MemoryArena
      uint32_t *mem_p = (uint32_t *) (shared_data + sizeof(State));
      mem_p[0] = (uint32_t) main_memory_arena->memory_area_type;
      // skip `name` field.
      mem_p[1] = (uint32_t) main_memory_arena->vma;
      mem_p[2] = (uint32_t) main_memory_arena->len;
      mem_p[3] = (uint32_t) main_memory_arena->heap_cur;
      // next address info
      uint32_t *next_addr_p = mem_p + 4;
      next_addr_p[0] = t_func_addr;
      next_addr_p[1] = t_next_pc;
      // call history
      uint32_t *history_p = next_addr_p + 2;
      auto copied_history = main_ecv_pr->call_history;
      uint32_t history_size = copied_history.size();
      history_p[0] = history_size;
      for (int i = 0; !copied_history.empty(); i += 2) {
        auto [f_addr, j_addr] = copied_history.top();
        copied_history.pop();
        history_p[1 + i] = f_addr;
        history_p[1 + i + 1] = j_addr;
      }

      // issue clone syscall to js-kernel.
      // future work: does not handle the actual arguments of original syscall for simplicity now.
      uint32_t child_pid =
          ___syscall_clone(main_ecv_pr->ecv_pid, (uint32_t) shared_data, shared_data_len,
                           (uint32_t) main_memory_arena->bytes, (uint32_t) MEMORY_ARENA_SIZE);

      uint32_t *child_pid_p = history_p + 1 + history_size * 2;
      *child_pid_p = child_pid;
      X0_Q = child_pid;
      break;
    }
    case ECV_EXECVE: /* int execve(const char * filename , char *const argv [], char *const envp []) */
    {
#if defined(__wasm64__)
#  error elfconv cannot support 64bit address space for `execve` emulation.
#endif
      // The every virtual address of `argv` and `envp` should be translated because memory access in JS world doesn't have MMU.
      auto _execve_argv_p = (char **) calloc(400, 1);
      auto _execve_envp_p = (char **) calloc(400, 1);
      auto argv_p = (char **) TranslateVMA(arena_ptr, X1_Q);
      auto envp_p = (char **) TranslateVMA(arena_ptr, X2_Q);
      // Note. ELF memory address is located based on 64 bit address space.
      for (int i = 0; argv_p[i * 2]; i++) {
        _execve_argv_p[i] = (char *) TranslateVMA(arena_ptr, (uint32_t) argv_p[i * 2]);
      }
      for (int i = 0; envp_p[i * 2]; i++) {
        _execve_envp_p[i] = (char *) TranslateVMA(arena_ptr, (uint32_t) envp_p[i * 2]);
      }
      int res = ___syscall_execve((uint32_t) TranslateVMA(arena_ptr, X0_Q), (uint32_t) _execve_argv_p,
                               (uint32_t) _execve_envp_p);
      if (res < 0) {
        errno = _LINUX_ENOEXEC;
        X0_Q = -errno;
      } else {
        elfconv_runtime_error("[ERROR] execve syscall emulation is invalid.\n");
      }
      free(_execve_argv_p);
      free(_execve_envp_p);
      break;
    }
    case ECV_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
    /* (FIXME) */
    {
      MemoryArena *memory_arena;
      memory_arena = main_ecv_pr->memory_arena;
      if (X4_D != (uint32_t) -1) {
        elfconv_runtime_error("Unsupported mmap (X4=0x%08x)\n", X4_D);
      }
      if (X5_D != 0) {
        elfconv_runtime_error("Unsupported mmap (X5=0x%016llx)\n", X5_Q);
      }
      if (X0_Q == 0) {
        X0_Q = memory_arena->heap_cur;
        memory_arena->heap_cur += X1_Q;
      } else {
        elfconv_runtime_error("Unsupported mmap (X0=0x%016llx)\n", X0_Q);
      }
      break;
    }
    case ECV_WAIT4: /* pid_t wait4 (pid_t pid, int *stat_addr, int options, struct rusage *ru) */
    {
      int res = ___syscall_wait4(main_ecv_pr->ecv_pid);
      X0_Q = SetSyscallRes(res);
      break;
    }
    case ECV_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      uint32_t len = (uint32_t)X1_Q;
      auto res = getentropy(TranslateVMA(arena_ptr, X0_Q), len);
      X0_Q = SetSyscallRes(len);
      break;
    }
    case ECV_MPROTECT: /* mprotect (unsigned long start, size_t len, unsigned long prot) */
      // mprotect implementaion of wasi-libc doesn't change the memory access and only check arguments, and Wasm page size (64KiB) is different from Linux Page size (4KiB).
      // Therefore elfconv doesn't use it. ref: https://github.com/WebAssembly/wasi-libc/blob/45252554b765e3db11d0ef5b41d6dd290ed33382/libc-bottom-half/mman/mman.c#L127-L157
    {
      X0_D = 0;
      break;
    }
    case ECV_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
    {
      int dfd = X0_D;
      _ecv_reg_t flags = X2_D;
      struct stat _stat;
      // execute fstat
      int res = fstat(dfd, &_stat);
      if (res == 0) {
        struct _linux_statx _statx;
        memset(&_statx, 0, sizeof(_statx));
        _statx.stx_mask = _statx.stx_mask = _LINUX_STATX_BASIC_STATS;
        _statx.stx_blksize = _stat.st_blksize;
        _statx.stx_attributes = 0;
        _statx.stx_nlink = _stat.st_nlink;
        _statx.stx_uid = _stat.st_uid;
        _statx.stx_gid = _stat.st_gid;
        _statx.stx_mode = _stat.st_mode;
        _statx.stx_ino = _stat.st_ino;
        _statx.stx_size = _stat.st_size;
        _statx.stx_blocks = _stat.st_blocks;
        memcpy(TranslateVMA(arena_ptr, X4_Q), &_statx, sizeof(_statx));
        X0_Q = 0;
      } else {
        X0_Q = -wasi2linux_errno[errno];
      }
      break;
    }
    default: {
      UnImplementedBrowserSyscall(); 
      errno = _LINUX_ENOSYS; 
      X0_Q = -errno; 
      break;
    }
  }
}

void RuntimeManager::UnImplementedBrowserSyscall() {
  // Check if syscall is in the unimplemented list
  if (IsSyscallUnimplemented(SYSNUMREG)) {
    return;
  }

  elfconv_runtime_error("unknown syscall number: %ld\n", SYSNUMREG);
}