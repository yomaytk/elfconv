#include "SysTable.h"
#include "remill/Arch/Runtime/Types.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <remill/BC/HelperMacro.h>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
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

/*
  for ioctl syscall
*/
typedef uint32_t _ecv_tcflag_t;
typedef uint8_t _ecv_cc_t;

struct _elfarm64_termios {
  _ecv_tcflag_t c_iflag;
  _ecv_tcflag_t c_oflag;
  _ecv_tcflag_t c_cflag;
  _ecv_tcflag_t c_lflag;
  _ecv_cc_t c_line;
  _ecv_cc_t c_cc[_LINUX_NCCS];
};

struct _elfarm64_winsize {
  uint16_t ws_row;
  uint16_t ws_col;
  uint16_t ws_xpixel;
  uint16_t ws_ypixel;
};

/* for stat */
struct _elfarm64df_timespec {
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
  struct _elfarm64df_timespec st_atim;
  struct _elfarm64df_timespec st_mtim;
  struct _elfarm64df_timespec st_ctim;
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

/* 
  for statx 
*/
struct _ecv_statx_timestamp {
  int64_t tv_sec;
  uint32_t tv_nsec;
};
struct _ecv_statx {
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
  syscall emulate function
  
  Calling Conventions
  arch: arm64, syscall NR: x8, return: x0, arg0: x0, arg1: x1, arg2: x2, arg3: x3, arg4: x4, arg5: x5
  ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/

  arch: x86-64, sycall NR: rax, return: rax, arg0: rdi, arg1: rsi, arg2: rdx, arg3: r10, arg4: r8, arg5: r9
  ref: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
*/
void RuntimeManager::SVCBrowserCall(void) {

  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] __svc_call started. syscall number: %u, PC: 0x%016llx\n", SYSNUMREG, PCREG);
#endif
  switch (SYSNUMREG) {
    case ECV_GETCWD: /* getcwd (char *buf, unsigned long size) */
      getcwd((char *) TranslateVMA(X0_Q), X1_Q);
      break;
    case ECV_DUP: /* dup (unsigned int fildes) */ X0_D = dup(X0_D); break;
    case ECV_DUP3: /*  int dup3(int oldfd, int newfd, int flags) */
      X0_D = dup3(X0_D, X1_D, X2_D);
      break;
    case ECV_FCNTL: /* int fcntl(int fd, int cmd, ... arg ); */
      if (X1_D == ECV_F_DUPFD || X1_D == ECV_F_SETFD || X1_D == ECV_F_SETFL) {
        X0_D = fcntl(X0_D, X1_D, X2_D);
      } else if (X1_D == ECV_F_GETFD || X1_D == ECV_F_GETFL) {
        X0_D = fcntl(X0_D, X1_D);
      } else {
        X0_Q = -_LINUX_EINVAL;
      }
      break;
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
            memcpy(TranslateVMA(arg), &t, sizeof(_elfarm64_termios));
            X0_Q = 0;
          } else {
            X0_Q = -errno;
          }
          break;
        }
        case _LINUX_TIOCGWINSZ: X0_Q = -_LINUX_ENOTTY; break;
        default: X0_Q = -_LINUX_ENOTTY; break;
      }
    } break;
    case ECV_MKDIRAT: /* int mkdirat (int dfd, const char *pathname, umode_t mode) */
      X0_D = mkdirat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_UNLINKAT: /* int unlinkat (int dfd, const char *pathname, int flag) */
      X0_D = unlinkat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_STATFS: /* int statfs(const char *path, struct statfs *buf) */
      X0_D = statfs((char *) TranslateVMA(X0_Q), (struct statfs *) TranslateVMA(X1_Q));
      break;
    case ECV_TRUNCATE: /* int truncate(const char *path, off_t length) */
      X0_D = truncate((char *) TranslateVMA(X0_Q), (_ecv_long) X1_Q);
      break;
    case ECV_FTRUNCATE: /* int ftruncate(int fd, off_t length) */
      X0_D = ftruncate(X0_Q, (_ecv_long) X1_Q);
      break;
    case ECV_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      X0_D = faccessat(X0_D, (const char *) TranslateVMA(X1_Q), X2_D, X3_D);
      break;
    case ECV_CHDIR: /* int chdir (const char * path) */
      X0_D = chdir((const char *) TranslateVMA(X0_Q));
      break;
    case ECV_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
      X0_D = openat(X0_D, (char *) TranslateVMA(X1_Q), X2_D, X3_D);
      break;
    case ECV_CLOSE: /* int close (unsigned int fd) */ X0_D = close(X0_D); break;
    case ECV_GETDENTS: /* long getdents64 (int fd, void *dirp, size_t count) */
      X0_Q = getdents(X0_D, (struct dirent *) TranslateVMA(X1_Q), X2_Q);
      break;
    case ECV_LSEEK: /* int lseek(unsigned int fd, off_t offset, unsigned int whence) */
      X0_D = lseek(X0_D, (_ecv_long) X1_Q, X2_D);
      break;
    case ECV_READ: /* read (unsigned int fd, char *buf, size_t count) */
      X0_Q = read(X0_D, (char *) TranslateVMA(X1_Q), static_cast<size_t>(X2_Q));
      break;
    case ECV_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
      X0_Q = write(X0_D, TranslateVMA(X1_Q), static_cast<size_t>(X2_Q));
      break;
    case ECV_WRITEV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
    {
      unsigned long fd = X0_Q;
      unsigned long vlen = X2_Q;
      auto tr_vec = reinterpret_cast<iovec *>(TranslateVMA(X1_Q));
      auto cache_vec = reinterpret_cast<iovec *>(malloc(sizeof(iovec) * vlen));
      // translate every iov_base
      for (unsigned long i = 0; i < vlen; i++) {
        cache_vec[i].iov_base = TranslateVMA(reinterpret_cast<addr_t>(tr_vec[i].iov_base));
        cache_vec[i].iov_len = tr_vec[i].iov_len;
      }
      X0_Q = writev(fd, cache_vec, vlen);
      free(cache_vec);
    } break;
    case ECV_SENDFILE: /* sendfile (int out_fd, int in_fd, off_t *offset, size_t count) */
      elfconv_runtime_error("sendfile must be implemented for Wasm browser.");
      break;
    case ECV_PPOLL: /* ppoll (struct pollfd*, unsigned int, const struct timespec *, const unsigned long int) */
      X0_D = poll((struct pollfd *) TranslateVMA(X0_Q), (unsigned long int) X1_D, 60);
      break;
    case ECV_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
      X0_Q = readlinkat(X0_D, (const char *) TranslateVMA(X1_Q), (char *) TranslateVMA(X2_Q), X3_D);
      break;
    case ECV_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
    {
      struct stat _tmp_wasm_stat;
      int res = fstatat(X0_D, (const char *) TranslateVMA(X1_Q), &_tmp_wasm_stat, X3_D);
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
        memcpy((struct _elfarm64df_stat *) TranslateVMA(X2_Q), &_elf_stat, sizeof(_elf_stat));
        X0_D = 0;
      } else {
        X0_Q = -errno;
      }
    } break;
    case ECV_FSYNC: /* fsync (unsigned int fd) */ X0_D = fsync(X0_D); break;
    case ECV_UTIMENSAT: /* int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) */
    {
      struct timespec emu_tp[2];
      int res = utimensat(X0_D, (char *) TranslateVMA(X1_Q), emu_tp, X3_D);
      if (res == 0) {
        struct _elfarm64df_timespec _elf_tp[2];
        _elf_tp[0].tv_sec = emu_tp[0].tv_sec;
        _elf_tp[0].tv_nsec = emu_tp[0].tv_nsec;
        _elf_tp[1].tv_sec = emu_tp[1].tv_sec;
        _elf_tp[1].tv_nsec = emu_tp[1].tv_nsec;
        _elfarm64df_timespec *emu_tp_addr = (_elfarm64df_timespec *) TranslateVMA(X2_Q);
        memcpy(emu_tp_addr, &emu_tp[0], sizeof(emu_tp[0]));
        emu_tp_addr++;
        memcpy(emu_tp_addr, &emu_tp[1], sizeof(emu_tp[1]));
        X0_D = res;
      } else {
        X0_Q = -errno;
      }
    } break;
    case ECV_EXIT: /* exit (int error_code) */ exit(X0_D); break;
    case ECV_EXIT_GROUP: /* exit_group (int error_code) */ exit(X0_D); break;
    case ECV_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = gettid();
      *reinterpret_cast<int *>(TranslateVMA(X0_Q)) = tid;
      X0_Q = tid;
    } break;
    case ECV_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u23 val3) */
      /* TODO */
      if ((X1_D & 0x7F) == 0) {
        /* FUTEX_WAIT */
        X0_Q = 0;
      } else {
        elfconv_runtime_error("Unknown futex op 0x%08u\n", X1_D);
      }
      NOP_SYSCALL(ECV_FUTEX);
      break;
    case ECV_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
    {
      struct timespec emu_tp;
      int clock_time = clock_gettime(CLOCK_REALTIME, &emu_tp);
      // int clock_time = clock_gettime(X0_D, &emu_tp); throw error.
      struct {
        uint64_t tv_sec; /* time_t */
        uint64_t tv_nsec; /* long (assume that the from target architecture is 64bit) */
      } tp = {
          .tv_sec = (uint64_t) emu_tp.tv_sec,
          .tv_nsec = (uint64_t) (_ecv_long) emu_tp.tv_nsec,
      };
      memcpy(TranslateVMA(X1_Q), &tp, sizeof(tp));
      X0_Q = (_ecv_reg64_t) clock_time;
    } break;
    case ECV_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */ X0_Q = kill(X0_D, X1_D); break;
    case ECV_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
      X0_D = sigaction(X0_D, (const struct sigaction *) TranslateVMA(X1_Q),
                       (struct sigaction *) TranslateVMA(X2_Q));
      break;
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
      memcpy(TranslateVMA(X0_Q), &new_utsname, sizeof(new_utsname));
      X0_D = 0;
    } break;
    case ECV_GETTIMEOFDAY: /* gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) */
      X0_D = gettimeofday((struct timeval *) TranslateVMA(X0_Q),
                          (struct timezone *) 0); /* FIXME (second argument) */
      break;
    case ECV_GETRUSAGE: /* getrusage (int who, struct rusage *ru) */
      X0_D = getrusage(X0_D, (struct rusage *) TranslateVMA(X1_Q));
    case ECV_PRCTL: /* prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */
    {
      uint32_t option = X0_D;
      switch (option) {
        case ECV_PR_GET_NAME:
          memcpy(TranslateVMA(X1_Q), TranslateVMA(TASK_STRUCT_VMA), /* TASK_COMM_LEN */ 16);
          X0_D = 0;
          break;
        default: X0_D = -_LINUX_EINVAL; break;
      }
    } break;
    case ECV_GETPID: /* getpid () */ X0_D = getpid(); break;
    case ECV_GETPPID: /* getppid () */ X0_D = getppid(); break;
    case ECV_GETUID: /* getuid () */ X0_D = getuid(); break;
    case ECV_GETEUID: /* geteuid () */ X0_D = geteuid(); break;
    case ECV_GETGID: /* getgid () */ X0_D = getgid(); break;
    case ECV_GETEGID: /* getegid () */ X0_D = getegid(); break;
    case ECV_GETTID: /* getttid () */ X0_D = gettid(); break;
    case ECV_BRK: /* brk (unsigned long brk) */
    {
      if (X0_Q == 0) {
        /* init program break (FIXME) */
        X0_Q = memory_arena->heap_cur;
      } else if (HEAPS_START_VMA <= X0_Q && X0_Q < HEAPS_START_VMA + HEAP_UNIT_SIZE) {
        /* change program break */
        memory_arena->heap_cur = X0_Q;
      } else {
        elfconv_runtime_error("Unsupported brk(0x%016llx).\n", X0_Q);
      }
    } break;
    case ECV_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
      /* FIXME */
      {
        if (X4_D != -1)
          elfconv_runtime_error("Unsupported mmap (X4=0x%08x)\n", X4_D);
        if (X5_D != 0)
          elfconv_runtime_error("Unsupported mmap (X5=0x%016llx)\n", X5_Q);
        if (X0_Q == 0) {
          X0_Q = memory_arena->heap_cur;
          memory_arena->heap_cur += X1_Q;
        } else {
          elfconv_runtime_error("Unsupported mmap (X0=0x%016llx)\n", X0_Q);
        }
      }
      break;
    case ECV_WAIT4: /* pid_t wait4 (pid_t pid, int *stat_addr, int options, struct rusage *ru) */
      X0_D = wait4(X0_D, (int *) TranslateVMA(X1_Q), X2_D, (struct rusage *) TranslateVMA(X3_Q));
      break;
    case ECV_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      auto res = getentropy(TranslateVMA(X0_Q), static_cast<size_t>(X1_Q));
      X0_Q = 0 == res ? X1_Q : -errno;
    } break;
    case ECV_MPROTECT: /* mprotect (unsigned long start, size_t len, unsigned long prot) */
      // mprotect implementaion of wasi-libc doesn't change the memory access and only check arguments, and Wasm page size (64KiB) is different from Linux Page size (4KiB).
      // Therefore elfconv doesn't use it. ref: https://github.com/WebAssembly/wasi-libc/blob/45252554b765e3db11d0ef5b41d6dd290ed33382/libc-bottom-half/mman/mman.c#L127-L157
      X0_D = 0;
      break;
    case ECV_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
    {
      int dfd = X0_D;
      _ecv_reg_t flags = X2_D;
      if ((flags & _LINUX_AT_EMPTY_PATH) == 0) {
        elfconv_runtime_error("[ERROR] Unsupported statx(flags=0x%08u)\n", flags);
      }
      struct stat _stat;
      // execute fstat
      errno = fstat(dfd, &_stat);
      if (errno == 0) {
        struct _ecv_statx _statx;
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
        memcpy(TranslateVMA(X4_Q), &_statx, sizeof(_statx));
        X0_Q = 0;
      } else {
        X0_Q = -errno;
      }
    } break;
    default: UnImplementedBrowserSyscall(); break;
  }
}

void RuntimeManager::UnImplementedBrowserSyscall() {
  switch (SYSNUMREG) {
    case ECV_IO_SETUP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_DESTROY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_SUBMIT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_CANCEL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_GETEVENTS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LSETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LGETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FGETXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LISTXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LLISTXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FLISTXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_REMOVEXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LREMOVEXATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FREMOVEXATTR: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETCWD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LOOKUP_DCOOKIE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EVENTFD2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EPOLL_CREATE1: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EPOLL_CTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EPOLL_PWAIT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_DUP: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_DUP3: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_FCNTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_INOTIFY_INIT1: UNIMPLEMENTED_SYSCALL; break;
    case ECV_INOTIFY_ADD_WATCH: UNIMPLEMENTED_SYSCALL; break;
    case ECV_INOTIFY_RM_WATCH: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_IOCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IOPRIO_SET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IOPRIO_GET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FLOCK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MKNODAT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_MKDIRAT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_UNLINKAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYMLINKAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LINKAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RENAMEAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_UMOUNT2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MOUNT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PIVOT_ROOT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_NFSSERVCTL: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_STATFS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSTATFS: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_TRUNCATE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_FTRUNCATE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FALLOCATE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_FACCESSAT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_CHDIR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FCHDIR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CHROOT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FCHMOD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FCHMODAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FCHOWNAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FCHOWN: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_OPENAT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_CLOSE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_VHANGUP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PIPE2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_QUOTACTL: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETDENTS: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_LSEEK: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_READ: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_WRITE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_READV: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_WRITEV: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PREAD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PWRITE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PREADV: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PWRITEV: UNIMPLEMENTED_SYSCALL; break;
    /* UNDECLARED! */  // case ECV_SENDFILE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PSELECT6: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_PPOLL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SIGNALFD4: UNIMPLEMENTED_SYSCALL; break;
    case ECV_VMSPLICE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SPLICE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TEE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_READLINKAT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_NEWFSTATAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_NEWFSTAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYNC: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_FSYNC: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FDATASYNC: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYNC_FILE_RANGE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMERFD_CREATE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMERFD_SETTIME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMERFD_GETTIME: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_UTIMENSAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_ACCT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CAPGET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CAPSET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PERSONALITY: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_EXIT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_EXIT_GROUP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_WAITID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_SET_TID_ADDRESS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_UNSHARE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_FUTEX: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SET_ROBUST_LIST: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GET_ROBUST_LIST: UNIMPLEMENTED_SYSCALL; break;
    case ECV_NANOSLEEP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETITIMER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETITIMER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_KEXEC_LOAD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_INIT_MODULE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_DELETE_MODULE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMER_CREATE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMER_GETTIME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMER_GETOVERRUN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMER_SETTIME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMER_DELETE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLOCK_SETTIME: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_CLOCK_GETTIME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLOCK_GETRES: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLOCK_NANOSLEEP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYSLOG: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PTRACE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_SETPARAM: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_SETSCHEDULER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GETSCHEDULER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GETPARAM: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_SETAFFINITY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GETAFFINITY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_YIELD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GET_PRIORITY_MAX: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GET_PRIORITY_MIN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_RR_GET_INTERVAL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RESTART_SYSCALL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_KILL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TKILL: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_TGKILL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SIGALTSTACK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_SIGSUSPEND: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_RT_SIGACTION: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_RT_SIGPROCMASK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_SIGPENDING: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_SIGTIMEDWAIT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_SIGQUEUEINFO: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_SIGRETURN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETPRIORITY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETPRIORITY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_REBOOT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETREGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETREUID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETUID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETRESUID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETRESUID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETRESGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETRESGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETFSUID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETFSGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_TIMES: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETPGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETPGID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETSID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETSID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETGROUPS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETGROUPS: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_UNAME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETHOSTNAME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETDOMAINNAME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETRLIMIT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETRLIMIT: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETRUSAGE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_UMASK: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_PRCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETCPU: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETTIMEOFDAY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETTIMEOFDAY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_ADJTIMEX: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETPID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETPPID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETUID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETEUID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETGID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETEGID: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETTID: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYSINFO: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_OPEN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_UNLINK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_TIMEDSEND: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_TIMEDRECEIVE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_NOTIFY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MQ_GETSETATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MSGGET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MSGCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MSGRCV: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MSGSND: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SEMGET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SEMCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SEMTIMEDOP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SEMOP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SHMGET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SHMCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SHMAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SHMDT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SOCKET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SOCKETPAIR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_BIND: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LISTEN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_ACCEPT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CONNECT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETSOCKNAME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETPEERNAME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SENDTO: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RECVFROM: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETSOCKOPT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GETSOCKOPT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SHUTDOWN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SENDMSG: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RECVMSG: UNIMPLEMENTED_SYSCALL; break;
    case ECV_READAHEAD: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_BRK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MUNMAP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MREMAP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_ADD_KEY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_REQUEST_KEY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_KEYCTL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLONE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EXECVE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_MMAP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FADVISE64: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SWAPON: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SWAPOFF: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_MPROTECT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MSYNC: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MLOCK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MUNLOCK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MLOCKALL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MUNLOCKALL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MINCORE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MADVISE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_REMAP_FILE_PAGES: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MBIND: UNIMPLEMENTED_SYSCALL; break;
    case ECV_GET_MEMPOLICY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SET_MEMPOLICY: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MIGRATE_PAGES: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MOVE_PAGES: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RT_TGSIGQUEUEINFO: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PERF_EVENT_OPEN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_ACCEPT4: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RECVMMSG: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_WAIT4: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_PRLIMIT64: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FANOTIFY_INIT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FANOTIFY_MARK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_NAME_TO_HANDLE_AT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_OPEN_BY_HANDLE_AT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLOCK_ADJTIME: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SYNCFS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SETNS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SENDMMSG: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PROCESS_VM_READV: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PROCESS_VM_WRITEV: UNIMPLEMENTED_SYSCALL; break;
    case ECV_KCMP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FINIT_MODULE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_SETATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SCHED_GETATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RENAMEAT2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_SECCOMP: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_GETRANDOM: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MEMFD_CREATE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_BPF: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EXECVEAT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_USERFAULTFD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MEMBARRIER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MLOCK2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_COPY_FILE_RANGE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PREADV2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PWRITEV2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PKEY_MPROTECT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PKEY_ALLOC: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PKEY_FREE: UNIMPLEMENTED_SYSCALL; break;
    // case ECV_STATX: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_PGETEVENTS: UNIMPLEMENTED_SYSCALL; break;
    case ECV_RSEQ: UNIMPLEMENTED_SYSCALL; break;
    case ECV_KEXEC_FILE_LOAD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PIDFD_SEND_SIGNAL: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_URING_SETUP: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_URING_ENTER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_IO_URING_REGISTER: UNIMPLEMENTED_SYSCALL; break;
    case ECV_OPEN_TREE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MOVE_MOUNT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSOPEN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSCONFIG: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSMOUNT: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FSPICK: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PIDFD_OPEN: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLONE3: UNIMPLEMENTED_SYSCALL; break;
    case ECV_CLOSE_RANGE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_OPENAT2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PIDFD_GETFD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FACCESSAT2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PROCESS_MADVISE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_EPOLL_PWAIT2: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MOUNT_SETATTR: UNIMPLEMENTED_SYSCALL; break;
    case ECV_QUOTACTL_FD: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LANDLOCK_CREATE_RULESET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LANDLOCK_ADD_RULE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_LANDLOCK_RESTRICT_SELF: UNIMPLEMENTED_SYSCALL; break;
    case ECV_MEMFD_SECRET: UNIMPLEMENTED_SYSCALL; break;
    case ECV_PROCESS_MRELEASE: UNIMPLEMENTED_SYSCALL; break;
    case ECV_FUTEX_WAITV: UNIMPLEMENTED_SYSCALL; break;
    default: UNIMPLEMENTED_SYSCALL; break;
  }
}