#include "SysTable.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <remill/BC/HelperMacro.h>
#include <stdlib.h>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
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
typedef uint32_t _ecv_long;
#endif

extern _ecv_reg64_t TASK_STRUCT_VMA;

/*
  for ioctl syscall
*/
#define _ECV_TCGETS 0x5401
#define _ECV_NCCS 19
typedef uint32_t _ecv_tcflag_t;
typedef uint8_t _ecv_cc_t;
struct _ecv_termios {
  _ecv_tcflag_t c_iflag;
  _ecv_tcflag_t c_oflag;
  _ecv_tcflag_t c_cflag;
  _ecv_tcflag_t c_lflag;
  _ecv_cc_t c_line;
  _ecv_cc_t c_cc[_ECV_NCCS];
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

#define _ECV_AT_EMPTY_PATH 0x1000
#define _ECV_STATX_BASIC_STATS 0x000007ffU

// macros specified to Linux
#define LINUX_AD_FDCWD -100
#define LINUX_O_CREAT 64
#define LINUX_O_RDONLY 0
#define LINUX_O_WRONLY 1
#define LINUX_O_RDWR 2

#define ERROR_CODE -1

/*
  syscall emulate function
  
  Calling Conventions
  arch: arm64, syscall NR: x8, return: x0, arg0: x0, arg1: x1, arg2: x2, arg3: x3, arg4: x4, arg5: x5
  ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/

  arch: x86-64, sycall NR: rax, return: rax, arg0: rdi, arg1: rsi, arg2: rdx, arg3: r10, arg4: r8, arg5: r9
  ref: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
*/
void RuntimeManager::SVCWasiCall(void) {

  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] __svc_call started. syscall number: %u, PC: 0x%016llx\n", SYSNUMREG, PCREG);
#endif
  switch (SYSNUMREG) {
    case ECV_SYS_DUP: /* dup (unsinged int fildes)*/
      EMPTY_SYSCALL(ECV_SYS_DUP)
      X0_Q = -1;
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_IOCTL: /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
      EMPTY_SYSCALL(ECV_SYS_IOCTL)
      X0_Q = -1;
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_MKDIRAT: /* int mkdirat (int dfd, const char *pathname, umode_t mode) */
      if (LINUX_AD_FDCWD == X0_D) {
        X0_Q = AT_FDCWD;
      }
      X0_D = mkdirat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_SYS_UNLINKAT: /* unlinkat (int dfd, const char *pathname, int flag) */
      if (LINUX_AD_FDCWD == X0_D) {
        X0_Q = AT_FDCWD;
      }
      X0_D = unlinkat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_SYS_STATFS: /* int statfs(const char *path, struct statfs *buf) */
      EMPTY_SYSCALL(ECV_SYS_IOCTL)
      X0_Q = -1;
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_TRUNCATE: /* int truncate(const char *path, off_t length) */
      X0_D = truncate((char *) TranslateVMA(X0_Q), (_ecv_long) X1_Q);
      break;
    case ECV_SYS_FTRUNCATE: /* int ftruncate(int fd, off_t length) */
      X0_D = ftruncate(X0_Q, (_ecv_long) X1_Q);
      break;
    case ECV_SYS_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      /* TODO */
      X0_Q = -1;
      EMPTY_SYSCALL(ECV_SYS_FACCESSAT);
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
      if (LINUX_AD_FDCWD == X0_D) {
        X0_Q = AT_FDCWD;
      }
      if (LINUX_O_RDONLY == (X2_D & LINUX_O_RDONLY)) {
        X2_D &= ~LINUX_O_RDONLY;
        X2_D |= O_RDONLY;
      }
      if (LINUX_O_RDWR == (X2_D & LINUX_O_RDWR)) {
        X2_D &= ~LINUX_O_RDWR;
        X2_D |= O_RDWR;
      }
      if (LINUX_O_WRONLY == (X2_D & LINUX_O_WRONLY)) {
        X2_D &= ~LINUX_O_WRONLY;
        X2_D |= O_WRONLY;
      }
      if (LINUX_O_CREAT == (X2_D & LINUX_O_CREAT)) {
        X2_D &= ~LINUX_O_CREAT;
        X2_D |= O_CREAT;
      }
      X0_D = openat(X0_D, (char *) TranslateVMA(X1_Q), X2_D, X3_D);
      if (ERROR_CODE == X0_D) {
        perror("openat error!");
      }
      break;
    case ECV_SYS_CLOSE: /* int close (unsigned int fd) */ X0_D = close(X0_D); break;
    case ECV_SYS_LSEEK: /* int lseek(unsigned int fd, off_t offset, unsigned int whence) */
      X0_D = lseek(X0_D, (_ecv_long) X1_Q, X2_D);
      break;
    case ECV_SYS_READ: /* read (unsigned int fd, char *buf, size_t count) */
      X0_Q = read(X0_D, (char *) TranslateVMA(X1_Q), static_cast<size_t>(X2_Q));
      break;
    case ECV_SYS_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
      X0_Q = write(X0_D, TranslateVMA(X1_Q), static_cast<size_t>(X2_Q));
      break;
    case ECV_SYS_WRITEV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
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
    case ECV_SYS_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
      if (LINUX_AD_FDCWD == X0_D) {
        X0_Q = AT_FDCWD;
      }
      X0_Q = readlinkat(X0_D, (const char *) TranslateVMA(X1_Q), (char *) TranslateVMA(X2_Q), X3_D);
      break;
    case ECV_SYS_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
      /* TODO */
      X0_Q = -1;
      EMPTY_SYSCALL(ECV_SYS_NEWFSTATAT);
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_FSYNC: /* fsync (unsigned int fd) */ X0_D = fsync(X0_D); break;
    case ECV_SYS_EXIT: /* exit (int error_code) */ exit(X0_D); break;
    case ECV_SYS_EXITGROUP: /* exit_group (int error_code) note. there is no function of 'exit_group', so must use syscall. */
      exit(X0_D);
      break;
    case ECV_SYS_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = 42;
      *reinterpret_cast<int *>(TranslateVMA(X0_Q)) = tid;
      X0_Q = tid;
    } break;
    case ECV_SYS_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u23 val3) */
      /* TODO */
      if ((X1_D & 0x7F) == 0) {
        /* FUTEX_WAIT */
        X0_Q = 0;
      } else {
        elfconv_runtime_error("Unknown futex op 0x%08u\n", X1_D);
      }
      NOP_SYSCALL(ECV_SYS_FUTEX);
      break;
    case ECV_SYS_SET_ROBUST_LIST: /* set_robust_list (struct robust_list_head *head, size_t len) */
      X0_Q = 0;
      NOP_SYSCALL(ECV_SYS_SET_ROBUST_LIST);
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
    {
      struct _ecv__clockid {
        uint32_t id;
      } which_clock = {.id = X0_D};
      struct timespec emu_tp;
      int clock_time = clock_gettime((clockid_t) &which_clock, &emu_tp);
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
    case ECV_SYS_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */
      EMPTY_SYSCALL(ECV_SYS_TGKILL);
      X0_Q = -1;
      errno = _ECV_EACCESS;
      break;
    case ECV_SYS_RT_SIGPROCMASK: /* rt_sigprocmask (int how, sigset_t *set, sigset_t *oset, size_t sigsetsize) */
      /* TODO */
      X0_Q = 0;
      EMPTY_SYSCALL(ECV_SYS_RT_SIGPROCMASK);
      break;
    case ECV_SYS_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
      X0_Q = -1;
      errno = _ECV_EACCESS;
      EMPTY_SYSCALL(ECV_SYS_RT_SIGACTION)
      break;
    case ECV_SYS_UNAME: /* uname (struct old_utsname* buf) */
    {
      struct __ecv_utsname {
        char sysname[65];
        char nodename[65];
        char release[65];
        char version[65];
        char machine[65];
      } new_utsname = {"Linux", "xxxxxxx-QEMU-Virtual-Machine",
                       "6.0.0-00-generic", /* cause error if the kernel version is too old. */
                       "#0~elfconv", "aarch64"};
      memcpy(TranslateVMA(X0_Q), &new_utsname, sizeof(new_utsname));
      X0_D = 0;
    } break;
    case ECV_SYS_GETTIMEOFDAY: /* gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) */
      X0_D = gettimeofday((struct timeval *) TranslateVMA(X0_Q),
                          (struct timezone *) 0); /* FIXME (second argument) */
      break;
    case ECV_SYS_GETRUSAGE: /* getrusage (int who, struct rusage *ru) */
      X0_D = getrusage(X0_D, (struct rusage *) TranslateVMA(X1_Q));
    case ECV_SYS_PRCTL: /* prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */
    {
      uint32_t option = X0_D;
      if (ECV_PR_GET_NAME == option) {
        memcpy(TranslateVMA(X1_Q), TranslateVMA(TASK_STRUCT_VMA), /* TASK_COMM_LEN */ 16);
      } else {
        elfconv_runtime_error("prctl unimplemented option!: %d\n", option);
      }
    }
    case ECV_SYS_GETPID: /* getpid () */ X0_D = 42; break;
    case ECV_SYS_GETPPID: /* getppid () */ X0_D = 42; break;
    case ECV_SYS_GETUID: /* getuid () */ X0_D = 42; break;
    case ECV_SYS_GETEUID: /* geteuid () */ X0_D = 42; break;
    case ECV_SYS_GETGID: /* getgid () */ X0_D = 42; break;
    case ECV_SYS_GETEGID: /* getegid () */ X0_D = 42; break;
    case ECV_SYS_GETTID: /* getttid () */ X0_D = 42; break;
    case ECV_SYS_BRK: /* brk (unsigned long brk) */
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
    case ECV_SYS_MUNMAP: /* munmap (unsigned long addr, size_t len) */
      /* TODO */
      X0_Q = 0;
      EMPTY_SYSCALL(ECV_SYS_MUNMAP);
      break;
    case ECV_SYS_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
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
      NOP_SYSCALL(ECV_SYS_MMAP);
      break;
    case ECV_SYS_MPROTECT: /* mprotect (unsigned long start, size_t len, unsigned long prot) */
      X0_Q = 0;
      NOP_SYSCALL(ECV_SYS_MPROTECT);
      break;
    case ECV_SYS_PRLIMIT64: /* prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *oldrlim) */
      X0_Q = 0;
      NOP_SYSCALL(ECV_SYS_PRLIMIT64);
      break;
    case ECV_SYS_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      memset(TranslateVMA(X0_Q), 1, static_cast<size_t>(X1_Q));
      X0_Q = X1_Q;
    } break;
    case ECV_SYS_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
    {
      int dfd = X0_D;
      _ecv_reg_t flags = X2_D;
      if ((flags & _ECV_AT_EMPTY_PATH) == 0)
        elfconv_runtime_error("[ERROR] Unsupported statx(flags=0x%08u)\n", flags);
      struct stat _stat;
      // execute fstat
      errno = _ECV_EACCESS;
      EMPTY_SYSCALL(ECV_SYS_STATX);
      if (errno == 0) {
        struct _ecv_statx _statx;
        memset(&_statx, 0, sizeof(_statx));
        _statx.stx_mask = _statx.stx_mask = _ECV_STATX_BASIC_STATS;
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
        X0_Q = -1;
      }
    } break;
    case ECV_SYS_RSEQ:
      /* TODO */
      X0_Q = 0;
      NOP_SYSCALL(ECV_SYS_RSEQ);
      break;
    default: NOSYS_CODE(SYSNUMREG); break;
  }
}