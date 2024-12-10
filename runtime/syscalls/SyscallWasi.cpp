#include "SysTable.h"
#include "runtime/Runtime.h"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <remill/Arch/AArch64/Runtime/State.h>
#include <remill/BC/HelperMacro.h>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utils/Util.h>
#include <utils/elfconv.h>

#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
#  define EMPTY_SYSCALL(sysnum) printf("[WARNING] syscall \"" #sysnum "\" is empty now.\n");
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
#define LINUX_O_WRONLY 1
#define LINUX_O_RDWR 2

#define ERROR_CODE -1

/*
  syscall emulate function
  
  Calling Conventions
  arch: arm64, syscall NR: x8, return: x0, arg0: x0, arg1: x1, arg2: x2, arg3: x3, arg4: x4, arg5: x5
  ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/
*/
void RuntimeManager::SVCWasiCall(void) {

  auto &state_gpr = g_state.gpr;
  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] __svc_call started. syscall number: %u, PC: 0x%016llx\n", g_state.gpr.x8.dword,
         g_state.gpr.pc.qword);
#endif
  switch (state_gpr.x8.qword) {
    case AARCH64_SYS_DUP: /* dup (unsinged int fildes)*/
      EMPTY_SYSCALL(AARCH64_SYS_DUP)
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_IOCTL: /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
      EMPTY_SYSCALL(AARCH64_SYS_IOCTL)
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_MKDIRAT: /* int mkdirat (int dfd, const char *pathname, umode_t mode) */
      if (LINUX_AD_FDCWD == state_gpr.x0.dword) {
        state_gpr.x0.qword = AT_FDCWD;
      }
      state_gpr.x0.dword = mkdirat(state_gpr.x0.dword, (char *) TranslateVMA(state_gpr.x1.qword),
                                   state_gpr.x2.dword);
      break;
    case AARCH64_SYS_UNLINKAT: /* unlinkat (int dfd, const char *pathname, int flag) */
      if (LINUX_AD_FDCWD == state_gpr.x0.dword) {
        state_gpr.x0.qword = AT_FDCWD;
      }
      state_gpr.x0.dword = unlinkat(state_gpr.x0.dword, (char *) TranslateVMA(state_gpr.x1.qword),
                                    state_gpr.x2.dword);
      break;
    case AARCH64_SYS_STATFS: /* int statfs(const char *path, struct statfs *buf) */
      EMPTY_SYSCALL(AARCH64_SYS_IOCTL)
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_TRUNCATE: /* int truncate(const char *path, off_t length) */
      state_gpr.x0.dword = truncate((char *) TranslateVMA(state_gpr.x0.qword), (_ecv_long) state_gpr.x1.qword);
      break;
    case AARCH64_SYS_FTRUNCATE: /* int ftruncate(int fd, off_t length) */
      state_gpr.x0.dword = ftruncate(state_gpr.x0.qword, (_ecv_long) state_gpr.x1.qword);
      break;
    case AARCH64_SYS_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      /* TODO */
      state_gpr.x0.qword = -1;
      EMPTY_SYSCALL(AARCH64_SYS_FACCESSAT);
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
      if (LINUX_AD_FDCWD == state_gpr.x0.dword) {
        state_gpr.x0.qword = AT_FDCWD;
      }
      if (LINUX_O_CREAT == (state_gpr.x2.dword & LINUX_O_CREAT)) {
        state_gpr.x2.dword &= ~LINUX_O_CREAT;
        state_gpr.x2.dword |= O_CREAT;
      }
      if (LINUX_O_RDWR == (state_gpr.x2.dword & LINUX_O_RDWR)) {
        state_gpr.x2.dword &= ~LINUX_O_RDWR;
        state_gpr.x2.dword |= O_RDWR;
      }
      if (LINUX_O_WRONLY == (state_gpr.x2.dword & LINUX_O_WRONLY)) {
        state_gpr.x2.dword &= ~LINUX_O_WRONLY;
        state_gpr.x2.dword |= O_WRONLY;
      }
      state_gpr.x0.dword = openat(state_gpr.x0.dword, (char *) TranslateVMA(state_gpr.x1.qword),
                                  state_gpr.x2.dword, state_gpr.x3.dword);
      if (ERROR_CODE == state_gpr.x0.dword) {
        perror("openat error!");
      }
      break;
    case AARCH64_SYS_CLOSE: /* int close (unsigned int fd) */
      state_gpr.x0.dword = close(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_LSEEK: /* int lseek(unsigned int fd, off_t offset, unsigned int whence) */
      state_gpr.x0.dword =
          lseek(state_gpr.x0.dword, (_ecv_long) state_gpr.x1.qword, state_gpr.x2.dword);
      break;
    case AARCH64_SYS_READ: /* read (unsigned int fd, char *buf, size_t count) */
      state_gpr.x0.qword = read(state_gpr.x0.dword, (char *) TranslateVMA(state_gpr.x1.qword),
                                static_cast<size_t>(state_gpr.x2.qword));
      break;
    case AARCH64_SYS_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
      state_gpr.x0.qword = write(state_gpr.x0.dword, TranslateVMA(state_gpr.x1.qword),
                                 static_cast<size_t>(state_gpr.x2.qword));
      break;
    case AARCH64_SYS_WRITEV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
    {
      unsigned long fd = state_gpr.x0.qword;
      unsigned long vlen = state_gpr.x2.qword;
      auto tr_vec = reinterpret_cast<iovec *>(TranslateVMA(state_gpr.x1.qword));
      auto cache_vec = reinterpret_cast<iovec *>(malloc(sizeof(iovec) * vlen));
      // translate every iov_base
      for (unsigned long i = 0; i < vlen; i++) {
        cache_vec[i].iov_base = TranslateVMA(reinterpret_cast<addr_t>(tr_vec[i].iov_base));
        cache_vec[i].iov_len = tr_vec[i].iov_len;
      }
      state_gpr.x0.qword = writev(fd, cache_vec, vlen);
      free(cache_vec);
    } break;
    case AARCH64_SYS_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
      if (LINUX_AD_FDCWD == state_gpr.x0.dword) {
        state_gpr.x0.qword = AT_FDCWD;
      }
      state_gpr.x0.qword =
          readlinkat(state_gpr.x0.dword, (const char *) TranslateVMA(state_gpr.x1.qword),
                     (char *) TranslateVMA(state_gpr.x2.qword), state_gpr.x3.dword);
      break;
    case AARCH64_SYS_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
      /* TODO */
      state_gpr.x0.qword = -1;
      EMPTY_SYSCALL(AARCH64_SYS_NEWFSTATAT);
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_FSYNC: /* fsync (unsigned int fd) */
      state_gpr.x0.dword = fsync(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_EXIT: /* exit (int error_code) */ exit(state_gpr.x0.dword); break;
    case AARCH64_SYS_EXITGROUP: /* exit_group (int error_code) note. there is no function of 'exit_group', so must use syscall. */
      exit(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = 42;
      *reinterpret_cast<int *>(TranslateVMA(state_gpr.x0.qword)) = tid;
      state_gpr.x0.qword = tid;
    } break;
    case AARCH64_SYS_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u23 val3) */
      /* TODO */
      if ((state_gpr.x1.dword & 0x7F) == 0) {
        /* FUTEX_WAIT */
        state_gpr.x0.qword = 0;
      } else {
        elfconv_runtime_error("Unknown futex op 0x%08u\n", state_gpr.x1.dword);
      }
      NOP_SYSCALL(AARCH64_SYS_FUTEX);
      break;
    case AARCH64_SYS_SET_ROBUST_LIST: /* set_robust_list (struct robust_list_head *head, size_t len) */
      state_gpr.x0.qword = 0;
      NOP_SYSCALL(AARCH64_SYS_SET_ROBUST_LIST);
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
    {
      struct _ecv__clockid {
        uint32_t id;
      } which_clock = {.id = state_gpr.x0.dword};
      struct timespec emu_tp;
      int clock_time = clock_gettime((clockid_t) &which_clock, &emu_tp);
      struct {
        uint64_t tv_sec; /* time_t */
        uint64_t tv_nsec; /* long (assume that the from target architecture is 64bit) */
      } tp = {
          .tv_sec = (uint64_t) emu_tp.tv_sec,
          .tv_nsec = (uint64_t) (_ecv_long) emu_tp.tv_nsec,
      };
      memcpy(TranslateVMA(state_gpr.x1.qword), &tp, sizeof(tp));
      state_gpr.x0.qword = (_ecv_reg64_t) clock_time;
    } break;
    case AARCH64_SYS_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */
      EMPTY_SYSCALL(AARCH64_SYS_TGKILL);
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_RT_SIGPROCMASK: /* rt_sigprocmask (int how, sigset_t *set, sigset_t *oset, size_t sigsetsize) */
      /* TODO */
      state_gpr.x0.qword = 0;
      EMPTY_SYSCALL(AARCH64_SYS_RT_SIGPROCMASK);
      break;
    case AARCH64_SYS_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      EMPTY_SYSCALL(AARCH64_SYS_RT_SIGACTION)
      break;
    case AARCH64_SYS_UNAME: /* uname (struct old_utsname* buf) */
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
      memcpy(TranslateVMA(state_gpr.x0.qword), &new_utsname, sizeof(new_utsname));
      state_gpr.x0.dword = 0;
    } break;
    case AARCH64_SYS_GETTIMEOFDAY: /* gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) */
      state_gpr.x0.dword = gettimeofday((struct timeval *) TranslateVMA(state_gpr.x0.qword),
                                        (struct timezone *) 0); /* FIXME (second argument) */
      break;
    case AARCH64_SYS_GETPID: /* getpid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETPPID: /* getppid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETTUID: /* getuid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETEUID: /* geteuid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETGID: /* getgid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETEGID: /* getegid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETTID: /* getttid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_BRK: /* brk (unsigned long brk) */
    {
      auto __heap_memory = heap_memory;
      if (state_gpr.x0.qword == 0) {
        /* init program break (FIXME) */
        state_gpr.x0.qword = __heap_memory->heap_cur;
      } else if (__heap_memory->vma <= state_gpr.x0.qword &&
                 state_gpr.x0.qword < __heap_memory->vma + __heap_memory->len) {
        /* change program break */
        __heap_memory->heap_cur = state_gpr.x0.qword;
      } else {
        elfconv_runtime_error("Unsupported brk(0x%016llx).\n", state_gpr.x0.qword);
      }
    } break;
    case AARCH64_SYS_MUNMAP: /* munmap (unsigned long addr, size_t len) */
      /* TODO */
      state_gpr.x0.qword = 0;
      EMPTY_SYSCALL(AARCH64_SYS_MUNMAP);
      break;
    case AARCH64_SYS_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
      /* FIXME */
      {
        auto __heap_memory = heap_memory;
        if (state_gpr.x4.dword != -1)
          elfconv_runtime_error("Unsupported mmap (X4=0x%08x)\n", state_gpr.x4.dword);
        if (state_gpr.x5.dword != 0)
          elfconv_runtime_error("Unsupported mmap (X5=0x%016llx)\n", state_gpr.x5.qword);
        if (state_gpr.x0.qword == 0) {
          state_gpr.x0.qword = __heap_memory->heap_cur;
          __heap_memory->heap_cur += state_gpr.x1.qword;
        } else {
          elfconv_runtime_error("Unsupported mmap (X0=0x%016llx)\n", state_gpr.x0.qword);
        }
      }
      NOP_SYSCALL(AARCH64_SYS_MMAP);
      break;
    case AARCH64_SYS_MPROTECT: /* mprotect (unsigned long start, size_t len, unsigned long prot) */
      state_gpr.x0.qword = 0;
      NOP_SYSCALL(AARCH64_SYS_MPROTECT);
      break;
    case AARCH64_SYS_PRLIMIT64: /* prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *oldrlim) */
      state_gpr.x0.qword = 0;
      NOP_SYSCALL(AARCH64_SYS_PRLIMIT64);
      break;
    case AARCH64_SYS_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      memset(TranslateVMA(state_gpr.x0.qword), 1, static_cast<size_t>(state_gpr.x1.qword));
      state_gpr.x0.qword = state_gpr.x1.qword;
    } break;
    case AARCH64_SYS_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
    {
      int dfd = state_gpr.x0.dword;
      _ecv_reg_t flags = state_gpr.x2.dword;
      if ((flags & _ECV_AT_EMPTY_PATH) == 0)
        elfconv_runtime_error("[ERROR] Unsupported statx(flags=0x%08u)\n", flags);
      struct stat _stat;
      // execute fstat
      errno = _ECV_EACCESS;
      EMPTY_SYSCALL(AARCH64_SYS_STATX);
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
        memcpy(TranslateVMA(state_gpr.x4.qword), &_statx, sizeof(_statx));
        state_gpr.x0.qword = 0;
      } else {
        state_gpr.x0.qword = -1;
      }
    } break;
    case AARCH64_SYS_RSEQ:
      /* TODO */
      state_gpr.x0.qword = 0;
      NOP_SYSCALL(AARCH64_SYS_RSEQ);
      break;
    default:
      elfconv_runtime_error("Unknown syscall number: %llu, PC: 0x%llx\n", state_gpr.x8.qword,
                            state_gpr.pc.qword);
      break;
  }
}