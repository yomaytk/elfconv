#include "SysTable.h"

#include <algorithm>
#include <asm-generic/ioctls.h>
#include <bits/types/struct_timespec.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <remill/BC/HelperMacro.h>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
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

typedef uint64_t _ecv_long;

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
void RuntimeManager::SVCNativeCall(void) {

  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] __svc_call started. syscall number: %u, PC: 0x%016llx\n", SYSNUMREG, PCREG);
#endif
  switch (SYSNUMREG) {
    case ECV_SYS_GETCWD: /* getcwd (char *buf, unsigned long size) */
      getcwd((char *) TranslateVMA(X0_Q), X1_Q);
      break;
    case ECV_SYS_DUP: /* int dup(int oldfd) */ X0_D = dup(X0_D); break;
    case ECV_SYS_DUP3: /*  int dup3(int oldfd, int newfd, int flags) */
      X0_D = dup3(X0_D, X1_D, X2_D);
      break;
    case ECV_SYS_FCNTL: /* int fcntl(int fd, int cmd, ... arg ); */
      if (X1_D == ECV_F_DUPFD || X1_D == ECV_F_SETFD || X1_D == ECV_F_SETFL) {
        X0_D = fcntl(X0_D, X1_D, X2_D);
      } else if (X1_D == ECV_F_GETFD || X1_D == ECV_F_GETFL) {
        X0_D = fcntl(X0_D, X1_D);
      } else {
        X0_Q = -_LINUX_EINVAL;
      }
      break;
    case ECV_SYS_IOCTL: /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
    {
      unsigned int fd = X0_D;
      unsigned int cmd = X1_D;
      unsigned long arg = X2_Q;
      switch (cmd) {
        case TCGETS:
        case TCSETS:
        case TIOCGWINSZ: {
          X0_D = ioctl(fd, cmd, TranslateVMA(arg));
        } break;
        default: X0_Q = -_LINUX_ENOTTY; break;
      }
    } break;
    case ECV_SYS_MKDIRAT: /* int mkdirat (int dfd, const char *pathname, umode_t mode) */
      X0_D = mkdirat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_SYS_UNLINKAT: /* unlinkat (int dfd, const char *pathname, int flag) */
      X0_D = unlinkat(X0_D, (char *) TranslateVMA(X1_Q), X2_D);
      break;
    case ECV_SYS_STATFS: /* int statfs(const char *path, struct statfs *buf) */
      X0_D = statfs((char *) TranslateVMA(X0_Q), (struct statfs *) TranslateVMA(X1_Q));
      break;
    case ECV_SYS_TRUNCATE: /* int truncate(const char *path, off_t length) */
      X0_D = truncate((char *) TranslateVMA(X0_Q), (_ecv_long) X1_Q);
      break;
    case ECV_SYS_FTRUNCATE: /* int ftruncate(int fd, off_t length) */
      X0_D = ftruncate(X0_Q, (_ecv_long) X1_Q);
      break;
    case ECV_SYS_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      X0_D = faccessat(X0_D, (const char *) TranslateVMA(X1_Q), X2_D, X3_D);
      break;
    case ECV_SYS_CHDIR: /* int chdir (const char * path) */
      X0_D = chdir((const char *) TranslateVMA(X0_Q));
      break;
    case ECV_SYS_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
      X0_D = openat(X0_D, (char *) TranslateVMA(X1_Q), X2_D, X3_D);
      break;
    case ECV_SYS_CLOSE: /* int close (unsigned int fd) */ X0_D = close(X0_D); break;
    case ECV_SYS_GETDENTS64: /* long getdents64 (int fd, void *dirp, size_t count) */
      X0_Q = syscall(ECV_SYS_GETDENTS64, X0_D, TranslateVMA(X1_Q), X2_Q);
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
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
    case ECV_SYS_SENDFILE: /* sendfile (int out_fd, int in_fd, off_t *offset, size_t count) */
      X0_Q = sendfile(X0_D, X1_D, (off_t *) TranslateVMA(X2_Q), X3_Q);
    case ECV_SYS_PPOLL: /* ppoll (struct pollfd*, unsigned int, const struct timespec *, const unsigned long int) */
      X0_D = ppoll((struct pollfd *) TranslateVMA(X0_Q), (unsigned long int) X1_D,
                   (const struct timespec *) TranslateVMA(X2_Q),
                   (const sigset_t *) TranslateVMA(X3_Q));
      break;
    case ECV_SYS_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
      X0_Q = readlinkat(X0_D, (const char *) TranslateVMA(X1_Q), (char *) TranslateVMA(X2_Q), X3_D);
      break;
    case ECV_SYS_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
      X0_Q = syscall(ECV_SYS_NEWFSTATAT, X0_D, TranslateVMA(X1_Q), TranslateVMA(X2_Q), X3_D);
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
    case ECV_SYS_FSYNC: /* fsync (unsigned int fd) */ X0_D = fsync(X0_D); break;
    case ECV_SYS_UTIMENSAT: /* int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) */
      X0_D = utimensat(X0_D, (char *) TranslateVMA(X1_Q),
                       (const struct timespec *) TranslateVMA(X2_Q), X3_D);
      break;
    case ECV_SYS_EXIT: /* exit (int error_code) */ exit(X0_D); break;
    case ECV_SYS_EXITGROUP: /* exit_group (int error_code) note. there is no function of 'exit_group', so must use syscall. */
      syscall(ECV_SYS_EXITGROUP, X0_D);
      break;
    case ECV_SYS_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = gettid();
      *reinterpret_cast<int *>(TranslateVMA(X0_Q)) = tid;
      X0_Q = tid;
    } break;
    case ECV_SYS_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u32 val3) */
      X0_Q = syscall(ECV_SYS_FUTEX, TranslateVMA(X0_Q), X1_D, X2_D, TranslateVMA(X3_Q),
                     TranslateVMA(X4_Q), X5_D);
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
    case ECV_SYS_SET_ROBUST_LIST: /* set_robust_list (struct robust_list_head *head, size_t len) */
      X0_Q = 0;
      NOP_SYSCALL(ECV_SYS_SET_ROBUST_LIST);
      errno = _LINUX_EACCES;
      break;
    case ECV_SYS_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
    {
      clockid_t which_clock = X0_D;
      struct timespec emu_tp;
      int clock_time = clock_gettime(which_clock, &emu_tp);
      memcpy(TranslateVMA(X1_Q), &emu_tp, sizeof(timespec));
      X0_Q = (_ecv_reg64_t) clock_time;
    } break;
    case ECV_SYS_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */
      X0_Q = tgkill(X0_D, X1_D, X2_D);
      break;
    case ECV_SYS_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
      X0_D = sigaction(X0_D, (const struct sigaction *) TranslateVMA(X1_Q),
                       (struct sigaction *) TranslateVMA(X2_Q));
      break;
    case ECV_SYS_RT_SIGPROCMASK: /* rt_sigprocmask (int how, sigset_t *set, sigset_t *oset, size_t sigsetsize) */
      X0_Q = syscall(ECV_SYS_RT_SIGPROCMASK, TranslateVMA(X1_Q), TranslateVMA(X2_Q), X3_D);
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
    case ECV_SYS_SETREGID: /* int setregid(gid_t rgid, gid_t egid) gid_t: unsigned int at /usr/aarch64-linux-gnu/include/sys/types.h */
      X0_D = setregid(X0_D, X1_D);
      break;
    case ECV_SYS_SETGID: /* int setgid (gid_t gid) */ X0_D = setgid(X0_D); break;
    case ECV_SYS_SETREUID: /* int setreuid(uid_t ruid, uid_t euid) uid_t: unsigned int at /usr/aarch64-linux-gnu/include/sys/types.h */
      X0_D = setreuid(X0_D, X1_D);
      break;
    case ECV_SYS_SETUID: /* int setuid(uid_t uid) */ X0_D = setuid(X0_D); break;
    case ECV_SYS_SETRESUID: /* int setresuid(uid_t ruid , uid_t euid , uid_t suid ) */
      X0_D = setresuid(X0_D, X1_D, X2_D);
      break;
    case ECV_SYS_UNAME: /* uname (struct old_utsname* buf) */
    {
      struct utsname _utsname;
      int ret = uname(&_utsname);
      memcpy(TranslateVMA(X0_Q), &_utsname, sizeof(utsname));
      X0_D = ret;
    } break;
    case ECV_SYS_GETTIMEOFDAY: /* gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) */
      X0_D = gettimeofday((struct timeval *) TranslateVMA(X0_Q),
                          (struct timezone *) 0); /* FIXME (second argument) */
      break;
    case ECV_SYS_GETRUSAGE: /* getrusage (int who, struct rusage *ru) */
      X0_D = getrusage(X0_D, (struct rusage *) TranslateVMA(X1_Q));
    case ECV_SYS_PRCTL: /* prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) */
    {
      auto option = X0_D;
      if (ECV_PR_GET_NAME == option) {
        X0_D = prctl(option, TranslateVMA(X1_Q));
      } else {
        elfconv_runtime_error("prctl unknown option!: %d\n", option);
      }
    } break;
    case ECV_SYS_GETPID: /* getpid () */ X0_D = getpid(); break;
    case ECV_SYS_GETPPID: /* getppid () */ X0_D = getppid(); break;
    case ECV_SYS_GETUID: /* getuid () */ X0_D = getuid(); break;
    case ECV_SYS_GETEUID: /* geteuid () */ X0_D = geteuid(); break;
    case ECV_SYS_GETGID: /* getgid () */ X0_D = getgid(); break;
    case ECV_SYS_GETEGID: /* getegid () */ X0_D = getegid(); break;
    case ECV_SYS_GETTID: /* gettid () */ X0_D = gettid(); break;
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
      X0_Q = syscall(ECV_SYS_MPROTECT, X0_D, X1_Q, X2_Q);
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
    case ECV_SYS_WAIT4: /* pid_t wait4 (pid_t pid, int *stat_addr, int options, struct rusage *ru) */
      X0_D = wait4(X0_D, (int *) TranslateVMA(X1_Q), X2_D, (struct rusage *) TranslateVMA(X3_Q));
    case ECV_SYS_PRLIMIT64: /* prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *oldrlim) */
      X0_Q = syscall(ECV_SYS_PRLIMIT64, X0_D, X1_D, TranslateVMA(X2_Q), TranslateVMA(X3_Q));
      if (X0_Q < 0) {
        errno = -X0_Q;
      }
      break;
    case ECV_SYS_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      auto res = getentropy(TranslateVMA(X0_Q), static_cast<size_t>(X1_Q));
      X0_Q = 0 == res ? X1_Q : -1;
    } break;
    case ECV_SYS_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
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
        X0_Q = -1;
      }
    } break;
    case ECV_SYS_RSEQ:
      X0_Q = -1;
      errno = -_LINUX_EACCES;
      NOP_SYSCALL(ECV_SYS_RSEQ);
      break;
    default: X0_Q = -_LINUX_ENOSYS; break;
  }
}