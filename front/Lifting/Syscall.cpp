#include "remill/Arch/AArch64/Runtime/State.h"
#include <string>
#include <cstring>
#include <termios.h>
#include <algorithm>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include "memory.h"

/*
    syscall number table
*/
#define AARCH64_SYS_IOCTL 29
#define AARCH64_SYS_FACCESSAT 48
#define AARCH64_SYS_READ 63
#define AARCH64_SYS_WRITE 64
#define AARCH64_SYS_WRITEV 66
#define AARCH64_SYS_READLINKAT 78
#define AARCH64_SYS_NEWFSTATAT 79
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
#define AARCH64_SYS_PRLIMIT64 261
#define AARCH64_SYS_GETRANDOM 278
#define AARCH64_SYS_STATX 291
#define AARCH64_SYS_RSEQ 293

#define _ECV_EACESS 13
#define _ECV_ENOSYS 38

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

/*
  syscall emulate function
  
  Calling Conventions
  arch: arm64, syscall NR: x8, return: x0, arg0: x0, arg1: x1, arg2: x2, arg3: x3, arg4: x4, arg5: x5
  ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/
*/
void __svc_call(void) {

  auto &state_gpr = g_state.gpr;
  errno = 0;
  // printf("__svc_call started. syscall number: %u, PC: 0x%016llx\n", g_state.gpr.x8.dword, g_state.gpr.pc.qword);
  switch (state_gpr.x8.qword)
  {
    case AARCH64_SYS_IOCTL:  /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
      {
        unsigned int fd = state_gpr.x0.dword;
        unsigned int cmd = state_gpr.x1.dword;
        unsigned long arg = state_gpr.x2.qword;
        switch (cmd)
        {
        case _ECV_TCGETS:
          {
            struct termios t_host;
            int rc = tcgetattr(fd, &t_host);
            if (rc == 0) {
              struct _ecv_termios t;
              memset(&t, 0, sizeof(_ecv_termios));
              t.c_iflag = t_host.c_iflag;
              t.c_oflag = t_host.c_oflag;
              t.c_cflag = t_host.c_cflag;
              t.c_lflag = t_host.c_lflag;
              memcpy(t.c_cc, t_host.c_cc, std::min(NCCS, _ECV_NCCS));
              memcpy(_ecv_translate_ptr(arg), &t, sizeof(_ecv_termios));
              state_gpr.x0.qword = 0;
            } else {
              state_gpr.x0.qword = -1;
            }
            break;
          }
        default:
          break;
        }
      }
    case AARCH64_SYS_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      /* TODO */
      state_gpr.x0.qword = -1;
      errno = _ECV_EACESS;
      break;
    case AARCH64_SYS_READ: /* read (unsigned int fd, char *buf, size_t count) */
      state_gpr.x0.qword = read(state_gpr.x0.dword, _ecv_translate_ptr(state_gpr.x1.qword), static_cast<size_t>(state_gpr.x2.qword));
      break;
    case AARCH64_SYS_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
      state_gpr.x0.qword = write(state_gpr.x0.dword, _ecv_translate_ptr(state_gpr.x1.qword), static_cast<size_t>(state_gpr.x2.qword));
      break;
    case AARCH64_SYS_WRITEV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
      {
        unsigned long fd = state_gpr.x0.qword;
        unsigned long vlen = state_gpr.x2.qword;
        auto tr_vec = reinterpret_cast<iovec*>(_ecv_translate_ptr(state_gpr.x1.qword));
        auto cache_vec = reinterpret_cast<iovec*>(malloc(sizeof(iovec) * vlen));
        // translate every iov_base
        for (unsigned long i = 0;i < vlen;i++) {
          cache_vec[i].iov_base = _ecv_translate_ptr(reinterpret_cast<addr_t>(tr_vec[i].iov_base));
          cache_vec[i].iov_len = tr_vec[i].iov_len;
        }
        state_gpr.x0.qword = writev(fd, cache_vec, vlen);
        free(cache_vec);
      }
      break;
    case AARCH64_SYS_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
      /* TODO */
      state_gpr.x0.qword = -1;
      errno = _ECV_EACESS;
      break;
    case AARCH64_SYS_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
      /* TODO */
      state_gpr.x0.qword = -1;
      errno = _ECV_EACESS;
      break;
    case AARCH64_SYS_EXIT: /* exit (int error_code) */
      exit(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_EXITGROUP: /* exit_group (int error_code) note. there is no function of 'exit_group', so must use syscall. */
#if defined(__linux__)
      syscall(AARCH64_SYS_EXITGROUP, state_gpr.x0.dword);
#else
      exit(state_gpr.x0.dword);
#endif
      break;
    case AARCH64_SYS_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
      {
        pid_t tid = gettid();
        *reinterpret_cast<int*>(_ecv_translate_ptr(state_gpr.x0.qword)) = tid;
        state_gpr.x0.qword = tid;
      }  
      break;
    case AARCH64_SYS_FUTEX: /* futex (u32 *uaddr, int op, u32 val, const struct __kernel_timespec *utime, u32 *uaddr2, u23 val3) */
      /* TODO */
      if ((state_gpr.x1.dword & 0x7F) == 0) {
        /* FUTEX_WAIT */
        state_gpr.x0.qword = 0;
      } else {
        printf("Unknown futex op 0x%08u\n", state_gpr.x1.dword);
        abort();
      }
      break;
    case AARCH64_SYS_SET_ROBUST_LIST: /* set_robust_list (struct robust_list_head *head, size_t len) */
      state_gpr.x0.qword = 0;
      errno = _ECV_ENOSYS;
      break;
    case AARCH64_SYS_CLOCK_GETTIME: /* clock_gettime (clockid_t which_clock, struct __kernel_timespace *tp) */
      {
        clockid_t which_clock = state_gpr.x0.dword;
        struct timespec emu_tp;
        int clock_time = clock_gettime(which_clock, &emu_tp);
        memcpy(_ecv_translate_ptr(state_gpr.x1.qword), &emu_tp, sizeof(timespec));
        state_gpr.x0.qword = clock_time;
      }
      break;
    case AARCH64_SYS_TGKILL: /* tgkill (pid_t tgid, pid_t pid, int sig) */
#if defined(__linux__)
      state_gpr.x0.qword = tgkill(state_gpr.x0.dword, state_gpr.x1.dword, state_gpr.x2.dword);
#elif defined(__EMSCRIPTEN__)
      state_gpr.x0.qword = kill(state_gpr.x0.dword, state_gpr.x1.dword);
#else
      printf("Unknown Environment\n");
      abort();
#endif
      break;
    case AARCH64_SYS_RT_SIGPROCMASK: /* rt_sigprocmask (int how, sigset_t *set, sigset_t *oset, size_t sigsetsize) */
      /* TODO */
      state_gpr.x0.qword = 0;
      break;
    case AARCH64_SYS_RT_SIGACTION: /* rt_sigaction (int signum, const struct sigaction *act, struct sigaction *oldact) */
      state_gpr.x0.dword = sigaction(state_gpr.x0.dword, 
                                      (const struct sigaction*)_ecv_translate_ptr(state_gpr.x1.qword),
                                      (struct sigaction*)_ecv_translate_ptr(state_gpr.x2.qword));
      break;
    case AARCH64_SYS_UNAME: /* uname (struct old_utsname* buf) */
      {
        struct utsname _utsname;
        int ret = uname(&_utsname);
        memcpy(_ecv_translate_ptr(state_gpr.x0.qword), &_utsname, sizeof(utsname));
        state_gpr.x0.dword = ret;
      }
      break;
    case AARCH64_SYS_GETPID: /* getpid () */
      state_gpr.x0.dword = getpid();
      break;
    case AARCH64_SYS_GETPPID: /* getppid () */
      state_gpr.x0.dword = getppid();
      break;
    case AARCH64_SYS_GETTUID: /* getuid () */
      state_gpr.x0.dword = getuid();
      break;
    case AARCH64_SYS_GETEUID: /* geteuid () */
      state_gpr.x0.dword = geteuid();
      break;
    case AARCH64_SYS_GETGID: /* getgid () */
      state_gpr.x0.dword = getgid();
      break;
    case AARCH64_SYS_GETEGID: /* getegid () */
      state_gpr.x0.dword = getegid();
      break;
    case AARCH64_SYS_GETTID: /* getttid () */
#if defined(__linux__)
      state_gpr.x0.dword = gettid();
#else
      state_gpr.x0.qword = 0;
#endif
      break;
    case AARCH64_SYS_BRK: /* brk (unsigned long brk) */
    {
      auto heap_memory = g_run_mgr->emulated_memorys[1];
      if (state_gpr.x0.qword == 0) {
        /* init program break (FIXME) */
        state_gpr.x0.qword = heap_memory->heap_cur;
      } else if (heap_memory->vma <= state_gpr.x0.qword && state_gpr.x0.qword < heap_memory->vma + heap_memory->len) {
        /* change program break */
        heap_memory->heap_cur = state_gpr.x0.qword;
      } else {
        printf("Unsupported brk(0x%016llx).\n", state_gpr.x0.qword);
        abort();
      }
    }
      break;
    case AARCH64_SYS_MUNMAP: /* munmap (unsigned long addr, size_t len) */
      /* TODO */
      state_gpr.x0.qword = 0;
      break;
    case AARCH64_SYS_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
      /* TODO */
    {
      auto heap_memory = g_run_mgr->emulated_memorys[1];
      if (state_gpr.x4.dword != -1) {
        printf("Unsupported mmap (X4=0x%08ld)\n", state_gpr.x4.dword);
        abort();
      }
      if (state_gpr.x5.dword != 0) {
        printf("Unsupported mmap (X5=0x%016lld)\n", state_gpr.x5.qword);
        abort();
      }
      if (state_gpr.x0.qword == 0) {
        state_gpr.x0.qword = heap_memory->heap_cur;
        heap_memory->heap_cur += state_gpr.x1.qword;
      } else {
        printf("Unsupported mmap (X0=0x%016llx)\n", state_gpr.x0.qword);
        abort();
      }
    }
      break;
    case AARCH64_SYS_MPROTECT: /* mprotect (unsigned long start, size_t len, unsigned long prot) */
      state_gpr.x0.qword = 0;
      break;
    case AARCH64_SYS_PRLIMIT64: /* prlimit64 (pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *oldrlim) */
      state_gpr.x0.qword = 0;
      break;
    case AARCH64_SYS_GETRANDOM: /* getrandom (char *buf, size_t count, unsigned int flags) */
    {
      auto res = getentropy(_ecv_translate_ptr(state_gpr.x0.qword), static_cast<size_t>(state_gpr.x1.qword));
      if (res == 0) {
        state_gpr.x0.qword = state_gpr.x1.qword;
      } else {
        state_gpr.x0.qword = -1;
        errno = _ECV_ENOSYS;
      }
    }
      break;
    case AARCH64_SYS_STATX: /* statx (int dfd, const char *path, unsigned flags, unsigned mask, struct statx *buffer) */
      {
        int dfd = state_gpr.x0.dword;
        _ecv_reg_t flags = state_gpr.x2.dword;
        if ((flags & _ECV_AT_EMPTY_PATH) == 0) {
          printf("[ERROR] Unsupported statx(flags=0x%08u)\n", flags);
          abort();
        }
        struct stat _stat;
        // execute fstat
        // errno = fstat(dfd, &_stat);
        errno = 0;
        if (errno == 0) {
          struct _ecv_statx _statx;
          memset(&_statx, 0, sizeof(_statx));
          _statx.stx_mask = 
          _statx.stx_mask = _ECV_STATX_BASIC_STATS;
          _statx.stx_blksize = _stat.st_blksize;
          _statx.stx_attributes = 0;
          _statx.stx_nlink = _stat.st_nlink;
          _statx.stx_uid = _stat.st_uid;
          _statx.stx_gid = _stat.st_gid;
          _statx.stx_mode = _stat.st_mode;
          _statx.stx_ino = _stat.st_ino;
          _statx.stx_size = _stat.st_size;
          _statx.stx_blocks = _stat.st_blocks;
          memcpy(_ecv_translate_ptr(state_gpr.x4.qword), &_statx, sizeof(_statx));
          state_gpr.x0.qword = 0;
        } else {
          state_gpr.x0.qword = -1;
        }
      }
      break;
    case AARCH64_SYS_RSEQ:
      /* TODO */
      state_gpr.x0.qword = 0;
      break;
    default:
      printf("Unknown syscall number: %lu, PC: 0x%llx\n", state_gpr.x8.qword, state_gpr.pc.qword);
      abort();
      break;
  }
}