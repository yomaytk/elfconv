#include "SysTable.h"
#include "runtime/Memory.h"

#include <algorithm>
#include <alloca.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
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


struct Fdmap : XMemory {
  int fd;
  off_t offset;
  Fdmap(int a, off_t offset) : fd(a), offset(offset) {}
  Fdmap(Fdmap const &x) : fd(x.fd), offset(x.offset) {}
  // ~Fdmap() {
  //   close(fd);
  // }
  uint8_t get(uint64_t x) override {
    auto t = lseek(fd, 0, SEEK_CUR);
    lseek(fd, offset + x, SEEK_SET);
    uint8_t a;
    read(fd, &a, 1);
    lseek(fd, t, SEEK_SET);
    return a;
  }
  void set(uint64_t x, uint8_t y) override {
    auto t = lseek(fd, 0, SEEK_CUR);
    lseek(fd, offset + x, SEEK_SET);
    write(fd, &y, 1);
    lseek(fd, t, SEEK_SET);
  };
};


#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
#  define EMPTY_SYSCALL(sysnum) printf("[WARNING] syscall \"" #  sysnum "\" is empty now.\n");
#  define NOP_SYSCALL(sysnum) \
    printf("[INFO] syscall \"" #sysnum "\" is nop (but maybe allowd) now.\n");
#else
#  define EMPTY_SYSCALL(sysnum) ;
#  define NOP_SYSCALL(sysnum) ;
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

/*
  syscall emulate function
  
  Calling Conventions
  arch: arm64, syscall NR: x8, return: x0, arg0: x0, arg1: x1, arg2: x2, arg3: x3, arg4: x4, arg5: x5
  ref: https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/
*/
void __svc_wasi_call(void) {

  auto &state_gpr = g_state.gpr;
  errno = 0;
#if defined(ELFC_RUNTIME_SYSCALL_DEBUG)
  printf("[INFO] __svc_call started. syscall number: %u, PC: 0x%016llx\n", g_state.gpr.x8.dword,
         g_state.gpr.pc.qword);
#endif
  switch (state_gpr.x8.qword) {
    case AARCH64_SYS_IOCTL: /* ioctl (unsigned int fd, unsigned int cmd, unsigned long arg) */
      EMPTY_SYSCALL(AARCH64_SYS_IOCTL)
      state_gpr.x0.qword = -1;
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_FACCESSAT: /* faccessat (int dfd, const char *filename, int mode) */
      /* TODO */
      state_gpr.x0.qword = -1;
      EMPTY_SYSCALL(AARCH64_SYS_FACCESSAT);
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_OPENAT: /* openat (int dfd, const char* filename, int flags, umode_t mode) */
    {
      if (-100 == state_gpr.x0.dword)
        state_gpr.x0.qword = AT_FDCWD;  // AT_FDCWD on WASI: -2 (-100 on Linux)
      auto old = state_gpr.x2.dword;
      state_gpr.x2.dword = O_RDWR;
      if (old & 0x100)
        state_gpr.x2.dword |= O_CREAT;
      // uint8_t x1[state_gpr.x2.dword];
      // g_run_mgr->read(state_gpr.x1.qword, &x1[0], state_gpr.x2.dword);
      state_gpr.x0.dword = openat(state_gpr.x0.dword, g_run_mgr->cstr(state_gpr.x1.qword).c_str(),
                                  state_gpr.x2.dword);
      if (-1 == state_gpr.x0.dword)
        perror("openat error!");
    } break;
    case AARCH64_SYS_CLOSE: /* int close (unsigned int fd) */
      state_gpr.x0.dword = close(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_READ: /* read (unsigned int fd, char *buf, size_t count) */
    {
      uint8_t buf[state_gpr.x2.qword];
      state_gpr.x0.qword = read(state_gpr.x0.dword, buf, static_cast<size_t>(state_gpr.x2.qword));
      g_run_mgr->write(state_gpr.x1.qword, &buf[0], state_gpr.x2.qword);
    } break;
    case AARCH64_SYS_WRITE: /* write (unsigned int fd, const char *buf, size_t count) */
    {
      uint8_t buf[state_gpr.x2.qword];
      g_run_mgr->read(state_gpr.x1.qword, &buf[0], state_gpr.x2.qword);
      state_gpr.x0.qword = write(state_gpr.x0.dword, buf, static_cast<size_t>(state_gpr.x2.qword));
    } break;
    case AARCH64_SYS_WRITEV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
    {
      unsigned long fd = state_gpr.x0.qword;
      unsigned long vlen = state_gpr.x2.qword;
      // auto tr_vec = reinterpret_cast<iovec *>(_ecv_translate_ptr(state_gpr.x1.qword));
      auto cache_vec = reinterpret_cast<iovec *>(malloc(sizeof(iovec) * vlen));
      g_run_mgr->read(state_gpr.x1.qword, cache_vec, vlen);
      // translate every iov_base
      for (unsigned long i = 0; i < vlen; i++) {
        uint8_t *x = (uint8_t *) alloca(cache_vec[i].iov_len);
        g_run_mgr->read((uint64_t) cache_vec[i].iov_base, x, cache_vec[i].iov_len);
        cache_vec[i].iov_base = x;
        // cache_vec[i].iov_len = tr_vec[i].iov_len;
      }
      state_gpr.x0.qword = writev(fd, cache_vec, vlen);
      free(cache_vec);
    } break;
    case AARCH64_SYS_READV: /* writev (unsgined long fd, const struct iovec *vec, unsigned long vlen) */
    {
      unsigned long fd = state_gpr.x0.qword;
      unsigned long vlen = state_gpr.x2.qword;
      // auto tr_vec = reinterpret_cast<iovec *>(_ecv_translate_ptr(state_gpr.x1.qword));
      auto cache_vec = reinterpret_cast<iovec *>(malloc(sizeof(iovec) * vlen));
      g_run_mgr->read(state_gpr.x1.qword, cache_vec, vlen);
      uint64_t roots[vlen];
      // translate every iov_base
      for (unsigned long i = 0; i < vlen; i++) {
        uint8_t *x = (uint8_t *) alloca(cache_vec[i].iov_len);
        roots[i] = (uint64_t) cache_vec[i].iov_base;
        // g_run_mgr->read((uint64_t) cache_vec[i].iov_base, x, cache_vec[i].iov_len);
        cache_vec[i].iov_base = x;
        // cache_vec[i].iov_len = tr_vec[i].iov_len;
      }
      state_gpr.x0.qword = readv(fd, cache_vec, vlen);
      for (unsigned long i = 0; i < vlen; i++) {
        auto b = (uint64_t) cache_vec[i].iov_base;
        g_run_mgr->write((uint64_t) roots[i], &b, cache_vec[i].iov_len);
      }
      free(cache_vec);
    } break;
    case AARCH64_SYS_READLINKAT: /* readlinkat (int dfd, const char *path, char *buf, int bufsiz) */
    {
      uint8_t buf[state_gpr.x3.dword];
      state_gpr.x0.qword =
          readlinkat(state_gpr.x0.dword, g_run_mgr->cstr(state_gpr.x1.qword).c_str(), (char *) buf,
                     state_gpr.x3.dword);
      g_run_mgr->write(state_gpr.x2.qword, buf, state_gpr.x3.dword);
    } break;
    case AARCH64_SYS_NEWFSTATAT: /* newfstatat (int dfd, const char *filename, struct stat *statbuf, int flag) */
      /* TODO */
      state_gpr.x0.qword = -1;
      EMPTY_SYSCALL(AARCH64_SYS_NEWFSTATAT);
      errno = _ECV_EACCESS;
      break;
    case AARCH64_SYS_EXIT: /* exit (int error_code) */ exit(state_gpr.x0.dword); break;
    case AARCH64_SYS_EXITGROUP: /* exit_group (int error_code) note. there is no function of 'exit_group', so must use syscall. */
      exit(state_gpr.x0.dword);
      break;
    case AARCH64_SYS_SET_TID_ADDRESS: /* set_tid_address(int *tidptr) */
    {
      pid_t tid = 42;
      g_run_mgr->write(state_gpr.x0.qword, &tid);
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
      } which_clock;
      which_clock.id = state_gpr.x0.dword;
      struct timespec emu_tp;
      int clock_time = clock_gettime((clockid_t) &which_clock, &emu_tp);
      // memcpy(_ecv_translate_ptr(state_gpr.x1.qword), &emu_tp, sizeof(timespec));
      g_run_mgr->write(state_gpr.x1.qword, &emu_tp);
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
      struct __my_utsname {
        char sysname[65];
        char nodename[65];
        char relase[65];
        char version[65];
        char machine[65];
      } new_utsname = {"Linux", "xxxxxxx-QEMU-Virtual-Machine",
                       "6.0.0-00-generic", /* cause error if the kernel version is too old. */
                       "#0~elfconv", "aarch64"};
      // memcpy(_ecv_translate_ptr(state_gpr.x0.qword), &new_utsname, sizeof(new_utsname));
      g_run_mgr->write(state_gpr.x0.qword, &new_utsname);
      state_gpr.x0.dword = 0;
    } break;
    case AARCH64_SYS_GETPID: /* getpid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETPPID: /* getppid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETTUID: /* getuid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETEUID: /* geteuid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETGID: /* getgid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETEGID: /* getegid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_GETTID: /* getttid () */ state_gpr.x0.dword = 42; break;
    case AARCH64_SYS_BRK: /* brk (unsigned long brk) */
    {
      auto heap_memory = g_run_mgr->heap_memory;
      if (state_gpr.x0.qword == 0) {
        /* init program break (FIXME) */
        state_gpr.x0.qword = heap_memory->heap_cur;
      } else if (heap_memory->vma <= state_gpr.x0.qword &&
                 state_gpr.x0.qword < heap_memory->vma + heap_memory->len) {
        /* change program break */
        heap_memory->heap_cur = state_gpr.x0.qword;
      } else {
        elfconv_runtime_error("Unsupported brk(0x%016llx).\n", state_gpr.x0.qword);
      }
    } break;
    case AARCH64_SYS_MUNMAP: /* munmap (unsigned long addr, size_t len) */
      /* TODO */ {
        auto vma_addr = state_gpr.x0.qword;
        auto it = std::find_if(g_run_mgr->mapped_memorys.begin(), g_run_mgr->mapped_memorys.end(),
                               [=](MappedMemory *memory) {
                                 return memory->vma <= vma_addr && vma_addr < memory->vma_end;
                               });

        if (it != g_run_mgr->mapped_memorys.end()) {
          using std::swap;

          // swap the one to be removed with the last element
          // and remove the item at the end of the container
          // to prevent moving all items after '5' by one
          swap(*it, g_run_mgr->mapped_memorys.back());
          g_run_mgr->mapped_memorys.pop_back();
        }
        state_gpr.x0.qword = 0;
        EMPTY_SYSCALL(AARCH64_SYS_MUNMAP);
      }
      break;
    case AARCH64_SYS_MMAP: /* mmap (void *start, size_t lengt, int prot, int flags, int fd, off_t offset) */
      /* FIXME */
      {
        auto heap_memory = g_run_mgr->heap_memory;
        if (state_gpr.x0.qword == 0) {
          if (state_gpr.x4.dword != -1)
            elfconv_runtime_error("Unsupported mmap (X4=0x%08x)\n", state_gpr.x4.dword);
          if (state_gpr.x5.dword != 0)
            elfconv_runtime_error("Unsupported mmap (X5=0x%016llx)\n", state_gpr.x5.qword);
          state_gpr.x0.qword = heap_memory->heap_cur;
          heap_memory->heap_cur += state_gpr.x1.qword;
        } else {
          if (state_gpr.x4.dword == -1) {
            if (state_gpr.x1.qword <= 1 << 24) {
              auto bytes = reinterpret_cast<uint8_t *>(malloc(state_gpr.x1.dword));
              auto size = state_gpr.x1.dword;
              auto upper_bytes = bytes + size;
              auto s = state_gpr.x0.qword;
              auto heap = new MappedMemory(MemoryAreaType::OTHER, "MMap", s, s + HEAP_UNIT_SIZE,
                                           size, bytes, upper_bytes, true);
              g_run_mgr->mapped_memorys.push_back(heap);
            } else {
              uint8_t *bytes = nullptr;
              auto size = state_gpr.x1.qword;
              auto upper_bytes = bytes + size;
              auto s = state_gpr.x0.qword;
              auto heap = new MappedMemory(MemoryAreaType::OTHER, "MMap", s, s + HEAP_UNIT_SIZE,
                                           size, bytes, upper_bytes, true);
              heap->other_memory =
                  std::shared_ptr<XMemory>(new MapXMemory<std::map<uint64_t, uint8_t>>({}));
              g_run_mgr->mapped_memorys.push_back(heap);
            }
            // return heap;
          } else {
            // elfconv_runtime_error("Unsupported mmap (X0=0x%016llx)\n", state_gpr.x0.qword);
            uint8_t *bytes = nullptr;
            auto size = state_gpr.x1.qword;
            auto upper_bytes = bytes + size;
            auto s = state_gpr.x0.qword;
            auto heap = new MappedMemory(MemoryAreaType::OTHER, "MMap", s, s + HEAP_UNIT_SIZE, size,
                                         bytes, upper_bytes, true);
            heap->other_memory =
                std::shared_ptr<XMemory>(new Fdmap(state_gpr.x4.dword, state_gpr.x5.qword));
            g_run_mgr->mapped_memorys.push_back(heap);
          }
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
      // memset(_ecv_translate_ptr(state_gpr.x0.qword), 1, static_cast<size_t>(state_gpr.x1.qword));
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
        // memcpy(_ecv_translate_ptr(state_gpr.x4.qword), &_statx, sizeof(_statx));
        g_run_mgr->write(state_gpr.x4.qword, &_statx);
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