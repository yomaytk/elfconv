/* 
  This file is used to check whether the every system call is supported by WASI SDK or Emscripten.
*/

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>  // need -D_WASI_EMULATED_SIGNAL and -lwasi-emulated-signal
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>  // need -D_WASI_EMULATED_MMAN and -lwasi-emulated-mman
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// check with WASI SDK
#if defined(__wasi__)
#  include <poll.h>
// #include <sys/statfs.h> undeclared
// #include <sys/vfs.h> undeclared
int wasm_sys() {

  char str_a[] = "str_a";
  void *null_p = (void *) str_a;

  /* dup .. undeclared */
  // int res = dup(0);

  /* dup3 .. undeclared */
  // int res = dup3(0, 0, 0);

  /* ppoll .. undeclared */
  // ppoll((struct pollfd *) str_a, 0, (const struct timespec *) str_a, 0);

  /* poll .. success */
  poll((struct pollfd *) str_a, 0, 0);

  /* getcwd .. success */
  getcwd(NULL, 100);

  /* statfs .. undeclared */
  // statfs(str_a, (struct statfs *) str_a);

  /* fstatfs .. undeclared */
  // fstatfs(0, (struct statfs *) str_a);

  /* faccessat (int dirfd, const char *pathname, int mode, int flags) */
  faccessat(0, str_a, 0, 0);

  /* stat .. success */
  stat(str_a, (struct stat *) str_a);

  /* fstatat .. success */
  fstatat(0, str_a, (struct stat *) null_p, 0);

  /* ioctl .. success */
  ioctl(0, 0, NULL);

  /* mmap .. success (with -D_WASI_EMULATED_MMAN and lwasi-emulated-mman) */
  void *r1 = mmap(NULL, 0, 0, 0, 0, 0);
  printf("mmap res: %p\n", r1);

  /* chdir .. success */
  chdir(str_a);

  /* getdents .. success */
  getdents(0, (struct dirent *) str_a, 0);

  /* sendfile .. undeclared */
  // sendfile(0, 1, (off_t *) str_a, 0);

  /* utimensat .. success */
  utimensat(0, str_a, (struct timespec *) str_a, 0);

  /* kill .. undeclared */
  // kill(0, 0);

  /* sigprocmask .. undeclared */
  // sigprocmask(0, (sigset_t *) str_a, (sigset_t *) str_a);

  /* mprotect .. success */
  mprotect(str_a, 0, 0);

  /* prlimit .. undeclared */
  // prlimit(1000, 0, (const struct rlimit *) str_a, (struct rlimit *) str_a);

  /* getentropy .. success */
  getentropy(str_a, 100);

  /* getrandom .. undeclared */
  // getrandom(str_a, 10, 1);

  return 0;
}
#endif

#if defined(__EMSCRIPTEN__)
#  include <sys/poll.h>
// check with emscripten
int emcc_sys() {

  char str_a[] = "str_a";
  void *null_p = (void *) str_a;

  /* fstatat .. success */
  fstatat(0, str_a, (struct stat *) null_p, 0);

  /* ppoll .. success */
  ppoll((struct pollfd *) str_a, 0, (struct timespec *) str_a, 0);

  /* ioctl .. success */
  ioctl(10, 0, 0);

  /* getdents .. success */
  getdents(0, 0, 0);

  /* clock_nanosleep .. success */
  clock_nanosleep(0, 0, NULL, NULL);

  return 0;
}

int emcc_libc() {
  fdopendir(0);
}
#endif

int main() {
  printf("AT_EACCESS: %d, AT_SYMLINK_NOFOLLOW: %d\n", AT_EACCESS, AT_SYMLINK_NOFOLLOW);
  return 0;
}