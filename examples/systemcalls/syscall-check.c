#include <dirent.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <unistd.h>

// check with WASI SDK
int wasm_sys() {

  char str_a[] = "str_a";
  void *null_p = (void *) str_a;

  /* dup .. undeclared */
  // int res = dup(0);

  /* dup3 .. undeclared */
  // int res = dup3(0, 0, 0);

  /* ppoll .. undeclared */
  // ppoll((struct pollfd *) str_a, 0, (const struct timespec *) str_a, 0);

  /* getcwd .. success */
  getcwd(NULL, 100);

  /* fstatat .. success */
  fstatat(0, str_a, (struct stat *) null_p, 0);

  return 0;
}

// check with emscripten
int emcc_sys() {

  char str_a[] = "str_a";
  void *null_p = (void *) str_a;

  /* fstatat .. success */
  fstatat(0, str_a, (struct stat *) null_p, 0);

  /* ppoll .. success */
  ppoll((struct pollfd *) str_a, 0, (struct timespec *) str_a, 0);

  ioctl(10, 0, 0);

  /* not undeclared */
  // getdents(0, 0, 0);

  return 0;
}

int emcc_libc() {
  fdopendir(0);
}

int main() {
  return 0;
}