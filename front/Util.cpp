#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>

void elfconv_runtime_error(char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
#if defined(__wasm__)
  vprintf(fmt, args);
  abort();
  va_end(args);
#else
  char error_message[1000];
  vsnprintf(error_message, sizeof(error_message), fmt, args);
  va_end(args);
  std::__throw_runtime_error(error_message);
#endif
}
