#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdarg.h>
#include <stdexcept>
#include <stdlib.h>

char ERROR_PREFIX[] = "[\033[0;31mERROR\033[0m] ";
size_t ERROR_PREFIX_LEN = std::strlen(ERROR_PREFIX);

void elfconv_runtime_error(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
#if defined(__wasm__)
  vprintf(fmt, args);
  abort();
  va_end(args);
#else
  char error_message[1000];
  std::strncpy(error_message, ERROR_PREFIX, sizeof(ERROR_PREFIX));
  vsnprintf(error_message + ERROR_PREFIX_LEN, sizeof(error_message) - ERROR_PREFIX_LEN, fmt, args);
  va_end(args);
  std::__throw_runtime_error(error_message);
#endif
}
