#include <stdexcept>

void elfconv_runtime_error(char *fmt, ...) {
#if defined(__wasm__)
  printf(fmt);
  abort();
#else
  char error_message[1000];
  snprintf(error_message, sizeof(error_message), fmt);
  std::__throw_runtime_error(error_message);
#endif
}
