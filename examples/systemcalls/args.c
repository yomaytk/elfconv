#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[]) {
  for (int i = 0; i < argc; i++) {
    printf("&argv[%d]: %p, args[%d]: ptr: %p ~ %p, strlen(args): %ld, content: %s\n", i, &argv[i],
           i, argv[i], argv[i] + strlen(argv[i]) + 1, strlen(argv[i]), argv[i]);
  }
  for (int i = 0; envp[i] != NULL; i++) {
    printf("&envp[%d]: %p, envp[%d]: ptr: %p ~ %p, strlen(envp): %ld, content: %s\n", i, &envp[i],
           i, envp[i], envp[i] + strlen(envp[i]) + 1, strlen(envp[i]), envp[i]);
  }
  return 0;
}