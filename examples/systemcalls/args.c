#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[]) {
  printf("argc addr: %p, argc, %d, argv[0]: %p,  argv addr: %p\n", &argc, argc, (void *) argv[0],
         argv);
  printf("argc addr: %p, argc: %d, argv[-1]: 0x%lx\n", &argc, argc, *(unsigned long *) (argv - 1));
  printf("argv addr: %p, envp addr: %p\n", argv, envp);
  for (int i = 0; i < argc; i++) {
    printf("&argv[%d]: %p, args[%d]: ptr: %p ~ %p, strlen(args): %ld, content: %s\n", i, &argv[i],
           i, argv[i], argv[i] + strlen(argv[i]) + 1, strlen(argv[i]), argv[i]);
  }
  for (int i = 0; envp[i]; i++) {
    printf("envp[%d]: content: %s\n", i, envp[i]);
  }
  return 0;
}