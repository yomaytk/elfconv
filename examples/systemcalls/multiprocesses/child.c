// child.c
#include <stdio.h>

int main(int argc, char *argv[]) {
  printf("Hello from child program!\n");
  printf("execved child argc: %d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("execved child arg[%d]: %s\n", i, argv[i]);
  }
  return 0;
}