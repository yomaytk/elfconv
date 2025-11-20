// parent.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  pid_t pid = fork();

  if (pid < 0) {
    perror("fork failed");
    exit(1);
  }

  if (pid == 0) {
    printf("Child: exec ./child.wasm\n");
    execl("./child", "hello from parent args!", "second argument!", (char *) NULL);

    perror("exec failed");
    exit(1);
  } else {
    printf("Parent: waiting for child (pid=%d)\n", pid);
    int status;
    waitpid(pid, &status, 0);
    printf("Parent: child finished with status %d\n", status);
  }

  return 0;
}