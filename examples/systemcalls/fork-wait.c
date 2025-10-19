#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  pid_t pid = fork();

  if (pid < 0) {
    // fork failed
    perror("fork");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    // Child process
    printf("Child process: PID=%d, Parent PID=%d\n", getpid(), getppid());
    sleep(2);  // Simulated processing
    printf("Child process terminated\n");
    exit(42);  // Return exit code 42
  } else {
    // Parent process
    printf("Parent process: PID=%d, Child PID=%d\n", getpid(), pid);

    int status;
    pid_t wpid = wait(&status);  // Wait for the child to finish

    if (wpid == -1) {
      perror("wait");
      exit(EXIT_FAILURE);
    }

    if (WIFEXITED(status)) {
      printf("Child process %d exited normally (exit code=%d)\n", wpid, WEXITSTATUS(status));
    } else {
      printf("Child process %d terminated abnormally\n", wpid);
    }
  }

  return 0;
}