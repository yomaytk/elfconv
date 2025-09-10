#include <sched.h>  // sched_yield
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int main(void) {
  pid_t pid = fork();

  // setvbuf(stdout, NULL, _IOLBF, 0);

  if (pid == 0) {
    // child
    // srand((unsigned) (getpid() ^ time(NULL)));
    for (int i = 0; i < 5; i++) {
      printf("child  (pid: %d). count: %d\n", getpid(), i);
    }
  } else {
    // parent
    // srand((unsigned) (getpid() ^ time(NULL)));
    for (int i = 0; i < 5; i++) {
      printf("parent (pid: %d). count: %d\n", getpid(), i);
    }
  }
  return 0;
}