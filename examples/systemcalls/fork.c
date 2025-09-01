#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    pid_t pid;

    // 1回目の fork
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    // 2回目の fork
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    // どのプロセスからでもここに到達する
    printf("PID: %d, PPID: %d\n", getpid(), getppid());

    return 0;
}
