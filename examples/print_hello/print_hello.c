#define HELLO_LEN 13

static char hello_world[] = "Hello, World!";

void write_stdout(char *str, unsigned long length) {
     __asm__ volatile(
        "mov x2, x1;"          // x2 = length
        "mov x1, x0;"          // x1 = str
        "mov x0, #1;"          // fd = STDOUT
        "mov x8, #64;"         // syscall: write
        "svc #0;"              // make syscall
        :
        : "r" (str), "r" (length)
        : "x0", "x1", "x2", "x8"
    );
}

void print_hello() {
  write_stdout(hello_world, HELLO_LEN);
}
