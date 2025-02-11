        .section .data
hello_msg:
        .ascii  "Hello, World!\n"   // 14 characters total

        .section .text
        .global _start
_start:
        // sys_write(1, hello_msg, 14)
        mov     x0, #1              // 1: File descriptor (stdout)
        adrp    x1, hello_msg       // Load page address of hello_msg
        add     x1, x1, :lo12:hello_msg
        mov     x2, #14             // Number of bytes to write
        mov     x8, #64             // sys_write syscall number on AArch64
        svc     #0

        // sys_exit(0)
        mov     x0, #0              // exit code
        mov     x8, #93             // sys_exit syscall number on AArch64
        svc     #0