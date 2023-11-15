.global _start
.section .text
.extern add

_start:
        mov     x0, 12
        mov     x1, 32
        bl      add        // call easy_func
        // exit system call
        mov     x8, #93         // syscall: exit
        svc     #0              // make syscall
