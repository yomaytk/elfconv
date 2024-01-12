.global _start
.section .text
.extern easy_cal

_start:
        bl      easy_cal        // call easy_func
        // exit system call
        mov     x8, #93         // syscall: exit
        mov     x0, #0          // success status
        svc     #0              // make syscall
