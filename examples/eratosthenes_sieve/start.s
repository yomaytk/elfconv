.global _start
.section .text
.extern prime_cal

_start:
        bl      prime_cal        // call target_cal_func
        // exit system call
        mov     x8, #93         // syscall: exit
        mov     x0, #0          // success status
        svc     #0              // make syscall
