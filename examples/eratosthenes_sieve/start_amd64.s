.global _start
.section .text
.extern prime_cal

_start:
        call    prime_cal       # call target function
        # exit system call
        movq    $60, %rax       # syscall: exit
        xorq    %rdi, %rdi      # success status (0)
        syscall                 # make syscall