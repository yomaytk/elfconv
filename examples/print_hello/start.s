.global _start
.section .text
.extern print_hello

_start:
        bl      print_hello        // call print_hello
        // exit system call
        mov     x0, #0          // success status
        mov     x8, #93         // syscall: exit
        svc     #0              // make syscall
