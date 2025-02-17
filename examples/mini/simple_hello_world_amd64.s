.section .data
hello_msg: 
    .string "Hello, World!\n"

.section .text
.globl _start
_start:
    # write syscall
    movq $1, %rax            # syscall number (1: write)
    movq $1, %rdi            # first arg: (1: stdout)
    leaq hello_msg(%rip), %rsi  # second arg: address to write
    movq $14, %rdx           # third arg: data size (14 byte)
    syscall                  

    # exit syscall
    movq $50, %rax           
    add $10, %rax            # syscall number (60: exit)
    xorq %rdi, %rdi          # first arg: exit status (0)
    syscall                  