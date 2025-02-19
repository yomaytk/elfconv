.intel_syntax noprefix
.section .data
success_msg: 
    .string "success.\n"

mov_gprv_immz_error_msg:
    .string "[ERROR]: MOV_GPRv_IMMz\n"

add_gprv_immb_error_msg:
    .string "[ERROR] ADD_GPRv_IMMb\n"

.section .text
.globl _start
_start:                  
    jmp test_mov_gprv_immz

test_mov_gprv_immz:
    mov rbx, 50   
    cmp rbx, 50
    jne fail_mov_gprv_immz
    jmp test_add_gprv_immb

fail_mov_gprv_immz:
    mov rax, 1
    lea rsi, [rip + mov_gprv_immz_error_msg]
    mov rdx, 24
    syscall
    jmp exit

test_add_gprv_immb:
    mov rbx, 10
    add rbx, 20
    cmp rbx, 30
    jne fail_add_gprv_immb
    jmp success

fail_add_gprv_immb:
    mov rax, 1
    lea rsi, [rip + add_gprv_immb_error_msg]
    mov rdx, 23
    syscall
    jmp exit
    
success:
    mov rax, 1
    lea rsi, [rip + success_msg]
    mov rdx, 9
    syscall
    jmp exit

exit:
    mov rax, 60
    xor rdi, rdi
    syscall