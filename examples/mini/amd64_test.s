.intel_syntax noprefix
.section .data

success_msg: 
    .string "success.\n"

mov_gprv_immz_error_msg:
    .string "[ERROR]: MOV_GPRv_IMMz\n"

add_gprv_immb_error_msg:
    .string "[ERROR] ADD_GPRv_IMMb\n"

mov_memv_gprv_error_msg:
    .string "[ERROR] MOV_MEMv_GPRv\n"

call_procedure_error_msg:
    .string "[ERROR] CALL_NEAR_RELBRd\n"

.section .text
.globl _start

_start:                  
    jmp test_mov_gprv_immz

func1:
    push rbp
    mov rbp, rsp
    mov qword ptr [rbp - 8], rdi
    mov qword ptr [rbp - 16], rsi
    mov rax, qword ptr [rbp - 8]
    add rax, qword ptr [rbp - 16]
    pop rbp
    ret

test_mov_gprv_immz:
    mov rbx, 50   
    cmp rbx, 50
    jne fail_mov_gprv_immz
    jmp test_add_gprv_immb

fail_mov_gprv_immz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_gprv_immz_error_msg]
    mov rdx, 24
    syscall
    jmp exit

test_add_gprv_immb:
    mov rbx, 10
    add rbx, 20
    cmp rbx, 30
    jne fail_add_gprv_immb
    jmp test_mov_memv_gprv

fail_add_gprv_immb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + add_gprv_immb_error_msg]
    mov rdx, 23
    syscall
    jmp exit

test_mov_memv_gprv:
    mov rbp, rsp
    sub rsp, 8
    mov qword ptr [rbp - 4], 20
    mov rbx, qword ptr [rbp - 4]
    cmp rbx, 20
    jne fail_mov_memv_gprv
    jmp test_call_procedure
    
fail_mov_memv_gprv:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_memv_gprv_error_msg]
    mov rdx, 23
    syscall
    jmp exit

test_call_procedure:
    mov rdi, 30
    mov rsi, 30
    call func1
    cmp rax, 60
    jne fail_call_procedure
    jmp success

fail_call_procedure:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + call_procedure_error_msg]
    mov rdx, 25
    syscall
    jmp exit

success:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + success_msg]
    mov rdx, 9
    syscall
    jmp exit

exit:
    mov rax, 60
    xor rdi, rdi
    syscall