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

push_pop_error_msg:
    .string "[ERROR] PUSH_POP\n"

jnl_relbrd_error_msg:
    .string "[ERROR] JNL_RELBRd\n"

cmp_memv_immz_error_msg:
    .string "[ERROR] CMP_MEMv_IMMz\n"

sub_gprv_immz_error_msg:
    .string "[ERROR] SUB_GPRv_IMMz\n"

cmp_memv_immb_error_msg:
    .string "[ERROR] CMP_MEMv_IMMb\n"

jnz_relbrd_error_msg:
    .string "[ERROR] JNZ_RELBRd\n"

movsxd_gprv_memz_error_msg:
    .string "[ERROR] MOVSXD_GPRv_MEMz\n"

shl_gprv_immb_c1r4_error_msg:
    .string "[ERROR] SHL_GPRv_IMMb_C1r4\n"

mov_gpr8_immb_b0_error_msg:
    .string "[ERROR] MOV_GPR8_IMMb_B0\n"

cmp_al_immb_error_msg:
    .string "[ERROR] CMP_AL_IMMb\n"

mov_memb_gpr8_error_msg:
    .string "[ERROR] MOV_MEMb_GPR8\n"

setl_gpr8_error_msg:
    .string "[ERROR] SETL_GPR8\n"

mov_gpr8_memb_error_msg:
    .string "[ERROR] MOV_GPR8_MEMb\n"

test_al_immb_error_msg:
    .string "[ERROR] TEST_AL_IMMb\n"

mov_memb_immb_error_msg:
    .string "[ERROR] MOV_MEMb_IMMb\n"

cdq_error_msg:
    .string "[ERROR] CDQ\n"

cdqe_error_msg:
    .string "[ERROR] CDQE\n"

jle_relbrd_error_msg:
    .string "[ERROR] JLE_RELBRd\n"

mov_gprv_immv_error_msg:
    .string "[ERROR] MOV_GPRv_IMMv\n"

add_gprv_immz_error_msg:
    .string "[ERROR] ADD_GPRv_IMMz\n"

idiv_memv_32_error_msg:
    .string "[ERROR] IDIV_MEMv_32\n"

idiv_gprv_32_error_msg:
    .string "[ERROR] IDIV_GPRv_32\n"

mov_gpr8_gpr8_88_error_msg:
    .string "[ERROR] MOV_GPR8_GPR8_88\n"

imul_gprv_memv_imm8_error_msg:
    .string "[ERROR] IMUL_GPRv_MEMv_IMM8\n"

imul_gprv_gprv_error_msg:
    .string "[ERROR] IMUL_GPRv_GPRv\n"
    
sub_gprv_gprv_29_error_msg:
    .string "[ERROR] SUB_GPRv_GPRv_29\n"

cmp_gprv_gprv_39_error_msg:
    .string "[ERROR] CMP_GPRv_GPRv_39\n"

add_orax_immz_error_msg:
    .string "[ERROR] ADD_OrAX_IMMz\n"

jnl_relbrb_error_msg:
    .string "[ERROR] JNL_RELBRb\n"

.section .text
.global _start

_start:
    jmp test_jnl_relbrb

test_jnl_relbrb:
    mov eax, 10
    sub eax, 5
    jnl test_add_orax_immz
    jmp fail_jnl_relbrb

fail_jnl_relbrb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + jnl_relbrb_error_msg]
    mov rdx, 20
    syscall
    jmp exit

test_add_orax_immz:
    mov eax, 0
    add eax, 0x12345678
    cmp eax, 0x12345678
    jne fail_add_orax_immz
    jmp test_cmp_gprv_gprv_39

fail_add_orax_immz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + add_orax_immz_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_cmp_gprv_gprv_39:
    mov eax, 10              # First operand
    mov ebx, 10              # Second operand
    cmp eax, ebx
    jne fail_cmp_gprv_gprv_39
    jmp test_sub_gprv_gprv_29

fail_cmp_gprv_gprv_39:
    mov rax, 1               # syscall: write
    mov rdi, 1               # stdout
    lea rsi, [rip + cmp_gprv_gprv_39_error_msg] # Load error message
    mov rdx, 27              # Message length
    syscall
    jmp exit

test_sub_gprv_gprv_29:
    mov eax, 10
    mov ebx, 3
    sub eax, ebx
    cmp eax, 7
    jne fail_sub_gprv_gprv_29
    jmp test_imul_gprv_gprv

fail_sub_gprv_gprv_29:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + sub_gprv_gprv_29_error_msg]
    mov rdx, 27
    syscall
    jmp exit

test_imul_gprv_gprv:
    mov eax, 3
    mov ebx, -5
    imul eax, ebx
    cmp eax, -15
    jne fail_imul_gprv_gprv
    jmp test_imul_gprv_memv_imm8

fail_imul_gprv_gprv:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + imul_gprv_gprv_error_msg]
    mov rdx, 27
    syscall
    jmp exit
    
test_imul_gprv_memv_imm8:
    mov rbp, rsp
    sub rsp, 8
    mov dword ptr [rbp], -2   # Store -2 in memory
    xor eax, eax
    imul eax, dword ptr [rbp], -5
    cmp eax, 10
    jne fail_imul_gprv_memv_imm8
    jmp test_mov_gpr8_gpr8_88

fail_imul_gprv_memv_imm8:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + imul_gprv_memv_imm8_error_msg]
    mov rdx, 29
    syscall
    jmp exit

test_mov_gpr8_gpr8_88:
    mov al, 0x5A              # Set AL
    mov bl, 0x00              # Clear BL
    mov bl, al
    cmp bl, 0x5A
    jne fail_mov_gpr8_gpr8_88
    jmp test_idiv_gprv_32

fail_mov_gpr8_gpr8_88:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_gpr8_gpr8_88_error_msg]
    mov rdx, 26
    syscall
    jmp exit

test_idiv_gprv_32:
    mov ebx, -5               # Divisor
    mov eax, -23              # Dividend
    cdq
    idiv ebx
    cmp eax, 4
    jne fail_idiv_gprv_32
    cmp edx, -3
    jne fail_idiv_gprv_32
    jmp test_idiv_memv_32

fail_idiv_gprv_32:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + idiv_gprv_32_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_idiv_memv_32:
    mov rbp, rsp
    sub rsp, 8
    mov dword ptr [rbp], -5
    mov eax, -23
    cdq
    idiv dword ptr [rbp]
    cmp eax, 4
    jne fail_idiv_memv_32
    cmp edx, -3
    jne fail_idiv_memv_32
    jmp test_add_gprv_immz

fail_idiv_memv_32:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + idiv_memv_32_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_add_gprv_immz:
    mov eax, 0
    .byte 0x81, 0xC0  # ADD EAX, IMM32
    .long 0x12345678  # IMM32
    cmp eax, 0x12345678
    jne fail_add_gprv_immz
    jmp test_mov_gprv_immv

fail_add_gprv_immz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + add_gprv_immz_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_mov_gprv_immv:
    xor rax, rax
    mov rax, 0x12345678
    cmp rax, 0x12345678
    jne fail_mov_gprv_immv
    jmp test_jle_relbrd  # Jump to the next test

fail_mov_gprv_immv:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_gprv_immv_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_jle_relbrd:
    mov eax, 0
    sub eax, 1
    jle force_jle_relbrd
    jmp fail_jle_relbrd

fail_jle_relbrd:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + jle_relbrd_error_msg]
    mov rdx, 20
    syscall
    jmp exit

test_cdqe:
    mov rbp, rsp
    sub rsp, 8

    # Test with a negative value
    mov eax, -1
    cdqe
    cmp rax, 0xFFFFFFFFFFFFFFFF
    jne fail_cdqe

    # Test with a positive value
    mov eax, 1
    cdqe
    cmp rax, 0x0000000000000001
    jne fail_cdqe
    jmp test_cdq

fail_cdqe:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + cdqe_error_msg]
    mov rdx, 14
    syscall
    jmp exit

test_cdq:
    mov rbp, rsp
    sub rsp, 8

    # Test with a negative value
    mov eax, -1
    cdq
    cmp edx, 0xFFFFFFFF
    jne fail_cdq

    # Test with a positive value
    mov eax, 1
    cdq
    cmp edx, 0x00000000
    jne fail_cdq
    jmp test_mov_memb_immb

fail_cdq:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + cdq_error_msg]
    mov rdx, 17
    syscall
    jmp exit

test_mov_memb_immb:
    mov rbp, rsp
    sub rsp, 8
    mov byte ptr [rbp - 1], 0x40
    cmp byte ptr [rbp - 1], 0x40
    jne fail_mov_memb_immb
    jmp test_test_al_immb

fail_mov_memb_immb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_memb_immb_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_test_al_immb:
    mov rbp, rsp
    sub rsp, 8
    mov al, 0x41
    test al, 0x41
    cmp al, 0x41
    jne fail_test_al_immb
    # Check if ZF (Zero Flag) is set correctly
    jnz fail_test_al_immb
    jmp test_mov_gpr8_memb

fail_test_al_immb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + test_al_immb_error_msg]
    mov rdx, 21
    syscall
    jmp exit

test_mov_gpr8_memb:
    mov rbp, rsp
    sub rsp, 8
    mov byte ptr [rbp - 1], 0x42
    mov al, byte ptr [rbp - 1]
    cmp al, 0x42
    jne fail_mov_gpr8_memb
    jmp test_setl_gpr8

fail_mov_gpr8_memb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_gpr8_memb_error_msg]
    mov rdx, 23
    syscall
    jmp exit

test_setl_gpr8:
    mov rbp, rsp
    sub rsp, 8
    mov al, -1
    sub al, 1
    setl al
    cmp al, 1
    jne fail_setl_gpr8
    jmp test_mov_memb_gpr8

fail_setl_gpr8:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + setl_gpr8_error_msg]
    mov rdx, 22
    syscall
    jmp exit

test_mov_memb_gpr8:
    mov rbp, rsp
    sub rsp, 8
    mov al, 0x40
    mov byte ptr [rbp - 1], al
    cmp byte ptr [rbp - 1], 0x40
    jne fail_mov_memb_gpr8
    jmp test_cmp_al_immb

fail_mov_memb_gpr8:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_memb_gpr8_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_cmp_al_immb:
    mov rbp, rsp
    sub rsp, 8
    mov al, 0x41
    cmp al, 0x41
    jne fail_cmp_al_immb
    jmp test_mov_gpr8_immb_b0

fail_cmp_al_immb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + cmp_al_immb_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_mov_gpr8_immb_b0:
    mov rbp, rsp
    sub rsp, 8
    mov al, 0x42
    cmp al, 0x42
    jne fail_mov_gpr8_immb_b0
    jmp test_mov_gprv_immz

fail_mov_gpr8_immb_b0:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_gpr8_immb_b0_error_msg]
    mov rdx, 25
    syscall
    jmp exit

.globl func1
.type  func1, @function

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
    jmp test_push_pop
    
fail_mov_memv_gprv:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + mov_memv_gprv_error_msg]
    mov rdx, 23
    syscall
    jmp exit

test_push_pop:
    mov rax, 15
    push rax
    pop rbx
    cmp rbx, 15
    jne fail_push_pop
    jmp test_call_procedure

fail_push_pop:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + push_pop_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_call_procedure:
    mov rdi, 30
    mov rsi, 30
    call func1
    cmp rax, 60
    jne fail_call_procedure
    jmp test_jnl_relbrd

fail_call_procedure:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + call_procedure_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_jnl_relbrd:
    mov rax, 20
    cmp rax, 20
    jge test_cmp_memv_immz
    jmp fail_jnl_relbrd

fail_jnl_relbrd:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + jnl_relbrd_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_cmp_memv_immz:
    mov rbp, rsp
    sub rsp, 8
    mov dword ptr [rbp - 4], 100
    cmp dword ptr [rbp - 4], 100
    jne fail_cmp_memv_immz
    jmp test_sub_gprv_immz

fail_cmp_memv_immz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + cmp_memv_immz_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_sub_gprv_immz:
    mov rax, 20
    sub rax, 10
    cmp rax, 10
    jne fail_sub_gprv_immz
    jmp test_cmp_memv_immb

fail_sub_gprv_immz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + sub_gprv_immz_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_cmp_memv_immb:
    mov rbp, rsp
    sub rsp, 8
    mov dword ptr [rbp - 4], 0
    cmp dword ptr [rbp - 4], 0
    jne fail_cmp_memv_immb
    jmp test_jnz_relbrd

fail_cmp_memv_immb:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + cmp_memv_immb_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_jnz_relbrd:
    mov rax, 15
    cmp rax, 15
    jne fail_jnz_relbrd
    jmp test_movsxd_gprv_memz

fail_jnz_relbrd:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + jnz_relbrd_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_movsxd_gprv_memz:
    mov rbp, rsp
    sub rsp, 8
    mov dword ptr [rbp - 4], 5
    movsxd rax, dword ptr [rbp - 4]
    cmp rax, 5
    jne fail_movsxd_gprv_memz
    jmp test_shl_gprv_immb_c1r4

fail_movsxd_gprv_memz:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + movsxd_gprv_memz_error_msg]
    mov rdx, 25
    syscall
    jmp exit

test_shl_gprv_immb_c1r4:
    mov rbp, rsp
    sub rsp, 8
    mov rax, 0x1
    shl rax, 2
    cmp rax, 4
    jne fail_shl_gprv_immb_c1r4
    jmp success

fail_shl_gprv_immb_c1r4:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + shl_gprv_immb_c1r4_error_msg]
    mov rdx, 26
    syscall
    jmp exit

force_jle_relbrd:
    jmp test_cdqe

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