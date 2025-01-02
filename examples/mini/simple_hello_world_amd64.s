.section .data
hello_msg: 
    .string "Hello, World!\n"  # グローバル文字列データ

.section .text
.globl _start
_start:
    # writeシステムコール
    movq $1, %rax            # syscall番号 (1: write)
    movq $1, %rdi            # 第一引数: ファイルディスクリプタ (1: stdout)
    leaq hello_msg(%rip), %rsi  # 第二引数: 書き込むデータのアドレス
    movq $14, %rdx           # 第三引数: 書き込むデータのサイズ (14 bytes)
    syscall                  # システムコール呼び出し

    # exitシステムコール
    movq $60, %rax           # syscall番号 (60: exit)
    xorq %rdi, %rdi          # 第一引数: 終了ステータス (0)
    syscall                  # システムコール呼び出し