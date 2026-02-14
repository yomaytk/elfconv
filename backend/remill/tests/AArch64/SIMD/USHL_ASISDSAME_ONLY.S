TEST_BEGIN(USHL_ASISDSAME_ONLY, ushl_d0_d1_d2, 1)
TEST_INPUTS(0)
    mov x2, #3
    fmov d2, x2
    ushl d0, d1, d2
TEST_END

TEST_BEGIN(USHL_ASISDSAME_ONLY_NEG, ushl_d0_d1_d2_neg, 1)
TEST_INPUTS(0)
    mov x2, #-4
    fmov d2, x2
    ushl d0, d1, d2
TEST_END

TEST_BEGIN(USHL_ASISDSAME_ONLY_ZERO, ushl_d0_d1_d2_zero, 1)
TEST_INPUTS(0)
    mov x2, #0
    fmov d2, x2
    ushl d0, d1, d2
TEST_END

TEST_BEGIN(USHL_ASISDSAME_ONLY_LARGE, ushl_d0_d1_d2_large, 1)
TEST_INPUTS(0)
    mov x2, #48
    fmov d2, x2
    ushl d0, d1, d2
TEST_END

TEST_BEGIN(USHL_ASISDSAME_ONLY_INPUTS, ushl_d_inputs, 2)
TEST_INPUTS(
    0x0000000000000001, 0x0000000000000003,
    0x8000000000000000, 0xFFFFFFFFFFFFFFFC,
    0xFFFFFFFFFFFFFFFF, 0x0000000000000000)
    fmov d1, ARG1_64
    fmov d2, ARG2_64
    ushl d0, d1, d2
TEST_END
