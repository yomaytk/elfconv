/* LDUR  <Bt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_B_LDST_UNSCALED, ldur_b0_unscaled, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304,
    0xABCDEF0123456789)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ldur b0, [x3, #0]
    ldur b1, [x3, #1]
    ldur b2, [x3, #2]
TEST_END

/* LDUR  <Ht>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_H_LDST_UNSCALED, ldur_h0_unscaled, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304,
    0xABCDEF0123456789)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ldur h0, [x3, #0]
    ldur h1, [x3, #2]
    ldur h2, [x3, #4]
TEST_END

/* LDUR  <St>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_S_LDST_UNSCALED, ldur_s0_unscaled, 1)
TEST_INPUTS(
    0x3F80000040000000,
    0x7F800000FF800000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x41414141ABABABAB,
    0x7FF8000000000001)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ldur s0, [x3, #0]
    ldur s1, [x3, #4]
TEST_END

/* LDUR  <Dt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_D_LDST_UNSCALED, ldur_d0_unscaled, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x7FF0000000000000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFF0000000000000,
    0x4141414141414141)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ldur d0, [x3, #0]
TEST_END

/* LDUR  <Qt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDUR_Q_LDST_UNSCALED, ldur_q0_unscaled, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x7FF0000000000000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0xFFF0000000000000,
    0x4141414141414141)
    add x3, sp, #-256
    stp ARG1_64, ARG1_64, [x3]
    ldur q0, [x3, #0]
TEST_END

/* LDURSH  <Xt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(LDURSH_64_LDST_UNSCALED, ldursh_x0_unscaled, 1)
TEST_INPUTS(
    0x0000000000000001,
    0x000000000000FFFF,
    0x0000000000008000,
    0x0000000000007FFF,
    0x0000000000000000,
    0x00000000000000FF)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ldursh x0, [x3, #0]
    ldursh x1, [x3, #0]
TEST_END
