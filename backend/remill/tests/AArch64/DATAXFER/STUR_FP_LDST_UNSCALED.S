/* STUR  <Bt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_B_LDST_UNSCALED, stur_b0_unscaled, 1)
TEST_INPUTS(
    0x00000000000000FF,
    0x0000000000000080,
    0x0000000000000041,
    0x0000000000000000,
    0x00000000000000AB,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    stur b0, [x3, #0]
    stur b0, [x3, #8]
    stur b0, [x3, #16]
TEST_END

/* STUR  <Ht>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_H_LDST_UNSCALED, stur_h0_unscaled, 1)
TEST_INPUTS(
    0x000000000000FFFF,
    0x0000000000008000,
    0x0000000000004141,
    0x0000000000000000,
    0x000000000000ABCD,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    stur h0, [x3, #0]
    stur h0, [x3, #8]
    stur h0, [x3, #16]
TEST_END

/* STUR  <St>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_S_LDST_UNSCALED, stur_s0_unscaled, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FF800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    stur s0, [x3, #0]
    stur s0, [x3, #8]
    stur s0, [x3, #16]
TEST_END

/* STUR  <Dt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_D_LDST_UNSCALED, stur_d0_unscaled, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    stur d0, [x3, #0]
    stur d0, [x3, #16]
    stur d0, [x3, #32]
TEST_END

/* STUR  <Qt>, [<Xn|SP>{, #<simm>}] */
TEST_BEGIN(STUR_Q_LDST_UNSCALED, stur_q0_unscaled, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    dup v0.2d, ARG1_64
    stur q0, [x3, #0]
    stur q0, [x3, #32]
    stur q0, [x3, #64]
TEST_END
