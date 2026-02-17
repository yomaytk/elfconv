/* STP  <St1>, <St2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(STP_S_LDSTPAIR_POST, stp_s0_s1_post, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    stp s0, s1, [x3], #0
    stp s0, s1, [x3], #16
    stp s0, s1, [x3], #32
TEST_END

/* STP  <Dt1>, <Dt2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(STP_D_LDSTPAIR_POST, stp_d0_d1_post, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    stp d0, d1, [x3], #0
    stp d0, d1, [x3], #32
    stp d0, d1, [x3], #64
TEST_END

/* STP  <Qt1>, <Qt2>, [<Xn|SP>], #<imm> */
TEST_BEGIN(STP_Q_LDSTPAIR_POST, stp_q0_q1_post, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    dup v0.2d, ARG1_64
    dup v1.2d, ARG1_64
    stp q0, q1, [x3], #0
    stp q0, q1, [x3], #64
    stp q0, q1, [x3], #128
TEST_END

/* STP  <St1>, <St2>, [<Xn|SP>, #<imm>]! */
TEST_BEGIN(STP_S_LDSTPAIR_PRE, stp_s0_s1_pre, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    stp s0, s1, [x3, #0]!
    stp s0, s1, [x3, #16]!
    stp s0, s1, [x3, #16]!
TEST_END

/* STP  <Dt1>, <Dt2>, [<Xn|SP>, #<imm>]! */
TEST_BEGIN(STP_D_LDSTPAIR_PRE, stp_d0_d1_pre, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    stp d0, d1, [x3, #0]!
    stp d0, d1, [x3, #32]!
    stp d0, d1, [x3, #32]!
TEST_END

/* STP  <Qt1>, <Qt2>, [<Xn|SP>, #<imm>]! */
TEST_BEGIN(STP_Q_LDSTPAIR_PRE, stp_q0_q1_pre, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    dup v0.2d, ARG1_64
    dup v1.2d, ARG1_64
    stp q0, q1, [x3, #0]!
    stp q0, q1, [x3, #64]!
    stp q0, q1, [x3, #64]!
TEST_END
