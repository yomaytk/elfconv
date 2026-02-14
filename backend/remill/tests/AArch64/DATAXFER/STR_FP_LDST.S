/* STR  <Bt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STR_B_LDST_IMMPOST, str_b0_immpost, 1)
TEST_INPUTS(
    0x00000000000000FF,
    0x0000000000000080,
    0x0000000000000000,
    0x0000000000000041,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str b0, [x3], #8
    str b0, [x3], #8
    str b0, [x3], #8
TEST_END

/* STR  <Ht>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STR_H_LDST_IMMPOST, str_h0_immpost, 1)
TEST_INPUTS(
    0x000000000000FFFF,
    0x0000000000008000,
    0x0000000000000000,
    0x0000000000004141,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str h0, [x3], #8
    str h0, [x3], #8
    str h0, [x3], #8
TEST_END

/* STR  <St>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STR_S_LDST_IMMPOST, str_s0_immpost, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str s0, [x3], #8
    str s0, [x3], #8
    str s0, [x3], #8
TEST_END

/* STR  <Dt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STR_D_LDST_IMMPOST, str_d0_immpost, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str d0, [x3], #16
    str d0, [x3], #16
    str d0, [x3], #16
TEST_END

/* STR  <Qt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(STR_Q_LDST_IMMPOST, str_q0_immpost, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    dup v0.2d, ARG1_64
    str q0, [x3], #32
    str q0, [x3], #32
    str q0, [x3], #32
TEST_END

/* STR  <Bt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STR_B_LDST_IMMPRE, str_b0_immpre, 1)
TEST_INPUTS(
    0x00000000000000FF,
    0x0000000000000080,
    0x0000000000000000,
    0x0000000000000041,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str b0, [x3, #0]!
    str b0, [x3, #8]!
    str b0, [x3, #8]!
TEST_END

/* STR  <Ht>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STR_H_LDST_IMMPRE, str_h0_immpre, 1)
TEST_INPUTS(
    0x000000000000FFFF,
    0x0000000000008000,
    0x0000000000000000,
    0x0000000000004141,
    0x0000000000000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str h0, [x3, #0]!
    str h0, [x3, #8]!
    str h0, [x3, #8]!
TEST_END

/* STR  <St>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STR_S_LDST_IMMPRE, str_s0_immpre, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str s0, [x3, #0]!
    str s0, [x3, #8]!
    str s0, [x3, #8]!
TEST_END

/* STR  <Dt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(STR_D_LDST_IMMPRE, str_d0_immpre, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    str d0, [x3, #0]!
    str d0, [x3, #16]!
    str d0, [x3, #16]!
TEST_END

/* STR  <Dt>, [<Xn|SP>, <Xm>{, <extend> {<amount>}}] */
TEST_BEGIN(STR_D_LDST_REGOFF, str_d0_regoff, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x4000000000000000,
    0x0000000000000000,
    0x7FF0000000000000,
    0xFFFFFFFFFFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #0
    str d0, [x3, x4]
    mov x4, #16
    str d0, [x3, x4]
    mov x4, #32
    str d0, [x3, x4]
TEST_END

/* STR  <St>, [<Xn|SP>, <Xm>{, <extend> {<amount>}}] */
TEST_BEGIN(STR_S_LDST_REGOFF, str_s0_regoff, 1)
TEST_INPUTS(
    0x000000003F800000,
    0x0000000040000000,
    0x0000000000000000,
    0x000000007F800000,
    0x00000000FFFFFFFF)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #0
    str s0, [x3, x4]
    mov x4, #8
    str s0, [x3, x4]
    mov x4, #16
    str s0, [x3, x4]
TEST_END
