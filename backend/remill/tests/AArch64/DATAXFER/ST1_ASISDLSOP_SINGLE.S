/* ST1  {<Vt>.B}[<index>], [<Xn|SP>], #1 */
TEST_BEGIN(ST1_ASISDLSOP_B1_I1B, st1_v0b_post_imm, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    st1 {v0.b}[0], [x3], #1
    st1 {v0.b}[3], [x3], #1
    st1 {v0.b}[7], [x3], #1
TEST_END

/* ST1  {<Vt>.B}[<index>], [<Xn|SP>], <Xm> */
TEST_BEGIN(ST1_ASISDLSOP_BX1_R1B, st1_v0b_post_reg, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #1
    st1 {v0.b}[0], [x3], x4
    st1 {v0.b}[3], [x3], x4
    st1 {v0.b}[7], [x3], x4
TEST_END

/* ST1  {<Vt>.H}[<index>], [<Xn|SP>], #2 */
TEST_BEGIN(ST1_ASISDLSOP_H1_I1H, st1_v0h_post_imm, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000FFFF7FFF0001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    st1 {v0.h}[0], [x3], #2
    st1 {v0.h}[1], [x3], #2
    st1 {v0.h}[3], [x3], #2
TEST_END

/* ST1  {<Vt>.H}[<index>], [<Xn|SP>], <Xm> */
TEST_BEGIN(ST1_ASISDLSOP_HX1_R1H, st1_v0h_post_reg, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000FFFF7FFF0001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #2
    st1 {v0.h}[0], [x3], x4
    st1 {v0.h}[1], [x3], x4
    st1 {v0.h}[3], [x3], x4
TEST_END

/* ST1  {<Vt>.S}[<index>], [<Xn|SP>], #4 */
TEST_BEGIN(ST1_ASISDLSOP_S1_I1S, st1_v0s_post_imm, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFF80000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    st1 {v0.s}[0], [x3], #4
    st1 {v0.s}[1], [x3], #4
TEST_END

/* ST1  {<Vt>.S}[<index>], [<Xn|SP>], <Xm> */
TEST_BEGIN(ST1_ASISDLSOP_SX1_R1S, st1_v0s_post_reg, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFF80000001)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #4
    st1 {v0.s}[0], [x3], x4
    st1 {v0.s}[1], [x3], x4
TEST_END

/* ST1  {<Vt>.D}[<index>], [<Xn|SP>], #8 */
TEST_BEGIN(ST1_ASISDLSOP_D1_I1D, st1_v0d_post_imm, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x7FF0000000000000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000)
    add x3, sp, #-256
    fmov d0, ARG1_64
    st1 {v0.d}[0], [x3], #8
TEST_END

/* ST1  {<Vt>.D}[<index>], [<Xn|SP>], <Xm> */
TEST_BEGIN(ST1_ASISDLSOP_DX1_R1D, st1_v0d_post_reg, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x7FF0000000000000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000)
    add x3, sp, #-256
    fmov d0, ARG1_64
    mov x4, #8
    st1 {v0.d}[0], [x3], x4
TEST_END
