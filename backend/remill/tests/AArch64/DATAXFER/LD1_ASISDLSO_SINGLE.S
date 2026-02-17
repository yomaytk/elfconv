/* LD1  {<Vt>.B}[<index>], [<Xn|SP>] */
TEST_BEGIN(LD1_ASISDLSO_B1_1B, ld1_v0b_idx0, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ld1 {v0.b}[0], [x3]
    ld1 {v1.b}[3], [x3]
    ld1 {v2.b}[7], [x3]
TEST_END

/* LD1  {<Vt>.H}[<index>], [<Xn|SP>] */
TEST_BEGIN(LD1_ASISDLSO_H1_1H, ld1_v0h_idx0, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000FFFF7FFF0001)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ld1 {v0.h}[0], [x3]
    ld1 {v1.h}[1], [x3]
    ld1 {v2.h}[3], [x3]
TEST_END

/* LD1  {<Vt>.S}[<index>], [<Xn|SP>] */
TEST_BEGIN(LD1_ASISDLSO_S1_1S, ld1_v0s_idx0, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x7FFFFFFF80000001)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ld1 {v0.s}[0], [x3]
    ld1 {v1.s}[1], [x3]
    ld1 {v2.s}[2], [x3]
TEST_END

/* LD1  {<Vt>.D}[<index>], [<Xn|SP>] */
TEST_BEGIN(LD1_ASISDLSO_D1_1D, ld1_v0d_idx0, 1)
TEST_INPUTS(
    0x3FF0000000000000,
    0x7FF0000000000000,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000)
    add x3, sp, #-256
    str ARG1_64, [x3]
    ld1 {v0.d}[0], [x3]
    ld1 {v1.d}[1], [x3]
TEST_END
