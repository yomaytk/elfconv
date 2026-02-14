TEST_BEGIN(FCVTAS_64D_FLOAT2INT, fcvtas_x0_d0, 1)
TEST_INPUTS(
    0x4004000000000000,  /* 2.5 -> 3 (round to nearest, ties away) */
    0xc004000000000000,  /* -2.5 -> -3 */
    0x3ff8000000000000,  /* 1.5 -> 2 */
    0x0000000000000000,  /* 0.0 -> 0 */
    0x3ff0000000000000,  /* 1.0 -> 1 */
    0x4024000000000000)  /* 10.0 -> 10 */

    fmov d0, ARG1_64
    fcvtas x0, d0
TEST_END
