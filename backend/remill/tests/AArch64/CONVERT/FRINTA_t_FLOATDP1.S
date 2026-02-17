TEST_BEGIN(FRINTA_D_FLOATDP1, frinta_d0_d1, 1)
TEST_INPUTS(
    0x4004000000000000,  /* 2.5 -> 3.0 (round away from zero) */
    0xc004000000000000,  /* -2.5 -> -3.0 */
    0x3ff8000000000000,  /* 1.5 -> 2.0 */
    0x0000000000000000,  /* 0.0 -> 0.0 */
    0x400c000000000000,  /* 3.5 -> 4.0 */
    0x4024000000000000)  /* 10.0 -> 10.0 */

    fmov d1, ARG1_64
    frinta d0, d1
TEST_END
