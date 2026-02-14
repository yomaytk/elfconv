TEST_BEGIN(FCVTZS_64S_FLOAT2INT, fcvtzs_x0_s0, 1)
TEST_INPUTS(
    0x40200000,  /* 2.5 -> 2 (truncate) */
    0xc0200000,  /* -2.5 -> -2 */
    0x3fc00000,  /* 1.5 -> 1 */
    0x00000000,  /* 0.0 -> 0 */
    0x3f800000,  /* 1.0 -> 1 */
    0x41200000)  /* 10.0 -> 10 */

    fmov s0, ARG1_32
    fcvtzs x0, s0
TEST_END
