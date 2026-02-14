TEST_BEGIN(FRINTM_D_FLOATDP1, frintm_d0_d1, 1)
TEST_INPUTS(
    0x4004000000000000,  /* 2.5 -> 2.0 (floor) */
    0xc004000000000000,  /* -2.5 -> -3.0 */
    0x3ff8000000000000,  /* 1.5 -> 1.0 */
    0x0000000000000000,  /* 0.0 -> 0.0 */
    0x400c000000000000,  /* 3.5 -> 3.0 */
    0xbff0000000000000)  /* -1.0 -> -1.0 */

    fmov d1, ARG1_64
    frintm d0, d1
TEST_END

TEST_BEGIN(FRINTM_S_FLOATDP1, frintm_s0_s1, 1)
TEST_INPUTS(
    0x40200000,  /* 2.5 -> 2.0 */
    0xc0200000,  /* -2.5 -> -3.0 */
    0x3fc00000,  /* 1.5 -> 1.0 */
    0x00000000,  /* 0.0 -> 0.0 */
    0x40600000,  /* 3.5 -> 3.0 */
    0xbf800000)  /* -1.0 -> -1.0 */

    fmov s1, ARG1_32
    frintm s0, s1
TEST_END
