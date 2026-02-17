TEST_BEGIN(FSQRT_S_FLOATDP1, fsqrt_s0_s1, 1)
TEST_INPUTS(
    0x40800000,  /* 4.0 */
    0x41c80000,  /* 25.0 */
    0x3f800000,  /* 1.0 */
    0x00000000,  /* +0.0 */
    0x80000000,  /* -0.0 */
    0x7f800000)  /* +inf */

    fmov s1, ARG1_32
    fsqrt s0, s1
TEST_END

TEST_BEGIN(FSQRT_D_FLOATDP1, fsqrt_d0_d1, 1)
TEST_INPUTS(
    0x4010000000000000,  /* 4.0 */
    0x4039000000000000,  /* 25.0 */
    0x3ff0000000000000,  /* 1.0 */
    0x0000000000000000,  /* +0.0 */
    0x8000000000000000,  /* -0.0 */
    0x7ff0000000000000)  /* +inf */

    fmov d1, ARG1_64
    fsqrt d0, d1
TEST_END
