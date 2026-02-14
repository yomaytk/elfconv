TEST_BEGIN(FCMPE_DZ_FLOATCMP, fcmpe_d0_0, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x8000000000000000,  /* -0.0 */
    0x3ff0000000000000,  /* 1.0 */
    0xbff0000000000000,  /* -1.0 */
    0x7ff0000000000000,  /* +inf */
    0xfff0000000000000,  /* -inf */
    0x7ff8000000000000)  /* NaN */

    fmov d0, ARG1_64
    fcmpe d0, #0.0
TEST_END
