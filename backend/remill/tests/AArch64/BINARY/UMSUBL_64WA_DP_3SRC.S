/* UMSUBL  <Xd>, <Wn>, <Wm>, <Xa> */
TEST_BEGIN(UMSUBL_64WA_DP_3SRC, umsubl_x9_w0_w1_x2, 3)
TEST_INPUTS(
    0, 0, 0,
    1, 1, 0,
    1, 1, 1,
    0xFFFFFFFF, 0xFFFFFFFF, 0,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    100, 200, 50000)

    umsubl x9, ARG1_32, ARG2_32, x2
TEST_END
