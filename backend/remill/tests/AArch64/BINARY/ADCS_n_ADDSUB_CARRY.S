/* ADCS  <Wd>, <Wn>, <Wm> */
TEST_BEGIN(ADCS_32_ADDSUB_CARRY, adcs_w9_w0_w1, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304)

    adcs w9, ARG1_32, ARG2_32
TEST_END


/* ADCS  <Xd>, <Xn>, <Xm> */
TEST_BEGIN(ADCS_64_ADDSUB_CARRY, adcs_x9_x0_x1, 2)
TEST_INPUTS(
    0, 0,
    0, 1,
    1, 0,
    1, 1,
    0xFFFFFFFF, 0xFFFFFFFF,
    0, 0xFFFFFFFF,
    0xfafbfbfd, 0xf1f2f3f4,
    0x0a0b0c0d, 0x01020304,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFF, 0,
    0, 0xFFFFFFFFFFFFFFFF,
    0xfafbfbfdf1f2f3f4, 0xf1f2f3f4fafbfbfd,
    0x0a0b0c0d01020304, 0x010203040a0b0c0d)

    adcs x9, ARG1_64, ARG2_64
TEST_END
