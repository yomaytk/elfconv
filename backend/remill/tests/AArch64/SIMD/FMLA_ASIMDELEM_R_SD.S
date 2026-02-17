TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2S, fmla_v0_v1_v2s0_2s, 1)
TEST_INPUTS(0)
    fmov v0.2s, #1.0
    fmov v1.2s, #2.0
    fmov v2.2s, #3.0
    fmla v0.2s, v1.2s, v2.s[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2S_v2, fmla_v0_v1_v2s0_2s_v2, 1)
TEST_INPUTS(0)
    fmov v0.2s, #-1.0
    fmov v1.2s, #0.5
    fmov v2.2s, #4.0
    fmla v0.2s, v1.2s, v2.s[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_4S, fmla_v0_v1_v2s0_4s, 1)
TEST_INPUTS(0)
    fmov v0.4s, #1.0
    fmov v1.4s, #2.0
    fmov v2.4s, #3.0
    fmla v0.4s, v1.4s, v2.s[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_4S_v2, fmla_v0_v1_v2s0_4s_v2, 1)
TEST_INPUTS(0)
    fmov v0.4s, #2.0
    fmov v1.4s, #-2.0
    fmov v2.4s, #3.0
    fmla v0.4s, v1.4s, v2.s[1]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2D, fmla_v0_v1_v2d0_2d, 1)
TEST_INPUTS(0)
    fmov v0.2d, #1.0
    fmov v1.2d, #2.0
    fmov v2.2d, #3.0
    fmla v0.2d, v1.2d, v2.d[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2D_v2, fmla_v0_v1_v2d0_2d_v2, 1)
TEST_INPUTS(0)
    fmov v0.2d, #0.5
    fmov v1.2d, #4.0
    fmov v2.2d, #0.125
    fmla v0.2d, v1.2d, v2.d[1]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2S_INPUTS, fmla_elem_v2s_inputs, 2)
TEST_INPUTS(
    0x3F8000003F800000, 0x4000000040000000,
    0xBF800000C0000000, 0x40A000003F000000,
    0x4120000041200000, 0x3F0000003F000000)
    fmov v0.2s, #1.0
    fmov d1, ARG1_64
    fmov d2, ARG2_64
    fmla v0.2s, v1.2s, v2.s[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_4S_INPUTS, fmla_elem_v4s_inputs, 2)
TEST_INPUTS(
    0x3F8000003F800000, 0x4000000040000000,
    0xBF800000C0000000, 0x40A000003F000000,
    0x4120000041200000, 0x3F0000003F000000)
    fmov v0.4s, #1.0
    dup v1.2d, ARG1_64
    dup v2.2d, ARG2_64
    fmla v0.4s, v1.4s, v2.s[0]
TEST_END

TEST_BEGIN(FMLA_ASIMDELEM_R_SD_2D_INPUTS, fmla_elem_v2d_inputs, 2)
TEST_INPUTS(
    0x3FF0000000000000, 0x4000000000000000,
    0xBFF0000000000000, 0x4014000000000000,
    0x4024000000000000, 0x3FE0000000000000)
    fmov v0.2d, #1.0
    dup v1.2d, ARG1_64
    dup v2.2d, ARG2_64
    fmla v0.2d, v1.2d, v2.d[0]
TEST_END
