TEST_BEGIN(CMLE_ASIMDMISC_Z_8B, cmle_v0v3v5_8b_zero, 1)
TEST_INPUTS(0)
    cmle v0.8b, v1.8b, #0
    cmle v3.8b, v4.8b, #0
    cmle v5.8b, v6.8b, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_16B, cmle_v0v3v5_16b_zero, 1)
TEST_INPUTS(0)
    cmle v0.16b, v1.16b, #0
    cmle v3.16b, v4.16b, #0
    cmle v5.16b, v6.16b, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_4H, cmle_v0v3v5_4h_zero, 1)
TEST_INPUTS(0)
    cmle v0.4h, v1.4h, #0
    cmle v3.4h, v4.4h, #0
    cmle v5.4h, v6.4h, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_8H, cmle_v0v3v5_8h_zero, 1)
TEST_INPUTS(0)
    cmle v0.8h, v1.8h, #0
    cmle v3.8h, v4.8h, #0
    cmle v5.8h, v6.8h, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_2S, cmle_v0v3v5_2s_zero, 1)
TEST_INPUTS(0)
    cmle v0.2s, v1.2s, #0
    cmle v3.2s, v4.2s, #0
    cmle v5.2s, v6.2s, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_4S, cmle_v0v3v5_4s_zero, 1)
TEST_INPUTS(0)
    cmle v0.4s, v1.4s, #0
    cmle v3.4s, v4.4s, #0
    cmle v5.4s, v6.4s, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_2D, cmle_v0v3v5_2d_zero, 1)
TEST_INPUTS(0)
    cmle v0.2d, v1.2d, #0
    cmle v3.2d, v4.2d, #0
    cmle v5.2d, v6.2d, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_8B_INPUTS, cmle_z_v8b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    fmov d1, ARG1_64
    cmle v0.8b, v1.8b, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_16B_INPUTS, cmle_z_v16b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    dup v1.2d, ARG1_64
    cmle v0.16b, v1.16b, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_4H_INPUTS, cmle_z_v4h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    fmov d1, ARG1_64
    cmle v0.4h, v1.4h, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_8H_INPUTS, cmle_z_v8h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    dup v1.2d, ARG1_64
    cmle v0.8h, v1.8h, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_2S_INPUTS, cmle_z_v2s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    fmov d1, ARG1_64
    cmle v0.2s, v1.2s, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_4S_INPUTS, cmle_z_v4s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    dup v1.2d, ARG1_64
    cmle v0.4s, v1.4s, #0
TEST_END

TEST_BEGIN(CMLE_ASIMDMISC_Z_2D_INPUTS, cmle_z_v2d_inputs, 1)
TEST_INPUTS(
    0x0000000000000001,
    0x8000000000000000,
    0xFFFFFFFFFFFFFFFF)
    dup v1.2d, ARG1_64
    cmle v0.2d, v1.2d, #0
TEST_END
