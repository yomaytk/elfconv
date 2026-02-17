TEST_BEGIN(BIC_ASIMDIMM_L_HL_4H, bic_v0_4h_imm, 1)
TEST_INPUTS(0)
    movi v0.4h, #0xff
    bic v0.4h, #0x0f
    movi v3.4h, #0xab
    bic v3.4h, #0x11
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_HL_8H, bic_v0_8h_imm, 1)
TEST_INPUTS(0)
    movi v0.8h, #0xff
    bic v0.8h, #0x0f
    movi v3.8h, #0xcd
    bic v3.8h, #0x22
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_SL_2S, bic_v0_2s_imm, 1)
TEST_INPUTS(0)
    movi v0.2s, #0xff
    bic v0.2s, #0x0f
    movi v3.2s, #0x55
    bic v3.2s, #0x33
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_SL_4S, bic_v0_4s_imm, 1)
TEST_INPUTS(0)
    movi v0.4s, #0xff
    bic v0.4s, #0x0f
    movi v3.4s, #0xef
    bic v3.4s, #0x44
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_HL_4H_INPUTS, bic_v4h_inputs, 1)
TEST_INPUTS(
    0x0001000200030004,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    fmov d0, ARG1_64
    bic v0.4h, #0x0f
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_HL_8H_INPUTS, bic_v8h_inputs, 1)
TEST_INPUTS(
    0x0001000200030004,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    dup v0.2d, ARG1_64
    bic v0.8h, #0x0f
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_SL_2S_INPUTS, bic_v2s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    fmov d0, ARG1_64
    bic v0.2s, #0x0f
TEST_END

TEST_BEGIN(BIC_ASIMDIMM_L_SL_4S_INPUTS, bic_v4s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    dup v0.2d, ARG1_64
    bic v0.4s, #0x0f
TEST_END
