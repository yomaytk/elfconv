TEST_BEGIN(FMAX_S_FLOATDP2, fmax_s4_s0_s1, 1)
TEST_INPUTS(0)
    fmov s0, #1.0
    fmov s1, #2.0
    fmax s4, s0, s1
TEST_END

TEST_BEGIN(FMAX_S_FLOATDP2_NEG, fmax_s4_s0_s1_neg, 1)
TEST_INPUTS(0)
    fmov s0, #-3.0
    fmov s1, #-1.0
    fmax s4, s0, s1
TEST_END

TEST_BEGIN(FMAX_S_FLOATDP2_ZERO, fmax_s4_s0_s1_zero, 1)
TEST_INPUTS(0)
    fmov s0, #1.0
    fmov s1, #0.0
    fmax s4, s0, s1
TEST_END

TEST_BEGIN(FMAX_S_FLOATDP2_SAME, fmax_s4_s0_s1_same, 1)
TEST_INPUTS(0)
    fmov s0, #5.0
    fmov s1, #5.0
    fmax s4, s0, s1
TEST_END

TEST_BEGIN(FMAX_S_FLOATDP2_LARGE, fmax_s4_s0_s1_large, 1)
TEST_INPUTS(0)
    fmov s0, #10.0
    fmov s1, #0.5
    fmax s4, s0, s1
TEST_END

TEST_BEGIN(FMAX_D_FLOATDP2, fmax_d4_d0_d1, 1)
TEST_INPUTS(0)
    fmov d0, #1.0
    fmov d1, #2.0
    fmax d4, d0, d1
TEST_END

TEST_BEGIN(FMAX_D_FLOATDP2_NEG, fmax_d4_d0_d1_neg, 1)
TEST_INPUTS(0)
    fmov d0, #-3.0
    fmov d1, #-1.0
    fmax d4, d0, d1
TEST_END

TEST_BEGIN(FMAX_D_FLOATDP2_ZERO, fmax_d4_d0_d1_zero, 1)
TEST_INPUTS(0)
    fmov d0, #1.0
    fmov d1, #0.0
    fmax d4, d0, d1
TEST_END

TEST_BEGIN(FMAX_D_FLOATDP2_SAME, fmax_d4_d0_d1_same, 1)
TEST_INPUTS(0)
    fmov d0, #5.0
    fmov d1, #5.0
    fmax d4, d0, d1
TEST_END

TEST_BEGIN(FMAX_D_FLOATDP2_LARGE, fmax_d4_d0_d1_large, 1)
TEST_INPUTS(0)
    fmov d0, #10.0
    fmov d1, #0.5
    fmax d4, d0, d1
TEST_END
