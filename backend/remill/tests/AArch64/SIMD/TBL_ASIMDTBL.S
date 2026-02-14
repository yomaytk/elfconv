TEST_BEGIN(TBL_ASIMDTBL_L1_1_8B, tbl_v0_v1_v2_8b_1, 1)
TEST_INPUTS(0)
    movi v2.8b, #3
    tbl v0.8b, {v1.16b}, v2.8b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L1_1_8B_V2, tbl_v0_v1_v2_8b_1_v2, 1)
TEST_INPUTS(0)
    movi v2.8b, #7
    tbl v0.8b, {v1.16b}, v2.8b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L1_1_16B, tbl_v0_v1_v2_16b_1, 1)
TEST_INPUTS(0)
    movi v2.16b, #5
    tbl v0.16b, {v1.16b}, v2.16b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L1_1_16B_V2, tbl_v0_v1_v2_16b_1_v2, 1)
TEST_INPUTS(0)
    movi v2.16b, #11
    tbl v0.16b, {v1.16b}, v2.16b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L2_2_8B, tbl_v0_v1v2_v3_8b_2, 1)
TEST_INPUTS(0)
    movi v3.8b, #10
    tbl v0.8b, {v1.16b, v2.16b}, v3.8b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L2_2_8B_V2, tbl_v0_v1v2_v3_8b_2_v2, 1)
TEST_INPUTS(0)
    movi v3.8b, #15
    tbl v0.8b, {v1.16b, v2.16b}, v3.8b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L2_2_16B, tbl_v0_v1v2_v3_16b_2, 1)
TEST_INPUTS(0)
    movi v3.16b, #10
    tbl v0.16b, {v1.16b, v2.16b}, v3.16b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L2_2_16B_V2, tbl_v0_v1v2_v3_16b_2_v2, 1)
TEST_INPUTS(0)
    movi v3.16b, #20
    tbl v0.16b, {v1.16b, v2.16b}, v3.16b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L1_1_8B_INPUTS, tbl_v8b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    fmov d1, ARG1_64
    movi v2.8b, #3
    tbl v0.8b, {v1.16b}, v2.8b
TEST_END

TEST_BEGIN(TBL_ASIMDTBL_L1_1_16B_INPUTS, tbl_v16b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    dup v1.2d, ARG1_64
    movi v2.16b, #5
    tbl v0.16b, {v1.16b}, v2.16b
TEST_END
