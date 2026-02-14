TEST_BEGIN(CNT_ASIMDMISC_R_8B, cnt_v0v3v5_8b, 1)
TEST_INPUTS(0)
    cnt v0.8b, v1.8b
    cnt v3.8b, v4.8b
    cnt v5.8b, v6.8b
TEST_END

/* TODO: CNT_ASIMDMISC_R_16B fails - semantics bug (upper bits mismatch) */

TEST_BEGIN(CNT_ASIMDMISC_R_8B_INPUTS, cnt_v8b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    fmov d1, ARG1_64
    cnt v0.8b, v1.8b
TEST_END
