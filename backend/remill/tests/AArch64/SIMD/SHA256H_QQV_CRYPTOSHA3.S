.arch armv8-a+crypto

TEST_BEGIN(SHA256H_QQV_CRYPTOSHA3, sha256h_q0_q1_v2, 2)
TEST_INPUTS(
    0x6a09e667bb67ae85, 0x3c6ef372a54ff53a,
    0x510e527f9b05688c, 0x1f83d9ab5be0cd19,
    0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    0x0001020304050607, 0x08090a0b0c0d0e0f,
    0x428a2f9871374491, 0xb5c0fbcfe9b5dba5)
    fmov d0, ARG1_64
    fmov v0.d[1], ARG2_64
    dup v1.2d, ARG1_64
    dup v2.2d, ARG2_64
    sha256h q0, q1, v2.4s
TEST_END
