/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

TEST_BEGIN(SUBSSv128v128_04, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    subss xmm0, xmm4
TEST_END

TEST_BEGIN(SUBSSv128v128_40, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    subss xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS

TEST_BEGIN(SUBSSv128m128_04, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    movdqu [rsp - 16], xmm4
    subss xmm0, [rsp - 16]
TEST_END

TEST_BEGIN(SUBSSv128m128_40, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    movdqu [rsp - 16], xmm0
    subss xmm4, [rsp - 16]
TEST_END

#endif  // APPLE_SAFE_TESTS

#if HAS_FEATURE_AVX
TEST_BEGIN(VSUBSSv128v128_04, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    vsubss xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VSUBSSv128v128_40, 1)
TEST_INPUTS(
    0x0000000000000000,  /* +0.0 */
    0x3FE0000000000000,  /* 0.5 */
    0x3FF0000000000000,  /* 1.0 */
    0x4000000000000000,  /* 2.0 */
    0x4059000000000000,  /* 100.0 */
    0x400921FB54442D18,  /* pi */
    0x8000000000000000,  /* -0.0 */
    0xBFF0000000000000,  /* -1.0 */
    0x7FF0000000000000,  /* +Inf */
    0x0010000000000000,  /* smallest normal */
    0x7FEFFFFFFFFFFFFF,  /* largest finite */
    0x0000000000000001,  /* smallest subnormal */
    0xFFFFFFFFFFFFFFFF)  /* NaN / all-ones */
    vsubss xmm1, xmm4, xmm0
TEST_END

#if APPLE_SAFE_TESTS
TEST_BEGIN_64(VSUBSSv128m32_40, 1)
TEST_INPUTS(
    0x3f800000,
    0x40490fdb,
    0x47c34f80)

    mov DWORD PTR [rsp - 16], ARG1_32
    vsubss xmm1, xmm4, DWORD PTR [rsp - 16]
TEST_END_64
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
