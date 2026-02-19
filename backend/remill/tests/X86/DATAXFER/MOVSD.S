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

#if APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv128m64, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    movsd xmm0,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVSDv128m64_4, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    movsd xmm1,QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(MOVSDm64v128, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    movsd QWORD PTR [rsp - 8], xmm0
TEST_END

#endif  // APPLE_SAFE_TESTS

TEST_BEGIN(MOVSDv128v128, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    movsd xmm0, xmm4
TEST_END

TEST_BEGIN(MOVSDv128v128_4, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    movsd xmm4, xmm0
TEST_END

#if HAS_FEATURE_AVX
#if APPLE_SAFE_TESTS

TEST_BEGIN(VMOVSDv128m64, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd xmm0, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVSDv128m64_4, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd xmm4, QWORD PTR [rsp - 8]
TEST_END

TEST_BEGIN(VMOVSDm64v128, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd QWORD PTR [rsp - 8], xmm0
TEST_END

TEST_BEGIN(VMOVSDm64v128_4, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd QWORD PTR [rsp - 8], xmm4
TEST_END

TEST_BEGIN(VMOVSDv128v128v128, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd xmm0, xmm1, xmm4
TEST_END

TEST_BEGIN(VMOVSDv128v128v128_4, 1)
TEST_INPUTS(
    0,
    1,
    0x41,
    0xFF,
    0x7F,
    0xFFFF,
    0x7FFF,
    0xFFFFFFFF,
    0x7FFFFFFF,
    0x7FFFFFFFFFFFFFFF)
    vmovsd xmm4, xmm1, xmm0
TEST_END
#endif  // APPLE_SAFE_TESTS
#endif  // HAS_FEATURE_AVX
