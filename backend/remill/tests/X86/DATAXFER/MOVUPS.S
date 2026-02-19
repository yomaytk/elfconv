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

/* NOTE:
 * YMM0 - YMM3 are filled will 0xFF.
 * YMM4 and on are filled with 0x0. */

TEST_BEGIN(MOVUPSv128v128_1to0, 1)
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
    movups xmm4, xmm0
TEST_END


TEST_BEGIN(MOVUPSv128v128_0to1, 1)
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
    movups xmm0, xmm4
TEST_END

#if HAS_FEATURE_AVX

TEST_BEGIN(VMOVUPSv128v128_1to0, 1)
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
    vmovups xmm4, xmm0
TEST_END

TEST_BEGIN(VMOVUPSv128v128_0to1, 1)
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
    vmovups xmm0, xmm4
TEST_END

TEST_BEGIN(VMOVUPSv256v256_1to0, 1)
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
    vmovups ymm4, ymm0
TEST_END

TEST_BEGIN(VMOVUPSv256v256_0to1, 1)
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
    vmovups ymm0, ymm4
TEST_END

#endif
