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

TEST_BEGIN(UMINV_ASIMDALL_ONLY_8B, uminv_v8b, 1)
TEST_INPUTS(0)
    uminv b5, v0.8b
    uminv b6, v1.8b
    uminv b7, v2.8b
    uminv b8, v3.8b
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_16B, uminv_v16b, 1)
TEST_INPUTS(0)
    uminv b5, v0.16b
    uminv b6, v1.16b
    uminv b7, v2.16b
    uminv b8, v3.16b
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_4H, uminv_v4h, 1)
TEST_INPUTS(0)
    uminv h5, v0.4h
    uminv h6, v1.4h
    uminv h7, v2.4h
    uminv h8, v3.4h
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_8H, uminv_v8h, 1)
TEST_INPUTS(0)
    uminv h5, v0.8h
    uminv h6, v1.8h
    uminv h7, v2.8h
    uminv h8, v3.8h
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_4S, uminv_v4s, 1)
TEST_INPUTS(0)
    uminv s5, v0.4s
    uminv s6, v1.4s
    uminv s7, v2.4s
    uminv s8, v3.4s
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_8B_INPUTS, uminv_v8b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    fmov d1, ARG1_64
    uminv b0, v1.8b
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_16B_INPUTS, uminv_v16b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    dup v1.2d, ARG1_64
    uminv b0, v1.16b
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_4H_INPUTS, uminv_v4h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    fmov d1, ARG1_64
    uminv h0, v1.4h
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_8H_INPUTS, uminv_v8h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    dup v1.2d, ARG1_64
    uminv h0, v1.8h
TEST_END

TEST_BEGIN(UMINV_ASIMDALL_ONLY_4S_INPUTS, uminv_v4s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    dup v1.2d, ARG1_64
    uminv s0, v1.4s
TEST_END
