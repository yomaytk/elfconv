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

TEST_BEGIN(ADDV_ASIMDALL_ONLY_8B, addv_v8b, 1)
TEST_INPUTS(0)
    addv b5, v0.8b
    addv b6, v1.8b
    addv b7, v2.8b
    addv b8, v3.8b
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_16B, addv_v16b, 1)
TEST_INPUTS(0)
    addv b5, v0.16b
    addv b6, v1.16b
    addv b7, v2.16b
    addv b8, v3.16b
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_4H, addv_v4h, 1)
TEST_INPUTS(0)
    addv h5, v0.4h
    addv h6, v1.4h
    addv h7, v2.4h
    addv h8, v3.4h
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_8H, addv_v8h, 1)
TEST_INPUTS(0)
    addv h5, v0.8h
    addv h6, v1.8h
    addv h7, v2.8h
    addv h8, v3.8h
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_4S, addv_v4s, 1)
TEST_INPUTS(0)
    addv s5, v0.4s
    addv s6, v1.4s
    addv s7, v2.4s
    addv s8, v3.4s
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_8B_INPUTS, addv_v8b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    fmov d1, ARG1_64
    addv b0, v1.8b
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_16B_INPUTS, addv_v16b_inputs, 1)
TEST_INPUTS(
    0x0102040810204080,
    0xFF00FF00FF00FF00,
    0x80817F7E01020304)
    dup v1.2d, ARG1_64
    addv b0, v1.16b
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_4H_INPUTS, addv_v4h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    fmov d1, ARG1_64
    addv h0, v1.4h
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_8H_INPUTS, addv_v8h_inputs, 1)
TEST_INPUTS(
    0x0001800000017FFF,
    0xFFFF000000010002,
    0x8000FFFF7FFF0001)
    dup v1.2d, ARG1_64
    addv h0, v1.8h
TEST_END

TEST_BEGIN(ADDV_ASIMDALL_ONLY_4S_INPUTS, addv_v4s_inputs, 1)
TEST_INPUTS(
    0x0000000180000000,
    0xFFFFFFFF00000001,
    0x7FFFFFFF80000001)
    dup v1.2d, ARG1_64
    addv s0, v1.4s
TEST_END
