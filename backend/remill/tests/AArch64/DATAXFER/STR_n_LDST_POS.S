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

TEST_BEGIN(STR_32_LDST_POS, str_w0_m32, 1)
TEST_INPUTS(
    0x41414141,
    0x00000000,
    0xFFFFFFFF,
    0x80000000,
    0x7FFFFFFF)
    add x3, sp, #-256
    str ARG1_32, [x3, #0]
    str ARG1_32, [x3, #16]
    str ARG1_32, [x3, #32]
TEST_END

TEST_BEGIN(STR_64_LDST_POS, str_x0_m64, 1)
TEST_INPUTS(
    0x4141414151515151,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000,
    0x7FFFFFFFFFFFFFFF)
    add x3, sp, #-256
    str ARG1_64, [x3, #0]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #32]
TEST_END

TEST_BEGIN(STR_B_LDST_POS, str_b0_m8, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    fmov d3, ARG1_64
    str b0, [x3, #0]
    str b1, [x3, #16]
    str b3, [x3, #32]
TEST_END

TEST_BEGIN(STR_H_LDST_POS, str_h0_m16, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    fmov d3, ARG1_64
    str h0, [x3, #0]
    str h1, [x3, #16]
    str h3, [x3, #32]
TEST_END

TEST_BEGIN(STR_S_LDST_POS, str_s0_m32, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    fmov d3, ARG1_64
    str s0, [x3, #0]
    str s1, [x3, #16]
    str s3, [x3, #32]
TEST_END

TEST_BEGIN(STR_D_LDST_POS, str_d0_m64, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    fmov d0, ARG1_64
    fmov d1, ARG1_64
    fmov d3, ARG1_64
    str d0, [x3, #0]
    str d1, [x3, #16]
    str d3, [x3, #32]
TEST_END

TEST_BEGIN(STR_Q_LDST_POS, str_q0_m128, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    dup v0.2d, ARG1_64
    dup v1.2d, ARG1_64
    dup v3.2d, ARG1_64
    str q0, [x3, #0]
    str q1, [x3, #16]
    str q3, [x3, #32]
TEST_END
