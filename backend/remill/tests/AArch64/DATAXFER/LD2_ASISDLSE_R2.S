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

TEST_BEGIN(LD2_ASISDLSE_R2_16B, ld2_r2_16b, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #24]
    ld2 {v3.16b, v4.16b}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_8B, ld2_r2_8b, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.8b, v4.8b}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_4H, ld2_r2_4h, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.4h, v4.4h}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_8H, ld2_r2_8h, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #24]
    ld2 {v3.8h, v4.8h}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_4S, ld2_r2_4s, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #24]
    ld2 {v3.4s, v4.4s}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_2S, ld2_r2_2s, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.2s, v4.2s}, [x3]
TEST_END

TEST_BEGIN(LD2_ASISDLSE_R2_2D, ld2_r2_2d, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #24]
    ld2 {v3.2d, v4.2d}, [x3]
TEST_END
