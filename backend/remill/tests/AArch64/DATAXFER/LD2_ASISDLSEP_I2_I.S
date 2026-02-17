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

TEST_BEGIN(LD2_ASISDLSEP_I2_I_16B, ld2_i2_i_16b, 1)
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
    ld2 {v3.16b, v4.16b}, [x3], #32
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_8B, ld2_i2_i_8b, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.8b, v4.8b}, [x3], #16
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_4H, ld2_i2_i_4h, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.4h, v4.4h}, [x3], #16
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_8H, ld2_i2_i_8h, 1)
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
    ld2 {v3.8h, v4.8h}, [x3], #32
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_4S, ld2_i2_i_4s, 1)
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
    ld2 {v3.4s, v4.4s}, [x3], #32
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_2S, ld2_i2_i_2s, 1)
TEST_INPUTS(
    0x0102030405060708,
    0xFF00FF00FF00FF00,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x80817F7E01020304)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    ld2 {v3.2s, v4.2s}, [x3], #16
TEST_END

TEST_BEGIN(LD2_ASISDLSEP_I2_I_2D, ld2_i2_i_2d, 1)
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
    ld2 {v3.2d, v4.2d}, [x3], #32
TEST_END
