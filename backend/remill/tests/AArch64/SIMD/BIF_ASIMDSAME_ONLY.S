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

TEST_BEGIN(BIF_ASIMDSAME_ONLY_8B, bif_v8b, 1)
TEST_INPUTS(0)
    bif v5.8b, v0.8b, v1.8b
    bif v6.8b, v2.8b, v3.8b
    bif v7.8b, v4.8b, v5.8b
TEST_END

TEST_BEGIN(BIF_ASIMDSAME_ONLY_16B, bif_v16b, 1)
TEST_INPUTS(0)
    bif v5.16b, v0.16b, v1.16b
    bif v6.16b, v2.16b, v3.16b
    bif v7.16b, v4.16b, v5.16b
TEST_END

TEST_BEGIN(BIF_ASIMDSAME_ONLY_8B_INPUTS, bif_v8b_inputs, 2)
TEST_INPUTS(
    0x0102030405060708, 0x0807060504030201,
    0x80FF7F0001FE0200, 0x7F00807FFF01FE02,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)
    fmov d1, ARG1_64
    fmov d2, ARG2_64
    bif v0.8b, v1.8b, v2.8b
TEST_END

TEST_BEGIN(BIF_ASIMDSAME_ONLY_16B_INPUTS, bif_v16b_inputs, 2)
TEST_INPUTS(
    0x0102030405060708, 0x0807060504030201,
    0x80FF7F0001FE0200, 0x7F00807FFF01FE02,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)
    dup v1.2d, ARG1_64
    dup v2.2d, ARG2_64
    bif v0.16b, v1.16b, v2.16b
TEST_END
