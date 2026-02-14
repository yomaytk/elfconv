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

/* UMAXP  <Vd>.<T>, <Vn>.<T>, <Vm>.<T> */

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_8B, umaxp_v8b, 1)
TEST_INPUTS(0)
    umaxp v5.8b, v0.8b, v1.8b
    umaxp v6.8b, v2.8b, v3.8b
    umaxp v7.8b, v4.8b, v5.8b
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_16B, umaxp_v16b, 1)
TEST_INPUTS(0)
    umaxp v5.16b, v0.16b, v1.16b
    umaxp v6.16b, v2.16b, v3.16b
    umaxp v7.16b, v4.16b, v5.16b
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_4H, umaxp_v4h, 1)
TEST_INPUTS(0)
    umaxp v5.4h, v0.4h, v1.4h
    umaxp v6.4h, v2.4h, v3.4h
    umaxp v7.4h, v4.4h, v5.4h
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_8H, umaxp_v8h, 1)
TEST_INPUTS(0)
    umaxp v5.8h, v0.8h, v1.8h
    umaxp v6.8h, v2.8h, v3.8h
    umaxp v7.8h, v4.8h, v5.8h
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_2S, umaxp_v2s, 1)
TEST_INPUTS(0)
    umaxp v5.2s, v0.2s, v1.2s
    umaxp v6.2s, v2.2s, v3.2s
    umaxp v7.2s, v4.2s, v5.2s
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_4S, umaxp_v4s, 1)
TEST_INPUTS(0)
    umaxp v5.4s, v0.4s, v1.4s
    umaxp v6.4s, v2.4s, v3.4s
    umaxp v7.4s, v4.4s, v5.4s
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_8B_INPUTS, umaxp_v8b_inputs, 2)
TEST_INPUTS(
    0x0102030405060708, 0x0807060504030201,
    0x80FF7F0001FE0200, 0x7F00807FFF01FE02,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)
    fmov d0, ARG1_64
    fmov d1, ARG2_64
    umaxp v5.8b, v0.8b, v1.8b
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_16B_INPUTS, umaxp_v16b_inputs, 2)
TEST_INPUTS(
    0x0102030405060708, 0x0807060504030201,
    0x80FF7F0001FE0200, 0x7F00807FFF01FE02,
    0xAAAAAAAAAAAAAAAA, 0x5555555555555555)
    dup v0.2d, ARG1_64
    dup v1.2d, ARG2_64
    umaxp v5.16b, v0.16b, v1.16b
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_4H_INPUTS, umaxp_v4h_inputs, 2)
TEST_INPUTS(
    0x0001000200030004, 0x0004000300020001,
    0x8000FFFF7FFF0000, 0x7FFF000080000001,
    0xAAAA5555CCCC3333, 0x5555AAAA3333CCCC)
    fmov d0, ARG1_64
    fmov d1, ARG2_64
    umaxp v5.4h, v0.4h, v1.4h
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_8H_INPUTS, umaxp_v8h_inputs, 2)
TEST_INPUTS(
    0x0001000200030004, 0x0004000300020001,
    0x8000FFFF7FFF0000, 0x7FFF000080000001,
    0xAAAA5555CCCC3333, 0x5555AAAA3333CCCC)
    dup v0.2d, ARG1_64
    dup v1.2d, ARG2_64
    umaxp v5.8h, v0.8h, v1.8h
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_2S_INPUTS, umaxp_v2s_inputs, 2)
TEST_INPUTS(
    0x0000000100000002, 0x0000000200000001,
    0x80000000FFFFFFFF, 0x7FFFFFFF00000001,
    0xAAAAAAAA55555555, 0x55555555AAAAAAAA)
    fmov d0, ARG1_64
    fmov d1, ARG2_64
    umaxp v5.2s, v0.2s, v1.2s
TEST_END

TEST_BEGIN(UMAXP_ASIMDSAME_ONLY_4S_INPUTS, umaxp_v4s_inputs, 2)
TEST_INPUTS(
    0x0000000100000002, 0x0000000200000001,
    0x80000000FFFFFFFF, 0x7FFFFFFF00000001,
    0xAAAAAAAA55555555, 0x55555555AAAAAAAA)
    dup v0.2d, ARG1_64
    dup v1.2d, ARG2_64
    umaxp v5.4s, v0.4s, v1.4s
TEST_END
