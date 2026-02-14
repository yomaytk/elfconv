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

/* INS  <Vd>.<Ts>[<index>], <R><n> */
TEST_BEGIN(INS_ASIMDINS_IR_R_B, ins_ir_r_b, 1)
TEST_INPUTS(
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0xdeadbeef,
    0xFFFFFFFF,
    0x41F7FFFFFFD00000)

  ins v1.b[3], ARG1_32
TEST_END

TEST_BEGIN(INS_ASIMDINS_IR_R_H, ins_ir_r_h, 1)
TEST_INPUTS(
    0,
    1,
    0x7fff,
    0x8000,
    0xffff,
    0xdeadbeef,
    0xFFFFFFFF,
    0x41F7FFFFFFD00000)

  ins v1.h[3], ARG1_32
TEST_END

TEST_BEGIN(INS_ASIMDINS_IR_R_S, ins_ir_r_s, 1)
TEST_INPUTS(
    0,
    1,
    0x7fffffff,
    0x80000000,
    0xffffffff,
    0xdeadbeef,
    0x3f800000,
    0x41F7FFFFFFD00000)

  ins v1.s[3], ARG1_32
TEST_END

TEST_BEGIN(INS_ASIMDINS_IR_R_D, ins_ir_r_d, 1)
TEST_INPUTS(
    0,
    1,
    0x7fffffffffffffff,
    0x8000000000000000,
    0xffffffffffffffff,
    0xdeadbeefdeadbeef,
    0x3ff0000000000000,
    0x41F7FFFFFFD00000)

  ins v1.d[1], ARG1_64
TEST_END
