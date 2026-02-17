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

TEST_BEGIN(STR_32_LDST_IMMPOST, str_w0_m32_post, 1)
TEST_INPUTS(
    0x41414141,
    0x00000000,
    0xFFFFFFFF,
    0x80000000,
    0x7FFFFFFF)
    add x3, sp, #-256
    str ARG1_32, [x3], #0
    str ARG1_32, [x3], #16
    str ARG1_32, [x3], #32
TEST_END

TEST_BEGIN(STR_64_LDST_IMMPOST, str_x0_m64_post, 1)
TEST_INPUTS(
    0x4141414151515151,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000000,
    0x7FFFFFFFFFFFFFFF)
    add x3, sp, #-256
    str ARG1_64, [x3], #0
    str ARG1_64, [x3], #16
    str ARG1_64, [x3], #32
TEST_END
