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

/* LDRSW  <Xt>, [<Xn|SP>{, #<pimm>}] */
TEST_BEGIN(LDRSW_64_LDST_POS, ldrsw_x563_m32, 1)
TEST_INPUTS(
    0x4141414151515151,
    0xababababcdcdcdcd,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000001)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #32]
    ldrsw x5, [x3]
    ldrsw x6, [x3, #16]
    ldrsw x3, [x3, #32]
TEST_END

/* LDRSW  <Xt>, [<Xn|SP>], #<simm> */
TEST_BEGIN(LDRSW_64_LDST_IMMPOST, ldrsw_x56_m32_post, 1)
TEST_INPUTS(
    0x4141414151515151,
    0xababababcdcdcdcd,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000001)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #32]
    ldrsw x5, [x3], #0
    ldrsw x6, [x3], #32
TEST_END

TEST_BEGIN(LDRSW_64_LDST_IMMPOST, ldrsw_xzr_m32_post_alias, 1)
TEST_INPUTS(0)
    add sp, sp, #-256
    ldrsw xzr, [sp], #16
TEST_END

/* LDRSW  <Xt>, [<Xn|SP>, #<simm>]! */
TEST_BEGIN(LDRSW_64_LDST_IMMPRE, ldrsw_x5_m32_pre, 1)
TEST_INPUTS(
    0x4141414151515151,
    0xababababcdcdcdcd,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000001)
    add x3, sp, #-256
    str ARG1_64, [x3, #16]
    ldrsw x5, [x3, #16]!
TEST_END

/* LDRSW  <Xt>, [<Xn|SP>, (<Wm>|<Xm>), <extend> {<amount>}] */
TEST_BEGIN(LDRSW_64_LDST_REGOFF, ldrsw_x567_m32_off_w0_uxtw02, 1)
TEST_INPUTS(
    0,
    8)
    add x3, sp, #-256
    ldrsw x5, [x3, ARG1_32, uxtw]
    ldrsw x6, [x3, ARG1_32, uxtw #0]
    ldrsw x6, [x3, ARG1_32, uxtw #2]
TEST_END

TEST_BEGIN(LDRSW_64_LDST_REGOFF, ldrsw_x567_m32_off_w0_sxtw02, 1)
TEST_INPUTS(
    0,
    0xfffffff8)  /* -8 */
    add x3, sp, #-256
    ldrsw x5, [x3, ARG1_32, sxtw]
    ldrsw x6, [x3, ARG1_32, sxtw #0]
    ldrsw x7, [x3, ARG1_32, sxtw #2]
TEST_END

TEST_BEGIN(LDRSW_64_LDST_REGOFF, ldrsw_x567_m32_off_w0_lsl02, 1)
TEST_INPUTS(
    0,
    8,
    16,
    32,
    64)
    add x3, sp, #-256
    str ARG1_64, [x3]
    str ARG1_64, [x3, #8]
    str ARG1_64, [x3, #16]
    str ARG1_64, [x3, #32]
    str ARG1_64, [x3, #64]
    str ARG1_64, [x3, #128]
    ldrsw x5, [x3, ARG1_64]  /* Implicit LSL 0 */
    ldrsw x6, [x3, ARG1_64, lsl #0]  /* Explicit LSL 0 */
    ldrsw x7, [x3, ARG1_64, lsl #2]  /* Explicit LSL 2 */
TEST_END
