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

/* STLR  <Wt>, [<Xn|SP>{,#0}] */
TEST_BEGIN(STLR_SL32_LDSTEXCL, stlr_sl32_ldstexcl, 1)
TEST_INPUTS(
    0x41414141,
    0x00000000,
    0xFFFFFFFF,
    0x80000000,
    0x7FFFFFFF)
    add x3, sp, #-256
    str ARG1_32, [x3]
    stlr ARG1_32, [x3]
TEST_END

