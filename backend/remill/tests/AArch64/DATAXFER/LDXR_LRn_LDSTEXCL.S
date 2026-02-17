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

TEST_BEGIN(LDXR_LR32_LDSTEXCL, ldxr_m32, 1)
TEST_INPUTS(
    0x4141414151515151,
    0xababababcdcdcdcd,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000001)

    add x3, sp, #-256
    str ARG1_64, [x3]
    ldxr w5, [x3]
    ldxr w6, [x3]
TEST_END

TEST_BEGIN(LDXR_LR64_LDSTEXCL, ldxr_m64, 1)
TEST_INPUTS(
    0x4141414151515151,
    0xababababcdcdcdcd,
    0x0000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x8000000000000001)

    add x3, sp, #-256
    str ARG1_64, [x3]
    ldxr x5, [x3]
    ldxr x6, [x3]
TEST_END
