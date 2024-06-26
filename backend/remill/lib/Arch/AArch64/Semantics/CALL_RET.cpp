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

namespace {

template <typename S>
DEF_SEM(CALL, S target_addr, PC ret_addr) {
  const auto return_pc = Read(ret_addr);
  Write(REG_LP, return_pc);
}

DEF_SEM(RET, R64 target_pc) {
  const auto new_pc = Read(target_pc);
  Write(REG_PC, new_pc);
}

}  // namespace

DEF_ISEL(RET_64R_BRANCH_REG) = RET;
DEF_ISEL(BLR_64_BRANCH_REG) = CALL<R64>;
DEF_ISEL(BL_ONLY_BRANCH_IMM) = CALL<PC>;
