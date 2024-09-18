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

#include "remill/Arch/AArch64/Runtime/Operators.h"
#include "remill/Arch/AArch64/Runtime/State.h"
#include "remill/Arch/AArch64/Runtime/Types.h"
#include "remill/Arch/Name.h"
#include "remill/Arch/Runtime/Float.h"
#include "remill/Arch/Runtime/Intrinsics.h"
#include "remill/Arch/Runtime/Operators.h"
#include "remill/Arch/Runtime/Types.h"

namespace {

// BLR  <Xn>
// x30 will be changed.
template <typename S>
DEF_SEM_U64(CALL, R64 next_addr, PC ret_addr) {
  return Read(ret_addr);
}

// RET  {<Xn>}
// pc will be changed.
DEF_SEM_U64(RET, R64 target_pc) {
  return Read(target_pc);
}

}  // namespace

DEF_ISEL(RET_64R_BRANCH_REG) = RET;  // RET  {<Xn>}
DEF_ISEL(BLR_64_BRANCH_REG) = CALL<R64>;  // BLR  <Xn>
DEF_ISEL(BL_ONLY_BRANCH_IMM) = CALL<PC>;  // BL  <label>
