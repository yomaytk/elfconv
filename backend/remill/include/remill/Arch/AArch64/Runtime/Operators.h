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

#pragma once

namespace {

// Read a register directly. Sometimes this is needed for suppressed operands.
ALWAYS_INLINE static addr_t _Read(RuntimeManager *, Reg reg) {
  return reg.aword;
}

// Write directly to a register. This is sometimes needed for suppressed
// register operands.
ALWAYS_INLINE static void _Write(RuntimeManager *, Reg &reg, addr_t val) {
  reg.aword = val;
}

}  // namespace
