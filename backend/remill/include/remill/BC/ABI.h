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

#include <string_view>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {

// Describes the arguments to a basic block function.
enum : size_t {
  kArenaPointerArgNum = 0,
  kStatePointerArgNum = 1,
  kPCArgNum = 2,
  kRuntimePointerArgNum = 3,
  kNumBlockArgs = 4
};

extern const std::string_view kArenaVariableName;
extern const std::string_view kStateVariableName;
extern const std::string_view kPCVariableName;
extern const std::string_view kRIPVariableName;
extern const std::string_view kReturnPCVariableName;
extern const std::string_view kNextPCVariableName;
extern const std::string_view kBranchTakenVariableName;
extern const std::string_view kRuntimeVariableName;
extern const std::string_view kEcvNZCVVariableName;
extern const std::string_view kForkEntryFunAddrVariableName;
extern const std::string_view kInstCountVariableName;
extern const std::string_view kFuncDepthVariableName;

extern const std::string_view kInvalidInstructionISelName;
extern const std::string_view kUnsupportedInstructionISelName;
extern const std::string_view kIgnoreNextPCVariableName;

}  // namespace remill
