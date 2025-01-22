/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include <memory>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Context.h>
#include <unordered_map>
#include <vector>

namespace llvm {
class FunctionType;
class PointerType;
class StructType;
}  // namespace llvm
namespace remill {

struct Register;


// Internal base architecture for all Remill-internal architectures.
class ArchBase : public remill::Arch {
 public:
  using ArchPtr = std::unique_ptr<const Arch>;

  ArchBase(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

  virtual ~ArchBase(void) = default;

  // Return the type of the state structure.
  llvm::StructType *StateStructType(void) const final;

  // Pointer to a state structure type.
  llvm::PointerType *StatePointerType(void) const final;

  // The type of memory.
  llvm::PointerType *MemoryPointerType(void) const final;

  // Return the type of a lifted function.
  llvm::FunctionType *LiftedFunctionType(void) const final;

  llvm::StructType *RegisterWindowType(void) const final;

  // Apply `cb` to every register.
  void ForEachRegister(std::function<void(const Register *)> cb) const final;

  // Return information about the register at offset `offset` in the `State`
  // structure.
  const Register *RegisterAtStateOffset(uint64_t offset) const final;

  // Return information about a register, given its name.
  const Register *RegisterByName(std::string_view name) const final;

  const IntrinsicTable *GetInstrinsicTable(void) const final;

  unsigned RegMdID(void) const final;

  // Get the state pointer and various other types from the `llvm::LLVMContext`
  // associated with `module`.
  //
  // NOTE(pag): This is an internal API.
  void InitFromSemanticsModule(llvm::Module *module) const final;

  // Add a register into this architecture.
  const Register *AddRegister(const char *reg_name, llvm::Type *val_type, size_t offset,
                              const char *parent_reg_name) const final;

  // State type. Initially this is `nullptr` because we can construct and arch
  // without loading in a semantics module. When we load a semantics module, we
  // learn about the LLVM type of the state structure, and so we need to be
  // able to update this in-place.
  mutable llvm::StructType *state_type{nullptr};

  // Runtime pointer type.
  mutable llvm::PointerType *runtime_type{nullptr};

  // Lifted function type.
  mutable llvm::FunctionType *lifted_function_type{nullptr};

  // Register window type.
  mutable llvm::StructType *register_window_type{nullptr};

  // Metadata type ID for remill registers.
  mutable unsigned reg_md_id{0};

  mutable std::vector<std::unique_ptr<Register>> registers;
  mutable std::vector<const Register *> reg_by_offset;
  mutable std::unordered_map<std::string, const Register *> reg_by_name;
  mutable std::unique_ptr<IntrinsicTable> instrinsics{nullptr};
};

class DefaultContextAndLifter : virtual public remill::ArchBase {
 private:
  Instruction::FallthroughFlow GetFallthrough() const;

  Instruction::DirectFlow GetDirectFlow(uint64_t target) const;

  Instruction::IndirectFlow GetIndirectFlow() const;

  Instruction::InstructionFlowCategory
  FillInFlowFromCategoryAndDefaultContext(const remill::Instruction &inst) const;

 public:
  virtual DecodingContext CreateInitialContext(void) const override;

  virtual bool DecodeInstruction(uint64_t address, std::string_view instr_bytes, Instruction &inst,
                                 DecodingContext context) const override;


  OperandLifter::OpLifterPtr DefaultLifter(const remill::IntrinsicTable &intrinsics) const override;


  DefaultContextAndLifter(llvm::LLVMContext *context_, OSName os_name_, ArchName arch_name_);

 protected:
  virtual bool ArchDecodeInstruction(uint64_t address, std::string_view instr_bytes,
                                     Instruction &inst) const = 0;
};


}  // namespace remill
