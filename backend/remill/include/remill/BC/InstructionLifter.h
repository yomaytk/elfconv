/*
 * Copyright (c) 202 Trail of Bits, Inc.
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

#include <cstdint>
#include <glog/logging.h>
#include <llvm/IR/Instructions.h>
#include <memory>
#include <optional>
#include <string_view>

namespace llvm {
class Argument;
class ConstantInt;
class Function;
class Module;
class GlobalVariable;
class LLVMContext;
class IntegerType;
class BasicBlock;
class Value;
class Type;
}  // namespace llvm

namespace remill {

class Arch;
class Instruction;
class IntrinsicTable;
class Operand;
class OperandExpression;
class TraceLifter;

enum LiftStatus {
  kLiftedInvalidInstruction,
  kLiftedUnsupportedInstruction,
  kLiftedLifterError,
  kLiftedUnknownISEL,
  kLiftedMismatchedISEL,
  kLiftedInstruction
};

// Instruction independent lifting
class OperandLifter {
 public:
  using OpLifterPtr = std::shared_ptr<OperandLifter>;

  // Load the address of a register.
  virtual std::pair<llvm::Value *, llvm::Type *>
  LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                 std::string_view reg_name) const = 0;

  // Load the value of a register.
  virtual llvm::Value *LoadRegValue(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                    std::string_view reg_name) const = 0;

  virtual llvm::Value *LoadRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                              std::string_view reg_name,
                                              llvm::Instruction *instBefore) const = 0;

  virtual llvm::Instruction *
  StoreRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                          std::string_view reg_name, llvm::Value *stored_value,
                          llvm::Instruction *instBefore) const = 0;

  virtual llvm::Type *GetRuntimeType() = 0;

  virtual void ClearCache(void) const = 0;
};

#define SP_ORDER 32
#define PC_ORDER 33
#define STATE_ORDER 34
#define RUNTIME_ORDER 35
#define BRANCH_TAKEN_ORDER 36
#define ECV_NZCV_ORDER 37
#define WZR_ORDER 38
#define XZR_ORDER 39

enum class EcvRegClass : uint32_t {
  RegW = 'W' - 'A',
  RegX = 'X' - 'A',
  RegB = 'B' - 'A',
  RegH = 'H' - 'A',
  RegS = 'S' - 'A',
  RegD = 'D' - 'A',
  RegQ = 'Q' - 'A',
  RegP = 100,
  RegNULL = 101
};

std::string EcvRegClass2String(EcvRegClass ecv_reg_class);

enum class RegKind : uint32_t {
  General,
  Vector,
  Special,  // SP ~ XZR
};

class EcvReg {
 public:
  RegKind reg_kind;
  uint8_t number;

  EcvReg() {}
  EcvReg(RegKind __reg_kind, uint8_t __number) : reg_kind(__reg_kind), number(__number) {}

  bool operator==(const EcvReg &rhs) const {
    return reg_kind == rhs.reg_kind && number == rhs.number;
  }

  bool operator!=(const EcvReg &rhs) const {
    return !(*this == rhs);
  }

  bool operator<(const EcvReg &rhs) const {
    return number < rhs.number;
  }

  bool operator>(const EcvReg &rhs) const {
    return !(*this == rhs) && !(*this < rhs);
  }

  // get reg_info from general or vector registers
  static std::optional<std::pair<EcvReg, EcvRegClass>> GetRegInfo(const std::string &_reg_name);

  static std::pair<EcvReg, EcvRegClass> GetSpecialRegInfo(const std::string &_reg_name);
  std::string GetRegName(EcvRegClass ecv_reg_class) const;
  std::string GetWholeRegName() const;
  bool CheckNoChangedReg() const;

  class Hash {
   public:
    std::size_t operator()(const EcvReg &ecv_reg) const {
      return std::hash<uint32_t>()(
                 static_cast<std::underlying_type<RegKind>::type>(ecv_reg.reg_kind)) ^
             std::hash<uint8_t>()(ecv_reg.number);
    }
  };  // namespace remill
};

template <typename VT>
using EcvRegMap = std::unordered_map<EcvReg, VT, EcvReg::Hash>;

class BBRegInfoNode {
 public:
  BBRegInfoNode() {}
  ~BBRegInfoNode() {}

  void join_reg_info_node(BBRegInfoNode *child) {
    // Join bb_load_reg_map
    for (auto [_ecv_reg, _ecv_reg_class] : child->bb_load_reg_map) {
      bb_load_reg_map.insert_or_assign(_ecv_reg, _ecv_reg_class);
    }
    // Join bb_store_reg_map
    for (auto [_ecv_reg, _ecv_reg_class] : child->bb_store_reg_map) {
      bb_store_reg_map.insert_or_assign(_ecv_reg, _ecv_reg_class);
    }
    // Join reg_latest_inst_map
    for (auto [_ecv_reg, reg_inst_value] : child->reg_latest_inst_map) {
      reg_latest_inst_map.insert_or_assign(_ecv_reg, reg_inst_value);
    }
    // Join sema_call_written_reg_map
    for (auto key_value : child->sema_call_written_reg_map) {
      sema_call_written_reg_map.insert(key_value);
    }
    // Join sema_func_args_reg_map
    for (auto key_value : child->sema_func_args_reg_map) {
      sema_func_args_reg_map.insert(key_value);
    }
  }

  // The register set which is `load`ed in this block.
  EcvRegMap<EcvRegClass> bb_load_reg_map;
  // The register set which is `store`d in this block.
  EcvRegMap<EcvRegClass> bb_store_reg_map;

  // llvm::Value ptr which explains the latest register.
  EcvRegMap<std::tuple<EcvRegClass, llvm::Value *, uint32_t>> reg_latest_inst_map;

  // Save the written registers by semantic functions
  std::unordered_map<llvm::CallInst *, std::vector<std::pair<EcvReg, EcvRegClass>>>
      sema_call_written_reg_map;
  // Save the args registers by semantic functions (for debug)
  std::unordered_map<llvm::CallInst *, std::vector<std::pair<EcvReg, EcvRegClass>>>
      sema_func_args_reg_map;

  // Map the added instructions that can be refered later on and register
  // In the current design, the target are llvm::CastInst, llvm::ExtractValueInst, llvm::PHINode.
  std::unordered_map<llvm::Value *, std::pair<EcvReg, EcvRegClass>>
      referred_able_added_inst_reg_map;
  // Map the register and added instructions.
  EcvRegMap<llvm::Value *> reg_derived_added_inst_map;
};

class InstructionLifterIntf : public OperandLifter {
 public:
  using LifterPtr = std::shared_ptr<InstructionLifterIntf>;

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  virtual LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, BBRegInfoNode *bb_reg_info_node,
                                   uint64_t debug_insn_addr = UINT64_MAX,
                                   bool is_delayed = false) = 0;

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                           BBRegInfoNode *bb_reg_info_node, uint64_t debug_insn_addr = UINT64_MAX,
                           bool is_delayed = false);
};

// Wraps the process of lifting an instruction into a block. This resolves
// the intended instruction target to a function, and ensures that the function
// is called with the appropriate arguments.
class InstructionLifter : public InstructionLifterIntf {
 public:
  virtual ~InstructionLifter(void);

  inline InstructionLifter(const std::unique_ptr<const Arch> &arch_,
                           const IntrinsicTable &intrinsics_)
      : InstructionLifter(arch_.get(), &intrinsics_) {}

  inline InstructionLifter(const Arch *arch_, const IntrinsicTable &intrinsics_)
      : InstructionLifter(arch_, &intrinsics_) {}

  InstructionLifter(const Arch *arch_, const IntrinsicTable *intrinsics_);

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  virtual LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, BBRegInfoNode *bb_reg_info_node,
                                   uint64_t debug_insn_addr = UINT64_MAX,
                                   bool is_delayed = false) override;


  // Load the address of a register.
  std::pair<llvm::Value *, llvm::Type *>
  LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                 std::string_view reg_name) const override final;

  // Load the value of a register.
  llvm::Value *LoadRegValue(llvm::BasicBlock *block, llvm::Value *state_ptr,
                            std::string_view reg_name) const override final;

  llvm::Value *LoadRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                      std::string_view reg_name,
                                      llvm::Instruction *instBefore) const override final;

  // Store the value of a register (Assume that the store_value already has been casted).
  llvm::Instruction *StoreRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                             std::string_view reg_name, llvm::Value *stored_value,
                                             llvm::Instruction *instBefore) const override final;

  // Clear out the cache of the current register values/addresses loaded.
  void ClearCache(void) const override;


  virtual llvm::Type *GetRuntimeType() override final;

 protected:
  // Lift an operand to an instruction.
  virtual llvm::Value *LiftOperand(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, llvm::Argument *arg, Operand &op);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftShiftRegisterOperand(Instruction &inst, llvm::BasicBlock *block,
                                                llvm::Value *state_ptr, llvm::Argument *arg,
                                                Operand &reg);

  // Lift a register operand to a value.
  virtual llvm::Value *LiftRegisterOperand(Instruction &inst, llvm::BasicBlock *block,
                                           llvm::Value *state_ptr, llvm::Argument *arg,
                                           Operand &reg);

  // Lift an immediate operand.
  virtual llvm::Value *LiftImmediateOperand(Instruction &inst, llvm::BasicBlock *block,
                                            llvm::Argument *arg, Operand &op);

  // Lift an expression operand.
  virtual llvm::Value *LiftExpressionOperand(Instruction &inst, llvm::BasicBlock *block,
                                             llvm::Value *state_ptr, llvm::Argument *arg,
                                             Operand &op);

  // Lift an expression operand.
  virtual llvm::Value *LiftExpressionOperandRec(Instruction &inst, llvm::BasicBlock *block,
                                                llvm::Value *state_ptr, llvm::Argument *arg,
                                                const OperandExpression *op);

  // Lift an indirect memory operand to a value.
  virtual llvm::Value *LiftAddressOperand(Instruction &inst, llvm::BasicBlock *block,
                                          llvm::Value *state_ptr, llvm::Argument *arg,
                                          Operand &mem);

  // Return a register value, or zero.
  llvm::Value *LoadWordRegValOrZero(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                    std::string_view reg_name, llvm::ConstantInt *zero);


 protected:
  llvm::Type *GetWordType();


  const IntrinsicTable *GetIntrinsicTable();
  bool ArchHasRegByName(std::string name);

 private:
  friend class TraceLifter;

  InstructionLifter(const InstructionLifter &) = delete;
  InstructionLifter(InstructionLifter &&) noexcept = delete;
  InstructionLifter(void) = delete;

  class Impl;

  const std::unique_ptr<Impl> impl;
  const std::string debug_memory_value_change_name;
  const std::string debug_insn_name;
};

}  // namespace remill
