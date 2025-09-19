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

#include "remill/Arch/Name.h"

#include <cstdint>
#include <functional>
#include <glog/logging.h>
#include <llvm/IR/Instructions.h>
#include <memory>
#include <optional>
#include <string_view>
#include <tuple>

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

extern std::unordered_map<llvm::Value *, uint64_t> Sema_func_vma_map;

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

class LiftConfig {
 public:
  bool float_exception_enabled;
  bool norm_mode;
  ArchName target_elf_arch;
  bool fork_emulation_emcc_fiber;

  LiftConfig() = delete;

  LiftConfig(bool __float_exception_enabled, bool __norm_mode, ArchName __target_elf_arch,
             bool __fork_emulation_emcc_fiber)
      : float_exception_enabled(__float_exception_enabled),
        norm_mode(__norm_mode),
        target_elf_arch(__target_elf_arch),
        fork_emulation_emcc_fiber(__fork_emulation_emcc_fiber) {}
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

  virtual llvm::Value *
  LoadRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr, std::string_view reg_name,
                         llvm::Instruction *instBefore, std::string var_name = "") const = 0;

  virtual llvm::Instruction *
  StoreRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                          std::string_view reg_name, llvm::Value *stored_value,
                          llvm::Instruction *instBefore) const = 0;

  virtual llvm::Type *GetRuntimeType() = 0;

  virtual void ClearCache(void) const = 0;
};

// AArch64 special registers
#define SP_ORDER 32
#define PC_ORDER 33
#define STATE_ORDER 34
#define RUNTIME_ORDER 35

#define ECV_NZCV_ORDER 37
#define IGNORE_WRITE_TO_WZR_ORDER 38
#define IGNORE_WRITE_TO_XZR_ORDER 39
#define MONITOR_ORDER 40
#define WZR_ORDER 41  // Actually, not used
#define XZR_ORDER 42  // Actually, not used
#define WSP_ORDER 43
#define FPSR_ORDER 44
#define FPCR_ORDER 45
#define FUN_ADDR_ORDER 46

// shared
#define BRANCH_TAKEN_ORDER 36

// x86-64 special registers
#define RIP_ORDER 133
#define CSBASE_ORDER 134
#define SSBASE_ORDER 135
#define ESBASE_ORDER 136
#define DSBASE_ORDER 137
#define RETURN_PC_ORDER 138
#define NEXT_PC_ORDER 139


enum class ERC : uint32_t {
  RegW = 'W' - 'A',  // 22
  RegX = 'X' - 'A',  // 23
  RegB = 'B' - 'A',  // 1
  RegH = 'H' - 'A',  // 7
  RegS = 'S' - 'A',  // 18
  RegD = 'D' - 'A',  // 3
  Reg8B = 'V' + 'B' - 'A' + 8,  // 95
  Reg16B = 'V' + 'B' - 'A' + 1,  // 88 (not 16 for EcvReg::GetRegInfo).
  Reg4H = 'V' + 'H' - 'A' + 4,  // 97
  Reg8H = 'V' + 'H' - 'A' + 8,  // 101
  Reg2S = 'V' + 'S' - 'A' + 2,  // 106
  Reg2SF = 'V' + 'S' + 'F' - 'A' + 2,  // 176
  Reg4S = 'V' + 'S' - 'A' + 4,  // 108
  Reg4SF = 'V' + 'S' + 'F' - 'A' + 4,  // 178
  Reg1D = 'V' + 'D' - 'A' + 1,  // 90
  Reg1DF = 'V' + 'D' + 'F' - 'A' + 1,  // 160
  Reg2D = 'V' + 'D' - 'A' + 2,  // 91
  Reg2DF = 'V' + 'D' + 'F' - 'A' + 2,  // 161
  RegQ = 'Q' - 'A',  // 16
  RegV = 'V' - 'A',  // 21
  RegP = 10000,
  RegNULL = 10001
};

// (FIXME) This functions is for aarch64 binary but it doesn't matter becuase this is used for debugging.
std::string ERC2str(ERC ecv_reg_class);

uint64_t ERCSize(ERC ecv_reg_class);

enum class RegKind : uint32_t {
  General,  // 0
  Vector,  // 1
  Special,  // 2
};

class EcvReg {
 public:
  RegKind reg_kind;
  uint32_t number;
  static ArchName target_elf_arch;

  EcvReg() {}
  EcvReg(RegKind __reg_kind, uint32_t __number) : reg_kind(__reg_kind), number(__number) {}

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
  static std::pair<EcvReg, ERC> GetRegInfo(const std::string &_reg_name);

  std::string GetRegName(ERC ecv_reg_class) const;
  std::string GetWideRegName() const;
  bool CheckPassedArgsRegs() const;
  bool CheckPassedReturnRegs() const;

  class Hash {
   public:
    std::size_t operator()(const EcvReg &ecv_reg) const {
      return std::hash<uint32_t>()(
                 static_cast<std::underlying_type<RegKind>::type>(ecv_reg.reg_kind)) ^
             std::hash<uint32_t>()(ecv_reg.number);
    }
  };  // namespace remill
};

template <typename VT>
using EcvRegMap = std::unordered_map<EcvReg, VT, EcvReg::Hash>;

class BBRegInfoNode {
 public:
  BBRegInfoNode(llvm::Function *func, llvm::Value *state_val, llvm::Value *runtime_val);
  ~BBRegInfoNode() {}

  void join_reg_info_node(BBRegInfoNode *child);

  // The register set which is `load`ed in this block.
  EcvRegMap<ERC> bb_ld_r_mp;
  // The register set which is `store`d in this block.
  EcvRegMap<ERC> bb_str_r_mp;

  // llvm::Value ptr which explains the latest register.
  EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> r_fresh_inst_mp;

  // Save the written registers by semantic functions
  std::unordered_map<llvm::CallInst *, std::vector<std::pair<EcvReg, ERC>>>
      sema_call_written_reg_map;
  // Save the args registers by semantic functions (for debug)
  std::unordered_map<llvm::CallInst *, std::vector<std::pair<EcvReg, ERC>>> sema_func_args_reg_map;
  // Save the pc of semantics functions (for debug)
  std::unordered_map<llvm::CallInst *, uint64_t> sema_func_pc_map;

  std::unordered_map<llvm::Value *, std::pair<EcvReg, ERC>> post_update_regs;

  // Map the added instructions that can be refered later on and register
  // In the current design, the target are llvm::CastInst, llvm::ExtractValueInst, llvm::PHINode.
  std::unordered_map<llvm::Value *, std::pair<EcvReg, ERC>> refable_inst_r_mp;
  // Map the register and added instructions.
  EcvRegMap<llvm::Value *> added_r_phi_mp;
};

class InstructionLifterIntf : public OperandLifter {
 public:
  using LifterPtr = std::shared_ptr<InstructionLifterIntf>;

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  virtual LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, BBRegInfoNode *bb_reg_info_node,
                                   bool is_delayed = false) = 0;

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  LiftStatus LiftIntoBlock(Instruction &inst, llvm::BasicBlock *block,
                           BBRegInfoNode *bb_reg_info_node, bool is_delayed = false);
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
                                   bool is_delayed = false) override;


  // Load the address of a register.
  std::pair<llvm::Value *, llvm::Type *>
  LoadRegAddress(llvm::BasicBlock *block, llvm::Value *state_ptr,
                 std::string_view reg_name) const override final;

  // Load the value of a register.
  llvm::Value *LoadRegValue(llvm::BasicBlock *block, llvm::Value *state_ptr,
                            std::string_view reg_name) const override final;

  llvm::Value *LoadRegValueBeforeInst(llvm::BasicBlock *block, llvm::Value *state_ptr,
                                      std::string_view reg_name, llvm::Instruction *instBefore,
                                      std::string var_name = "") const override final;

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
