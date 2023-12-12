/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "remill/BC/Lifter.h"
#include "remill/Arch/Arch.h"
#include <functional>
#include <unordered_map>

namespace remill {

using TraceMap = std::unordered_map<uint64_t, llvm::Function *>;
using DecoderWorkList = std::set<uint64_t>;  // For ordering.

enum class DevirtualizedTargetKind { kTraceLocal, kTraceHead };

enum class LLVMFunTypeIdent : uint64_t {
  VOID_VOID,
  NULL_FUN_TY,
};

// Manages information about traces. Permits a user of the trace lifter to
// provide more global information to the decoder as it goes, e.g. by pre-
// declaring the existence of many traces, and by supporting devirtualization.
class TraceManager {
 public:
  virtual ~TraceManager(void);

  // Figure out the name for the trace starting at address `addr`.
  //
  // By default, the naming scheme is `sub_XXX` where `XXX` is the lower case
  // hexadecimal representation of `addr`.
  virtual std::string TraceName(uint64_t addr);

  // Called when we have lifted, i.e. defined the contents, of a new trace.
  // The derived class is expected to do something useful with this.
  virtual void SetLiftedTraceDefinition(uint64_t addr,
                                        llvm::Function *lifted_func) = 0;

  // Get a declaration for a lifted trace. The idea here is that a derived
  // class might have additional global info available to them that lets
  // them declare traces ahead of time. In order to distinguish between
  // stuff we've lifted, and stuff we haven't lifted, we allow the lifter
  // to access "defined" vs. "declared" traces.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  //
  // NOTE: This must return a function with our special 3-argument
  //       lifted function form.
  virtual llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);

  // Get a definition for a lifted trace.
  //
  // NOTE: This is permitted to return a function from an arbitrary module.
  //
  // NOTE: This is permitted to return a function of an arbitrary
  //       type. The trace lifter only invokes this function when
  //       it is checking if some trace has already been lifted.
  virtual llvm::Function *GetLiftedTraceDefinition(uint64_t addr);

  /* get lifted function name of the target address */
  virtual std::string GetLiftedFuncName(uint64_t addr) = 0;

  /* get whether or not addr is entry of function */
  virtual bool isFunctionEntry(uint64_t addr) = 0;

  // Apply a callback that gives the decoder access to multiple
  // targets of this instruction (indirect call or jump). This enables the
  // lifter to support devirtualization, e.g. handling jump tables as
  // `switch` statements, or handling indirect calls through the PLT as
  // direct jumps.
  virtual void ForEachDevirtualizedTarget(
      const Instruction &inst,
      std::function<void(uint64_t, DevirtualizedTargetKind)> func);

  // Try to read an executable byte of memory. Returns `true` of the byte
  // at address `addr` is executable and readable, and updates the byte
  // pointed to by `byte` with the read value.
  virtual bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) = 0;

  /* judge whether the addr is end vma of function or not. */
  virtual bool isWithinFunction(uint64_t trace_addr, uint64_t inst_addr) = 0;

  /* get vma end address of the target function */
  virtual uint64_t GetFuncVMA_E(uint64_t vma_s) = 0;

  /* global array of block address various data */
  std::vector<llvm::Constant*> g_block_address_ptrs_array;
  std::vector<llvm::Constant*> g_block_address_vmas_array;
  std::vector<llvm::Constant*> g_block_address_sizes_array;
};

// Implements a recursive decoder that lifts a trace of instructions to bitcode.
class TraceLifter {
 protected:
  class Impl;
  std::unique_ptr<Impl> impl;

 public:
  ~TraceLifter(void);

  inline TraceLifter(const Arch *arch_, TraceManager &manager_)
    : TraceLifter(arch_, &manager_) {}
    
  TraceLifter(const Arch *arch_, TraceManager *manager_);
  
  /* called derived class */
  TraceLifter(Impl *impl_) : impl(impl_) {}

  static void NullCallback(uint64_t, llvm::Function *);

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool
  Lift(uint64_t addr, const char *fun_name = "",
       std::function<void(uint64_t, llvm::Function *)> callback = NullCallback);


 private:
  TraceLifter(void) = delete;

};

class TraceLifter::Impl {
 public:
  Impl(const Arch *arch_, TraceManager *manager_)
    : arch(arch_),
      intrinsics(arch->GetInstrinsicTable()),
      word_type(arch->AddressType()),
      context(word_type->getContext()),
      module(intrinsics->async_hyper_call->getParent()),
      addr_mask(arch->address_size >= 64 ? ~0ULL
                                         : (~0ULL >> arch->address_size)),
      manager(*manager_),
      func(nullptr),
      block(nullptr),
      switch_inst(nullptr),
      // TODO(Ian): The trace lfiter is not supporting contexts
      max_inst_bytes(arch->MaxInstructionSize(arch->CreateInitialContext())),
      indirectbr_block_name("INDIRECT_BR_BB"),
      debug_insn_name("debug_insn"),
      debug_pc_name("debug_pc"),
      debug_call_stack_name("debug_call_stack") {
    inst_bytes.reserve(max_inst_bytes);
  }
  
  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(uint64_t addr, const char* fn_name = "",
            std::function<void(uint64_t, llvm::Function *)> callback = NullCallback);

  // Reads the bytes of an instruction at `addr` into `state.inst_bytes`.
  bool ReadInstructionBytes(uint64_t addr);

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr);

  // Return an already lifted trace starting with the code at address
  // `addr`.
  //
  // NOTE: This is guaranteed to return either `nullptr`, or a function
  //       within `module`.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr);

  llvm::BasicBlock *GetOrCreateBlock(uint64_t block_pc);

  llvm::BasicBlock *GetOrCreateBranchTakenBlock(void);

  llvm::BasicBlock *GetOrCreateBranchNotTakenBlock(void);

  llvm::BasicBlock *GetOrCreateNextBlock(void);

  llvm::BasicBlock *GetOrCreateIndirectJmpBlock(void);

  uint64_t PopTraceAddress(void);

  uint64_t PopInstructionAddress(void);

  /* Global variable array definition helper */
  virtual llvm::GlobalVariable *GenGlobalArrayHelper(
    llvm::Type *elem_type,
    std::vector<llvm::Constant*> &constant_array, 
    const llvm::Twine &Name = "",
    bool isConstant = true, 
    llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage
  );

  const Arch *const arch;
  const remill::IntrinsicTable *intrinsics;
  llvm::Type *word_type;
  llvm::LLVMContext &context;
  llvm::Module *const module;
  const uint64_t addr_mask;
  TraceManager &manager;

  std::vector<llvm::Constant*> g_block_address_ptrs_array;
  std::vector<llvm::Constant*> g_block_address_vmas_array;
  std::vector<llvm::Constant*> g_block_address_sizes_array;

  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::BasicBlock *indirectbr_block;
  llvm::SwitchInst *switch_inst;
  std::string indirectbr_block_name;
  std::map<uint64_t, llvm::BasicBlock*> indirectbr_block_map;
  uint64_t vma_s;
  uint64_t vma_e;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  Instruction delayed_inst;
  std::unordered_map<uint64_t, bool> control_flow_debug_list;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  uint64_t __trace_addr;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  std::string debug_pc_name;
  std::string debug_insn_name;
  std::string debug_call_stack_name;
};

}  // namespace remill
