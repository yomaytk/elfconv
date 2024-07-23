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

#include "remill/Arch/Arch.h"
#include "remill/BC/Lifter.h"

#include <functional>
#include <queue>
#include <unordered_map>

namespace remill {

using TraceMap = std::unordered_map<uint64_t, llvm::Function *>;
using DecoderWorkList = std::set<uint64_t>;  // For ordering.

enum class DevirtualizedTargetKind { kTraceLocal, kTraceHead };

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
  virtual void SetLiftedTraceDefinition(uint64_t addr, llvm::Function *lifted_func) = 0;

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
  virtual void
  ForEachDevirtualizedTarget(const Instruction &inst,
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
  std::vector<llvm::Constant *> g_block_address_ptrs_array;
  std::vector<llvm::Constant *> g_block_address_vmas_array;
  std::vector<llvm::Constant *> g_block_address_size_array;
  std::vector<llvm::Constant *> g_block_address_fn_vma_array;

  uint64_t _io_file_xsputn_vma = 0;
};

class PhiRegsBBBagNode {
 public:
  PhiRegsBBBagNode(EcvRegMap<EcvRegClass> &&__preceding_load_reg_map,
                   EcvRegMap<EcvRegClass> &&__succeeding_load_reg_map,
                   EcvRegMap<EcvRegClass> &&__req_preceding_store_reg_map,
                   std::set<llvm::BasicBlock *> &&__in_bbs)
      : bag_preceding_load_reg_map(std::move(__preceding_load_reg_map)),
        bag_succeeding_load_reg_map(std::move(__succeeding_load_reg_map)),
        bag_preceding_store_reg_map(std::move(__req_preceding_store_reg_map)),
        in_bbs(std::move(__in_bbs)) {}

  static void Reset() {
    bb_regs_bag_map.clear();
    bag_num = 0;
  }

  static void GetPhiReadWriteRegsBags(llvm::BasicBlock *root_bb);
  static void GetPhiDerivedReadRegsBags(llvm::BasicBlock *root_bb);
  static void RemoveLoop(llvm::BasicBlock *bb);
  static void GetPhiRegsBags(llvm::BasicBlock *root_bb);

  static inline std::unordered_map<llvm::BasicBlock *, PhiRegsBBBagNode *> bb_regs_bag_map = {};
  static inline std::size_t bag_num = 0;

  // The regsiter set which may be loaded on the way to the basic blocks of this bag node.
  EcvRegMap<EcvRegClass> bag_preceding_load_reg_map;
  // The register set which may be loaded on the succeeding block (includes the own block).
  EcvRegMap<EcvRegClass> bag_succeeding_load_reg_map;

  // The register set which is stored in the way to the bag node (required).
  EcvRegMap<EcvRegClass> bag_preceding_store_reg_map;
  // The register set which should be referenced in this block (required).
  EcvRegMap<EcvRegClass> bag_load_reg_map;
  // bag_preceding_store_reg_map + bag_load_reg_map
  EcvRegMap<EcvRegClass> bag_req_reg_map;

  // The basic block set which is included in this bag.
  std::set<llvm::BasicBlock *> in_bbs;

  std::set<PhiRegsBBBagNode *> parents;
  std::set<PhiRegsBBBagNode *> children;
};

// Implements a recursive decoder that lifts a trace of instructions to bitcode.
class TraceLifter {
 protected:
  class Impl;
  std::unique_ptr<Impl> impl;

 public:
  ~TraceLifter(void);

  inline TraceLifter(const Arch *arch_, TraceManager &manager_) : TraceLifter(arch_, &manager_) {}

  TraceLifter(const Arch *arch_, TraceManager *manager_);

  /* called derived class */
  TraceLifter(Impl *impl_) : impl(impl_) {}

  static void NullCallback(uint64_t, llvm::Function *);

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(uint64_t addr, const char *fun_name = "",
            std::function<void(uint64_t, llvm::Function *)> callback = NullCallback);


 private:
  TraceLifter(void) = delete;

  friend class VirtualRegsOpt;
};

class VirtualRegsOpt {
 public:
  VirtualRegsOpt(llvm::Function *__func, TraceLifter::Impl *__impl, uint64_t __fun_vma)
      : func(__func),
        impl(__impl),
        fun_vma(__fun_vma) {}
  VirtualRegsOpt() {}
  ~VirtualRegsOpt() {}

  llvm::Type *GetLLVMTypeFromRegZ(EcvRegClass ecv_reg_class);
  llvm::Value *GetValueFromTargetBBAndReg(llvm::BasicBlock *target_bb, llvm::BasicBlock *request_bb,
                                          std::pair<EcvReg, EcvRegClass> ecv_reg_info);
  llvm::Value *CastFromInst(EcvReg target_ecv_reg, llvm::Value *from_inst, llvm::Type *to_inst_ty,
                            llvm::Instruction *inst_at_before, llvm::Value *to_inst = nullptr);

  llvm::Value *CastToStoredValue(llvm::Value *from_value, EcvReg target_ecv_reg,
                                 llvm::Instruction *insert_at_before);
  void OptimizeVirtualRegsUsage();

  llvm::Function *func;
  TraceLifter::Impl *impl;

  // for debug
  uint64_t fun_vma;
  uint64_t block_num;
  // All llvm::CallInst* of the lifted function.
  // Use to distinguish semantic function and lifted function.
  std::set<llvm::CallInst *> lifted_func_caller_set;

  std::unordered_map<llvm::BasicBlock *, std::set<llvm::BasicBlock *>> bb_parents;
  std::unordered_map<llvm::BasicBlock *, BBRegInfoNode *> bb_reg_info_node_map;

  std::queue<llvm::BasicBlock *> phi_bb_queue;
  std::set<llvm::BasicBlock *> relay_bbs;
  std::unordered_map<llvm::BasicBlock *, std::set<EcvReg>> relay_reg_need_load_inst_map;
};

class TraceLifter::Impl {
 public:
  Impl(const Arch *arch_, TraceManager *manager_)
      : arch(arch_),
        intrinsics(arch->GetInstrinsicTable()),
        word_type(arch->AddressType()),
        context(word_type->getContext()),
        module(intrinsics->async_hyper_call->getParent()),
        addr_mask(arch->address_size >= 64 ? ~0ULL : (~0ULL >> arch->address_size)),
        manager(*manager_),
        func(nullptr),
        block(nullptr),
        bb_reg_info_node(nullptr),
        // TODO(Ian): The trace lifter is not supporting contexts
        max_inst_bytes(arch->MaxInstructionSize(arch->CreateInitialContext())),
        runtime_manager_name("RuntimeManager"),
        indirectbr_block_name("L_indirectbr"),
        g_get_indirectbr_block_address_func_name("__g_get_indirectbr_block_address"),
        debug_memory_value_change_name("debug_memory_value_change"),
        debug_insn_name("debug_insn"),
        debug_call_stack_push_name("debug_call_stack_push"),
        debug_call_stack_pop_name("debug_call_stack_pop"),
        data_layout(llvm::DataLayout(module)) {
    inst_bytes.reserve(max_inst_bytes);
  }

  virtual ~Impl() {}

  // Lift one or more traces starting from `addr`. Calls `callback` with each
  // lifted trace.
  bool Lift(uint64_t addr, const char *fn_name = "",
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

  llvm::Value *GetRuntimePtrOnEntry();

  /* Global variable array definition helper (need override) */
  virtual llvm::GlobalVariable *GenGlobalArrayHelper(
      llvm::Type *, std::vector<llvm::Constant *> &, const llvm::Twine &Name = "",
      bool isConstant = true,
      llvm::GlobalValue::LinkageTypes linkage = llvm::GlobalValue::ExternalLinkage);

  /* Declare global helper function called by lifted llvm bitcode (need override) */
  virtual void DeclareHelperFunction();

  /* Prepare the virtual machine for instruction test (need override) */
  virtual llvm::BasicBlock *PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                         llvm::BranchInst *);
  /* Check the virtual machine for instruction test (need override) */
  virtual llvm::BranchInst *CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &);

  /* Add L_test_failed (need override) */
  virtual void AddTestFailedBlock();

  // Save the basic block parents on the new direct branch
  void DirectBranchWithSaveParents(llvm::BasicBlock *dst_bb, llvm::BasicBlock *src_bb);
  // Save the basic block paretns on the new conditional branch
  void ConditionalBranchWithSaveParents(llvm::BasicBlock *true_bb, llvm::BasicBlock *false_bb,
                                        llvm::Value *condition, llvm::BasicBlock *src_bb);

  llvm::Value *GetValueFromTargetBBAndReg(llvm::BasicBlock *target_bb, llvm::BasicBlock *request_bb,
                                          std::pair<EcvReg, EcvRegClass> ecv_reg_info);

  const Arch *const arch;
  const remill::IntrinsicTable *intrinsics;
  llvm::Type *word_type;
  llvm::LLVMContext &context;
  llvm::Module *const module;
  const uint64_t addr_mask;
  TraceManager &manager;

  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::BasicBlock *indirectbr_block;
  BBRegInfoNode *bb_reg_info_node;
  std::map<uint64_t, llvm::BasicBlock *> lifted_block_map;
  std::vector<std::pair<llvm::BasicBlock *, llvm::Value *>> br_blocks;
  bool lift_all_insn;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  Instruction delayed_inst;
  std::unordered_map<uint64_t, bool> control_flow_debug_list;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  DecoderWorkList dead_inst_work_list;
  uint64_t __trace_addr;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  VirtualRegsOpt *virtual_regs_opt;

  std::unordered_map<llvm::Function *, VirtualRegsOpt *> func_virtual_regs_opt_map;
  std::set<llvm::Function *> no_indirect_lifted_funcs;

  std::string runtime_manager_name;

  std::string indirectbr_block_name;
  std::string g_get_indirectbr_block_address_func_name;
  std::string debug_memory_value_change_name;
  std::string debug_insn_name;
  std::string debug_call_stack_push_name;
  std::string debug_call_stack_pop_name;

  const llvm::DataLayout data_layout;

  bool tmp_patch_fn_check = false;
};

}  // namespace remill
