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
#include "remill/BC/InstructionLifter.h"
#include "remill/BC/Lifter.h"

#include <cstdint>
#include <functional>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <queue>
#include <tuple>
#include <unordered_map>

namespace remill {

extern std::ostringstream ECV_DEBUG_STREAM;

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

  virtual std::string AddRestDisasmFunc(uint64_t addr) = 0;
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

  virtual uint64_t GetFuncNums() = 0;

  /* global array of block address various data */
  std::vector<llvm::Constant *> g_block_address_ptrs_array;
  std::vector<llvm::Constant *> g_block_address_vmas_array;
  std::vector<llvm::Constant *> g_block_address_size_array;
  std::vector<llvm::Constant *> g_block_address_fn_vma_array;

  uint64_t _io_file_xsputn_vma = 0;
  uint64_t noopt_lift_fin_cnt = 0;
};

class BBBag {
 public:
  BBBag(EcvRegMap<ERC> __own_ld_reg_map, EcvRegMap<ERC> __succeeding_load_reg_map,
        EcvRegMap<ERC> &&__own_str_reg_map, std::set<llvm::BasicBlock *> &&__in_bbs)
      : own_ld_rmp(__own_ld_reg_map),
        own_str_rmp(std::move(__own_str_reg_map)),
        sucs_ld_rmp(__succeeding_load_reg_map),
        in_bbs(std::move(__in_bbs)),
        converted_bag(nullptr) {}

  BBBag() {}
  static void Reset() {
    bb_regs_bag_map.clear();
    bag_num = 0;
    debug_bag_map.clear();
  }

  static void GetPrecedingVirtualRegsBags(llvm::BasicBlock *root_bb);
  static void GetSucceedingVirtualRegsBags(llvm::BasicBlock *root_bb);
  static void RemoveLoop(llvm::BasicBlock *bb);
  static void
  GetPhiRegsBags(llvm::BasicBlock *root_bb,
                 std::unordered_map<llvm::BasicBlock *, BBRegInfoNode *> &bb_info_node_map);

  static inline std::unordered_map<llvm::BasicBlock *, BBBag *> bb_regs_bag_map = {};
  static inline std::size_t bag_num = 0;
  static inline std::unordered_map<BBBag *, uint32_t> debug_bag_map = {};
  // The register set which should be passed from caller function.

  BBBag *GetTrueBag();
  void MergeOwnRegs(BBBag *moved_bag);
  void MergeFamilyBags(BBBag *merged_bag);

  static void DebugGraphStruct(BBBag *target_bag);

  // The register set which is loaded in the own bag.
  EcvRegMap<ERC> own_ld_rmp;
  // The register set which is stored in the own bag.
  EcvRegMap<ERC> own_str_rmp;

  // The regsiter set which is loaded on the way to the basic blocks of this bag node ("not" include the own block).
  // We "don't" use this after calculating `drvd_rmp`
  EcvRegMap<ERC> pres_ld_rmp;
  // The register set which is stored in the way to the bag node ("not" includes the own block).
  // We use this to store the modified register on the preceding basic blocks before calling the lifted_function.
  EcvRegMap<ERC> pres_str_rmp;

  // The register set which is loaded on the succeeding block (includes the own block).
  // We "don't" use this after calculating `drvd_rmp`
  EcvRegMap<ERC> sucs_ld_rmp;

  // pres_str_rmp + (pres_ld_rmp & sucs_ld_rmp)
  // The register set which should be devived from the parents bags.
  EcvRegMap<ERC> drvd_rmp;

  // The basic block set which is included in this bag.
  std::set<llvm::BasicBlock *> in_bbs;

  std::set<BBBag *> parents;
  std::set<BBBag *> children;

  BBBag *converted_bag;

  bool is_loop;
};

// Implements a recursive decoder that lifts a trace of instructions to bitcode.
class TraceLifter {
 public:
  class Impl;
  std::unique_ptr<Impl> impl;

 public:
  ~TraceLifter(void);

  inline TraceLifter(const Arch *arch_, TraceManager &manager_, LiftConfig lift_config_)
      : TraceLifter(arch_, &manager_, lift_config_) {}

  TraceLifter(const Arch *arch_, TraceManager *manager_, LiftConfig lift_config_);

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

// This class is the base class for the optimization of virtual registers propagation (VRP).
// ref: https://github.com/yomaytk/elfconv/pull/53
class VirtualRegsOpt {
 public:
  VirtualRegsOpt(llvm::Function *__func, TraceLifter::Impl *__impl, uint64_t __fun_vma);

  llvm::Type *ERC2LLVMTy(ERC erc);
  llvm::Type *ERC2WholeLLVMTy(EcvReg);
  ERC LLVMTy2ERC(llvm::Type *value_type);
  llvm::Value *GetDrvdValue(llvm::BasicBlock *t_bb, llvm::BasicBlock *request_bb,
                            std::pair<EcvReg, ERC> er_info);
  llvm::Value *CastFromInst(EcvReg t_er, llvm::Value *from_inst, llvm::Type *to_inst_ty,
                            llvm::Instruction *inst_at_before);

  llvm::Value *
  GetRegValueFromCacheMap(EcvReg t_er, llvm::Type *to_type, llvm::Instruction *inst_at_before,
                          EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> &cache_map);

  void AnalyzeRegsBags();
  static void CalPassedCallerRegForBJump();

  void OptimizeVirtualRegsUsage();

  static inline std::unordered_map<llvm::Function *, VirtualRegsOpt *> func_v_r_opt_map = {};
  static inline std::unordered_map<llvm::Function *, std::vector<llvm::Function *>>
      b_jump_callees_map = {};

  llvm::Function *func;
  TraceLifter::Impl *impl;
  llvm::Value *arg_state_val;
  llvm::Value *arg_runtime_val;

  // All llvm::CallInst* of the lifted function.
  // Use to distinguish semantic function and lifted function.
  std::set<llvm::CallInst *> lifted_func_caller_set;

  std::unordered_map<llvm::BasicBlock *, std::set<llvm::BasicBlock *>> bb_parents;
  std::unordered_map<llvm::BasicBlock *, BBRegInfoNode *> bb_reg_info_node_map;

  std::queue<llvm::BasicBlock *> phi_bb_queue;
  std::set<llvm::BasicBlock *> relay_bb_cache;

  uint64_t phi_val_order;

  std::unordered_map<llvm::BasicBlock *, BBBag *> bb_regs_bag_map;
  EcvRegMap<ERC> passed_caller_reg_map;
  EcvRegMap<ERC> passed_callee_ret_reg_map;

  std::set<llvm::ReturnInst *> ret_inst_set;

  // for debug
  uint64_t fun_vma;
  uint64_t block_num;
  std::string func_name;
  // map llvm::Value* and the corresponding CPU register.
  std::unordered_map<llvm::Value *, std::pair<EcvReg, ERC>> value_reg_map;
  std::set<EcvReg> debug_reg_set = {};

  void InsertDebugVmaAndRegisters(
      llvm::Instruction *inst_at_before,
      EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> &ascend_reg_inst_map, uint64_t pc);
};

class TraceLifter::Impl {
 public:
  Impl(const Arch *arch_, TraceManager *manager_, LiftConfig lift_config_)
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
        lift_config(lift_config_),
        runtime_manager_name("RuntimeManager"),
        indirectbr_block_name("L_indirectbr"),
        g_get_indirectbr_block_address_func_name("_ecv_get_indirectbr_block_address"),
        _ecv_noopt_get_bb_name("_ecv_noopt_get_bb"),
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

  /* Global variable array definition helper (need override) */
  virtual llvm::GlobalVariable *
  SetGblArrayIr(llvm::Type *, std::vector<llvm::Constant *> &, const llvm::Twine &Name = "",
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

  void AddStoreForAllSemantics();
  void GenIndirectJumpCode(uint64_t trace_addr);

  // emscripten fiber (fork)
  void JoinBasicBlocksForFork();
  void AddFiberNearJump();
  void AddFiberSwitchBB();
  void AddBrBBIR();
  void AddFarJumpBB();
  void FiberContextSwitchMain(uint64_t trace_addr);

  // emscripten pthread (fork)
  void GenPthreadForkNearJump(uint64_t trace_addr);

  void Optimize();

  const Arch *const arch;
  const remill::IntrinsicTable *intrinsics;
  llvm::Type *word_type;
  llvm::LLVMContext &context;
  llvm::Module *const module;
  const uint64_t addr_mask;
  TraceManager &manager;

  llvm::Function *func;
  llvm::BasicBlock *block;
  llvm::Argument *arena_ptr, *state_ptr, *runtime_ptr;
  llvm::BasicBlock *br_bb, *far_jump_bb;
  std::vector<llvm::Constant *> bb_addrs, bb_addr_vmas;
  BBRegInfoNode *bb_reg_info_node;
  std::map<uint64_t, llvm::BasicBlock *> lifted_block_map;
  std::map<llvm::BasicBlock *, uint64_t> rev_lifted_block_map;
  std::vector<std::pair<llvm::BasicBlock *, llvm::Value *>> br_blocks;
  bool lift_all_insn;
  const size_t max_inst_bytes;
  std::string inst_bytes;
  Instruction inst;
  Instruction delayed_inst;
  DecoderWorkList trace_work_list;
  DecoderWorkList inst_work_list;
  DecoderWorkList dead_inst_work_list;
  std::map<uint64_t, llvm::BasicBlock *> blocks;
  VirtualRegsOpt *virtual_regs_opt;

  // process management
  std::set<llvm::BasicBlock *> lift_or_system_calling_bbs;
  std::map<llvm::BasicBlock *, uint64_t> inst_nums_in_bb;

  llvm::BasicBlock *_near_jump_bb;

  LiftConfig lift_config;

  // In the latest implementation, we don't use this because we can apply VPR optimization to the almost Linux/ELF binary.
  // Then, we occur the exception when we enter the process of the `not` VRP optimization, or comment out the relevant functions.
  bool vrp_opt_mode;

  bool norm_mode;

  std::set<llvm::Function *> opt_target_funcs;
  std::set<llvm::Function *> lifted_funcs;

  std::unordered_map<llvm::CallInst *, std::vector<std::pair<EcvReg, ERC>>> sema_func_args_regs_map;

  std::vector<std::pair<uint64_t, llvm::Constant *>> noopt_all_vma_bbs;

  std::string runtime_manager_name;

  std::string indirectbr_block_name;
  std::string g_get_indirectbr_block_address_func_name;
  std::string _ecv_noopt_get_bb_name;

  std::string debug_memory_value_change_name;
  std::string debug_insn_name;
  std::string debug_call_stack_push_name;
  std::string debug_call_stack_pop_name;

  const llvm::DataLayout data_layout;

  bool tmp_patch_fn_check = false;
};

}  // namespace remill
