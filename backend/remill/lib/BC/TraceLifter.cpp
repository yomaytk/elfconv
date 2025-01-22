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

#include "remill/Arch/Arch.h"

#include <glog/logging.h>
#include <iostream>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <map>
#include <remill/Arch/Instruction.h>
#include <remill/Arch/Name.h>
#include <remill/BC/HelperMacro.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <set>
#include <sstream>

extern remill::ArchName TARGET_ELF_ARCH;

namespace remill {


#if defined(OPT_ALGO_DEBUG)
#  define ECV_LOG(...) EcvLog(__VA_ARGS__)
#  define ECV_LOG_NL(...) EcvLogNL(__VA_ARGS__)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag) PhiRegsBBBagNode::DebugGraphStruct(bag)
#else
#  define ECV_LOG(...)
#  define ECV_LOG_NL(...)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag)
#endif

#if defined(OPT_REAL_REGS_DEBUG)
#  define DEBUG_PC_AND_REGISTERS(...) InsertDebugVmaAndRegisters(__VA_ARGS__)
#  define VAR_NAME(ecv_reg, ecv_reg_class) \
    ecv_reg->GetRegName(ecv_reg_class) + "_" + to_string(phi_val_order++)
#else
#  define DEBUG_PC_AND_REGISTERS(...)
#  define VAR_NAME(ecv_reg, ecv_reg_class) \
    ecv_reg.GetRegName(ecv_reg_class) + "_" + to_string(phi_val_order++)
#endif

std::ostringstream ECV_DEBUG_STREAM;

static void DebugStreamReset() {
  ECV_DEBUG_STREAM.str("");
  ECV_DEBUG_STREAM.clear(std::ostringstream::goodbit);
}

std::ostringstream &EcvLog() {
  return ECV_DEBUG_STREAM;
}

template <typename T, typename... Args>
std::ostringstream &EcvLog(T &&value, const Args &...args) {
  ECV_DEBUG_STREAM << value;
  return EcvLog(args...);
}

std::ostringstream &EcvLogNL() {
  ECV_DEBUG_STREAM << "\n";
  return ECV_DEBUG_STREAM;
}

template <typename T, typename... Args>
std::ostringstream &EcvLogNL(T &&value, const Args &...args) {
  ECV_DEBUG_STREAM << value;
  return EcvLogNL(args...);
}

/*
    TraceManager methods
  */
TraceManager::~TraceManager(void) {}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceManager::GetLiftedTraceDeclaration(uint64_t) {
  return nullptr;
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceManager::GetLiftedTraceDefinition(uint64_t) {
  return nullptr;
}

// Apply a callback that gives the decoder access to multiple virtual
// targets of this instruction (indirect call or jump).
void TraceManager::ForEachDevirtualizedTarget(
    const Instruction &, std::function<void(uint64_t, DevirtualizedTargetKind)>) {
  // Must be extended.
}

// Figure out the name for the trace starting at address `addr`.
std::string TraceManager::TraceName(uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

/*
    TraceLifter::Impl methods
  */
// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::Impl::GetLiftedTraceDeclaration(uint64_t addr) {
  auto func = manager.GetLiftedTraceDeclaration(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  return nullptr;
}

// Return an already lifted trace starting with the code at address
// `addr`.
llvm::Function *TraceLifter::Impl::GetLiftedTraceDefinition(uint64_t addr) {
  auto func = manager.GetLiftedTraceDefinition(addr);
  if (!func || func->getParent() == module) {
    return func;
  }

  CHECK_EQ(&(func->getContext()), &context);

  auto func_type =
      llvm::dyn_cast<llvm::FunctionType>(RecontextualizeType(func->getFunctionType(), context));

  // Handle the different module situation by declaring the trace in
  // this module to be external, with the idea that it will link to
  // another module.
  auto extern_func = module->getFunction(func->getName());
  if (!extern_func || extern_func->getFunctionType() != func_type) {
    extern_func = llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                         func->getName(), module);

  } else if (extern_func->isDeclaration()) {
    extern_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  return extern_func;
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateBlock(uint64_t block_pc) {
  auto &block = blocks[block_pc];
  if (!block)
    block = llvm::BasicBlock::Create(context, "", func);
  if (lifted_block_map.count(block_pc) == 0)
    lifted_block_map[block_pc] = block;
  return block;
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateBranchTakenBlock(void) {
  inst_work_list.insert(inst.branch_taken_pc);
  return GetOrCreateBlock(inst.branch_taken_pc);
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateBranchNotTakenBlock(void) {
  CHECK(inst.branch_not_taken_pc != 0);
  inst_work_list.insert(inst.branch_not_taken_pc);
  return GetOrCreateBlock(inst.branch_not_taken_pc);
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateNextBlock(void) {
  inst_work_list.insert(inst.next_pc);
  return GetOrCreateBlock(inst.next_pc);
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateIndirectJmpBlock(void) {
  llvm::Function::iterator fun_iter = func->begin();
  llvm::Function::iterator fun_iter_e = func->end();
  for (; fun_iter != fun_iter_e; fun_iter++) {
    llvm::BasicBlock *bb = &*fun_iter;
    if (bb->getName() == indirectbr_block_name) {
      return bb;
    }
  }
  return llvm::BasicBlock::Create(context, indirectbr_block_name, func);
}

uint64_t TraceLifter::Impl::PopTraceAddress(void) {
  auto trace_it = trace_work_list.begin();
  const auto trace_addr = *trace_it;
  trace_work_list.erase(trace_it);
  return trace_addr;
}

uint64_t TraceLifter::Impl::PopInstructionAddress(void) {
  auto inst_it = inst_work_list.begin();
  const auto inst_addr = *inst_it;
  inst_work_list.erase(inst_it);
  return inst_addr;
}

/* Global variable array definition helper (need override) */
llvm::GlobalVariable *TraceLifter::Impl::GenGlobalArrayHelper(llvm::Type *,
                                                              std::vector<llvm::Constant *> &,
                                                              const llvm::Twine &, bool,
                                                              llvm::GlobalValue::LinkageTypes) {
  printf("[ERROR] %s must be called by derived class instance.\n", __func__);
  abort();
}

void TraceLifter::Impl::DeclareHelperFunction() {
  printf("[ERROR] %s must be called by derived class instance.\n", __func__);
  abort();
}

/* prepare the virtual machine for instruction test (need override) */
llvm::BasicBlock *TraceLifter::Impl::PreVirtualMachineForInsnTest(uint64_t, TraceManager &,
                                                                  llvm::BranchInst *) {
  printf("[ERROR] %s must be called by derived class instance.\n", __func__);
  abort();
}

/* check the virtual machine for instruction test (need override) */
llvm::BranchInst *TraceLifter::Impl::CheckVirtualMahcineForInsnTest(uint64_t, TraceManager &) {
  printf("[ERROR] %s must be called by derived class instance.\n", __func__);
  abort();
}

/* add L_test_failed (need override) */
void TraceLifter::Impl::AddTestFailedBlock() {
  printf("[ERROR] %s must be called by derived class instance.\n", __func__);
  abort();
}

void TraceLifter::Impl::DirectBranchWithSaveParents(llvm::BasicBlock *dst_bb,
                                                    llvm::BasicBlock *src_bb) {
  auto &parents = virtual_regs_opt->bb_parents[dst_bb];
  parents.insert(src_bb);
  llvm::BranchInst::Create(dst_bb, src_bb);
}

void TraceLifter::Impl::ConditionalBranchWithSaveParents(llvm::BasicBlock *true_bb,
                                                         llvm::BasicBlock *false_bb,
                                                         llvm::Value *condition,
                                                         llvm::BasicBlock *src_bb) {
  auto &true_parents = virtual_regs_opt->bb_parents[true_bb];
  auto &false_parents = virtual_regs_opt->bb_parents[false_bb];
  true_parents.insert(src_bb);
  false_parents.insert(src_bb);
  llvm::BranchInst::Create(true_bb, false_bb, condition, src_bb);
}

/*
    TraceLifter methods
  */
TraceLifter::~TraceLifter(void) {}

TraceLifter::TraceLifter(const Arch *arch_, TraceManager *manager_)
    : impl(new Impl(arch_, manager_)) {}

void TraceLifter::NullCallback(uint64_t, llvm::Function *) {}

// Reads the bytes of an instruction at `addr` into `inst_bytes`.
bool TraceLifter::Impl::ReadInstructionBytes(uint64_t addr) {
  inst_bytes.clear();
  for (size_t i = 0; i < max_inst_bytes; ++i) {
    const auto byte_addr = (addr + i) & addr_mask;
    if (byte_addr < addr) {
      break;  // 32- or 64-bit address overflow.
    }
    uint8_t byte = 0;
    if (!manager.TryReadExecutableByte(byte_addr, &byte)) {
#if defined(WARNING_OUTPUT)
      printf("[WARNING] Couldn't read executable byte at 0x%lx\n", byte_addr);
#endif
      DLOG(WARNING) << "Couldn't read executable byte at " << std::hex << byte_addr << std::dec;
      break;
    }
    inst_bytes.push_back(static_cast<char>(byte));
  }
  return !inst_bytes.empty();
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Lift(uint64_t addr, const char *fn_name,
                       std::function<void(uint64_t, llvm::Function *)> callback) {
  return impl->Lift(addr, fn_name, callback);
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Impl::Lift(uint64_t addr, const char *fn_name,
                             std::function<void(uint64_t, llvm::Function *)> callback) {
  // Reset the lifting state.
  trace_work_list.clear();
  inst_work_list.clear();
  blocks.clear();
  inst_bytes.clear();
  func = nullptr;
  block = nullptr;
  bb_reg_info_node = nullptr;
  lifted_block_map.clear();
  lift_all_insn = false;
  indirectbr_block = nullptr;
  inst.Reset();
  delayed_inst.Reset();

  // Get a trace head that the manager knows about, or that we
  // will eventually tell the trace manager about.
  auto get_trace_decl = [=](uint64_t trace_addr) -> llvm::Function * {
    if (!manager.isFunctionEntry(trace_addr))
      return nullptr;

    if (auto lifted_fn = GetLiftedTraceDeclaration(trace_addr)) {
      return lifted_fn;
    } else if (auto declared_fn = module->getFunction(manager.GetLiftedFuncName(trace_addr))) {
      return declared_fn;
    } else {
      return arch->DeclareLiftedFunction(manager.GetLiftedFuncName(trace_addr), module);
    }
  };

  trace_work_list.insert(addr);

  while (!trace_work_list.empty()) {
    const auto trace_addr = PopTraceAddress();
    __trace_addr = trace_addr;

    // Already lifted.
    func = GetLiftedTraceDefinition(trace_addr);
    if (func) {
      continue;
    }

    DLOG(INFO) << "Lifting trace at address " << std::hex << trace_addr << std::dec;

    func = get_trace_decl(trace_addr);
    blocks.clear();
    lifted_block_map.clear();
    br_blocks.clear();
    indirectbr_block = nullptr;
    lift_all_insn = false;

    lifted_funcs.insert(func);

    CHECK(func->isDeclaration());
    virtual_regs_opt = new VirtualRegsOpt(func, this, trace_addr);
    virtual_regs_opt->func_name = func->getName().str();
    VirtualRegsOpt::func_v_r_opt_map.insert({func, virtual_regs_opt});

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    arch->InitializeEmptyLiftedFunction(func);

    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    auto runtime_ptr = NthArgument(func, kRuntimePointerArgNum);

/* insert debug call stack function (for debug) */
#if defined(LIFT_CALLSTACK_DEBUG)
    do {
      llvm::BasicBlock &first_block =
          *std::prev(func->end()); /* arch->InitializeEmptyLiftedFunction(func)
                                        generates first block */
      llvm::IRBuilder<> __debug_ir(&first_block);
      auto _debug_call_stack_push_fn = module->getFunction(debug_call_stack_push_name);
      if (!_debug_call_stack_push_fn) {
        printf("[ERROR] debug_call_stack_fn is undeclared.\n");
        abort();
      }
      std::vector<llvm::Value *> args = {
          runtime_ptr, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr)};
      __debug_ir.CreateCall(_debug_call_stack_push_fn, args);
    } while (false);
#endif


    if (auto entry_block = &(func->front())) {
      // Branch to the block of trace_addr.
      DirectBranchWithSaveParents(GetOrCreateBlock(trace_addr), entry_block);
      auto entry_bb_reg_info_node = new BBRegInfoNode(func, state_ptr, runtime_ptr);
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(entry_block))
          << "The entry block has been already added illegally to the VirtualRegsOpt.";
      virtual_regs_opt->bb_reg_info_node_map.insert({entry_block, entry_bb_reg_info_node});
    } else {
      LOG(FATAL) << "Initialized function must have the entry block. address: " << trace_addr;
    }

    CHECK(inst_work_list.empty());
    inst_work_list.insert(trace_addr);

  // Decode instructions.
  inst_lifting_start:
    while (!inst_work_list.empty()) {
      const auto inst_addr = PopInstructionAddress();

      block = GetOrCreateBlock(inst_addr);
      lifted_block_map.insert({inst_addr, block});

      // We have already lifted this instruction block.
      if (!block->empty()) {
        continue;
      }

      bb_reg_info_node = new BBRegInfoNode(func, state_ptr, runtime_ptr);
      // map the block to the bb_reg_info_node
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(block))
          << "The block and the bb_reg_info_node have already been appended to the map.";
      virtual_regs_opt->bb_reg_info_node_map.insert({block, bb_reg_info_node});

      // Check to see if this instruction corresponds with an existing
      // trace head, and if so, tail-call into that trace directly without
      // decoding or lifting the instruction.
      if (inst_addr != trace_addr) {
        if (auto inst_as_trace = get_trace_decl(inst_addr)) {
          auto inst_as_trace_call = AddTerminatingTailCall(
              block, inst_as_trace, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
          virtual_regs_opt->lifted_func_caller_set.insert(inst_as_trace_call);
          continue;
        }
      }

      // No executable bytes here.
      if (!ReadInstructionBytes(inst_addr)) {
        AddTerminatingTailCall(block, intrinsics->missing_block, *intrinsics, trace_addr);
        continue;
      }

      inst.Reset();

      // TODO(Ian): not passing context around in trace lifter
      std::ignore =
          arch->DecodeInstruction(inst_addr, inst_bytes, inst, this->arch->CreateInitialContext());

      // Lift instruction
      auto lift_status = inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr, bb_reg_info_node);

      if (!tmp_patch_fn_check && manager._io_file_xsputn_vma == trace_addr) {
        llvm::IRBuilder<> ir(block);
        auto [x0_ptr, _] = inst.GetLifter()->LoadRegAddress(block, state_ptr, "X0");
        std::vector<llvm::Value *> args = {runtime_ptr,
                                           ir.CreateLoad(llvm::Type::getInt64Ty(context), x0_ptr)};
        auto tmp_patch_fn = module->getFunction("temp_patch_f_flags");
        ir.CreateCall(tmp_patch_fn, args);
        tmp_patch_fn_check = true;
      }

      if (kLiftedInstruction != lift_status) {
        // LOG(FATAL) << "lifted_status is invalid at: " << inst.function;
        AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr);
#if defined(WARNING_OUTPUT)
        if (manager.isWithinFunction(trace_addr, inst.next_pc)) {
          DirectBranchWithSaveParents(GetOrCreateNextBlock(), block);
        }
#endif
        continue;
      }

      // Handle lifting a delayed instruction.
      auto try_delay = arch->MayHaveDelaySlot(inst);
      if (try_delay) {
        delayed_inst.Reset();
        if (!ReadInstructionBytes(inst.delayed_pc) ||
            !arch->DecodeDelayedInstruction(inst.delayed_pc, inst_bytes, delayed_inst,
                                            this->arch->CreateInitialContext())) {
          LOG(ERROR) << "Couldn't read delayed inst " << delayed_inst.Serialize();
          AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr);
          continue;
        }
      }

      // Functor used to add in a delayed instruction.
      auto try_add_delay_slot = [&](bool on_branch_taken_path,
                                    llvm::BasicBlock *into_block) -> void {
        if (!try_delay) {
          return;
        }
        if (!arch->NextInstructionIsDelayed(inst, delayed_inst, on_branch_taken_path)) {
          return;
        }
        CHECK(false) << "Expected not to be unreachable?";
        // lift_status = delayed_inst.GetLifter()->LiftIntoBlock(delayed_inst, into_block, state_ptr,
        //                                                       true /* is_delayed */);
        // if (kLiftedInstruction != lift_status) {
        //   AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr);
        // }
      };

      // Connect together the basic blocks.
      switch (inst.category) {
        case Instruction::kCategoryInvalid:
        case Instruction::kCategoryError:
          AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr);
          break;

        case Instruction::kCategoryNormal:
        case Instruction::kCategoryNoOp:
          DirectBranchWithSaveParents(GetOrCreateNextBlock(), block);
          break;

        // Direct jumps could either be local or could be tail-calls. In the
        // case of a tail call, we'll assume that the trace manager contains
        // advanced knowledge of this, and so when we go to make a block for
        // the targeted instruction, we'll either tail call to the target
        // trace, or we'll just extend out the current trace. Either way, no
        // sacrifice in correctness is made.
        case Instruction::kCategoryDirectJump:
          try_add_delay_slot(true, block);
          if (!manager.isWithinFunction(trace_addr, inst.branch_taken_pc)) {
            auto callee_def_func = get_trace_decl(inst.branch_taken_pc);
            if (callee_def_func) {
              if (VirtualRegsOpt::b_jump_callees_map.contains(func)) {
                VirtualRegsOpt::b_jump_callees_map.at(func).push_back(callee_def_func);
              } else {
                VirtualRegsOpt::b_jump_callees_map.insert({func, {callee_def_func}});
              }
            }
          }
          DirectBranchWithSaveParents(GetOrCreateBranchTakenBlock(), block);
          break;

        /* case: BR instruction (only BR in glibc) */
        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);
          /* indirectbr entry block */
          indirectbr_block = GetOrCreateIndirectJmpBlock();
          if (!virtual_regs_opt->bb_reg_info_node_map.contains(indirectbr_block)) {
            virtual_regs_opt->bb_reg_info_node_map.insert(
                {indirectbr_block, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
          }
          br_blocks.push_back({block, FindIndirectBrAddress(block)});
          /* jmp to indirectbr block */
          DirectBranchWithSaveParents(indirectbr_block, block);
          break;
        }

        case Instruction::kCategoryAsyncHyperCall:
          // In the current implementation, __remill_async_hyper_call is empty.
          // AddCall(block, intrinsics->async_hyper_call, *intrinsics,
          //         llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));

          // if the next instruction is not included in this function, jumping to it is illegal.
          // Therefore, we force to return at this block because we assume that this instruction don't come back to.
          if (manager.isFunctionEntry(inst.next_pc)) {
            llvm::ReturnInst::Create(context, block);
          } else {
            goto check_call_return;
          }
          break;

        /* case: BLR instruction (only BLR in glibc) */
        case Instruction::kCategoryIndirectFunctionCall: {
          try_add_delay_slot(true, block);
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();
          // indirect jump address is value of %Xzzz just before
          auto lifted_func_call =
              AddCall(block, intrinsics->function_call, *intrinsics, FindIndirectBrAddress(block));
          DirectBranchWithSaveParents(not_taken_block, block);
          virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);
          block = not_taken_block;
          continue;
        }

        // no instruction in aarch64?
        case Instruction::kCategoryConditionalIndirectFunctionCall: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "`Instruction::kCategoryConditionalIndirectFunctionCall` instruction exists in aarch64?";
          auto taken_block = llvm::BasicBlock::Create(context, "", func);
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();
          const auto orig_not_taken_block = not_taken_block;

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            not_taken_block = llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, taken_block);
            try_add_delay_slot(false, not_taken_block);

            DirectBranchWithSaveParents(orig_not_taken_block, not_taken_block);
          }

          ConditionalBranchWithSaveParents(taken_block, not_taken_block, LoadBranchTaken(block),
                                           block);

          AddCall(taken_block, intrinsics->function_call, *intrinsics);

          const auto ret_pc_ref = LoadReturnProgramCounterRef(taken_block);
          const auto next_pc_ref = LoadNextProgramCounterRef(taken_block);
          llvm::IRBuilder<> ir(taken_block);
          ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
          DirectBranchWithSaveParents(orig_not_taken_block, taken_block);
          block = orig_not_taken_block;
          continue;
        }

        // In the case of a direct function call, we try to handle the
        // pattern of a call to the next PC as a way of getting access to
        // an instruction pointer. It is the case where a call to the next
        // PC could also be something more like a call to a `noreturn` function
        // and that is OK, because either a user of the trace manager has
        // already told us that the next PC is a trace head (and we'll pick
        // that up when trying to lift it), or we'll just have a really big
        // trace for this function without sacrificing correctness.
        case Instruction::kCategoryDirectFunctionCall: {
        direct_func_call:
          try_add_delay_slot(true, block);
          auto target_trace = get_trace_decl(inst.branch_taken_pc);
          // The ELF/aarch64 binary generated by cross compilation of clang-16 has the instruction like a `bl _d_24`.
          // However, the symbol like `_d_24` doesn't indicate the function, so lifting it is invalid.
          // When we find such a instruction, we treat it as `nop`.
          if (target_trace && inst.branch_not_taken_pc != inst.branch_taken_pc) {
            trace_work_list.insert(inst.branch_taken_pc);
            auto lifted_func_call = AddCall(
                block, target_trace, *intrinsics,
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.branch_taken_pc));
            virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);
          }
          DirectBranchWithSaveParents(GetOrCreateBranchNotTakenBlock(), block);
          continue;
        }

        case Instruction::kCategoryConditionalDirectFunctionCall: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "`Instruction::kCategoryConditionalDirectFunctionCall` instruction exists in aarch64?";
          if (inst.branch_not_taken_pc == inst.branch_taken_pc) {
            goto direct_func_call;
          }

          auto taken_block = llvm::BasicBlock::Create(context, "", func);
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();
          const auto orig_not_taken_block = not_taken_block;

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            not_taken_block = llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, taken_block);
            try_add_delay_slot(false, not_taken_block);

            DirectBranchWithSaveParents(orig_not_taken_block, not_taken_block);
          }

          ConditionalBranchWithSaveParents(taken_block, not_taken_block, LoadBranchTaken(block),
                                           block);

          trace_work_list.insert(inst.branch_taken_pc);
          auto target_trace = get_trace_decl(inst.branch_taken_pc);

          AddCall(taken_block, intrinsics->function_call, *intrinsics);
          AddCall(taken_block, target_trace, *intrinsics);

          DirectBranchWithSaveParents(orig_not_taken_block, taken_block);
          block = orig_not_taken_block;
          continue;
        }

        // Lift an async hyper call to check if it should do the hypercall.
        // If so, it will jump to the `do_hyper_call` block, otherwise it will
        // jump to the block associated with the next PC. In the case of the
        // `do_hyper_call` block, we assign it to `state.block`, then go
        // to `check_call_return` to add the hyper call into that block,
        // checking if the hyper call returns to the next PC or not.
        //
        // TODO(pag): Delay slots?
        case Instruction::kCategoryConditionalAsyncHyperCall: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "`Instruction::kCategoryConditionalAsyncHyperCall` instruction exists in aarch64?";
          auto do_hyper_call = llvm::BasicBlock::Create(context, "", func);
          ConditionalBranchWithSaveParents(do_hyper_call, GetOrCreateNextBlock(),
                                           LoadBranchTaken(block), block);
          block = do_hyper_call;
          AddCall(block, intrinsics->async_hyper_call, *intrinsics,
                  llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
          goto check_call_return;
        }

        check_call_return:
          do {
            DirectBranchWithSaveParents(GetOrCreateNextBlock(), block);
            // WARNING: if there is no next instruction in this function, this create the branch instruction
            // to the invalid instruction of next address.
          } while (false);
          break;

        case Instruction::kCategoryFunctionReturn: {
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(
              block, intrinsics->function_return, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
          auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>(block->getTerminator());
          CHECK(ret_inst) << "ret_inst must be ReturnInst. inst: " << LLVMThingToString(ret_inst);
          virtual_regs_opt->ret_inst_set.insert(ret_inst);

        } break;

        case Instruction::kCategoryConditionalFunctionReturn: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "`Instruction::kCategoryConditionalFunctionReturn` instruction exists in aarch64?";
          auto taken_block = llvm::BasicBlock::Create(context, "", func);
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();
          const auto orig_not_taken_block = not_taken_block;

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            not_taken_block = llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, taken_block);
            try_add_delay_slot(false, not_taken_block);

            DirectBranchWithSaveParents(orig_not_taken_block, not_taken_block);
          }

          ConditionalBranchWithSaveParents(taken_block, not_taken_block, LoadBranchTaken(block),
                                           block);

          AddTerminatingTailCall(
              taken_block, intrinsics->function_return, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
          block = orig_not_taken_block;
          continue;
        }

        case Instruction::kCategoryConditionalBranch: {
          auto taken_block = GetOrCreateBranchTakenBlock();
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
                << "try delay of `Instruction::kCategoryConditionalBranch` instruction exists in aarch64?";
            auto new_taken_block = llvm::BasicBlock::Create(context, "", func);
            auto new_not_taken_block = llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, new_taken_block);
            try_add_delay_slot(false, new_not_taken_block);

            DirectBranchWithSaveParents(taken_block, new_taken_block);
            DirectBranchWithSaveParents(not_taken_block, new_not_taken_block);

            taken_block = new_taken_block;
            not_taken_block = new_not_taken_block;
          }

          ConditionalBranchWithSaveParents(taken_block, not_taken_block, LoadBranchTaken(block),
                                           block);
          break;
        }
        // no instruction in aarch64?
        case Instruction::kCategoryConditionalIndirectJump: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "Instruction::kCategoryConditionalIndirectJump` instruction exists in aarch64?";
          auto taken_block = llvm::BasicBlock::Create(context, "", func);
          auto not_taken_block = GetOrCreateBranchNotTakenBlock();
          const auto orig_not_taken_block = not_taken_block;

          // If we might need to add delay slots, then try to lift the delayed
          // instruction on each side of the conditional branch, injecting in
          // new blocks (for the delayed instruction) between the branch
          // and its original targets.
          if (try_delay) {
            not_taken_block = llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, taken_block);
            try_add_delay_slot(false, not_taken_block);

            DirectBranchWithSaveParents(orig_not_taken_block, not_taken_block);
          }

          ConditionalBranchWithSaveParents(taken_block, not_taken_block, LoadBranchTaken(block),
                                           block);

          AddTerminatingTailCall(taken_block, intrinsics->jump, *intrinsics, trace_addr);
          block = orig_not_taken_block;
          continue;
        }
      }
    }

    /* if func includes BR instruction, it is necessary to lift all instructions of the
       * func. */
    if (!lift_all_insn && indirectbr_block) {
      CHECK(inst_work_list.empty());
      for (uint64_t insn_vma = trace_addr; insn_vma < manager.GetFuncVMA_E(trace_addr);
           insn_vma += 4)
        if (lifted_block_map.count(insn_vma) == 0)
          inst_work_list.insert(insn_vma);
      lift_all_insn = true;
      goto inst_lifting_start;
    }

    /* indirectbr block for BR instruction */
    if (indirectbr_block) {
      auto br_to_func_block = llvm::BasicBlock::Create(context, "", func);
      /* generate gvar of block address array (g_bb_addrs) and vma array of it
         * (g_bb_addr_vmas) */
      std::vector<llvm::Constant *> bb_addrs, bb_addr_vmas;
      for (auto &[_vma, _bb] : lifted_block_map) {
        bb_addrs.push_back(llvm::BlockAddress::get(func, _bb));
        bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), _vma));
      }
      /* the end element is br_to_func_block */
      bb_addrs.push_back(llvm::BlockAddress::get(func, br_to_func_block));
      bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), UINT64_MAX));
      auto g_bb_addrs = GenGlobalArrayHelper(llvm::Type::getInt64PtrTy(context), bb_addrs,
                                             func->getName() + ".bb_addrs");
      auto g_bb_addr_vmas = GenGlobalArrayHelper(llvm::Type::getInt64Ty(context), bb_addr_vmas,
                                                 func->getName() + ".bb_addr_vmas");
      /* save pointers of the array */
      manager.g_block_address_ptrs_array.push_back(
          llvm::ConstantExpr::getBitCast(g_bb_addrs, llvm::Type::getInt64PtrTy(context)));
      manager.g_block_address_vmas_array.push_back(
          llvm::ConstantExpr::getBitCast(g_bb_addr_vmas, llvm::Type::getInt64PtrTy(context)));
      manager.g_block_address_size_array.push_back(
          llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), bb_addrs.size()));
      manager.g_block_address_fn_vma_array.push_back(
          llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
      /* indirectbr_block */
      llvm::IRBuilder<> ir_1(indirectbr_block);
      /* calculate the target block address */
      auto g_get_jmp_helper_fn = module->getFunction(
          g_get_indirectbr_block_address_func_name); /* return type: uint64_t* */
      CHECK(g_get_jmp_helper_fn);
      auto br_vma_phi = ir_1.CreatePHI(llvm::Type::getInt64Ty(context), br_blocks.size());
      for (auto &br_pair : br_blocks) {
        auto br_block = br_pair.first;
        auto dest_addr = br_pair.second;
        br_vma_phi->addIncoming(dest_addr, br_block);
        virtual_regs_opt->bb_parents[br_block].insert(indirectbr_block);
      }
      auto target_bb_i64 = ir_1.CreateCall(
          g_get_jmp_helper_fn,
          {runtime_ptr, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr),
           br_vma_phi});
      auto indirect_br_i = ir_1.CreateIndirectBr(
          ir_1.CreatePointerCast(target_bb_i64, llvm::Type::getInt64PtrTy(context)),
          bb_addrs.size());
      for (auto &[_, _block] : lifted_block_map) {
        indirect_br_i->addDestination(_block);
      }
      indirect_br_i->addDestination(br_to_func_block);
      // Update cache for `remill_jump` block.
      virtual_regs_opt->bb_parents.insert({br_to_func_block, {indirectbr_block}});
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(br_to_func_block))
          << "The entry block has been already added illegally to the VirtualRegsOpt.";
      virtual_regs_opt->bb_reg_info_node_map.insert(
          {br_to_func_block, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
      // Add terminate.
      AddTerminatingTailCall(br_to_func_block, intrinsics->jump, *intrinsics, -1, br_vma_phi);

      // Add StoreInst for the every semantics functions.
      auto &inst_lifter = inst.GetLifter();
      for (auto &bb : *func) {
        auto inst = &*bb.begin();
        auto t_bb_reg_info_node = virtual_regs_opt->bb_reg_info_node_map.at(&bb);
        while (inst) {
          auto call_inst = llvm::dyn_cast<llvm::CallInst>(inst);
          inst = inst->getNextNode();
          if (t_bb_reg_info_node->sema_call_written_reg_map.contains(call_inst)) {
#if defined(OPT_REAL_REGS_DEBUG)
            auto debug_llvmir_u64_fn = module->getFunction("debug_llvmir_u64value");
            auto sema_pc = t_bb_reg_info_node->sema_func_pc_map.at(call_inst);
            llvm::CallInst::Create(
                debug_llvmir_u64_fn,
                {llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), sema_pc)}, "", call_inst);
#endif
            auto &write_regs = t_bb_reg_info_node->sema_call_written_reg_map.at(call_inst);
            auto call_next_inst = call_inst->getNextNode();
            if (write_regs.size() == 1) {
              auto store_ecv_reg = write_regs[0].first;
              auto store_ecv_reg_class = write_regs[0].second;
              inst_lifter->StoreRegValueBeforeInst(
                  &bb, state_ptr, store_ecv_reg.GetRegName(store_ecv_reg_class),
                  virtual_regs_opt->CastFromInst(
                      store_ecv_reg, call_inst,
                      virtual_regs_opt->GetWholeLLVMTypeFromRegZ(store_ecv_reg), call_next_inst),
                  call_next_inst);
            } else if (write_regs.size() > 1) {
              for (uint32_t i = 0; i < write_regs.size(); i++) {
                llvm::Instruction *from_extracted_inst;
                auto store_ecv_reg = write_regs[i].first;
                auto store_ecv_reg_class = write_regs[i].second;
                if (store_ecv_reg.number == IGNORE_WRITE_TO_WZR_ORDER ||
                    store_ecv_reg.number == IGNORE_WRITE_TO_XZR_ORDER) {
                  continue;
                }
                if (llvm::dyn_cast<llvm::StructType>(call_inst->getType()) ||
                    llvm::dyn_cast<llvm::ArrayType>(call_inst->getType())) {
                  from_extracted_inst =
                      llvm::ExtractValueInst::Create(call_inst, {i}, "", call_next_inst);
                } else if (isu128v2Ty(context, call_inst->getType())) {
                  from_extracted_inst = llvm::ExtractElementInst::Create(
                      call_inst, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), i), "",
                      call_next_inst);
                } else {
                  LOG(FATAL) << "[Bug] call_inst: " << LLVMThingToString(call_inst)
                             << "pc: " << Sema_func_vma_map.at(call_inst);
                }
                inst_lifter->StoreRegValueBeforeInst(
                    &bb, state_ptr, store_ecv_reg.GetRegName(store_ecv_reg_class),
                    virtual_regs_opt->CastFromInst(
                        store_ecv_reg, from_extracted_inst,
                        virtual_regs_opt->GetWholeLLVMTypeFromRegZ(store_ecv_reg), call_next_inst),
                    call_next_inst);
              }
            }
          }
        }
      }

      // Add passed_caller_reg_map and passed_callee_ret_reg_map.
      for (int i = 0; i < 8; i++) {
        virtual_regs_opt->passed_caller_reg_map.insert({EcvReg(RegKind::General, i), ERC::RegX});
        virtual_regs_opt->passed_caller_reg_map.insert({EcvReg(RegKind::Vector, i), ERC::RegV});
        virtual_regs_opt->passed_callee_ret_reg_map.insert(
            {EcvReg(RegKind::General, i), ERC::RegX});
        virtual_regs_opt->passed_callee_ret_reg_map.insert({EcvReg(RegKind::Vector, i), ERC::RegV});
      }
      virtual_regs_opt->passed_caller_reg_map.insert(
          {EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});
      virtual_regs_opt->passed_callee_ret_reg_map.insert(
          {EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});

    } else {
      no_indirect_lifted_funcs.insert(func);
    }

    // add terminator to the all basic block to avoid error on CFG flat
    for (auto &block : *func) {
      if (!block.getTerminator()) {
        AddTerminatingTailCall(&block, intrinsics->missing_block, *intrinsics, trace_addr);
      }
    }

    callback(trace_addr, func);
    manager.SetLiftedTraceDefinition(trace_addr, func);
    virtual_regs_opt->block_num = lifted_block_map.size();
  }

  return true;
}

void TraceLifter::Impl::Optimize() {
  // Prepare the optimization
  inst.Reset();
  arch->InstanceMinimumInst(inst);

  // Opt: AnalyzeRegsBags.
  int opt_cnt = 1;
  for (auto lifted_func : no_indirect_lifted_funcs) {
    std::cout << "\r["
              << "\033[32m"
              << "INFO"
              << "\033[0m"
              << "]"
              << " Opt Pass 1: [" << opt_cnt << "/" << no_indirect_lifted_funcs.size() << "]"
              << std::flush;
    auto virtual_regs_opt = VirtualRegsOpt::func_v_r_opt_map[lifted_func];
    virtual_regs_opt->AnalyzeRegsBags();
    opt_cnt++;
  }
  std::cout << std::endl;

  // Add __remill_function_call to func_v_r_opt_map for register store selection of calling it.
  auto __remill_func_call_fn = module->getFunction("__remill_function_call");
  auto __remill_func_call_v_r_o = new VirtualRegsOpt(__remill_func_call_fn, this, 0xffffff);
  for (int i = 0; i < 8; i++) {
    __remill_func_call_v_r_o->passed_caller_reg_map.insert(
        {EcvReg(RegKind::General, i), ERC::RegX});
    __remill_func_call_v_r_o->passed_caller_reg_map.insert({EcvReg(RegKind::Vector, i), ERC::RegV});
  }
  __remill_func_call_v_r_o->passed_caller_reg_map.insert(
      {EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});
  VirtualRegsOpt::func_v_r_opt_map.insert({__remill_func_call_fn, __remill_func_call_v_r_o});

  // re-calculate passed_caller_reg_map considering direct jump function.
  VirtualRegsOpt::CalPassedCallerRegForBJump();

  // Opt: OptimizeVirtualRegsUsage.
  int opt_cnt2 = 1;
  for (auto lifted_func : no_indirect_lifted_funcs) {
    std::cout << "\r["
              << "\033[32m"
              << "INFO"
              << "\033[0m"
              << "]"
              << " Opt Pass 2: [" << opt_cnt2 << "/" << no_indirect_lifted_funcs.size() << "]"
              << std::flush;
    auto virtual_regs_opt = VirtualRegsOpt::func_v_r_opt_map[lifted_func];
    virtual_regs_opt->OptimizeVirtualRegsUsage();
    opt_cnt2++;
  }
  std::cout << std::endl;

  // Insert `debug_string` for the every function
#if defined(OPT_CALL_FUNC_DEBUG) || defined(OPT_REAL_REGS_DEBUG)
  for (auto lifted_func : lifted_funcs) {
    auto &entry_bb_start_inst = *lifted_func->getEntryBlock().begin();
#  if defined(OPT_CALL_FUNC_DEBUG)
    auto debug_string_fn = module->getFunction("debug_string");
    auto fun_name_val =
        llvm::ConstantDataArray::getString(context, lifted_func->getName().str(), true);
    auto fun_name_gvar = new llvm::GlobalVariable(
        *module, fun_name_val->getType(), true, llvm::GlobalVariable::ExternalLinkage, fun_name_val,
        lifted_func->getName().str() + "debug_name");
    llvm::CallInst::Create(debug_string_fn, {fun_name_gvar}, "", &entry_bb_start_inst);
#  endif
#  if defined(OPT_REAL_REGS_DEBUG)
    auto debug_state_machine_fun = module->getFunction("debug_state_machine");
    llvm::CallInst::Create(debug_state_machine_fun, {}, "", &entry_bb_start_inst);
#  endif
  }
#endif
}

PhiRegsBBBagNode *PhiRegsBBBagNode::GetTrueBag() {
  auto res = this;
  while (res != res->converted_bag) {
    res = res->converted_bag;
  }
  return res;
}

void PhiRegsBBBagNode::MergePrecedingRegMap(PhiRegsBBBagNode *moved_bag) {
  // Merge bag_preceding_load_reg_map
  for (auto [pre_load_r, pre_load_r_c] : moved_bag->bag_preceding_load_reg_map) {
    if (bag_preceding_load_reg_map.contains(pre_load_r)) {
      if (GetRegClassSize(bag_preceding_load_reg_map.at(pre_load_r)) <
          GetRegClassSize(pre_load_r_c)) {
        bag_preceding_load_reg_map.insert_or_assign(pre_load_r, pre_load_r_c);
      }
    } else {
      bag_preceding_load_reg_map.insert({pre_load_r, pre_load_r_c});
    }
  }
  // Merge bag_preceding_load_reg_map
  for (auto [pre_store_r, pre_store_r_c] : moved_bag->bag_preceding_store_reg_map) {
    if (bag_preceding_store_reg_map.contains(pre_store_r)) {
      if (GetRegClassSize(bag_preceding_store_reg_map.at(pre_store_r)) <
          GetRegClassSize(pre_store_r_c)) {
        bag_preceding_store_reg_map.insert_or_assign(pre_store_r, pre_store_r_c);
      }
    } else {
      bag_preceding_store_reg_map.insert({pre_store_r, pre_store_r_c});
    }
  }
  // Merge bag_within_store
}

void PhiRegsBBBagNode::MergeFamilyConvertedBags(PhiRegsBBBagNode *merged_bag) {
  for (auto merged_par : merged_bag->parents) {
    auto true_merged_par = merged_par->GetTrueBag();
    parents.insert(true_merged_par);
    true_merged_par->children.insert(this);
  }
  for (auto merged_child : merged_bag->children) {
    auto true_merged_child = merged_child->GetTrueBag();
    children.insert(true_merged_child);
    true_merged_child->parents.insert(this);
  }
}

void PhiRegsBBBagNode::RemoveLoop(llvm::BasicBlock *root_bb) {

  ECV_LOG_NL(std::dec, "[DEBUG LOG]: ", "func: PhiRegsBBbagNode::RemoveLoop. target func: ",
             root_bb->getParent()->getName().str());
  {

#define TUPLE_ELEM_T \
  PhiRegsBBBagNode *, std::vector<PhiRegsBBBagNode *>, std::set<PhiRegsBBBagNode *>
    std::stack<std::tuple<TUPLE_ELEM_T>> bag_stack;
    auto root_bag = bb_regs_bag_map.at(root_bb);
    bag_stack.emplace(
        std::make_tuple<TUPLE_ELEM_T>((remill::PhiRegsBBBagNode *) root_bag, {},
                                      {}));  // Why (remill::PhiResgBBBagNode *) is needed?

    std::set<PhiRegsBBBagNode *> finished;
    uint32_t bag_i = 0;

    for (auto [_, bag] : bb_regs_bag_map) {
      CHECK(!bag->converted_bag) << ECV_DEBUG_STREAM.str();
      bag->converted_bag = bag;
      debug_bag_map.insert({bag, bag_i++});
    }

    while (!bag_stack.empty()) {
      auto target_bag = std::get<PhiRegsBBBagNode *>(bag_stack.top())->GetTrueBag();
      auto pre_path = std::get<std::vector<PhiRegsBBBagNode *>>(bag_stack.top());
      auto visited = std::get<std::set<PhiRegsBBBagNode *>>(bag_stack.top());
      bag_stack.pop();
      if (finished.contains(target_bag)) {
        continue;
      }
      DEBUG_REMOVE_LOOP_GRAPH(target_bag);
      bool loop_found = false;
      std::set<PhiRegsBBBagNode *> true_visited;
      for (auto _bag : visited) {
        auto true_bag = _bag->GetTrueBag();
        if (true_bag == target_bag) {
          loop_found = true;
        }
        true_visited.insert(true_bag);
      }
      visited = true_visited;

      if (loop_found) {
        auto it_loop_bag = pre_path.rbegin();
        std::set<PhiRegsBBBagNode *> true_deleted_bags;
        for (;;) {
          CHECK(!pre_path.empty()) << ECV_DEBUG_STREAM.str();
          it_loop_bag = pre_path.rbegin();
          auto moved_bag = (*it_loop_bag)->GetTrueBag();
          pre_path.pop_back();

          if (target_bag == moved_bag) {
            break;
          } else if (true_deleted_bags.contains(moved_bag)) {
            continue;
          }

          true_deleted_bags.insert(moved_bag);

          // translates moved_bag
          target_bag->MergePrecedingRegMap(moved_bag);
          target_bag->MergeFamilyConvertedBags(moved_bag);
          for (auto moved_bb : moved_bag->in_bbs) {
            target_bag->in_bbs.insert(moved_bb);
          }

          // update cache
          moved_bag->converted_bag = target_bag;
          visited.erase(moved_bag);
          bag_num--;

          if (it_loop_bag == pre_path.rend()) {
            LOG(FATAL) << "Unexpected path route on the PhiRegsBBBagNode::RemoveLoop()."
                       << ECV_DEBUG_STREAM.str();
          }
        }

        // re-search this target_bag
        visited.erase(target_bag);
        bag_stack.emplace(target_bag, pre_path, visited);
      } else {

        // push the children
        bool search_finished = true;
        for (auto __child_bag : target_bag->children) {
          auto child_bag = __child_bag->GetTrueBag();
          if (finished.contains(child_bag) || child_bag == target_bag) {
            continue;
          }
          search_finished = false;
          auto child_pre_path = pre_path;
          auto child_visited = visited;
          child_pre_path.push_back(target_bag);
          child_visited.insert(target_bag);
          bag_stack.emplace(child_bag, child_pre_path, child_visited);
        }

        // finish the target_bag if all children are finished.
        if (search_finished) {
          finished.insert(target_bag);
        }
      }
    }

    // Update all bags to the true bags.
    std::set<PhiRegsBBBagNode *> deleted_bag_set;
    for (auto [bb, bag] : bb_regs_bag_map) {
      // Update bag
      auto target_true_bag = bag->GetTrueBag();
      if (bag != target_true_bag) {
        bb_regs_bag_map.insert_or_assign(bb, target_true_bag);
        deleted_bag_set.insert(bag);
      }
      // Update parents
      std::set<PhiRegsBBBagNode *> new_pars;
      for (auto par : target_true_bag->parents) {
        auto t_par = par->GetTrueBag();
        if (t_par == target_true_bag) {
          continue;
        }
        new_pars.insert(t_par);
      }
      target_true_bag->parents = new_pars;
      // Update children
      std::set<PhiRegsBBBagNode *> new_children;
      for (auto child : target_true_bag->children) {
        auto t_child = child->GetTrueBag();
        if (t_child == target_true_bag) {
          continue;
        }
        new_children.insert(t_child);
      }
      target_true_bag->children = new_children;
    }
    // Delete the all unneccesary bags.
    for (auto deleted_bag : deleted_bag_set) {
      delete (deleted_bag);
    }
  }

#if defined(OPT_ALGO_DEBUG)

  // Check the consistency of the parents and children
  {
    std::set<PhiRegsBBBagNode *> bag_set;
    for (auto [_, bag] : bb_regs_bag_map) {
      if (!bag_set.contains(bag)) {
        bag_set.insert(bag);
        for (auto par : bag->parents) {
          if (!par->children.contains(bag)) {
            LOG(FATAL) << "parent: " << par << " must have the child: " << bag << "\n";
          }
        }
        for (auto child : bag->children) {
          if (!child->parents.contains(bag)) {
            LOG(FATAL) << "child: " << child << " must have the parent: " << bag << "\n";
          }
        }
      }
    }
  }

  // Check whether G of PhiregsBBBagNode* doesn't have loop. (for debug)
  {
    std::stack<PhiRegsBBBagNode *> bag_stack;
    std::set<PhiRegsBBBagNode *> visited, finished;
    bag_stack.push(bb_regs_bag_map.at(root_bb));

    while (!bag_stack.empty()) {
      auto target_bag = bag_stack.top();
      bag_stack.pop();
      if (finished.contains(target_bag)) {
        continue;
      }
      if (visited.contains(target_bag)) {
        for (auto child : target_bag->children) {
          if (!finished.contains(child)) {
            LOG(FATAL)
                << "[Bug] The loop was detected from the G of PhiRegsBBBagNode* after PhiRegsBBBagNode::RemoveLoop."
                << ECV_DEBUG_STREAM.str();
          }
        }
        finished.insert(target_bag);
        continue;
      }
      visited.insert(target_bag);
      // after searching all children, re-search this target_bag.
      bag_stack.push(target_bag);
      for (auto child : target_bag->children) {
        if (!finished.contains(child)) {
          bag_stack.push(child);
        }
      }
    }
    CHECK(bag_num == finished.size())
        << "[Bug] bag_num: " << bag_num << ", finished.size(): " << finished.size()
        << ". They should be equal at PhiRegsBBBagNode::RemoveLoop." << ECV_DEBUG_STREAM.str();
  }

  DebugStreamReset();
#endif
}

void PhiRegsBBBagNode::GetPrecedingVirtualRegsBags(llvm::BasicBlock *root_bb) {
  ECV_LOG_NL("[DEBUG LOG]: ", "func: PhiRegsBBbagNode::GetPrecedingVirtualRegsBags. target func: ",
             root_bb->getParent()->getName().str());
  std::queue<PhiRegsBBBagNode *> bag_queue;
  std::unordered_map<PhiRegsBBBagNode *, std::size_t> finished_pars_num_map;
  std::set<PhiRegsBBBagNode *> finished;
  bag_queue.push(bb_regs_bag_map.at(root_bb));

  while (!bag_queue.empty()) {
    auto target_bag = bag_queue.front();
    bag_queue.pop();
    if (finished.contains(target_bag)) {
      continue;
    }
    finished_pars_num_map.insert({target_bag, 0});
    if (target_bag->parents.size() == finished_pars_num_map.at(target_bag)) {
      // can finish the target_bag.
      for (auto par_bag : target_bag->parents) {
        // preceding load reg. priority: target_bag > par_bag.
        for (auto ecv_reg_info : par_bag->bag_preceding_load_reg_map) {
          target_bag->bag_preceding_load_reg_map.insert(ecv_reg_info);
        }
        // preceding store reg. priority: target_bag > par_bag.
        for (auto ecv_reg_info : par_bag->bag_preceding_store_reg_map) {
          target_bag->bag_preceding_store_reg_map.insert(ecv_reg_info);
        }
      }
      // target_bag was finished.
      finished.insert(target_bag);
      // update the finised_pars_map for all the childlen of this target_bag.
      // push all the no finished children
      for (auto child : target_bag->children) {
        finished_pars_num_map.insert_or_assign(child, finished_pars_num_map[child] + 1);
        if (!finished.contains(child)) {
          bag_queue.push(child);
        }
      }
    }
  }

  CHECK(finished.size() == bag_num)
      << "[Bug] bag_num: " << bag_num << ", finished_bag.size(): " << finished.size()
      << ". They should be equal after PhiRegsBBagNode::GetPrecedingVirtualRegsBags."
      << ECV_DEBUG_STREAM.str();

  DebugStreamReset();
}

void PhiRegsBBBagNode::GetSucceedingVirtualRegsBags(llvm::BasicBlock *root_bb) {
  ECV_LOG_NL("[DEBUG LOG]: ", "func: PhiRegsBBbagNode::GetSucceedingVirtualRegsBags. target func: ",
             root_bb->getParent()->getName().str());
  std::stack<PhiRegsBBBagNode *> bag_stack;
  std::unordered_map<PhiRegsBBBagNode *, std::size_t> finished_children_num_map;
  std::set<PhiRegsBBBagNode *> finished;
  bag_stack.push(bb_regs_bag_map.at(root_bb));

  while (!bag_stack.empty()) {
    auto target_bag = bag_stack.top();
    bag_stack.pop();
    if (finished.contains(target_bag)) {
      continue;
    }
    finished_children_num_map.insert({target_bag, 0});
    if (target_bag->children.size() == finished_children_num_map.at(target_bag)) {
      // Can finish the target_bag.
      for (auto child_bag : target_bag->children) {
        // succeeding load reg. priority: target_bag > child_bag
        for (auto ecv_reg_info : child_bag->bag_succeeding_load_reg_map) {
          target_bag->bag_succeeding_load_reg_map.insert(ecv_reg_info);
        }
      }
      // The target_bag was finished.
      finished.insert(target_bag);
      // Update the finised_children_map for all the parents of this target_bag.
      for (auto parent_bag : target_bag->parents) {
        finished_children_num_map.insert_or_assign(parent_bag,
                                                   finished_children_num_map[parent_bag] + 1);
      }
      continue;
    }
    // After searching all children, re-search the target_bag.
    bag_stack.push(target_bag);
    for (auto child_bag : target_bag->children) {
      if (!finished.contains(child_bag)) {
        bag_stack.push(child_bag);
      }
    }
  }

  CHECK(finished.size() == finished_children_num_map.size() && finished.size() == bag_num)
      << "[Bug] Search argorithm is incorrect of PhiRegsBBBagNode::GetPhiDerivedRegsBags: Search is insufficient."
      << ECV_DEBUG_STREAM.str();

  DebugStreamReset();
}

void PhiRegsBBBagNode::GetPhiRegsBags(
    llvm::BasicBlock *root_bb,
    std::unordered_map<llvm::BasicBlock *, BBRegInfoNode *> &bb_reg_info_node_map) {
  // Remove loop from the graph of PhiRegsBBBagNode.
  PhiRegsBBBagNode::RemoveLoop(root_bb);
  // Prepare the bug_succeeding_load_reg_map.
  for (auto [_, bag] : bb_regs_bag_map) {
    if (bag->bag_succeeding_load_reg_map.empty()) {
      bag->bag_succeeding_load_reg_map = bag->bag_preceding_load_reg_map;
    }
  }
  // Calculate the bag_preceding_(load | store)_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetPrecedingVirtualRegsBags(root_bb);
  // Calculate the bag_succeeding_load_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetSucceedingVirtualRegsBags(root_bb);
  // Calculate the bag_req_reg_map.
  std::set<PhiRegsBBBagNode *> finished;
  for (auto [_, phi_regs_bag] : bb_regs_bag_map) {
    if (!finished.contains(phi_regs_bag)) {
      auto &succeeding_load_reg_map = phi_regs_bag->bag_succeeding_load_reg_map;
      auto &preceding_load_reg_map = phi_regs_bag->bag_preceding_load_reg_map;
      auto &more_small_reg_map = succeeding_load_reg_map.size() <= preceding_load_reg_map.size()
                                     ? succeeding_load_reg_map
                                     : preceding_load_reg_map;
      phi_regs_bag->bag_req_reg_map = phi_regs_bag->bag_preceding_store_reg_map;
      for (auto &[ecv_reg, _] : more_small_reg_map) {
        if (succeeding_load_reg_map.contains(ecv_reg) && preceding_load_reg_map.contains(ecv_reg)) {
          auto t_ecv_r_c = succeeding_load_reg_map.at(ecv_reg);
          if (phi_regs_bag->bag_req_reg_map.contains(ecv_reg) &&
              GetRegClassSize(phi_regs_bag->bag_req_reg_map.at(ecv_reg)) <
                  GetRegClassSize(t_ecv_r_c)) {
            phi_regs_bag->bag_req_reg_map.insert_or_assign(ecv_reg, t_ecv_r_c);
          } else {
            phi_regs_bag->bag_req_reg_map.insert({ecv_reg, t_ecv_r_c});
          }
        }
      }
      finished.insert(phi_regs_bag);
    }
  }

  // Calculate bag_passed_caller_reg_map.
  auto func = root_bb->getParent();
  auto t_fun_v_r_o = VirtualRegsOpt::func_v_r_opt_map.at(func);
  for (auto &bb : *func) {
    if (&bb == root_bb) {
      continue;
    }
    auto t_bb = &bb;
    auto t_bag = bb_regs_bag_map.at(t_bb);
    auto t_bb_info_node = bb_reg_info_node_map.at(t_bb);
    for (auto [e_r, n_e_r_c] : t_bb_info_node->bb_load_reg_map) {
      bool already_load_flag = false;
      for (auto p_bag : t_bag->parents) {
        already_load_flag |= p_bag->bag_req_reg_map.contains(e_r);
      }
      if (!already_load_flag) {
        t_fun_v_r_o->passed_caller_reg_map.insert({e_r, n_e_r_c});
      }
    }
    t_fun_v_r_o->passed_caller_reg_map.insert({EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});
  }

  // Calculate passed_callee_ret_reg_map.
  auto &ret_set = t_fun_v_r_o->ret_inst_set;
  if (!ret_set.empty()) {
    auto ret_inst_bg_bag = bb_regs_bag_map.at((*ret_set.begin())->getParent());
    for (auto [e_r, e_r_c] : ret_inst_bg_bag->bag_preceding_store_reg_map) {
      bool is_ret_reg = true;
      for (auto iter = ret_set.begin(); iter != ret_set.end(); iter++) {
        auto t_bag = bb_regs_bag_map.at((*iter)->getParent());
        is_ret_reg &= t_bag->bag_preceding_store_reg_map.contains(e_r);
      }
      if (is_ret_reg) {
        t_fun_v_r_o->passed_callee_ret_reg_map.insert({e_r, e_r_c});
      }
    }
  }

  // if (func->getName().starts_with("_IO_file_xsputn")) {
  //   std::cout << func->getName().str() << std::endl;
  //   for (auto [e_r, e_r_c] : bag_passed_caller_reg_map) {
  //     std::cout << e_r->GetRegName(e_r_c) << ", ";
  //   }
  //   std::cout << std::endl;
  // }

  // (FIXME)
  if (func->getName().starts_with("_IO_do_write")) {
    t_fun_v_r_o->passed_caller_reg_map.insert({EcvReg(RegKind::General, 1), ERC::RegX});
    t_fun_v_r_o->passed_caller_reg_map.insert({EcvReg(RegKind::General, 3), ERC::RegX});
  }
}

void PhiRegsBBBagNode::DebugGraphStruct(PhiRegsBBBagNode *target_bag) {
  ECV_LOG_NL("target bag: ", debug_bag_map.at(target_bag));
  std::set<PhiRegsBBBagNode *> __bags;
  ECV_LOG("PhiRegsBBBagNode * G Parents: ");
  // stdout PhiRegsBBBagNode* G.
  for (auto [__bag, __bag_i] : debug_bag_map) {
    auto __t_bag = __bag->GetTrueBag();
    if (__bags.contains(__t_bag)) {
      continue;
    } else {
      __bags.insert(__t_bag);
      ECV_LOG("[[", debug_bag_map[__t_bag], "] -> [");
      auto _p_bag = __t_bag->children.begin();
      std::set<PhiRegsBBBagNode *> __t_out_bags;
      while (_p_bag != __t_bag->children.end()) {
        auto _t_p_bag = (*_p_bag)->GetTrueBag();
        if (__t_out_bags.contains(_t_p_bag)) {
          ++_p_bag;
          continue;
        }
        if (_p_bag != __t_bag->children.begin()) {
          ECV_LOG(", ");
        }
        ECV_LOG(debug_bag_map.at(_t_p_bag));
        __t_out_bags.insert(_t_p_bag);
        if (++_p_bag == __t_bag->children.end()) {
          break;
        }
      }
      ECV_LOG("]] ");
    }
  }
  ECV_LOG_NL();
  ECV_LOG_NL();
}

void VirtualRegsOpt::CalPassedCallerRegForBJump() {
  std::stack<llvm::Function *> func_stack;
  std::set<llvm::Function *> finished;
  for (auto [caller, _] : b_jump_callees_map) {
    func_stack.push(caller);
  }
  while (!func_stack.empty()) {
    auto t_fun = func_stack.top();
    func_stack.pop();
    if (finished.contains(t_fun)) {
      continue;
    }
    if (b_jump_callees_map.contains(t_fun)) {
      bool callee_fin = true;
      for (auto callee : b_jump_callees_map.at(t_fun)) {
        callee_fin &= finished.contains(callee);
      }
      if (callee_fin) {
        auto t_fun_v_r_o = func_v_r_opt_map.at(t_fun);
        for (auto callee : b_jump_callees_map.at(t_fun)) {
          auto callee_v_r_o = func_v_r_opt_map.at(callee);
          for (auto [e_r, e_r_c] : callee_v_r_o->passed_caller_reg_map) {
            t_fun_v_r_o->passed_caller_reg_map.insert({e_r, e_r_c});
          }
        }
        finished.insert(t_fun);
      } else {
        func_stack.push(t_fun);
        for (auto callee : b_jump_callees_map.at(t_fun)) {
          if (!finished.contains(callee)) {
            func_stack.push(callee);
          }
        }
      }
    } else {
      finished.insert(t_fun);
    }
  }
}

VirtualRegsOpt::VirtualRegsOpt(llvm::Function *__func, TraceLifter::Impl *__impl,
                               uint64_t __fun_vma)
    : func(__func),
      impl(__impl),
      relay_bb_cache({}),
      phi_val_order(0),
      fun_vma(__fun_vma) {
  arg_state_val = NULL;
  arg_runtime_val = NULL;
  // only declared function.
  if (func->getName().str() == "__remill_function_call") {
    auto args = func->args().begin();
    for (size_t i = 0; i < func->arg_size(); i++) {
      if (0 == i) {
        CHECK(llvm::dyn_cast<llvm::PointerType>(args[i].getType()));
        arg_state_val = &args[i];
      } else if (2 == i) {
        CHECK(llvm::dyn_cast<llvm::PointerType>(args[i].getType()));
        arg_runtime_val = &args[i];
      }
    }
  }
  // lifted function.
  else {
    for (auto &arg : func->args()) {
      if (arg.getName() == "state") {
        arg_state_val = &arg;
      } else if (arg.getName() == "runtime_manager") {
        arg_runtime_val = &arg;
      }
    }
  }
  CHECK(arg_state_val)
      << "[Bug] state arg is empty at the initialization of VirtualRegsOpt. target func: "
      << func->getName().str();
  CHECK(arg_runtime_val)
      << "[Bug] runtime_manager arg is empty at the initialization of VirtualRegsOpt. target func: "
      << func->getName().str();
}

void VirtualRegsOpt::AnalyzeRegsBags() {

  impl->virtual_regs_opt = this;

  ECV_LOG_NL(std::hex,
             "[DEBUG LOG]. func: VirtualRegsOpt::OptimizeVritualRegsUsage. target function: ",
             func->getName().str(), ".");

  // Flatten the control flow graph
  llvm::BasicBlock *target_bb;  // the parent bb of the joined bb
  std::queue<llvm::BasicBlock *> bb_queue;
  std::set<llvm::BasicBlock *> visited;
  auto entry_bb = &func->getEntryBlock();
  auto entry_terminator_br = llvm::dyn_cast<llvm::BranchInst>(entry_bb->getTerminator());
  CHECK(nullptr != entry_terminator_br)
      << "entry block of the lifted function must have the terminator instruction.";
  CHECK(1 == entry_terminator_br->getNumSuccessors())
      << "entry block terminator must have the one jump basic block.";
  target_bb = entry_terminator_br->getSuccessor(0);
  bb_queue.push(target_bb);

  auto push_successor_bb_queue = [&bb_queue, &visited](llvm::BasicBlock *successor_bb) {
    if (!visited.contains(successor_bb)) {
      bb_queue.push(successor_bb);
    }
  };

  while (!bb_queue.empty()) {
    auto target_bb = bb_queue.front();
    bb_queue.pop();
    visited.insert(target_bb);
    auto target_terminator = target_bb->getTerminator();
    auto child_num = target_terminator->getNumSuccessors();
    if (2 < child_num) {
      LOG(FATAL)
          << "Every block of the lifted function by elfconv must not have the child blocks more than two."
          << ECV_DEBUG_STREAM.str();
    } else if (2 == child_num) {
      push_successor_bb_queue(target_terminator->getSuccessor(0));
      push_successor_bb_queue(target_terminator->getSuccessor(1));
    } else if (1 == child_num) {
      auto candidate_bb = target_terminator->getSuccessor(0);
      auto &candidate_bb_parents = bb_parents.at(candidate_bb);
      if (1 == candidate_bb_parents.size()) {
        // join candidate_bb to the target_bb
        auto joined_bb = candidate_bb;
        auto target_terminator = target_bb->getTerminator();
        CHECK(llvm::dyn_cast<llvm::BranchInst>(target_terminator))
            << "The parent basic block of the lifted function must terminate by the branch instruction.";
        // delete the branch instruction of the target_bb and joined_bb
        target_terminator->eraseFromParent();
        // transfer the all instructions (target_bb = target_bb & joined_bb)
        target_bb->splice(target_bb->end(), joined_bb);
        // join BBRegInfoNode
        auto joined_bb_reg_info_node = bb_reg_info_node_map.extract(joined_bb).mapped();
        bb_reg_info_node_map.at(target_bb)->join_reg_info_node(joined_bb_reg_info_node);
        // update bb_parents
        bb_parents.erase(joined_bb);
        target_terminator = target_bb->getTerminator();
        if (llvm::dyn_cast<llvm::BranchInst>(target_terminator)) {
          // joined_bb has children
          for (uint32_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
            bb_parents.at(target_terminator->getSuccessor(i)).erase(joined_bb);
            bb_parents.at(target_terminator->getSuccessor(i)).insert(target_bb);
          }
          bb_queue.push(target_bb);
        }
        // delete the joined block
        joined_bb->eraseFromParent();
      } else {
        push_successor_bb_queue(candidate_bb);
      }
    } else /* if (0 == child_num)*/ {
      CHECK(llvm::dyn_cast<llvm::ReturnInst>(target_terminator))
          << "The basic block which doesn't have the successors must be ReturnInst.";
    }
  }

  DebugStreamReset();
  ECV_LOG_NL("target_func: ", func->getName().str());


  // Initialize the Graph of PhiRegsBBBagNode.
  for (auto &[bb, bb_reg_info_node] : bb_reg_info_node_map) {
    auto phi_regs_bag =
        new PhiRegsBBBagNode(bb_reg_info_node->bb_load_reg_map, bb_reg_info_node->bb_load_reg_map,
                             std::move(bb_reg_info_node->bb_store_reg_map), {bb});
    PhiRegsBBBagNode::bb_regs_bag_map.insert({bb, phi_regs_bag});
  }
  PhiRegsBBBagNode::bag_num = PhiRegsBBBagNode::bb_regs_bag_map.size();

  for (auto [bb, pars] : bb_parents) {
    for (auto par : pars) {
      auto par_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map.at(par);
      auto child_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map.at(bb);
      // Remove self-loop because it is not needed for the PhiRegsBBBagNode* Graph.
      if (par_phi_regs_bag == child_phi_regs_bag) {
        continue;
      }
      par_phi_regs_bag->children.insert(child_phi_regs_bag);
      child_phi_regs_bag->parents.insert(par_phi_regs_bag);
    }
  }

  // Calculate the registers which needs to get on the phi nodes for every basic block.
  PhiRegsBBBagNode::GetPhiRegsBags(&func->getEntryBlock(), bb_reg_info_node_map);
  bb_regs_bag_map = PhiRegsBBBagNode::bb_regs_bag_map;

  // Reset static data of PhiRegsBBBagNode.
  PhiRegsBBBagNode::Reset();

  ECV_LOG_NL(OutLLVMFunc(func).str().c_str());
  DebugStreamReset();
}

llvm::Value *VirtualRegsOpt::CastFromInst(EcvReg target_ecv_reg, llvm::Value *from_inst,
                                          llvm::Type *to_inst_ty,
                                          llvm::Instruction *inst_at_before) {
  auto &context = func->getContext();
  auto twine_null = llvm::Twine::createNull();

  llvm::Value *t_from_inst;

  if (from_inst->getType() == to_inst_ty) {
    return from_inst;
  } else if (from_inst->getType() == llvm::Type::getVoidTy(context)) {
    auto store_from_inst = llvm::dyn_cast<llvm::StoreInst>(from_inst);
    CHECK(store_from_inst)
        << "[Bug] If the type of the from_inst is `void`, from_inst must be llvm::StoreInst at CastFromInst. from_inst: "
        << LLVMThingToString(from_inst) << "\n"
        << ECV_DEBUG_STREAM.str();
    t_from_inst = store_from_inst->getValueOperand();
  } else {
    t_from_inst = from_inst;
  }

  auto t_from_inst_size = impl->data_layout.getTypeAllocSizeInBits(t_from_inst->getType());
  auto t_from_inst_ty = t_from_inst->getType();
  auto to_inst_size = impl->data_layout.getTypeAllocSizeInBits(to_inst_ty);

  auto type_asserct_check = [&t_from_inst, &to_inst_ty](bool condition, const char *message) {
    CHECK(condition) << "[ERROR]: from_inst: " << LLVMThingToString(t_from_inst)
                     << ", to_inst type: " << LLVMThingToString(to_inst_ty) << "\n"
                     << message << "\n"
                     << ECV_DEBUG_STREAM.str();
  };

  if (t_from_inst_size < to_inst_size) {
    if (RegKind::General == target_ecv_reg.reg_kind) {
      type_asserct_check(to_inst_ty->isIntegerTy() && t_from_inst_ty->isIntegerTy(),
                         "RegKind::General register should have only the integer type.");
      return new llvm::ZExtInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else if (RegKind::Vector == target_ecv_reg.reg_kind) {
      if (t_from_inst_ty->isVectorTy() || t_from_inst_ty->isFloatingPointTy()) {
        auto mono_from =
            new llvm::BitCastInst(t_from_inst, llvm::Type::getIntNTy(context, t_from_inst_size),
                                  twine_null, inst_at_before);
        auto zext_mono_from = new llvm::ZExtInst(
            mono_from, llvm::Type::getIntNTy(context, to_inst_size), twine_null, inst_at_before);
        return new llvm::BitCastInst(zext_mono_from, to_inst_ty, twine_null, inst_at_before);
      } else {
        auto zext_mono_from = new llvm::ZExtInst(
            t_from_inst, llvm::Type::getIntNTy(context, to_inst_size), twine_null, inst_at_before);
        return new llvm::BitCastInst(zext_mono_from, to_inst_ty, twine_null, inst_at_before);
      }
    } else if (RegKind::Special == target_ecv_reg.reg_kind) {
      type_asserct_check(
          /* 8 bit of the ECV_NZCV */ t_from_inst_ty->isIntegerTy(8) && to_inst_ty->isIntegerTy(),
          "RegKind::Special register must not be used different types other than ECV_NZCV.");
      return new llvm::ZExtInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    }
  } else if (t_from_inst_size > to_inst_size) {
    if (RegKind::General == target_ecv_reg.reg_kind) {
      type_asserct_check(to_inst_ty->isIntegerTy() && t_from_inst_ty->isIntegerTy(),
                         "RegKind::General register should have only the integer type.");
      return new llvm::TruncInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else if (RegKind::Vector == target_ecv_reg.reg_kind) {
      if (t_from_inst_ty->isVectorTy() || t_from_inst_ty->isFloatingPointTy()) {
        auto mono_from =
            new llvm::BitCastInst(t_from_inst, llvm::Type::getIntNTy(context, t_from_inst_size),
                                  twine_null, inst_at_before);
        auto trunc_mono_from = new llvm::TruncInst(
            mono_from, llvm::Type::getIntNTy(context, to_inst_size), twine_null, inst_at_before);
        return new llvm::BitCastInst(trunc_mono_from, to_inst_ty, twine_null, inst_at_before);
      } else {
        auto trunc_mono_from = new llvm::TruncInst(
            t_from_inst, llvm::Type::getIntNTy(context, to_inst_size), twine_null, inst_at_before);
        return new llvm::BitCastInst(trunc_mono_from, to_inst_ty, twine_null, inst_at_before);
      }
      return new llvm::TruncInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else if (RegKind::Special == target_ecv_reg.reg_kind) {
      type_asserct_check(
          t_from_inst_ty->isIntegerTy(8) && to_inst_ty->isIntegerTy(),
          "RegKind::Special register must not be used different types other than ECV_NZCV.");
      return new llvm::ZExtInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    }
  } else {
    if (t_from_inst->getType()->isPointerTy()) {
      return new llvm::PtrToIntInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else {
      return new llvm::BitCastInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    }
  }

  std::terminate();
}

llvm::Value *VirtualRegsOpt::GetRegValueFromCacheMap(
    EcvReg target_ecv_reg, llvm::Type *to_type, llvm::Instruction *inst_at_before,
    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t>> &cache_map) {
  llvm::Value *res_value;

  auto [_, from_value, from_order] = cache_map.at(target_ecv_reg);
  if (to_type == from_value->getType()) {
    res_value = from_value;
  } else {
    // Need to cast the from_inst to match the type of the load_inst.
    if (llvm::dyn_cast<llvm::StructType>(from_value->getType()) ||
        llvm::dyn_cast<llvm::ArrayType>(from_value->getType())) {
      auto from_extracted_inst = llvm::ExtractValueInst::Create(
          from_value, {from_order}, llvm::Twine::createNull(), inst_at_before);
      res_value = CastFromInst(target_ecv_reg, from_extracted_inst, to_type, inst_at_before);
      // for debug
      value_reg_map.insert(
          {from_extracted_inst,
           {target_ecv_reg, GetRegClassFromLLVMType(from_extracted_inst->getType())}});
    } else if (isu128v2Ty(impl->context, from_value->getType())) {
      auto from_extracted_inst = llvm::ExtractElementInst::Create(
          from_value, llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), from_order), "",
          inst_at_before);
      res_value = CastFromInst(target_ecv_reg, from_extracted_inst, to_type, inst_at_before);
      // for debug
      value_reg_map.insert(
          {from_extracted_inst,
           {target_ecv_reg, GetRegClassFromLLVMType(from_extracted_inst->getType())}});
    } else {
      res_value = CastFromInst(target_ecv_reg, from_value, to_type, inst_at_before);
    }
  }

  return res_value;
}

void VirtualRegsOpt::OptimizeVirtualRegsUsage() {

  impl->virtual_regs_opt = this;
  auto &inst_lifter = impl->inst.GetLifter();

// stdout the specified registers for the every semantics function.
#if defined(OPT_REAL_REGS_DEBUG)
  for (size_t i = 0; i < 31; i++) {
    debug_reg_set.insert({EcvReg(RegKind::General, i)});
    // debug_reg_set.insert({EcvReg(RegKind::Vector, i)});
  }
  debug_reg_set.insert({EcvReg(RegKind::Special, SP_ORDER)});
#endif

  // Add the phi nodes to the every basic block.
  std::set<llvm::BasicBlock *> finished;
  auto state_ptr = NthArgument(func, kStatePointerArgNum);

  phi_bb_queue.push(&func->getEntryBlock());

  while (!phi_bb_queue.empty()) {
    auto target_bb = phi_bb_queue.front();
    phi_bb_queue.pop();
    if (finished.contains(target_bb) || relay_bb_cache.contains(target_bb)) {
      continue;
    }
    ECV_LOG_NL(target_bb, ":");
    auto target_phi_regs_bag = bb_regs_bag_map.at(target_bb);
    auto target_bb_reg_info_node = bb_reg_info_node_map.at(target_bb);
    auto &reg_latest_inst_map = target_bb_reg_info_node->reg_latest_inst_map;
    auto &reg_derived_added_inst_map = target_bb_reg_info_node->reg_derived_added_inst_map;
    auto &referred_able_added_inst_reg_map =
        target_bb_reg_info_node->referred_able_added_inst_reg_map;

    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t>> ascend_reg_inst_map = {
        {EcvReg(RegKind::Special, STATE_ORDER), std::make_tuple(ERC::RegP, arg_state_val, 0)},
        {EcvReg(RegKind::Special, RUNTIME_ORDER),
         std::make_tuple(ERC::RegP, arg_runtime_val,
                         0)}};  // %state and %runtime_manager is defined as the argument

    llvm::BranchInst *br_inst = nullptr;
    llvm::ReturnInst *ret_inst = nullptr;

    // Add the phi node for the every register included in the bag_phi_reg_map.
    auto inst_start_it = &*target_bb->begin();
    for (auto &req_ecv_reg_info : target_phi_regs_bag->bag_req_reg_map) {
      auto &[target_ecv_reg, target_ecv_reg_class] = req_ecv_reg_info;
      llvm::Value *reg_derived_inst;
      // This phi has been already added.
      if (reg_derived_added_inst_map.contains(target_ecv_reg)) {
        auto no_casted_reg_derived_inst = reg_derived_added_inst_map.at(target_ecv_reg);
        reg_derived_inst = CastFromInst(
            target_ecv_reg, no_casted_reg_derived_inst, GetLLVMTypeFromRegZ(target_ecv_reg_class),
            llvm::dyn_cast<llvm::Instruction>(no_casted_reg_derived_inst)->getNextNode());

        // Update cache.
        if (no_casted_reg_derived_inst != reg_derived_inst) {
          referred_able_added_inst_reg_map.insert({reg_derived_inst, req_ecv_reg_info});
          CHECK(reg_derived_inst->getType() == GetLLVMTypeFromRegZ(target_ecv_reg_class));
        }
        // for debug
        value_reg_map.insert({reg_derived_inst, req_ecv_reg_info});
      }
      // Generate the new phi node.
      else {
        auto phi_op_type = GetLLVMTypeFromRegZ(target_ecv_reg_class);
        auto reg_derived_phi =
            llvm::PHINode::Create(phi_op_type, bb_parents.at(target_bb).size(),
                                  VAR_NAME(target_ecv_reg, target_ecv_reg_class), inst_start_it);
        // Add this phi to the reg_latest_inst_map (to avoid the infinity loop when running Impl::GetValueFromTargetBBAndReg).
        reg_latest_inst_map.insert(
            {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_phi, 0)});

        // Get the every virtual register from all the parent bb.
        auto par_bb_it = bb_parents.at(target_bb).begin();
        std::set<llvm::BasicBlock *> _finished;
        while (par_bb_it != bb_parents.at(target_bb).end()) {
          auto par_bb = *par_bb_it;
          if (_finished.contains(par_bb)) {
            ++par_bb_it;
            continue;
          }
          auto derived_reg_value = GetValueFromTargetBBAndReg(par_bb, target_bb, req_ecv_reg_info);
          // if the relay_bb is added as the parent of the target_bb, `par_bb` is not the parent.
          if (auto from_inst = llvm::dyn_cast<llvm::Instruction>(derived_reg_value)) {
            auto true_par = from_inst->getParent();
            reg_derived_phi->addIncoming(derived_reg_value, true_par);
            _finished.insert(true_par);
            if (par_bb != true_par) {
              par_bb_it = bb_parents.at(target_bb).begin();
              continue;
            }
          } else {
            reg_derived_phi->addIncoming(derived_reg_value, par_bb);
            _finished.insert(par_bb);
          }
          ++par_bb_it;
        }
        referred_able_added_inst_reg_map.insert({reg_derived_phi, req_ecv_reg_info});
        // for debug
        value_reg_map.insert({reg_derived_phi, req_ecv_reg_info});
        reg_derived_inst = reg_derived_phi;
      }
      // Add this phi to the ascend_reg_inst_map
      ascend_reg_inst_map.insert(
          {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_inst, 0)});
      CHECK(GetLLVMTypeFromRegZ(target_ecv_reg_class) == reg_derived_inst->getType());
    }

    reg_latest_inst_map.clear();
    auto target_inst_it = inst_start_it;
    ECV_LOG_NL("insts:");

    // Replace all the `load` to the CPU registers memory with the value of the phi nodes.
    while (target_inst_it) {
      ECV_LOG_NL("\t", LLVMThingToString(target_inst_it));
      // The target instruction was added. only update cache.
      if (referred_able_added_inst_reg_map.contains(&*target_inst_it)) {
        auto &[added_ecv_reg, added_ecv_reg_class] =
            referred_able_added_inst_reg_map.at(&*target_inst_it);
        ascend_reg_inst_map.insert_or_assign(
            added_ecv_reg, std::make_tuple(added_ecv_reg_class, target_inst_it, 0));
        CHECK(target_inst_it->getType() == GetLLVMTypeFromRegZ(added_ecv_reg_class));
        target_inst_it = target_inst_it->getNextNode();
      } else {
        // Target: llvm::LoadInst
        if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(target_inst_it)) {
          const auto &load_reg_name = load_inst->getPointerOperand()->getName().str();
          auto [target_ecv_reg, load_ecv_reg_class] = EcvReg::GetRegInfo(load_reg_name);

          llvm::Value *new_ecv_reg_inst;

          // Can replace this load with existig accessed value.
          if (ascend_reg_inst_map.contains(target_ecv_reg)) {
            new_ecv_reg_inst = GetRegValueFromCacheMap(target_ecv_reg, load_inst->getType(),
                                                       load_inst, ascend_reg_inst_map);
            target_inst_it = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
            // Replace all the Users.
            load_inst->replaceAllUsesWith(new_ecv_reg_inst);
            CHECK(new_ecv_reg_inst->getType() == GetLLVMTypeFromRegZ(load_ecv_reg_class));
            // Delete load_inst.
            load_inst->eraseFromParent();
          }
          // Should load this register because it is first access.
          else {
            new_ecv_reg_inst = load_inst;
            target_inst_it = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
            // Update cache.
            ascend_reg_inst_map.insert_or_assign(
                target_ecv_reg, std::make_tuple(load_ecv_reg_class, new_ecv_reg_inst, 0));
          }

          // for debug
          value_reg_map.insert(
              {new_ecv_reg_inst, {target_ecv_reg, GetRegClassFromLLVMType(load_inst->getType())}});
        }
        // Target: llvm::CallInst
        else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(target_inst_it)) {

          // Call the lifted function (includes `__remill_function_call`).
          if (lifted_func_caller_set.contains(call_inst)) {
            // Store already stored `bb_store_reg_map`
            for (auto [within_store_ecv_reg, ascend_value] : ascend_reg_inst_map) {
              if (
                  // !func_v_r_opt_map.at(call_inst->getCalledFunction())
                  //        ->passed_caller_reg_map.contains(within_store_ecv_reg) ||
                  !within_store_ecv_reg.CheckPassedArgsRegs() ||
                  !target_bb_reg_info_node->bb_store_reg_map.contains(within_store_ecv_reg)) {
                continue;
              }
              auto within_store_ecv_reg_class = std::get<ERC>(ascend_value);
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                  GetRegValueFromCacheMap(within_store_ecv_reg,
                                          GetWholeLLVMTypeFromRegZ(within_store_ecv_reg), call_inst,
                                          ascend_reg_inst_map),
                  call_inst);
            }
            // Store `preceding_store_map`
            for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_preceding_store_reg_map) {
              if (
                  // !func_v_r_opt_map.at(call_inst->getCalledFunction())
                  //        ->passed_caller_reg_map.contains(preceding_store_ecv_reg) ||
                  !preceding_store_ecv_reg.CheckPassedArgsRegs() ||
                  target_bb_reg_info_node->bb_store_reg_map.contains(preceding_store_ecv_reg)) {
                continue;
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr,
                  preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                  GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                          GetWholeLLVMTypeFromRegZ(preceding_store_ecv_reg),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load `preceding_store_map` + `load_map`
            for (auto [req_ecv_reg, tuple_set] : ascend_reg_inst_map) {
              if (!req_ecv_reg.CheckPassedReturnRegs()
                  // || !func_v_r_opt_map.at(call_inst->getParent()->getParent())
                  //      ->passed_callee_ret_reg_map.contains(req_ecv_reg)
              ) {
                continue;
              }
              auto [_, user_refd_val, order] = tuple_set;
              // must load `wide` register because the called lifted function may have changed the req_ecv_reg.
              auto req_wide_load =
                  llvm::dyn_cast<llvm::Instruction>(inst_lifter->LoadRegValueBeforeInst(
                      target_bb, state_ptr, req_ecv_reg.GetWideRegName(), call_next_inst));
              // Replace with new loaded register.
              std::set<llvm::User *> fin_users;
              std::unordered_map<llvm::Type *, llvm::Value *> new_casted_valmap;
              auto user = user_refd_val->user_begin();
              // run every user instruction of the user_refd_val and replace the user reffered value with the req_wide_load.
              while (user_refd_val->user_end() != user) {
                auto user_inst = llvm::dyn_cast<llvm::Instruction>(*user);
                if (fin_users.contains(*user) || (user_inst->getParent() == target_bb &&
                                                  user_inst->comesBefore(req_wide_load))) {
                  user++;
                  continue;
                }
                if (auto extrv_user = llvm::dyn_cast<llvm::ExtractValueInst>(user_inst)) {
                  // user_inst is ExtractValueInst.
                  if (extrv_user->getIndices()[0] == order) {
                    CHECK(req_wide_load->getType() == extrv_user->getType());
                    extrv_user->replaceAllUsesWith(req_wide_load);
                    fin_users.insert(user_inst);
                    user = user_refd_val->user_begin();
                    // extr_user->eraseFromParent();
                    continue;
                  }
                } else if (auto extre_user = llvm::dyn_cast<llvm::ExtractElementInst>(user_inst)) {
                  // user_inst is ExtractElementInst.
                  if (llvm::dyn_cast<llvm::ConstantInt>(extre_user->getIndexOperand())
                          ->getZExtValue() == order) {
                    CHECK(req_wide_load->getType() == extre_user->getType());
                    extre_user->replaceAllUsesWith(req_wide_load);
                    fin_users.insert(user_inst);
                    user = user_refd_val->user_begin();
                    // extre_user->eraseFromParent();
                    continue;
                  }
                } else {
                  auto user_refd_val_type = user_refd_val->getType();
                  llvm::Value *req_load_val;
                  if (new_casted_valmap.contains(user_refd_val_type)) {
                    req_load_val = new_casted_valmap.at(user_refd_val_type);
                  } else {
                    req_load_val = CastFromInst(req_ecv_reg, req_wide_load, user_refd_val_type,
                                                call_next_inst);
                    new_casted_valmap.insert({user_refd_val_type, req_load_val});
                    value_reg_map.insert(
                        {req_load_val, {req_ecv_reg, GetRegClassFromLLVMType(user_refd_val_type)}});
                  }
                  user_inst->replaceUsesOfWith(user_refd_val, req_load_val);
                  fin_users.insert(user_inst);
                }
                // increment user iterator
                user++;
              }
              auto req_wide_load_r_c = GetRegClassFromLLVMType(req_wide_load->getType());
              // Update cache.
              ascend_reg_inst_map.insert_or_assign(
                  req_ecv_reg, std::make_tuple(req_wide_load_r_c, req_wide_load, 0));
              // for debug
              value_reg_map.insert({req_wide_load, {req_ecv_reg, req_wide_load_r_c}});
            }
            target_inst_it = call_next_inst;
          }
          // Call the `emulate_system_call` semantic function.
          else if (call_inst->getCalledFunction()->getName().str() == "emulate_system_call") {
            // Store target: x0 ~ x5, x8
            for (auto [within_store_ecv_reg, ascend_value] : ascend_reg_inst_map) {
              if (kArchAArch64LittleEndian == TARGET_ELF_ARCH) {
                if (!(within_store_ecv_reg.number < 6 || within_store_ecv_reg.number == 8) ||
                    !target_bb_reg_info_node->bb_store_reg_map.contains(within_store_ecv_reg)) {
                  continue;
                }
              } else if (kArchAMD64 == TARGET_ELF_ARCH) {
                if (!(within_store_ecv_reg.number == 2 || within_store_ecv_reg.number == 6 ||
                      within_store_ecv_reg.number == 7 || within_store_ecv_reg.number == 8 ||
                      within_store_ecv_reg.number == 9 || within_store_ecv_reg.number == 10 ||
                      within_store_ecv_reg.number == 0) ||
                    !target_bb_reg_info_node->bb_store_reg_map.contains(within_store_ecv_reg)) {
                  continue;
                }
              }
              auto within_store_ecv_reg_class = std::get<ERC>(ascend_value);
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                  GetRegValueFromCacheMap(within_store_ecv_reg,
                                          GetWholeLLVMTypeFromRegZ(within_store_ecv_reg), call_inst,
                                          ascend_reg_inst_map),
                  call_inst);
            }
            // Store target: x0 ~ x5, x8
            for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_preceding_store_reg_map) {
              if (kArchAArch64LittleEndian == TARGET_ELF_ARCH) {
                if (!(preceding_store_ecv_reg.number < 6 || preceding_store_ecv_reg.number == 8) ||
                    target_bb_reg_info_node->bb_store_reg_map.contains(preceding_store_ecv_reg)) {
                  continue;
                }
              } else if (kArchAMD64 == TARGET_ELF_ARCH) {
                if (!(preceding_store_ecv_reg.number == 2 || preceding_store_ecv_reg.number == 6 ||
                      preceding_store_ecv_reg.number == 7 || preceding_store_ecv_reg.number == 8 ||
                      preceding_store_ecv_reg.number == 9 || preceding_store_ecv_reg.number == 10 ||
                      preceding_store_ecv_reg.number == 0) ||
                    target_bb_reg_info_node->bb_store_reg_map.contains(preceding_store_ecv_reg)) {
                  continue;
                }
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr,
                  preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                  GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                          GetWholeLLVMTypeFromRegZ(preceding_store_ecv_reg),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load target: x0
            for (auto [req_ecv_reg, tuple_set] : ascend_reg_inst_map) {
              if (0 != req_ecv_reg.number) {
                continue;
              }
              auto [_, user_refd_val, order] = tuple_set;
              // must load `wide` register because the called lifted function may have changed the req_ecv_reg.
              auto req_wide_load =
                  llvm::dyn_cast<llvm::Instruction>(inst_lifter->LoadRegValueBeforeInst(
                      target_bb, state_ptr, req_ecv_reg.GetWideRegName(), call_next_inst));
              // Replace with new loaded register.
              std::set<llvm::User *> fin_users;
              std::unordered_map<llvm::Type *, llvm::Value *> new_casted_valmap;
              auto user = user_refd_val->user_begin();
              // run every user instruction of the user_refd_val and replace the user reffered value with the req_wide_load.
              while (user_refd_val->user_end() != user) {
                auto user_inst = llvm::dyn_cast<llvm::Instruction>(*user);
                if (fin_users.contains(*user) || (user_inst->getParent() == target_bb &&
                                                  user_inst->comesBefore(req_wide_load))) {
                  user++;
                  continue;
                }
                if (auto extrv_user = llvm::dyn_cast<llvm::ExtractValueInst>(user_inst)) {
                  // user_inst is ExtractValueInst.
                  if (extrv_user->getIndices()[0] == order) {
                    CHECK(req_wide_load->getType() == extrv_user->getType());
                    extrv_user->replaceAllUsesWith(req_wide_load);
                    fin_users.insert(user_inst);
                    user = user_refd_val->user_begin();
                    // extr_user->eraseFromParent();
                    continue;
                  }
                } else if (auto extre_user = llvm::dyn_cast<llvm::ExtractElementInst>(user_inst)) {
                  // user_inst is ExtractElementInst.
                  if (llvm::dyn_cast<llvm::ConstantInt>(extre_user->getIndexOperand())
                          ->getZExtValue() == order) {
                    CHECK(req_wide_load->getType() == extre_user->getType());
                    extre_user->replaceAllUsesWith(req_wide_load);
                    fin_users.insert(user_inst);
                    user = user_refd_val->user_begin();
                    // extre_user->eraseFromParent();
                    continue;
                  }
                } else {
                  auto user_refd_val_type = user_refd_val->getType();
                  llvm::Value *req_load_val;
                  if (new_casted_valmap.contains(user_refd_val_type)) {
                    req_load_val = new_casted_valmap.at(user_refd_val_type);
                  } else {
                    req_load_val = CastFromInst(req_ecv_reg, req_wide_load, user_refd_val_type,
                                                call_next_inst);
                    new_casted_valmap.insert({user_refd_val_type, req_load_val});
                    value_reg_map.insert(
                        {req_load_val, {req_ecv_reg, GetRegClassFromLLVMType(user_refd_val_type)}});
                  }
                  user_inst->replaceUsesOfWith(user_refd_val, req_load_val);
                  fin_users.insert(user_inst);
                }
                // increment user iterator
                user++;
              }
              auto req_wide_load_r_c = GetRegClassFromLLVMType(req_wide_load->getType());
              // Update cache.
              ascend_reg_inst_map.insert_or_assign(
                  req_ecv_reg, std::make_tuple(req_wide_load_r_c, req_wide_load, 0));
              // for debug
              value_reg_map.insert({req_wide_load, {req_ecv_reg, req_wide_load_r_c}});
            }
            target_inst_it = call_next_inst;
            DEBUG_PC_AND_REGISTERS(call_next_inst, ascend_reg_inst_map, 0xdeadbeef);
          }
          // Call the general semantic functions.
          else {
            auto call_next_inst = call_inst->getNextNode();
            if (target_bb_reg_info_node->sema_call_written_reg_map.contains(call_inst)) {
              auto &sema_func_write_regs =
                  target_bb_reg_info_node->sema_call_written_reg_map.at(call_inst);
              // Load all the referenced registers.
              for (std::size_t i = 0; i < sema_func_write_regs.size(); i++) {
                ascend_reg_inst_map.insert_or_assign(
                    sema_func_write_regs[i].first,
                    std::make_tuple(sema_func_write_regs[i].second, call_inst, i));
              }
              // for debug
              // if the return type is struct, this key value is not used.
              if (!sema_func_write_regs.empty()) {
                value_reg_map.insert(
                    {call_inst, {sema_func_write_regs[0].first, sema_func_write_regs[0].second}});
              }
              DEBUG_PC_AND_REGISTERS(call_next_inst, ascend_reg_inst_map,
                                     Sema_func_vma_map.contains(call_inst)
                                         ? Sema_func_vma_map.at(call_inst)
                                         : 0xffff'ffff);
            }
            target_inst_it = call_next_inst;
          }
        }
        // Target: llvm::StoreInst
        else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(target_inst_it)) {
          auto stored_value = store_inst->getValueOperand();
          auto stored_reg_name = store_inst->getPointerOperand()->getName().str();
          auto [store_ecv_reg, store_ecv_reg_class] = EcvReg::GetRegInfo(stored_reg_name);
          // Update cache.
          ascend_reg_inst_map.insert_or_assign(
              store_ecv_reg, std::make_tuple(store_ecv_reg_class, stored_value, 0));
          CHECK(stored_value->getType() == GetLLVMTypeFromRegZ(store_ecv_reg_class));
          target_inst_it = store_inst->getNextNode();
          store_inst->eraseFromParent();
        }
        // Target: llvm::BranchInst
        else if (auto __br_inst = llvm::dyn_cast<llvm::BranchInst>(target_inst_it)) {
          CHECK(!br_inst) << "There are multiple branch instructions in the one BB.";
          br_inst = __br_inst;
          target_inst_it = br_inst->getNextNode();
        }
        // Target: llvm::CastInst
        else if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(target_inst_it)) {
          auto cast_op = cast_inst->getOperand(0);
          // for debug
          value_reg_map.insert({cast_inst, value_reg_map.at(cast_op)});
          target_inst_it = cast_inst->getNextNode();
        }
        // Target: llvm::BinaryOperator
        else if (auto binary_inst = llvm::dyn_cast<llvm::BinaryOperator>(target_inst_it)) {
          if (target_bb_reg_info_node->post_update_regs.contains(binary_inst)) {
            auto [bin_e_r, bin_e_r_c] = target_bb_reg_info_node->post_update_regs.at(binary_inst);
            ascend_reg_inst_map.insert_or_assign(bin_e_r,
                                                 std::make_tuple(bin_e_r_c, binary_inst, 0));
          }
          target_inst_it = target_inst_it->getNextNode();
          // for debug
          auto lhs = binary_inst->getOperand(0);
          // (FIXME) should check the second operand too.
          value_reg_map.insert({binary_inst, value_reg_map.at(lhs)});
        }
        // Target: llvm::ReturnInst
        else if (auto __ret_inst = llvm::dyn_cast<llvm::ReturnInst>(target_inst_it)) {
          // Store already stored `within_store_map`
          CHECK(!ret_inst) << "Found the multiple llvm::ReturnInst at the one Basic Block."
                           << ECV_DEBUG_STREAM.str();
          ret_inst = __ret_inst;
          for (auto [within_store_ecv_reg, ascend_value] : ascend_reg_inst_map) {
            if (
                // !func_v_r_opt_map.at(ret_inst->getParent()->getParent())
                //        ->passed_callee_ret_reg_map.contains(within_store_ecv_reg) ||
                !within_store_ecv_reg.CheckPassedReturnRegs() ||
                !target_bb_reg_info_node->bb_store_reg_map.contains(within_store_ecv_reg)) {
              continue;
            }
            auto within_store_ecv_reg_class = std::get<ERC>(ascend_value);
            inst_lifter->StoreRegValueBeforeInst(
                target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                GetRegValueFromCacheMap(within_store_ecv_reg,
                                        GetWholeLLVMTypeFromRegZ(within_store_ecv_reg), ret_inst,
                                        ascend_reg_inst_map),
                ret_inst);
          }
          // Store `preceding_store_map`
          for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
               target_phi_regs_bag->bag_preceding_store_reg_map) {
            if (
                // !func_v_r_opt_map.at(ret_inst->getParent()->getParent())
                //        ->passed_callee_ret_reg_map.contains(preceding_store_ecv_reg) ||
                !preceding_store_ecv_reg.CheckPassedReturnRegs() ||
                target_bb_reg_info_node->bb_store_reg_map.contains(preceding_store_ecv_reg)) {
              continue;
            }
            inst_lifter->StoreRegValueBeforeInst(
                target_bb, state_ptr,
                preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                        GetWholeLLVMTypeFromRegZ(preceding_store_ecv_reg), ret_inst,
                                        ascend_reg_inst_map),
                ret_inst);
          }
          target_inst_it = target_inst_it->getNextNode();
        }
        // Target: The instructions that can be ignored.
        else if (llvm::dyn_cast<llvm::CmpInst>(target_inst_it) ||
                 llvm::dyn_cast<llvm::GetElementPtrInst>(target_inst_it) ||
                 llvm::dyn_cast<llvm::AllocaInst>(target_inst_it)) {
          CHECK(true);
          target_inst_it = target_inst_it->getNextNode();
        } else {
          LOG(FATAL) << "Unexpected inst when adding phi nodes." << ECV_DEBUG_STREAM.str();
        }
      }
    }

    reg_latest_inst_map = ascend_reg_inst_map;

    finished.insert(target_bb);
    // Add the children to the queue
    if (br_inst) {
      for (std::size_t i = 0; i < br_inst->getNumSuccessors(); i++) {
        phi_bb_queue.push(br_inst->getSuccessor(i));
      }
    }
    CHECK((br_inst != nullptr) ^ (ret_inst != nullptr))
        << "Not found the Branch or Return instruction in the Basic Block."
        << ECV_DEBUG_STREAM.str();
  }

// Check
#if defined(OPT_GEN_IR_DEBUG)
  // Check the parent-child relationship
  for (auto &bb : *func) {
    auto inst_terminator = bb.getTerminator();
    for (size_t i = 0; i < inst_terminator->getNumSuccessors(); i++) {
      CHECK(bb_parents.at(inst_terminator->getSuccessor(i)).contains(&bb));
    }
  }
  // Check the optimized LLVM IR.
  for (auto &bb : *func) {
    auto bb_reg_info_node_2 = bb_reg_info_node_map.at(&bb);
    for (auto &inst : bb) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst);
          call_inst && !lifted_func_caller_set.contains(call_inst)) {
        if (bb_reg_info_node_2->sema_func_args_reg_map.contains(call_inst)) {
          auto sema_isel_args = bb_reg_info_node_2->sema_func_args_reg_map.at(call_inst);
          for (size_t i = 0; i < sema_isel_args.size(); i++) {
            auto sema_isel_arg_i = sema_isel_args[i];
            if (ERC::RegNULL == sema_isel_arg_i.second ||
                // `%state` is not loaded even before optimization, so can ignore.
                STATE_ORDER == sema_isel_arg_i.first.number ||
                llvm::dyn_cast<llvm::Function>(call_inst->getOperand(i))) {
              continue;
            }
            auto actual_arg_i = call_inst->getOperand(i);
            auto [actual_arg_ecv_reg, actual_arg_ecv_reg_class] = value_reg_map.at(actual_arg_i);
            CHECK(actual_arg_ecv_reg.number == sema_isel_arg_i.first.number)
                << "i: " << i
                << ", actual arg ecv_reg number: " << to_string(actual_arg_ecv_reg.number)
                << ", sema func arg ecv_reg: " << to_string(sema_isel_arg_i.first.number) << "\n";
            CHECK(actual_arg_ecv_reg_class == sema_isel_arg_i.second)
                << "ERC Mismatch. actual arg ecv_reg_class: "
                << EcvRegClass2String(actual_arg_ecv_reg_class)
                << ", sema isel arg ecv_reg_class: " << EcvRegClass2String(sema_isel_arg_i.second)
                << " at value: " << LLVMThingToString(actual_arg_i)
                << ", sema func: " << LLVMThingToString(call_inst)
                << ", func: " << func->getName().str() << "\n";
          }
        }
      }
    }
  }
  if (func->size() != finished.size() + relay_bb_cache.size()) {
    std::cout << "No optimized blocks!\n";
    for (auto &bb : *func) {
      if (!finished.contains(&bb) && !relay_bb_cache.contains(&bb)) {
        std::cout << std::hex << &bb << ":\n";
        for (auto &inst : bb) {
          llvm::outs() << "    " << inst << "\n";
        }
      }
    }
    LOG(FATAL) << "func->size: " << func->size() << ", finished size: " << finished.size()
               << ", relay_bb_num: " << relay_bb_cache.size() << "\n"
               << ECV_DEBUG_STREAM.str();
  }
#endif

  DebugStreamReset();
}

void VirtualRegsOpt::InsertDebugVmaAndRegisters(
    llvm::Instruction *inst_at_before,
    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t>> &ascend_reg_inst_map, uint64_t pc) {
  if (!debug_reg_set.empty()) {
    auto debug_vma_and_regiters_fun = impl->module->getFunction("debug_vma_and_registers");

    std::vector<llvm::Value *> args;
    args.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), pc));
    args.push_back(nullptr);

    for (auto debug_ecv_reg : debug_reg_set) {
      if (ascend_reg_inst_map.contains(debug_ecv_reg)) {
        llvm::GlobalVariable *reg_name_gvar = NULL;
        if (RegKind::General == debug_ecv_reg.reg_kind) {
          reg_name_gvar =
              impl->module->getGlobalVariable("debug_X" + to_string(debug_ecv_reg.number));
        } else if (RegKind::Vector == debug_ecv_reg.reg_kind) {
          reg_name_gvar =
              impl->module->getGlobalVariable("debug_V" + to_string(debug_ecv_reg.number));
        } else {
          if (ECV_NZCV_ORDER == debug_ecv_reg.number) {
            reg_name_gvar = impl->module->getGlobalVariable("debug_ECV_NZCV");
          } else if (SP_ORDER == debug_ecv_reg.number) {
            reg_name_gvar = impl->module->getGlobalVariable("debug_SP");
          }
        }
        args.push_back(reg_name_gvar);
        args.push_back(GetRegValueFromCacheMap(debug_ecv_reg,
                                               GetWholeLLVMTypeFromRegZ(debug_ecv_reg),
                                               inst_at_before, ascend_reg_inst_map));
      }
    }

    args[1] = llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), args.size() - 2);
    llvm::CallInst::Create(debug_vma_and_regiters_fun, args, llvm::Twine::createNull(),
                           inst_at_before);
  }
}

llvm::Type *VirtualRegsOpt::GetLLVMTypeFromRegZ(ERC ecv_reg_class) {
  auto &context = func->getContext();
  switch (ecv_reg_class) {
    case ERC::RegW: return llvm::Type::getInt32Ty(context);
    case ERC::RegX: return llvm::Type::getInt64Ty(context);
    case ERC::RegB: return llvm::Type::getInt8Ty(context);
    case ERC::RegH: return llvm::Type::getInt16Ty(context);
    case ERC::RegS: return llvm::Type::getFloatTy(context);
    case ERC::RegD: return llvm::Type::getDoubleTy(context);
    case ERC::RegQ: return llvm::Type::getInt128Ty(context);
    case ERC::RegV: return llvm::VectorType::get(llvm::Type::getInt128Ty(context), 1, false);
    case ERC::Reg8B: return llvm::VectorType::get(llvm::Type::getInt8Ty(context), 8, false);
    case ERC::Reg16B: return llvm::VectorType::get(llvm::Type::getInt8Ty(context), 16, false);
    case ERC::Reg4H: return llvm::VectorType::get(llvm::Type::getInt16Ty(context), 4, false);
    case ERC::Reg8H: return llvm::VectorType::get(llvm::Type::getInt16Ty(context), 8, false);
    case ERC::Reg2S: return llvm::VectorType::get(llvm::Type::getInt32Ty(context), 2, false);
    case ERC::Reg2SF: return llvm::VectorType::get(llvm::Type::getFloatTy(context), 2, false);
    case ERC::Reg4S: return llvm::VectorType::get(llvm::Type::getInt32Ty(context), 4, false);
    case ERC::Reg4SF: return llvm::VectorType::get(llvm::Type::getFloatTy(context), 4, false);
    case ERC::Reg1D: return llvm::VectorType::get(llvm::Type::getInt64Ty(context), 1, false);
    case ERC::Reg1DF: return llvm::VectorType::get(llvm::Type::getDoubleTy(context), 1, false);
    case ERC::Reg2D: return llvm::VectorType::get(llvm::Type::getInt64Ty(context), 2, false);
    case ERC::Reg2DF: return llvm::VectorType::get(llvm::Type::getDoubleTy(context), 2, false);
    case ERC::RegP: return llvm::Type::getInt64PtrTy(context);
    default: break;
  }

  LOG(FATAL)
      << "[Bug] Reach the unreachable code at VirtualRegsOpt::GetLLVMTypeFromRegZ. ecv_reg_class: "
      << std::underlying_type<ERC>::type(ecv_reg_class) << "\n"
      << ECV_DEBUG_STREAM.str();
  return nullptr;
}

llvm::Type *VirtualRegsOpt::GetWholeLLVMTypeFromRegZ(EcvReg ecv_reg) {
  auto &context = func->getContext();
  auto t_reg_kind = ecv_reg.reg_kind;
  if (RegKind::General == t_reg_kind || RegKind::Special == t_reg_kind) {
    CHECK(ecv_reg.number != STATE_ORDER && ecv_reg.number != RUNTIME_ORDER);
    return llvm::Type::getInt64Ty(context);
  } else /* RegKind::Vector */ {
    return llvm::Type::getInt128Ty(context);
  }
}

ERC VirtualRegsOpt::GetRegClassFromLLVMType(llvm::Type *value_type) {
  auto &context = func->getContext();
  if (llvm::Type::getInt32Ty(context) == value_type) {
    return ERC::RegW;
  } else if (llvm::Type::getInt64Ty(context) == value_type) {
    return ERC::RegX;
  } else if (llvm::Type::getInt8Ty(context) == value_type) {
    return ERC::RegB;
  } else if (llvm::Type::getInt16Ty(context) == value_type) {
    return ERC::RegH;
  } else if (llvm::Type::getFloatTy(context) == value_type) {
    return ERC::RegS;
  } else if (llvm::Type::getDoubleTy(context) == value_type) {
    return ERC::RegD;
  } else if (llvm::Type::getInt128Ty(context) == value_type) {
    return ERC::RegQ;
  } else if (llvm::VectorType::get(llvm::Type::getInt128Ty(context), 1, false) == value_type) {
    return ERC::RegV;
  } else if (llvm::VectorType::get(llvm::Type::getInt8Ty(context), 8, false) == value_type) {
    return ERC::Reg8B;
  } else if (llvm::VectorType::get(llvm::Type::getInt8Ty(context), 16, false) == value_type) {
    return ERC::Reg16B;
  } else if (llvm::VectorType::get(llvm::Type::getInt16Ty(context), 4, false) == value_type) {
    return ERC::Reg4H;
  } else if (llvm::VectorType::get(llvm::Type::getInt16Ty(context), 8, false) == value_type) {
    return ERC::Reg8H;
  } else if (llvm::VectorType::get(llvm::Type::getInt32Ty(context), 2, false) == value_type) {
    return ERC::Reg2S;
  } else if (llvm::VectorType::get(llvm::Type::getFloatTy(context), 2, false) == value_type) {
    return ERC::Reg2SF;
  } else if (llvm::VectorType::get(llvm::Type::getInt32Ty(context), 4, false) == value_type) {
    return ERC::Reg4S;
  } else if (llvm::VectorType::get(llvm::Type::getFloatTy(context), 4, false) == value_type) {
    return ERC::Reg4SF;
  } else if (llvm::VectorType::get(llvm::Type::getInt64Ty(context), 1, false) == value_type) {
    return ERC::Reg1D;
  } else if (llvm::VectorType::get(llvm::Type::getDoubleTy(context), 1, false) == value_type) {
    return ERC::Reg1DF;
  } else if (llvm::VectorType::get(llvm::Type::getInt64Ty(context), 2, false) == value_type) {
    return ERC::Reg2D;
  } else if (llvm::VectorType::get(llvm::Type::getDoubleTy(context), 2, false) == value_type) {
    return ERC::Reg2DF;
  } else if (llvm::Type::getInt64PtrTy(context) == value_type) {
    return ERC::RegP;
  }

  LOG(FATAL) << "[Bug] Reach the unreachable code at VirtualregsOpt::GetRegZfromLLVMType. Type: "
             << LLVMThingToString(value_type) << "\n"
             << ECV_DEBUG_STREAM.str();
}

llvm::Value *VirtualRegsOpt::GetValueFromTargetBBAndReg(llvm::BasicBlock *target_bb,
                                                        llvm::BasicBlock *request_bb,
                                                        std::pair<EcvReg, ERC> ecv_reg_info) {
  auto &[target_ecv_reg, req_ecv_reg_class] = ecv_reg_info;
  auto target_phi_regs_bag = bb_regs_bag_map.at(target_bb);
  auto target_bb_reg_info_node = bb_reg_info_node_map.at(target_bb);

  const llvm::DataLayout data_layout(impl->module);

  auto target_terminator = target_bb->getTerminator();
  llvm::Value *req_value = nullptr;

  // The target_bb already has the target virtual register.
  if (target_bb_reg_info_node->reg_latest_inst_map.contains(target_ecv_reg)) {
    auto &[_, from_inst, from_order] =
        target_bb_reg_info_node->reg_latest_inst_map.at(target_ecv_reg);
    if (from_inst->getType() == GetLLVMTypeFromRegZ(req_ecv_reg_class)) {
      req_value = from_inst;
    } else {
      if (llvm::dyn_cast<llvm::StructType>(from_inst->getType()) ||
          llvm::dyn_cast<llvm::ArrayType>(from_inst->getType())) {
        auto from_extracted_inst = llvm::ExtractValueInst::Create(
            from_inst, {from_order}, llvm::Twine::createNull(), target_terminator);
        auto from_extracted_inst_reg_class =
            GetRegClassFromLLVMType(from_extracted_inst->getType());
        // Update cache.
        target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
            {from_extracted_inst, {target_ecv_reg, from_extracted_inst_reg_class}});
        target_bb_reg_info_node->reg_latest_inst_map.insert_or_assign(
            target_ecv_reg, std::make_tuple(from_extracted_inst_reg_class, from_extracted_inst, 0));
        req_value = CastFromInst(target_ecv_reg, from_extracted_inst,
                                 GetLLVMTypeFromRegZ(req_ecv_reg_class), target_terminator);
        // for debug
        value_reg_map.insert(
            {from_extracted_inst, {target_ecv_reg, from_extracted_inst_reg_class}});
      } else if (isu128v2Ty(impl->context, from_inst->getType())) {
        auto from_extracted_inst = llvm::ExtractElementInst::Create(
            from_inst, llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), from_order),
            "", target_terminator);
        auto from_extracted_inst_reg_class =
            GetRegClassFromLLVMType(from_extracted_inst->getType());
        // Update cache.
        target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
            {from_extracted_inst, {target_ecv_reg, from_extracted_inst_reg_class}});
        target_bb_reg_info_node->reg_latest_inst_map.insert_or_assign(
            target_ecv_reg, std::make_tuple(from_extracted_inst_reg_class, from_extracted_inst, 0));
        req_value = CastFromInst(target_ecv_reg, from_extracted_inst,
                                 GetLLVMTypeFromRegZ(req_ecv_reg_class), target_terminator);
        // for debug
        value_reg_map.insert(
            {from_extracted_inst, {target_ecv_reg, from_extracted_inst_reg_class}});
      }

      else {
        req_value = CastFromInst(target_ecv_reg, from_inst, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                                 target_terminator);
      }
      // for debug
      value_reg_map.insert({req_value, {target_ecv_reg, req_ecv_reg_class}});
    }
  }
  // The bag_req_reg_map of the target_bb includes the target register.
  else if (target_phi_regs_bag->bag_req_reg_map.contains(target_ecv_reg)) {
    auto start_inst = target_bb->begin();
    auto phi_ecv_reg_class = target_phi_regs_bag->bag_req_reg_map.at(target_ecv_reg);
    auto phi_op_type = GetLLVMTypeFromRegZ(phi_ecv_reg_class);
    auto reg_phi = llvm::PHINode::Create(phi_op_type, bb_parents.at(target_bb).size(),
                                         VAR_NAME(target_ecv_reg, phi_ecv_reg_class), &*start_inst);
    // Update phi cache.
    // must update reg_latest_inst_map before addIncoming to correspond to the loop bbs.
    target_bb_reg_info_node->reg_latest_inst_map.insert(
        {target_ecv_reg, {phi_ecv_reg_class, reg_phi, 0}});
    // Get the every virtual register from all the parent bb.
    auto par_bb_it = bb_parents.at(target_bb).begin();
    std::set<llvm::BasicBlock *> _finished;
    while (par_bb_it != bb_parents.at(target_bb).end()) {
      auto par_bb = *par_bb_it;
      if (_finished.contains(par_bb)) {
        ++par_bb_it;
        continue;
      }
      auto derived_reg_value =
          GetValueFromTargetBBAndReg(par_bb, target_bb, {target_ecv_reg, phi_ecv_reg_class});
      if (auto from_inst = llvm::dyn_cast<llvm::Instruction>(derived_reg_value)) {
        auto from_inst_par = from_inst->getParent();
        reg_phi->addIncoming(derived_reg_value, from_inst_par);
        _finished.insert(from_inst_par);
        if (from_inst_par != par_bb) {
          par_bb_it = bb_parents.at(target_bb).begin();
          continue;
        }
      } else {
        reg_phi->addIncoming(derived_reg_value, par_bb);
      }
      ++par_bb_it;
    }
    CHECK(reg_phi->getNumIncomingValues() == bb_parents.at(target_bb).size());
    // Cast to the req_ecv_reg_class if necessary.
    req_value = CastFromInst(target_ecv_reg, reg_phi, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                             target_terminator);
    // for debug
    value_reg_map.insert({reg_phi, {target_ecv_reg, phi_ecv_reg_class}});
    value_reg_map.insert({req_value, {target_ecv_reg, req_ecv_reg_class}});
    // Update cache.
    target_bb_reg_info_node->reg_derived_added_inst_map.insert({target_ecv_reg, reg_phi});
    target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
        {reg_phi, {target_ecv_reg, phi_ecv_reg_class}});
    CHECK(reg_phi->getType() == GetLLVMTypeFromRegZ(phi_ecv_reg_class));
  }
  // The target_bb doesn't have the target register, so need to `load` the register.
  else {
    bool relay_bb_need = false;
    auto load_e_r_c = req_ecv_reg_class;
    for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
      auto &succi_bag_req_reg_map =
          bb_regs_bag_map.at(target_terminator->getSuccessor(i))->bag_req_reg_map;
      relay_bb_need |= !succi_bag_req_reg_map.contains(target_ecv_reg);
      if (succi_bag_req_reg_map.contains(target_ecv_reg) &&
          GetRegClassSize(load_e_r_c) < GetRegClassSize(succi_bag_req_reg_map.at(target_ecv_reg))) {
        load_e_r_c = succi_bag_req_reg_map.at(target_ecv_reg);
      }
    }

    // Need to insert `relay_bb`
    if (relay_bb_need) {
      // Create `relay_bb` and insert `load` to it.
      auto relay_bb = llvm::BasicBlock::Create(impl->context, llvm::Twine::createNull(), func);
      impl->DirectBranchWithSaveParents(request_bb, relay_bb);
      for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
        if (target_terminator->getSuccessor(i) == request_bb) {
          target_terminator->setSuccessor(i, relay_bb);
          auto &request_pars = bb_parents.at(request_bb);
          request_pars.erase(target_bb);
          bb_parents.insert({relay_bb, {target_bb}});
        }
      }
      relay_bb_cache.insert(relay_bb);

      // Add relay_bb to the PhiRegsBBBagNode and BBRegInfoNode.
      auto request_phi_regs_bag = bb_regs_bag_map.at(request_bb);
      bb_regs_bag_map.insert({relay_bb, request_phi_regs_bag});
      auto relay_bb_reg_info_node = new BBRegInfoNode(func, arg_state_val, arg_runtime_val);
      bb_reg_info_node_map.insert({relay_bb, relay_bb_reg_info_node});

      auto relay_terminator = relay_bb->getTerminator();

      // Fix all the aleady derived phi nodes on the request_bb from the target_bb.
      auto request_bb_reg_info_node = bb_reg_info_node_map.at(request_bb);
      auto request_bb_inst_it = request_bb->begin();
      while (auto request_phi_inst = llvm::dyn_cast<llvm::PHINode>(&*request_bb_inst_it)) {
        for (size_t i = 0; i < request_phi_inst->getNumIncomingValues(); ++i) {
          if (request_phi_inst->getIncomingBlock(i) == target_bb) {
            auto [request_ecv_reg, request_ecv_reg_class] =
                request_bb_reg_info_node->referred_able_added_inst_reg_map.at(request_phi_inst);
            // Generate the new phi node on the relay_bb.
            auto relay_phi_inst =
                llvm::PHINode::Create(GetLLVMTypeFromRegZ(request_ecv_reg_class), 1,
                                      llvm::Twine::createNull(), relay_terminator);
            relay_phi_inst->addIncoming(request_phi_inst->getIncomingValue(i), target_bb);
            // re-set the new value and bb of relay_bb for the request_phi_inst.
            request_phi_inst->setIncomingBlock(i, relay_bb);
            request_phi_inst->setIncomingValue(i, relay_phi_inst);

            // Update cache (relay_phi_inst).
            relay_bb_reg_info_node->reg_latest_inst_map.insert(
                {request_ecv_reg, {request_ecv_reg_class, relay_phi_inst, 0}});
            // for debug
            value_reg_map.insert({relay_phi_inst, {request_ecv_reg, request_ecv_reg_class}});
          }
        }
        ++request_bb_inst_it;
      }

      // load all the required registers that the target_bag doesn't require.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      for (auto &[need_ecv_reg, need_ecv_reg_class] : request_phi_regs_bag->bag_req_reg_map) {
        if (!target_bb_reg_info_node->reg_latest_inst_map.contains(need_ecv_reg) &&
            !target_phi_regs_bag->bag_req_reg_map.contains(need_ecv_reg)) {
          auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
              relay_bb, state_ptr, need_ecv_reg.GetRegName(need_ecv_reg_class), relay_terminator,
              VAR_NAME(need_ecv_reg, need_ecv_reg_class));
          // Update cache.
          relay_bb_reg_info_node->reg_latest_inst_map.insert(
              {need_ecv_reg, {need_ecv_reg_class, load_value, 0}});
          if (target_ecv_reg == need_ecv_reg) {
            req_value = load_value;
          }
          // for debug
          value_reg_map.insert(
              {load_value, {need_ecv_reg, GetRegClassFromLLVMType(load_value->getType())}});
          value_reg_map.insert({req_value, {need_ecv_reg, need_ecv_reg_class}});
        }
      }

      auto relay_bb_br_inst = llvm::dyn_cast<llvm::BranchInst>(relay_bb->getTerminator());
      if (relay_bb_br_inst) {
        phi_bb_queue.push(relay_bb_br_inst->getSuccessor(0));
      }
    }
    // Can insert `load` to the target_bb.
    else {
      // Add `load` instruction.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
          target_bb, state_ptr, target_ecv_reg.GetRegName(load_e_r_c), target_terminator,
          VAR_NAME(target_ecv_reg, load_e_r_c));
      req_value = CastFromInst(target_ecv_reg, load_value, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                               target_terminator);
      // Update cache.
      target_bb_reg_info_node->reg_latest_inst_map.insert(
          {target_ecv_reg, {load_e_r_c, load_value, 0}});
      target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
          {req_value, {target_ecv_reg, req_ecv_reg_class}});
      // for debug
      value_reg_map.insert({load_value, {target_ecv_reg, load_e_r_c}});
      value_reg_map.insert({req_value, {target_ecv_reg, req_ecv_reg_class}});
    }
  }

  CHECK(req_value);
  return req_value;
}

}  // namespace remill
