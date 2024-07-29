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
#include <remill/BC/HelperMacro.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>
#include <set>
#include <sstream>

#define OPT_DEBUG

namespace remill {

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

llvm::Value *TraceLifter::Impl::GetRuntimePtrOnEntry() {
  llvm::StringRef runtime_name(kRuntimeVariableName);
  llvm::Value *runtime_manager_ptr = nullptr;
  if (!func->empty()) {
    for (auto &instr : func->getEntryBlock()) {
      if (instr.getName() == runtime_name) {
        if (auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&instr)) {
          runtime_manager_ptr = alloca;
        }
      }
    }
  }

  if (!runtime_manager_ptr) {
    LOG(FATAL) << "Cannot find `RUNTIME` at the entry block of the Lifted function.";
  }

  return runtime_manager_ptr;
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

    CHECK(func->isDeclaration());
    virtual_regs_opt = new VirtualRegsOpt(func, this, trace_addr);
    virtual_regs_opt->func_name = func->getName().str();
    func_virtual_regs_opt_map.insert({func, virtual_regs_opt});

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    arch->InitializeEmptyLiftedFunction(func);
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
      auto runtime_manager_ptr = GetRuntimePtrOnEntry();
      std::vector<llvm::Value *> args = {
          __debug_ir.CreateLoad(llvm::Type::getInt64PtrTy(context), runtime_manager_ptr)
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr)};
      __debug_ir.CreateCall(_debug_call_stack_push_fn, args);
    } while (false);
#endif

    auto state_ptr = NthArgument(func, kStatePointerArgNum);

    if (auto entry_block = &(func->front())) {
      // Branch to the block of trace_addr.
      DirectBranchWithSaveParents(GetOrCreateBlock(trace_addr), entry_block);
      auto entry_bb_reg_info_node = new BBRegInfoNode();
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

      bb_reg_info_node = new BBRegInfoNode();

      // Check to see if this instruction corresponds with an existing
      // trace head, and if so, tail-call into that trace directly without
      // decoding or lifting the instruction.
      if (inst_addr != trace_addr) {
        if (auto inst_as_trace = get_trace_decl(inst_addr)) {
          AddTerminatingTailCall(
              block, inst_as_trace, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
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

#if defined(LIFT_DEBUG)
      (void) new llvm::StoreInst(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr),
                                 LoadProgramCounterRef(block), block);
#endif

      // Lift instruction
      auto lift_status =
          control_flow_debug_list.contains(trace_addr) && control_flow_debug_list[trace_addr]
              ? inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr, bb_reg_info_node, inst_addr)
              : inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr, bb_reg_info_node,
                                                UINT64_MAX);
      // map the block to the bb_reg_info_node
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(block))
          << "The block and the bb_reg_info_node have already been appended to the map.";
      virtual_regs_opt->bb_reg_info_node_map.insert({block, bb_reg_info_node});

      if (!tmp_patch_fn_check && manager._io_file_xsputn_vma == trace_addr) {
        llvm::IRBuilder<> ir(block);
        auto [x0_ptr, _] = inst.GetLifter()->LoadRegAddress(block, state_ptr, "X0");
        auto runtime_manager_ptr = GetRuntimePtrOnEntry();
        std::vector<llvm::Value *> args = {
            ir.CreateLoad(llvm::Type::getInt64PtrTy(context), runtime_manager_ptr),
            ir.CreateLoad(llvm::Type::getInt64Ty(context), x0_ptr)};
        auto tmp_patch_fn = module->getFunction("temp_patch_f_flags");
        ir.CreateCall(tmp_patch_fn, args);
        tmp_patch_fn_check = true;
      }

      if (kLiftedInstruction != lift_status) {
        LOG(FATAL) << "lifted_status is invalid at: " << inst.function;
        AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr);
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
          DirectBranchWithSaveParents(GetOrCreateBranchTakenBlock(), block);
          break;

        /* case: BR instruction (only BR in glibc) */
        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);
          /* indirectbr entry block */
          indirectbr_block = GetOrCreateIndirectJmpBlock();
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
          // Therefore, we force to return at this block because we assumet that this instruction don't come back to.
          if (manager.isFunctionEntry(inst.next_pc)) {
            llvm::ReturnInst::Create(context, block);
          } else {
            goto check_call_return;
          }
          break;

        /* case: BLR instruction (only BLR in glibc) */
        case Instruction::kCategoryIndirectFunctionCall: {
          try_add_delay_slot(true, block);
          const auto fall_through_block = llvm::BasicBlock::Create(context, "", func);

          DirectBranchWithSaveParents(GetOrCreateBranchNotTakenBlock(), fall_through_block);

          // indirect jump address is value of %Xzzz just before
          auto lifted_func_call =
              AddCall(block, intrinsics->function_call, *intrinsics, FindIndirectBrAddress(block));
          virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);
          DirectBranchWithSaveParents(fall_through_block, block);
          block = fall_through_block;
          continue;
        }

        // no instruction in aarch64?
        case Instruction::kCategoryConditionalIndirectFunctionCall: {
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
          if (inst.branch_not_taken_pc != inst.branch_taken_pc) {
            trace_work_list.insert(inst.branch_taken_pc);
            auto target_trace = get_trace_decl(inst.branch_taken_pc);
            auto lifted_func_call = AddCall(
                block, target_trace, *intrinsics,
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.branch_taken_pc));
            virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);
          }
          DirectBranchWithSaveParents(GetOrCreateBranchNotTakenBlock(), block);
          continue;
        }

        // no instruction in aarch64?
        case Instruction::kCategoryConditionalDirectFunctionCall: {
          LOG(FATAL) << "kCategoryConditionalDirectFunctionCall exist in aarch64?";
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

        case Instruction::kCategoryFunctionReturn:
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(
              block, intrinsics->function_return, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
          break;

        case Instruction::kCategoryConditionalFunctionReturn: {
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
      auto runtime_manager_ptr = GetRuntimePtrOnEntry();
      auto target_bb_i64 = ir_1.CreateCall(
          g_get_jmp_helper_fn,
          {ir_1.CreateLoad(llvm::Type::getInt64PtrTy(context), runtime_manager_ptr),
           llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr), br_vma_phi});
      auto indirect_br_i = ir_1.CreateIndirectBr(
          ir_1.CreatePointerCast(target_bb_i64, llvm::Type::getInt64PtrTy(context)),
          bb_addrs.size());
      for (auto &[_, _block] : lifted_block_map) {
        indirect_br_i->addDestination(_block);
      }
      indirect_br_i->addDestination(br_to_func_block);
      /* br_to_func_block */
      AddTerminatingTailCall(br_to_func_block, intrinsics->jump, *intrinsics, -1, br_vma_phi);
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

  // Prepare the optimization
  inst.Reset();
  arch->InstanceInstAArch64(inst);

  // Optimization of the usage of the LLVM IR virtual registers for the CPU registers instead of the memory usage.
  for (auto lifted_func : no_indirect_lifted_funcs) {
    if (lifted_func->getName().str().starts_with("easy_cal")) {
      llvm::outs() << "Optimization start: " << lifted_func->getName().str().c_str() << "\n";
      auto virtual_regs_opt = func_virtual_regs_opt_map[lifted_func];
      virtual_regs_opt->OptimizeVirtualRegsUsage();
    }
  }

  return true;
}

llvm::Value *VirtualRegsOpt::CastFromInst(EcvReg target_ecv_reg, llvm::Value *from_inst,
                                          llvm::Type *to_inst_ty, llvm::Instruction *inst_at_before,
                                          llvm::Value *to_inst) {
  auto from_inst_ty = from_inst->getType();
  auto from_inst_size = impl->data_layout.getTypeAllocSizeInBits(from_inst_ty);
  auto to_inst_size = impl->data_layout.getTypeAllocSizeInBits(to_inst_ty);

  if (from_inst_ty == to_inst_ty) {
    CHECK(to_inst) << "[Bug]: to_inst must not be NULL when from_inst_ty == to_inst_ty.";
    return to_inst;
  }

  if (from_inst_size < to_inst_size) {
    if (RegKind::General == target_ecv_reg.reg_kind) {
      CHECK(to_inst_ty->isIntegerTy() && from_inst_ty->isIntegerTy())
          << "RegKind::General register should have only the integer type.";

      return new llvm::ZExtInst(from_inst, to_inst_ty, llvm::Twine::createNull(), inst_at_before);
    } else if (RegKind::Vector == target_ecv_reg.reg_kind) {
      CHECK((to_inst_ty->isIntegerTy() && from_inst_ty->isIntegerTy()) ||
            (to_inst_ty->isFloatingPointTy() && from_inst_ty->isFloatingPointTy()))
          << "(FIXME!): occurs implicit cast between IntegerType and FloatingPointType on the vector register. (from_inst_size < to_inst_size)";

      return new llvm::ZExtInst(from_inst, to_inst_ty, llvm::Twine::createNull(), inst_at_before);
    } else if (RegKind::Special == target_ecv_reg.reg_kind) {
      LOG(FATAL) << "RegKind::Special register must not be used different types.";
    }
  } else if (from_inst_size > to_inst_size) {
    if (RegKind::General == target_ecv_reg.reg_kind) {
      CHECK(to_inst_ty->isIntegerTy() && from_inst_ty->isIntegerTy())
          << "RegKind::General register should have only the integer type.";

      return new llvm::TruncInst(from_inst, to_inst_ty, llvm::Twine::createNull(), inst_at_before);
    } else if (RegKind::Vector == target_ecv_reg.reg_kind) {
      CHECK((to_inst_ty->isIntegerTy() && from_inst_ty->isIntegerTy()) ||
            (to_inst_ty->isFloatingPointTy() && from_inst_ty->isFloatingPointTy()))
          << "(FIXME!): occurs implicit cast between IntegerType and FloatingPointType on the vector register. (from_inst_size > to_inst_size)";

      return new llvm::TruncInst(from_inst, to_inst_ty, llvm::Twine::createNull(), inst_at_before);
    } else if (RegKind::Special == target_ecv_reg.reg_kind) {
      LOG(FATAL) << "RegKind::Special register must not be used different types.";
    }
  } else {
    LOG(FATAL)
        << "(FIXME!): occurs implicit cast between IntegerType and FloatingPointType though they have the same size types.";
  }

  // unreachable
  return nullptr;
}

llvm::Value *VirtualRegsOpt::CastToStoredValue(llvm::Value *from_value, EcvReg target_ecv_reg,
                                               llvm::Instruction *insert_at_before) {
  auto from_ty = from_value->getType();
  auto from_size = impl->data_layout.getTypeAllocSizeInBits(from_ty);

  switch (target_ecv_reg.reg_kind) {
    case RegKind::General:
      if (64 == from_size) {
        return from_value;
      } else if (32 == from_size) {
        return new llvm::ZExtInst(from_value, llvm::Type::getInt64Ty(impl->context),
                                  llvm::Twine::createNull(), insert_at_before);
      } else {
        LOG(FATAL)
            << "Unexpected size of the RegKind::General regsiter at VirtualRegsOpt::CastToStoredValue.";
      }
      break;
    case RegKind::Vector:
      break;
      if (128 == from_size) {
        return from_value;
      } else if (64 == from_size || 32 == from_size || 16 == from_size || 8 == from_size) {
        return new llvm::ZExtInst(from_value, llvm::Type::getInt128Ty(impl->context),
                                  llvm::Twine::createNull(), insert_at_before);
      } else {
        LOG(FATAL)
            << "Unexpected RegKind::Vector register size at VirtualRegsOpt::CastToStoredValue.";
      }
    case RegKind::Special:
      if (64 == from_size) {
        return from_value;
      } else {
        LOG(FATAL)
            << "Expected that the size of the RegKind::Special register is 64 at VirtualRegsOpt::CastToStoredValue.";
      }
      break;
    default: LOG(FATAL) << "Unexpected: Unreachable. at VirtualRegsOpt::CastToStoredValue."; break;
  }

  LOG(FATAL) << "[Bug]: Reach the Unreachable code at VirtualRegsOpt::CastToStoredValue.";
  return nullptr;
}

void VirtualRegsOpt::OptimizeVirtualRegsUsage() {

  auto &inst_lifter = impl->inst.GetLifter();

  // Flatten the control flow graph
  llvm::BasicBlock *target_bb;  // the parent bb of the joined bb
  std::queue<llvm::BasicBlock *> bb_queue;
  std::unordered_map<llvm::BasicBlock *, bool> visited;
  auto entry_bb = &func->getEntryBlock();
  auto entry_terminator_br = llvm::dyn_cast<llvm::BranchInst>(entry_bb->getTerminator());
  CHECK(nullptr != entry_terminator_br)
      << "entry block of the lifted function must have the terminator instruction.";
  CHECK(1 == entry_terminator_br->getNumSuccessors())
      << "entry block terminator must have the one jump basic block.";
  target_bb = entry_bb;
  bb_queue.push(target_bb);

  auto push_successor_bb_queue = [&bb_queue, &visited](llvm::BasicBlock *successor_bb) {
    if (!visited[successor_bb]) {
      bb_queue.push(successor_bb);
    }
  };

  while (!bb_queue.empty()) {
    auto target_bb = bb_queue.front();
    bb_queue.pop();
    visited[target_bb] = true;
    auto target_terminator = target_bb->getTerminator();
    auto child_num = target_terminator->getNumSuccessors();
    if (2 < child_num) {
      LOG(FATAL)
          << "Every block of the lifted function by elfconv must not have the child blocks more than two.";
    } else if (2 == child_num) {
      push_successor_bb_queue(target_terminator->getSuccessor(0));
      push_successor_bb_queue(target_terminator->getSuccessor(1));
    } else if (1 == child_num) {
      auto candidate_bb = target_terminator->getSuccessor(0);
      auto &candidate_bb_parents = bb_parents[candidate_bb];
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
        auto target_bb_reg_info_node = bb_reg_info_node_map[target_bb];
        target_bb_reg_info_node->join_reg_info_node(joined_bb_reg_info_node);
        // update bb_parents
        bb_parents.erase(joined_bb);
        target_terminator = target_bb->getTerminator();
        if (llvm::dyn_cast<llvm::BranchInst>(target_terminator)) {
          // joined_bb has children
          for (uint32_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
            bb_parents[target_terminator->getSuccessor(i)].erase(joined_bb);
            bb_parents[target_terminator->getSuccessor(i)].insert(target_bb);
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

  llvm::outs() << "cfg flatten end.\n";

  // Initialize the Graph of PhiRegsBBBagNode.
  for (auto &[bb, bb_reg_info_node] : bb_reg_info_node_map) {
    auto phi_regs_bag = new PhiRegsBBBagNode(bb_reg_info_node->bb_load_reg_map,
                                             std::move(bb_reg_info_node->bb_load_reg_map),
                                             std::move(bb_reg_info_node->bb_store_reg_map), {bb});
    PhiRegsBBBagNode::bb_regs_bag_map.insert({bb, phi_regs_bag});
  }
  PhiRegsBBBagNode::bag_num = PhiRegsBBBagNode::bb_regs_bag_map.size();

  for (auto &bb_parent : bb_parents) {
    auto bb = bb_parent.first;
    auto &pars = bb_parent.second;
    for (auto par : pars) {
      auto par_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[par];
      auto child_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[bb];
      par_phi_regs_bag->children.insert(child_phi_regs_bag);
      child_phi_regs_bag->parents.insert(par_phi_regs_bag);
    }
  }

  llvm::outs() << func_name << " " << "cfg Initalization of the PhiRegsBBBagNode end.\n";

  // Calculate the registers which needs to get on the phis instruction for every basic block.
  PhiRegsBBBagNode::GetPhiRegsBags(&func->getEntryBlock());

  llvm::outs() << "GetPhiRegsBags end.\n";

  // Add the phi instructions to the every basic block.
  std::set<llvm::BasicBlock *> finished;
  auto state_ptr = NthArgument(func, kStatePointerArgNum);

  phi_bb_queue.push(&func->getEntryBlock());

  while (!phi_bb_queue.empty()) {
    auto target_bb = phi_bb_queue.front();
    phi_bb_queue.pop();
    if (finished.contains(target_bb)) {
      continue;
    }
    auto target_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[target_bb];
    auto target_bb_reg_info_node = bb_reg_info_node_map[target_bb];
    auto &reg_latest_inst_map = bb_reg_info_node_map[target_bb]->reg_latest_inst_map;
    auto &reg_phi_inst_map = bb_reg_info_node_map[target_bb]->reg_phi_inst_map;
    std::unordered_map<EcvReg, std::tuple<EcvRegClass, llvm::Value *, uint32_t>, EcvReg::Hash>
        ascend_reg_inst_map;

    llvm::BranchInst *br_inst;

    // Add the phi instruction for the every register included in the bag_phi_reg_map.
    auto inst_before_phi_it = target_bb->begin();
    for (auto &phi_ecv_reg_info : target_phi_regs_bag->bag_req_reg_map) {
      auto &[target_ecv_reg, target_ecv_reg_class] = phi_ecv_reg_info;
      llvm::PHINode *reg_derived_phi;
      // This phi has been already added.
      if (reg_phi_inst_map.contains(target_ecv_reg)) {
        reg_derived_phi = reg_phi_inst_map[target_ecv_reg];
        CHECK(reg_derived_phi->getNumIncomingValues() == bb_parents[target_bb].size())
            << "The once generated phi instruction should have all necessary incoming values.";
      }
      // Generate the new phi instruction.
      else {
        reg_derived_phi = llvm::PHINode::Create(GetLLVMTypeFromRegZ(target_ecv_reg_class),
                                                bb_parents[target_bb].size(),
                                                llvm::Twine::createNull(), &*inst_before_phi_it);
        reg_phi_inst_map.insert({target_ecv_reg, reg_derived_phi});
        // Add this phi to the reg_latest_inst_map (to avoid the infinity loop when running Impl::GetValueFromTargetBBAndReg).
        reg_latest_inst_map.insert(
            {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_phi, 0)});
        // Get the every virtual register from all the parent bb.
        for (auto par_bb : bb_parents[target_bb]) {
          auto derived_reg_value = GetValueFromTargetBBAndReg(par_bb, target_bb, phi_ecv_reg_info);
          reg_derived_phi->addIncoming(derived_reg_value, par_bb);
        }
      }
      // Add this phi to the ascend_reg_inst_map
      ascend_reg_inst_map.insert(
          {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_phi, 0)});
    }

    reg_latest_inst_map.clear();

    // Replace all the `load` to the CPU registers memory with the value of the phi instructions.
    for (auto target_inst_it = inst_before_phi_it; target_bb->end() != target_inst_it;
         target_inst_it++) {

      // Target: llvm::LoadInst
      if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(&*target_inst_it)) {
        const auto &load_reg = load_inst->getPointerOperand()->getName().str();
        auto load_reg_info = EcvReg::GetRegInfo(load_reg);
        if (!load_reg_info) {
          load_reg_info = EcvReg::GetSpecialRegInfo(load_reg);
        }
        auto target_ecv_reg = load_reg_info.value().first;
        auto load_ecv_reg_class = load_reg_info.value().second;
        auto [_, from_value, from_order] = ascend_reg_inst_map[target_ecv_reg];

        llvm::Value *new_ecv_reg_inst;

        if (!from_value) {
          // This `load` is the first access to the specified CPU register, so should load from memory.
          new_ecv_reg_inst = load_inst;
        } else {
          // Replace the load_inst with the from_inst
          auto from_inst = llvm::dyn_cast<llvm::Instruction>(from_value);
          CHECK(from_inst) << "referenced instruction must be derived from llvm::Instruction.";

          if (load_inst->getType() == from_inst->getType()) {
            new_ecv_reg_inst = from_inst;
          } else {
            // Need to cast the from_inst to match the type of the load_inst.
            if (llvm::dyn_cast<llvm::StructType>(from_inst->getType())) {
              auto from_extracted_inst = llvm::ExtractValueInst::Create(
                  from_inst, {from_order}, llvm::Twine::createNull(), load_inst);
              new_ecv_reg_inst = CastFromInst(target_ecv_reg, from_extracted_inst,
                                              load_inst->getType(), load_inst, from_extracted_inst);
            } else {
              new_ecv_reg_inst =
                  CastFromInst(target_ecv_reg, from_inst, load_inst->getType(), load_inst);
            }
          }
          // Replace all the User.
          load_inst->replaceAllUsesWith(new_ecv_reg_inst);
          // Update cache.
          ascend_reg_inst_map.insert_or_assign(
              target_ecv_reg, std::make_tuple(load_ecv_reg_class, new_ecv_reg_inst, 0));
          // Delete load_inst.
          load_inst->eraseFromParent();
        }
      }
      // Target: llvm::CallInst
      else if (auto *call_inst = llvm::dyn_cast<llvm::CallInst>(&*target_inst_it)) {
        // Call the lifted function (includes `__remill_function_call`).
        if (lifted_func_caller_set.contains(call_inst)) {
          // Store `store_map`
          for (auto [store_ecv_reg, _] : target_phi_regs_bag->bag_preceding_store_reg_map) {
            if (store_ecv_reg.CheckNoChangedReg()) {
              continue;
            }
            auto [_1, from_value, _2] = ascend_reg_inst_map[store_ecv_reg];
            CHECK(from_value)
                << "[Bug]: existing_value must not be empty. at VirtualRegsOpt::OptimizeVirtualRegsUsage.";
            inst_lifter->StoreRegValueBeforeInst(
                target_bb, state_ptr, store_ecv_reg.GetWholeRegName(),
                CastToStoredValue(from_value, store_ecv_reg, call_inst), call_inst);
          }
          auto call_next_inst = call_inst->getNextNode();
          // Load `store_map` + `load_map`
          for (auto [req_ecv_reg, req_ecv_reg_class] : target_phi_regs_bag->bag_req_reg_map) {
            if (req_ecv_reg.CheckNoChangedReg()) {
              continue;
            }
            auto load_value = inst_lifter->LoadRegValueBeforeInst(
                target_bb, state_ptr, req_ecv_reg.GetWholeRegName(), call_next_inst);
            auto req_value =
                CastFromInst(req_ecv_reg, load_value, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                             call_next_inst, load_value);
            // Update cache.
            ascend_reg_inst_map.insert_or_assign(req_ecv_reg,
                                                 std::make_tuple(req_ecv_reg_class, req_value, 0));
          }
        }
        // Call the semantic function.
        else {
          auto &sema_func_write_regs =
              target_bb_reg_info_node->sema_call_written_reg_map[call_inst];
          // Load all the referenced registers.
          for (std::size_t i = 0; i < sema_func_write_regs.size(); i++) {
            ascend_reg_inst_map.insert_or_assign(
                sema_func_write_regs[i].first,
                std::make_tuple(sema_func_write_regs[i].second, call_inst, i));
          }
        }
      }
      // Target: llvm::BranchInst
      else if (auto __br_inst = llvm::dyn_cast<llvm::BranchInst>(&*target_inst_it)) {
        CHECK(!br_inst) << "There are multiple branch instruction in the one BB.";
        br_inst = __br_inst;
      } else if (llvm::dyn_cast<llvm::StoreInst>(&*target_inst_it)) {
        CHECK(target_inst_it->getParent() == &func->getEntryBlock())
            << "lifted function cannot have llvm::StoreInst other than entry basic block.";
      }
      // Target: The instruction that can be ignored.
      else if (llvm::dyn_cast<llvm::BinaryOperator>(&*target_inst_it) ||
               llvm::dyn_cast<llvm::CastInst>(&*target_inst_it) ||
               llvm::dyn_cast<llvm::ReturnInst>(&*target_inst_it) ||
               llvm::dyn_cast<llvm::CmpInst>(&*target_inst_it) ||
               llvm::dyn_cast<llvm::GetElementPtrInst>(&*target_inst_it) ||
               llvm::dyn_cast<llvm::AllocaInst>(&*target_inst_it)) {
        CHECK(true);
      } else {
        llvm::outs() << *target_inst_it << "\n";
        LOG(FATAL) << "Unexpected inst when adding phi instructions.";
      }
    }

    reg_latest_inst_map = ascend_reg_inst_map;

    finished.insert(target_bb);
    // Add the children to the queue
    for (std::size_t i = 0; i < br_inst->getNumSuccessors(); i++) {
      phi_bb_queue.push(br_inst->getSuccessor(i));
    }
  }

  llvm::outs() << "replacing the all phi instructions end.\n";

  // Reset PhiRegsBBBagNode.
  PhiRegsBBBagNode::Reset();

  // assert
  for (auto &[relay_bb, reg_need_load_insts] : relay_reg_need_load_inst_map) {
    CHECK(reg_need_load_insts.empty())
        << "[Bug]: reg_need_load_insts must be empty at the end of VirtualRegsOpt::OptimizeVirtualRegsUsage().";
  }
}

llvm::Type *VirtualRegsOpt::GetLLVMTypeFromRegZ(EcvRegClass ecv_reg_class) {
  auto &context = func->getContext();
  switch (ecv_reg_class) {
    case EcvRegClass::RegW: return llvm::Type::getInt32Ty(context); break;
    case EcvRegClass::RegX: return llvm::Type::getInt64Ty(context); break;
    case EcvRegClass::RegB: return llvm::Type::getInt8Ty(context); break;
    case EcvRegClass::RegH: return llvm::Type::getHalfTy(context); break;
    case EcvRegClass::RegS: return llvm::Type::getFloatTy(context); break;
    case EcvRegClass::RegD: return llvm::Type::getDoubleTy(context); break;
    case EcvRegClass::RegQ: return llvm::Type::getInt128Ty(context); break;
    default: break;
  }

  LOG(FATAL) << "[Bug]: Reach the unreachable code at VirtualRegsOpt::GetLLVMTypeFromRegZ.";
  return nullptr;
}

llvm::Value *
VirtualRegsOpt::GetValueFromTargetBBAndReg(llvm::BasicBlock *target_bb,
                                           llvm::BasicBlock *request_bb,
                                           std::pair<EcvReg, EcvRegClass> ecv_reg_info) {
  auto &[target_ecv_reg, required_ecv_reg_class] = ecv_reg_info;
  auto target_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[target_bb];
  auto target_bb_reg_info_node = bb_reg_info_node_map[target_bb];

  const llvm::DataLayout data_layout(impl->module);

  auto target_terminator = target_bb->getTerminator();
  llvm::Value *required_value = nullptr;

  // The target_bb already has the target virtual register.
  if (target_bb_reg_info_node->reg_latest_inst_map.contains(target_ecv_reg)) {
    auto &[_, from_inst, from_order] = target_bb_reg_info_node->reg_latest_inst_map[target_ecv_reg];
    if (from_inst->getType() == GetLLVMTypeFromRegZ(required_ecv_reg_class)) {
      required_value = from_inst;
    } else {
      if (llvm::dyn_cast<llvm::StructType>(from_inst->getType())) {
        auto from_extracted_inst = llvm::ExtractValueInst::Create(
            from_inst, {from_order}, llvm::Twine::createNull(), target_terminator);
        required_value = CastFromInst(target_ecv_reg, from_extracted_inst,
                                      GetLLVMTypeFromRegZ(required_ecv_reg_class),
                                      target_terminator, from_extracted_inst);
      } else {
        required_value =
            CastFromInst(target_ecv_reg, from_inst, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                         target_terminator);
      }
      // Update cache.
      target_bb_reg_info_node->reg_latest_inst_map.insert_or_assign(
          target_ecv_reg, std::make_tuple(required_ecv_reg_class, required_value, 0));
    }
  }
  // The target_bb is relay_bb and the target register should be `load`ed.
  else if (relay_reg_need_load_inst_map.contains(target_bb) &&
           relay_reg_need_load_inst_map[target_bb].contains(target_ecv_reg)) {
    // Add `load` instruction.
    auto state_ptr = NthArgument(func, kStatePointerArgNum);
    auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
        target_bb, state_ptr, target_ecv_reg.GetWholeRegName(), target_terminator);
    required_value =
        CastFromInst(target_ecv_reg, load_value, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                     target_terminator, load_value);
    // Update cache.
    relay_reg_need_load_inst_map[target_bb].erase(target_ecv_reg);
    target_bb_reg_info_node->reg_latest_inst_map.insert(
        {target_ecv_reg, std::make_tuple(required_ecv_reg_class, required_value, 0)});
  }
  // The bag_req_reg_map of the target_bb includes the target register.
  else if (target_phi_regs_bag->bag_req_reg_map.contains(target_ecv_reg)) {
    // Add `phi` instruction.
    auto start_inst = target_bb->begin();
    auto phi_ecv_reg_class = target_phi_regs_bag->bag_req_reg_map[target_ecv_reg];
    auto reg_phi =
        llvm::PHINode::Create(GetLLVMTypeFromRegZ(phi_ecv_reg_class), bb_parents[target_bb].size(),
                              llvm::Twine::createNull(), &*start_inst);
    // Update cache.
    target_bb_reg_info_node->reg_phi_inst_map.insert({target_ecv_reg, reg_phi});
    target_bb_reg_info_node->reg_latest_inst_map.insert(
        {target_ecv_reg, std::make_tuple(phi_ecv_reg_class, reg_phi, 0)});
    // Get the every virtual register from all the parent bb.
    for (auto par_bb : bb_parents[target_bb]) {
      auto inherited_reg_value = GetValueFromTargetBBAndReg(par_bb, target_bb, ecv_reg_info);
      reg_phi->addIncoming(inherited_reg_value, par_bb);
    }
    // Cast to the required_ecv_reg_class if necessary.
    required_value =
        CastFromInst(target_ecv_reg, reg_phi, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                     target_terminator, reg_phi);
  }
  // The target_bb doesn't have the target register, so need to `load` the register.
  else {
    CHECK(!relay_bbs.contains(target_bb));
    bool relay_bb_need = false;
    for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
      relay_bb_need |= !PhiRegsBBBagNode::bb_regs_bag_map[target_terminator->getSuccessor(i)]
                            ->bag_req_reg_map.contains(target_ecv_reg);
    }
    // Create `relay_bb` and insert `load` to it.
    if (relay_bb_need) {
      auto relay_bb = llvm::BasicBlock::Create(impl->context, llvm::Twine::createNull(), func);
      impl->DirectBranchWithSaveParents(request_bb, relay_bb);
      for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
        if (target_terminator->getSuccessor(i) == request_bb) {
          target_terminator->setSuccessor(i, relay_bb);
        }
      }

      auto relay_terminator = relay_bb->getTerminator();
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
          relay_bb, state_ptr, target_ecv_reg.GetWholeRegName(), relay_terminator);
      required_value =
          CastFromInst(target_ecv_reg, load_value, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                       relay_terminator, load_value);

      // Update cache.
      relay_bbs.insert(relay_bb);
      // (WARNING!): bag_inherited_read_reg_map and bag_read_write_reg_map is incorrect for the relay_bb. However, it is not matter.
      auto request_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[request_bb];
      PhiRegsBBBagNode::bb_regs_bag_map.insert({relay_bb, request_phi_regs_bag});
      // Add the regiser which should be loaded in this relay_bb to the reg_load_inst_map.
      std::set<EcvReg> reg_need_load_insts;
      auto relay_par_phi_regs_bag = target_phi_regs_bag;
      for (auto &[_ecv_reg, _ecv_reg_class] : request_phi_regs_bag->bag_req_reg_map) {
        if (!relay_par_phi_regs_bag->bag_req_reg_map.contains(_ecv_reg)) {
          reg_need_load_insts.insert(_ecv_reg);
        }
      }
      CHECK(!relay_reg_need_load_inst_map.contains(relay_bb));
      relay_reg_need_load_inst_map.insert({relay_bb, reg_need_load_insts});
      bb_reg_info_node_map.insert({relay_bb, new BBRegInfoNode()});
      // push relay_bb to the phi_bb_queue
      phi_bb_queue.push(relay_bb);
    }
    // Can insert `load` to the target_bb.
    else {
      // Add `load` instruction.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
          target_bb, state_ptr, target_ecv_reg.GetWholeRegName(), target_terminator);
      required_value =
          CastFromInst(target_ecv_reg, load_value, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                       target_terminator, load_value);
      // Update cache.
      target_bb_reg_info_node->reg_latest_inst_map.insert(
          {target_ecv_reg, std::make_tuple(required_ecv_reg_class, required_value, 0)});
    }
  }

  CHECK(required_value);
  return required_value;
}

PhiRegsBBBagNode *PhiRegsBBBagNode::GetTrueBag() {
  auto res = this;
  while (res != res->converted_bag) {
    res = res->converted_bag;
  }
  return res;
}

void PhiRegsBBBagNode::MergeFamilyConvertedBags(PhiRegsBBBagNode *merged_bag) {
  for (auto merged_par : merged_bag->parents) {
    parents.insert(merged_par->GetTrueBag());
  }
  for (auto merged_child : merged_bag->children) {
    children.insert(merged_child->GetTrueBag());
  }
}

void PhiRegsBBBagNode::RemoveLoop(llvm::BasicBlock *root_bb) {
  {

#define TUPLE_ELEM_T \
  PhiRegsBBBagNode *, std::vector<PhiRegsBBBagNode *>, std::set<PhiRegsBBBagNode *>
    std::vector<std::tuple<TUPLE_ELEM_T>> bag_stack;
    auto root_bag = bb_regs_bag_map[root_bb];
    bag_stack.emplace_back(
        std::make_tuple<TUPLE_ELEM_T>((remill::PhiRegsBBBagNode *) root_bag, {},
                                      {}));  // Why (remill::PhiResgBBBagNode *) is needed?

    std::set<PhiRegsBBBagNode *> finished;

    for (auto [_, bag] : bb_regs_bag_map) {
      CHECK(!bag->converted_bag);
      bag->converted_bag = bag;
    }

    while (!bag_stack.empty()) {
      auto target_bag = std::get<PhiRegsBBBagNode *>(bag_stack.back())->GetTrueBag();
      auto pre_path = std::get<std::vector<PhiRegsBBBagNode *>>(bag_stack.back());
      auto visited = std::get<std::set<PhiRegsBBBagNode *>>(bag_stack.back());
      bag_stack.pop_back();
      if (finished.contains(target_bag)) {
        continue;
      }
      bool target_bag_is_in_visited = false;
      for (auto _bag : visited) {
        auto true_bag = _bag->GetTrueBag();
        if (true_bag == target_bag) {
          target_bag_is_in_visited = true;
          if (true_bag != _bag) {
            visited.erase(_bag);
            visited.insert(true_bag);
          }
          break;
        }
      }
      if (target_bag_is_in_visited) {
        auto it_loop_bag = pre_path.rbegin();
        PhiRegsBBBagNode *pre_loop_bag = nullptr;
        std::set<PhiRegsBBBagNode *> deleted_bags;
        for (;;) {
          CHECK(!pre_path.empty());
          it_loop_bag = pre_path.rbegin();
          auto moved_bag = (*it_loop_bag)->GetTrueBag();
          pre_path.pop_back();

          if (target_bag == moved_bag) {
            break;
          } else if (pre_loop_bag == moved_bag) {
            continue;
          }

          pre_loop_bag = moved_bag;
          deleted_bags.insert(moved_bag);

          // translates moved_bag
          target_bag->bag_succeeding_load_reg_map.merge(moved_bag->bag_succeeding_load_reg_map);
          target_bag->bag_preceding_load_reg_map.merge(moved_bag->bag_preceding_load_reg_map);
          target_bag->bag_preceding_store_reg_map.merge(moved_bag->bag_preceding_store_reg_map);
          target_bag->MergeFamilyConvertedBags(moved_bag);
          for (auto moved_bb : moved_bag->in_bbs) {
            target_bag->in_bbs.insert(moved_bb);
          }

          // update cache
          moved_bag->converted_bag = target_bag;
          visited.erase(moved_bag);
          bag_num--;

          if (it_loop_bag == pre_path.rend()) {
            LOG(FATAL) << "Unexpected path route on the PhiRegsBBBagNode::RemoveLoop().";
          }
        }

        // All the moved_bags in the loop should be deleted from the parents and children of the target_bag.
        // Assume that added parents and children are the true bags.
        for (auto &deleted_bag : deleted_bags) {
          target_bag->parents.erase(deleted_bag);
          target_bag->children.erase(deleted_bag);
        }
        target_bag->parents.erase(target_bag);
        target_bag->children.erase(target_bag);

        // re-search this target_bag
        visited.erase(target_bag);
        bag_stack.emplace_back(target_bag, pre_path, visited);
      } else {

        // push the children
        bool search_finished = true;
        for (auto __child_bag : target_bag->children) {
          auto child_bag = __child_bag->GetTrueBag();
          if (finished.contains(child_bag)) {
            continue;
          }
          CHECK(child_bag != target_bag)
              << "[Bug]: self-loop must not be included in the PhiRegsBBBagNode graph.";
          search_finished = false;
          auto child_pre_path = pre_path;
          auto child_visited = visited;
          child_pre_path.push_back(target_bag);
          child_visited.insert(target_bag);
          bag_stack.emplace_back(child_bag, child_pre_path, child_visited);
        }

        // finish the target_bag if all children are finished.
        if (search_finished) {
          finished.insert(target_bag);
        }
      }
    }

    // Delete the bag if it is converted to the other bag.
    std::set<PhiRegsBBBagNode *> deleted_bag_set;
    for (auto [bb, bag] : bb_regs_bag_map) {
      auto target_true_bag = bag->GetTrueBag();
      if (bag != target_true_bag) {
        bb_regs_bag_map.insert_or_assign(bb, target_true_bag);
        deleted_bag_set.insert(bag);
      }
    }
    // (FIXME) should delete already needless bags.
    // for (auto deleted_bag : deleted_bag_set) {
    //   delete (deleted_bag);
    // }
  }

#if defined(OPT_DEBUG)
  // Check whether G of PhiregsBBBagNode* doesn't have loop. (for debug)
  std::vector<PhiRegsBBBagNode *> bag_stack;
  std::set<PhiRegsBBBagNode *> visited, finished;
  bag_stack.push_back(bb_regs_bag_map[root_bb]);

  while (!bag_stack.empty()) {
    auto target_bag = bag_stack.back();
    bag_stack.pop_back();
    if (finished.contains(target_bag)) {
      LOG(FATAL) << "[Bug]: Unreachable this line.";
    }
    if (visited.contains(target_bag)) {
      for (auto child : target_bag->children) {
        if (!finished.contains(child)) {
          LOG(FATAL)
              << "[Bug]: The loop was detected from the G of PhiRegsBBBagNode* after PhiRegsBBBagNode::RemoveLoop.";
        }
      }
      finished.insert(target_bag);
      continue;
    }
    visited.insert(target_bag);
    // after searching all children, re-search this target_bag.
    bag_stack.push_back(target_bag);
    for (auto child : target_bag->children) {
      if (!finished.contains(child)) {
        bag_stack.push_back(child);
      }
    }
  }

  CHECK(bag_num == finished.size())
      << "[Bug]: bag_num: " << bag_num << ", finished.size(): " << finished.size()
      << ". They should be equal.";
#endif
}

void PhiRegsBBBagNode::GetPrecedingVirtualRegsBags(llvm::BasicBlock *root_bb) {
  std::queue<PhiRegsBBBagNode *> bag_queue;
  std::unordered_map<PhiRegsBBBagNode *, std::size_t> finished_pars_map;
  std::set<PhiRegsBBBagNode *> finished_bags;
  bag_queue.push(bb_regs_bag_map[root_bb]);

  while (!bag_queue.empty()) {
    auto target_bag = bag_queue.front();
    bag_queue.pop();
    if (finished_bags.contains(target_bag)) {
      LOG(FATAL)
          << "Search algorithm is incorrect of PhiRegsBBBagNode::GetPhiReadWriteRegsBags: Unreachable.";
    }
    finished_pars_map.insert({target_bag, 0});
    if (target_bag->parents.size() == finished_pars_map[target_bag]) {
      // can finish the target_bag.
      for (auto parent_bag : target_bag->parents) {
        for (auto ecv_reg_info : parent_bag->bag_preceding_load_reg_map) {
          target_bag->bag_preceding_load_reg_map.insert(ecv_reg_info);
        }
        for (auto ecv_reg_info : parent_bag->bag_preceding_store_reg_map) {
          target_bag->bag_preceding_store_reg_map.insert(ecv_reg_info);
        }
      }
      // target_bag was finished.
      finished_bags.insert(target_bag);
      // update the finised_pars_map for all the childlen of this target_bag.
      for (auto child_bag : target_bag->children) {
        finished_pars_map.insert_or_assign(child_bag, finished_pars_map[child_bag] + 1);
      }
    }
    // push all the no finished children
    for (auto child_bag : target_bag->children) {
      if (!finished_bags.contains(child_bag)) {
        bag_queue.push(child_bag);
      }
    }
  }

  CHECK(finished_bags.size() == finished_pars_map.size() && finished_bags.size() == bag_num)
      << "Search argorithm is incorrect of PhiRegsBBBagNode::GetPhiReadWriteRegsBags: Search is insufficient.";
}

void PhiRegsBBBagNode::GetSucceedingVirtualRegsBags(llvm::BasicBlock *root_bb) {
  std::vector<PhiRegsBBBagNode *> bag_stack;
  std::unordered_map<PhiRegsBBBagNode *, std::size_t> finished_children_map;
  std::set<PhiRegsBBBagNode *> finished_bags;
  bag_stack.push_back(bb_regs_bag_map[root_bb]);

  while (!bag_stack.empty()) {
    auto target_bag = bag_stack.back();
    bag_stack.pop_back();
    if (finished_bags.contains(target_bag)) {
      LOG(FATAL)
          << "Search algorithm is incorrect of PhiRegsBBBagNode::GetPhiDerivedRegsBags: Unreachable.";
    }
    if (target_bag->children.size() == finished_children_map[target_bag]) {
      // can finish the target_bag.
      for (auto child_bag : target_bag->children) {
        for (auto ecv_reg_info : child_bag->bag_succeeding_load_reg_map) {
          target_bag->bag_succeeding_load_reg_map.insert(ecv_reg_info);
        }
      }
      // target_bag was finished.
      finished_bags.insert(target_bag);
      // update the finised_map for all the parents of this target_bag.
      // push the parent_bag if it is not finished yet.
      for (auto parent_bag : target_bag->parents) {
        finished_children_map.insert_or_assign(parent_bag, finished_children_map[parent_bag] + 1);
        if (!finished_bags.contains(parent_bag)) {
          bag_stack.push_back(parent_bag);
        }
      }
    }
    for (auto child_bag : target_bag->children) {
      if (!finished_bags.contains(child_bag)) {
        bag_stack.push_back(child_bag);
      }
    }
  }
  CHECK(finished_bags.size() == finished_children_map.size() && finished_bags.size() == bag_num)
      << "Search argorithm is incorrect of PhiRegsBBBagNode::GetPhiDerivedRegsBags: Search is insufficient.";
}

void PhiRegsBBBagNode::GetPhiRegsBags(llvm::BasicBlock *root_bb) {
  // remove loop from the graph of PhiRegsBBBagNode.
  PhiRegsBBBagNode::RemoveLoop(root_bb);
  llvm::outs() << "RemoveLoop end.\n";
  // calculate the bag_preceding_(load | store)_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetPrecedingVirtualRegsBags(root_bb);
  llvm::outs() << "GetPhiReadWriteRegsBags end.\n";
  // calculate the bag_succeeding_load_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetSucceedingVirtualRegsBags(root_bb);
  llvm::outs() << "GetPhiDerivedReadRegsBags end.\n";
  // calculate the bag_phi_reg_map.
  std::set<PhiRegsBBBagNode *> finished;
  for (auto [_, phi_regs_bag] : bb_regs_bag_map) {
    if (!finished.contains(phi_regs_bag)) {
      auto &succeeding_load_reg_map = phi_regs_bag->bag_succeeding_load_reg_map;
      auto &preceding_load_reg_map = phi_regs_bag->bag_preceding_load_reg_map;
      auto &more_small_reg_map = succeeding_load_reg_map.size() <= preceding_load_reg_map.size()
                                     ? succeeding_load_reg_map
                                     : preceding_load_reg_map;
      phi_regs_bag->bag_req_reg_map = phi_regs_bag->bag_preceding_store_reg_map;
      for (auto &[ecv_reg, ecv_reg_class] : more_small_reg_map) {
        if (succeeding_load_reg_map.contains(ecv_reg) && preceding_load_reg_map.contains(ecv_reg)) {
          phi_regs_bag->bag_load_reg_map.insert({ecv_reg, succeeding_load_reg_map[ecv_reg]});
          phi_regs_bag->bag_req_reg_map.insert({ecv_reg, succeeding_load_reg_map[ecv_reg]});
        }
      }

      finished.insert(phi_regs_bag);
    }
  }
}

}  // namespace remill
