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
      printf("[WARNING] Couldn't read executable byte at 0x%lx\n", byte_addr);
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
  switch_inst = nullptr;
  block = nullptr;
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
    indirectbr_block = nullptr;
    lift_all_insn = false;

#if defined(TEST_MODE)
    llvm::BranchInst *pre_check_inst_branch = nullptr; /* for lifting test */
#endif

    CHECK(func->isDeclaration());

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
      auto _debug_call_stack_fn = module->getFunction(debug_call_stack_name);
      if (!_debug_call_stack_fn) {
        printf("[ERROR] debug_call_stack_fn is undeclared.\n");
        abort();
      }
      __debug_ir.CreateCall(_debug_call_stack_fn);
    } while (false);
#endif

    /* add basic block for initializing VMA_S and VMA_E */
    auto vma_bb = llvm::BasicBlock::Create(context, "L_vma_init", func);
    const uint64_t vma_e = manager.GetFuncVMA_E(trace_addr);
    llvm::IRBuilder<> vma_ir(vma_bb);
    auto vma_s_ref = LoadVMASRef(vma_bb);
    auto vma_e_ref = LoadVMAERef(vma_bb);
    vma_ir.CreateStore(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr),
                       vma_s_ref);
    vma_ir.CreateStore(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), vma_e), vma_e_ref);

    auto state_ptr = NthArgument(func, kStatePointerArgNum);

    if (auto entry_block = &(func->front())) {
      auto pc = LoadProgramCounterArg(func);
      auto [next_pc_ref, next_pc_ref_type] =
          this->arch->DefaultLifter(*this->intrinsics)
              ->LoadRegAddress(entry_block, state_ptr, kNextPCVariableName);

      // Initialize `NEXT_PC`.
      (void) new llvm::StoreInst(pc, next_pc_ref, entry_block);

      // Branch to the `L_vma_init`.
      llvm::BranchInst::Create(vma_bb, entry_block);
    }

    CHECK(inst_work_list.empty());
    inst_work_list.insert(trace_addr);

  // Decode instructions.
  inst_lifting_start:
    while (!inst_work_list.empty()) {
      const auto inst_addr = PopInstructionAddress();

      block = GetOrCreateBlock(inst_addr);
      switch_inst = nullptr;
      if (lifted_block_map.count(inst_addr) == 0)
        lifted_block_map[inst_addr] = block;

/* in the test mode, generates the basic block for initializing state and memory */
#if defined(TEST_MODE)
      /* 
        L_vma_init --> L_pre_vm --> inst block
      */
      auto pre_test_vm_bb = PreVirtualMachineForInsnTest(inst_addr, manager, pre_check_inst_branch);
      if (!vma_bb->getTerminator())
        vma_ir.CreateBr(pre_test_vm_bb);
      llvm::BranchInst::Create(block, pre_test_vm_bb);
#else
      if (!vma_bb->getTerminator())
        vma_ir.CreateBr(block);
#endif
      // We have already lifted this instruction block.
      if (!block->empty()) {
        continue;
      }

      // Check to see if this instruction corresponds with an existing
      // trace head, and if so, tail-call into that trace directly without
      // decoding or lifting the instruction.
      if (inst_addr != trace_addr) {
        if (auto inst_as_trace = get_trace_decl(inst_addr)) {
          AddTerminatingTailCall(block, inst_as_trace, *intrinsics);
          continue;
        }
      }

      // No executable bytes here.
      if (!ReadInstructionBytes(inst_addr)) {
        AddTerminatingTailCall(block, intrinsics->missing_block, *intrinsics);
        continue;
      }

      inst.Reset();

      // TODO(Ian): not passing context around in trace lifter
      std::ignore =
          arch->DecodeInstruction(inst_addr, inst_bytes, inst, this->arch->CreateInitialContext());

      // Lift instruction
      auto lift_status =
          control_flow_debug_list.contains(trace_addr) && control_flow_debug_list[trace_addr]
              ? inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr, inst_addr)
              : inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr, UINT64_MAX);

      if (kLiftedInstruction != lift_status) {
        AddTerminatingTailCall(block, intrinsics->error, *intrinsics);
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
          AddTerminatingTailCall(block, intrinsics->error, *intrinsics);
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
        lift_status = delayed_inst.GetLifter()->LiftIntoBlock(delayed_inst, into_block, state_ptr,
                                                              true /* is_delayed */);
        if (kLiftedInstruction != lift_status) {
          AddTerminatingTailCall(block, intrinsics->error, *intrinsics);
        }
      };

      // Connect together the basic blocks.
      switch (inst.category) {
        case Instruction::kCategoryInvalid:
        case Instruction::kCategoryError:
          AddTerminatingTailCall(block, intrinsics->error, *intrinsics);
          break;

        case Instruction::kCategoryNormal:
        case Instruction::kCategoryNoOp:
          llvm::BranchInst::Create(GetOrCreateNextBlock(), block);
          break;

        // Direct jumps could either be local or could be tail-calls. In the
        // case of a tail call, we'll assume that the trace manager contains
        // advanced knowledge of this, and so when we go to make a block for
        // the targeted instruction, we'll either tail call to the target
        // trace, or we'll just extend out the current trace. Either way, no
        // sacrifice in correctness is made.
        case Instruction::kCategoryDirectJump:
          try_add_delay_slot(true, block);
          llvm::BranchInst::Create(GetOrCreateBranchTakenBlock(), block);
          break;

        /* case: BR instruction */
        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);
          /* indirectbr entry block */
          indirectbr_block = GetOrCreateIndirectJmpBlock();
          llvm::IRBuilder<> ir(block);
          /* store indirectbr addr to `INDIRECT_BR_ADDR` */
          llvm::Value *indirect_br_addr = FindIndirectBrAddress(block);
          auto braddr_key_ref = LoadIndirectBrAddrRef(block);
          (void) new llvm::StoreInst(indirect_br_addr, braddr_key_ref, block);
          /* jmp to indirectbr block */
          ir.CreateBr(indirectbr_block);
          break;
        }

        case Instruction::kCategoryAsyncHyperCall:
          AddCall(block, intrinsics->async_hyper_call, *intrinsics);
          goto check_call_return;

        case Instruction::kCategoryIndirectFunctionCall: {
          try_add_delay_slot(true, block);
          const auto fall_through_block = llvm::BasicBlock::Create(context, "", func);

          const auto ret_pc_ref = LoadReturnProgramCounterRef(fall_through_block);
          const auto next_pc_ref = LoadNextProgramCounterRef(fall_through_block);
          llvm::IRBuilder<> ir(fall_through_block);
          ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
          ir.CreateBr(GetOrCreateBranchNotTakenBlock());

          AddCall(block, intrinsics->function_call, *intrinsics);
          llvm::BranchInst::Create(fall_through_block, block);
          block = fall_through_block;
          continue;
        }

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

            llvm::BranchInst::Create(orig_not_taken_block, not_taken_block);
          }

          llvm::BranchInst::Create(taken_block, not_taken_block, LoadBranchTaken(block), block);

          AddCall(taken_block, intrinsics->function_call, *intrinsics);

          const auto ret_pc_ref = LoadReturnProgramCounterRef(taken_block);
          const auto next_pc_ref = LoadNextProgramCounterRef(taken_block);
          llvm::IRBuilder<> ir(taken_block);
          ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
          ir.CreateBr(orig_not_taken_block);
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
            AddCall(block, target_trace, *intrinsics);
          }
          llvm::IRBuilder<> ir(block);
          const auto ret_pc_ref = LoadReturnProgramCounterRef(block);
          const auto next_pc_ref = LoadNextProgramCounterRef(block);
          ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
          ir.CreateBr(GetOrCreateBranchNotTakenBlock());
          continue;
        }

        case Instruction::kCategoryConditionalDirectFunctionCall: {
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

            llvm::BranchInst::Create(orig_not_taken_block, not_taken_block);
          }

          llvm::BranchInst::Create(taken_block, not_taken_block, LoadBranchTaken(block), block);

          trace_work_list.insert(inst.branch_taken_pc);
          auto target_trace = get_trace_decl(inst.branch_taken_pc);

          AddCall(taken_block, intrinsics->function_call, *intrinsics);
          AddCall(taken_block, target_trace, *intrinsics);

          const auto ret_pc_ref = LoadReturnProgramCounterRef(taken_block);
          const auto next_pc_ref = LoadNextProgramCounterRef(taken_block);
          llvm::IRBuilder<> ir(taken_block);
          ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
          ir.CreateBr(orig_not_taken_block);
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
          llvm::BranchInst::Create(do_hyper_call, GetOrCreateNextBlock(), LoadBranchTaken(block),
                                   block);
          block = do_hyper_call;
          AddCall(block, intrinsics->async_hyper_call, *intrinsics);
          goto check_call_return;
        }

        check_call_return:
          do {
            // auto pc = LoadProgramCounter(block, *intrinsics);
            auto next_pc = LoadNextProgramCounter(block, *intrinsics);
            auto ret_pc = llvm::ConstantInt::get(intrinsics->pc_type, inst.next_pc);

            llvm::IRBuilder<> ir(block);
            auto eq = ir.CreateICmpEQ(next_pc, ret_pc);
            auto unexpected_ret_pc = llvm::BasicBlock::Create(context, "", func);
            // WARNING: if there is no next instruction in this function, this create the branch instruction
            // to the invalid instruction of next address.
            ir.CreateCondBr(eq, GetOrCreateNextBlock(), unexpected_ret_pc);
            AddTerminatingTailCall(unexpected_ret_pc, intrinsics->missing_block, *intrinsics);
          } while (false);
          break;

        case Instruction::kCategoryFunctionReturn:
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(block, intrinsics->function_return, *intrinsics);
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

            llvm::BranchInst::Create(orig_not_taken_block, not_taken_block);
          }

          llvm::BranchInst::Create(taken_block, not_taken_block, LoadBranchTaken(block), block);

          AddTerminatingTailCall(taken_block, intrinsics->function_return, *intrinsics);
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

            llvm::BranchInst::Create(taken_block, new_taken_block);
            llvm::BranchInst::Create(not_taken_block, new_not_taken_block);

            taken_block = new_taken_block;
            not_taken_block = new_not_taken_block;
          }

          llvm::BranchInst::Create(taken_block, not_taken_block, LoadBranchTaken(block), block);
          break;
        }
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

            llvm::BranchInst::Create(orig_not_taken_block, not_taken_block);
          }

          llvm::BranchInst::Create(taken_block, not_taken_block, LoadBranchTaken(block), block);

          AddTerminatingTailCall(taken_block, intrinsics->jump, *intrinsics);
          block = orig_not_taken_block;
          continue;
        }
      }
/* check the state of virtual machine */
#if defined(TEST_MODE)
      AddTestFailedBlock();
      if (Instruction::kCategoryFunctionReturn != inst.category)
        pre_check_inst_branch = CheckVirtualMahcineForInsnTest(inst_addr, manager);
#endif
    }

    /* if func includes BR instruction, it is necessary to lift all instructions of the
       * func. */
    if (!lift_all_insn && indirectbr_block) {
      CHECK(inst_work_list.empty());
      for (uint64_t insn_vma = trace_addr; insn_vma < vma_e; insn_vma += 4)
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
      auto br_vma =
          ir_1.CreateLoad(llvm::Type::getInt64Ty(context), LoadIndirectBrAddrRef(indirectbr_block));
      auto fn_vma = ir_1.CreateLoad(llvm::Type::getInt64Ty(context), LoadVMASRef(indirectbr_block));
      /* calculate the target block address */
      auto g_get_jmp_helper_fn =
          module->getFunction(g_get_jmp_block_address_func_name); /* return type: uint64_t* */
      CHECK(g_get_jmp_helper_fn);
      auto target_bb_i64 = ir_1.CreateCall(g_get_jmp_helper_fn, {fn_vma, br_vma});
      auto indirect_br_i = ir_1.CreateIndirectBr(
          ir_1.CreatePointerCast(target_bb_i64, llvm::Type::getInt64PtrTy(context)),
          bb_addrs.size());
      for (auto &[_vma, _block] : lifted_block_map)
        indirect_br_i->addDestination(_block);
      indirect_br_i->addDestination(br_to_func_block);
      /* br_to_func_block */
      AddTerminatingTailCall(br_to_func_block, intrinsics->jump, *intrinsics);
    }

    for (auto &block : *func) {
      if (!block.getTerminator()) {
        AddTerminatingTailCall(&block, intrinsics->missing_block, *intrinsics);
      }
    }

    callback(trace_addr, func);
    manager.SetLiftedTraceDefinition(trace_addr, func);
  }

  return true;
}

}  // namespace remill
