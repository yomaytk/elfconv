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

#include <glog/logging.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>

#include <map>
#include <set>
#include <sstream>

#include "remill/Arch/Arch.h"

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
    const Instruction &,
    std::function<void(uint64_t, DevirtualizedTargetKind)>) {

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

  auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      RecontextualizeType(func->getFunctionType(), context));

  // Handle the different module situation by declaring the trace in
  // this module to be external, with the idea that it will link to
  // another module.
  auto extern_func = module->getFunction(func->getName());
  if (!extern_func || extern_func->getFunctionType() != func_type) {
    extern_func = llvm::Function::Create(
        func_type, llvm::GlobalValue::ExternalLinkage, func->getName(), module);

  } else if (extern_func->isDeclaration()) {
    extern_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }

  return extern_func;
}

llvm::BasicBlock *TraceLifter::Impl::GetOrCreateBlock(uint64_t block_pc) {
  auto &block = blocks[block_pc];
  if (!block) {
    block = llvm::BasicBlock::Create(context, "", func);
  }
  if (indirectbr_block_map.count(block_pc) == 0 && manager.isWithinFunction(__trace_addr, block_pc))
    indirectbr_block_map[block_pc] = block;
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
  for (;fun_iter != fun_iter_e;fun_iter++) {
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
      printf("[WARNING] Couldn't read executable byte at 0x%llx\n", byte_addr);
      DLOG(WARNING) << "Couldn't read executable byte at " << std::hex
                    << byte_addr << std::dec;
      break;
    }
    inst_bytes.push_back(static_cast<char>(byte));
  }
  return !inst_bytes.empty();
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Lift(
    uint64_t addr, const char* fn_name, std::function<void(uint64_t, llvm::Function *)> callback) {
  return impl->Lift(addr, fn_name, callback);
}

// Lift one or more traces starting from `addr`.
bool TraceLifter::Impl::Lift(
    uint64_t addr, const char *fn_name, std::function<void(uint64_t, llvm::Function *)> callback) {
  // Reset the lifting state.
  trace_work_list.clear();
  inst_work_list.clear();
  blocks.clear();
  inst_bytes.clear();
  func = nullptr;
  switch_inst = nullptr;
  block = nullptr;
  indirectbr_block_map.clear();
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

    DLOG(INFO) << "Lifting trace at address " << std::hex << trace_addr
               << std::dec;

    func = get_trace_decl(trace_addr);
    blocks.clear();
    indirectbr_block_map.clear();
    indirectbr_block = nullptr;

    CHECK(func->isDeclaration());

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    arch->InitializeEmptyLiftedFunction(func);    
/* insert debug call stack function (for debug) */
#if defined(LIFT_CALLSTACK_DEBUG)
    do {
      llvm::BasicBlock &first_block = *std::prev(func->end()); /* arch->InitializeEmptyLiftedFunction(func) generates first block */
      llvm::IRBuilder<> __debug_ir(&first_block);
      auto _debug_call_stack_fn = module->getFunction(debug_call_stack_name);
      if (!_debug_call_stack_fn) {
        printf("[ERROR] debug_pc is undeclared.\n");
        abort();
      }
      __debug_ir.CreateCall(_debug_call_stack_fn);
    } while (false);
#endif

    /* add basic block for initializing VMA_S and VMA_E */
    auto vma_bb = llvm::BasicBlock::Create(context, "VMA_INIT", func);
    const uint64_t vma_e = manager.GetFuncVMA_E(trace_addr);
    llvm::IRBuilder<> vma_ir(vma_bb);
    auto vma_s_ref = LoadVMASRef(vma_bb);
    auto vma_e_ref = LoadVMAERef(vma_bb);
    vma_ir.CreateStore(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr), vma_s_ref);
    vma_ir.CreateStore(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), vma_e), vma_e_ref);

    auto state_ptr = NthArgument(func, kStatePointerArgNum);

    if (auto entry_block = &(func->front())) {
      auto pc = LoadProgramCounterArg(func);
      auto [next_pc_ref, next_pc_ref_type] =
          this->arch->DefaultLifter(*this->intrinsics)
              ->LoadRegAddress(entry_block, state_ptr, kNextPCVariableName);

      // Initialize `NEXT_PC`.
      (void) new llvm::StoreInst(pc, next_pc_ref, entry_block);

      // Branch to the VMA_INIT basic block.
      llvm::BranchInst::Create(vma_bb, entry_block);
    }

    CHECK(inst_work_list.empty());
    inst_work_list.insert(trace_addr);

    // Decode instructions. 
    while (!inst_work_list.empty()) {
      const auto inst_addr = PopInstructionAddress();

      block = GetOrCreateBlock(inst_addr);
      switch_inst = nullptr;
      if (indirectbr_block_map.count(inst_addr) == 0 && manager.isWithinFunction(trace_addr, inst_addr))
        indirectbr_block_map[inst_addr] = block;
      if (!vma_bb->getTerminator())
        vma_ir.CreateBr(block);

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
      std::ignore = arch->DecodeInstruction(inst_addr, inst_bytes, inst, this->arch->CreateInitialContext());

      auto lift_status =
          inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr);
      if (kLiftedInstruction != lift_status) {
        AddTerminatingTailCall(block, intrinsics->error, *intrinsics);
        continue;
      }
      /* append debug pc function */
      do {
        if (control_flow_debug_list.contains(trace_addr) && control_flow_debug_list[trace_addr]) {
          llvm::IRBuilder<> __debug_ir(block);
          auto _debug_pc_fn = module->getFunction(debug_pc_name);
          if (!_debug_pc_fn) {
            printf("[ERROR] debug_pc is undeclared.\n");
            abort();
          }
          __debug_ir.CreateCall(_debug_pc_fn);
        }
      } while (false);
      // Handle lifting a delayed instruction.
      auto try_delay = arch->MayHaveDelaySlot(inst);
      if (try_delay) {
        delayed_inst.Reset();
        if (!ReadInstructionBytes(inst.delayed_pc) ||
            !arch->DecodeDelayedInstruction(
                inst.delayed_pc, inst_bytes, delayed_inst,
                this->arch->CreateInitialContext())) {
          LOG(ERROR) << "Couldn't read delayed inst "
                     << delayed_inst.Serialize();
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
        if (!arch->NextInstructionIsDelayed(inst, delayed_inst,
                                            on_branch_taken_path)) {
          return;
        }
        lift_status = delayed_inst.GetLifter()->LiftIntoBlock(
            delayed_inst, into_block, state_ptr, true /* is_delayed */);
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
          if (manager.isWithinFunction(trace_addr, inst_addr + sizeof(uint32_t))) {
            llvm::BranchInst::Create(GetOrCreateNextBlock(), block);
          } else {
            llvm::IRBuilder<> _nop_ir(block);
            const auto [mem_ptr_ref, mem_ptr_ref_type] =
              this->arch->DefaultLifter(*this->intrinsics)
                ->LoadRegAddress(block, state_ptr, kMemoryVariableName);
            _nop_ir.CreateRet(_nop_ir.CreateLoad(mem_ptr_ref_type, mem_ptr_ref));
          }
            
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
          const auto fall_through_block =
              llvm::BasicBlock::Create(context, "", func);

          const auto ret_pc_ref =
              LoadReturnProgramCounterRef(fall_through_block);
          const auto next_pc_ref =
              LoadNextProgramCounterRef(fall_through_block);
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

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);

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
          if (manager.isWithinFunction(trace_addr, inst_addr + sizeof(uint32_t))) {
            const auto ret_pc_ref = LoadReturnProgramCounterRef(block);
            const auto next_pc_ref = LoadNextProgramCounterRef(block);
            ir.CreateStore(ir.CreateLoad(word_type, ret_pc_ref), next_pc_ref);
            ir.CreateBr(GetOrCreateBranchNotTakenBlock());
          } else {
            const auto [mem_ptr_ref, mem_ptr_ref_type] =
              this->arch->DefaultLifter(*this->intrinsics)
                ->LoadRegAddress(block, state_ptr, kMemoryVariableName);
            ir.CreateRet(ir.CreateLoad(mem_ptr_ref_type, mem_ptr_ref));
          }

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

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);

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
          llvm::BranchInst::Create(do_hyper_call, GetOrCreateNextBlock(),
                                   LoadBranchTaken(block), block);
          block = do_hyper_call;
          AddCall(block, intrinsics->async_hyper_call, *intrinsics);
          goto check_call_return;
        }

        check_call_return:
          do {
            // auto pc = LoadProgramCounter(block, *intrinsics);
            auto next_pc = LoadNextProgramCounter(block, *intrinsics);
            auto ret_pc =
                llvm::ConstantInt::get(intrinsics->pc_type, inst.next_pc);

            llvm::IRBuilder<> ir(block);
            auto eq = ir.CreateICmpEQ(next_pc, ret_pc);
            auto unexpected_ret_pc =
                llvm::BasicBlock::Create(context, "", func);
            ir.CreateCondBr(eq, GetOrCreateNextBlock(), unexpected_ret_pc);
            AddTerminatingTailCall(unexpected_ret_pc, intrinsics->missing_block,
                                   *intrinsics);
          } while (false);
          break;

        case Instruction::kCategoryFunctionReturn:
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(block, intrinsics->function_return,
                                 *intrinsics);
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

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);

          AddTerminatingTailCall(taken_block, intrinsics->function_return,
                                 *intrinsics);
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
            auto new_not_taken_block =
                llvm::BasicBlock::Create(context, "", func);

            try_add_delay_slot(true, new_taken_block);
            try_add_delay_slot(false, new_not_taken_block);

            llvm::BranchInst::Create(taken_block, new_taken_block);
            llvm::BranchInst::Create(not_taken_block, new_not_taken_block);

            taken_block = new_taken_block;
            not_taken_block = new_not_taken_block;
          }

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);
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

          llvm::BranchInst::Create(taken_block, not_taken_block,
                                   LoadBranchTaken(block), block);

          AddTerminatingTailCall(taken_block, intrinsics->jump, *intrinsics);
          block = orig_not_taken_block;
          continue;
        }
      }

      if (manager.isWithinFunction(trace_addr, inst_addr + sizeof(uint32_t)))
        GetOrCreateNextBlock();

    }

    /* indirect br block for BR instruction */
    if (indirectbr_block) {
      if (((vma_e - trace_addr) >> 2) != indirectbr_block_map.size()) {
        printf("[WARNING] func: %s, vma_e: 0x%lx, trace_addr: 0x%lx, lhs: %ld, rhs: %ld\n", func->getName().str().c_str(), vma_e, trace_addr, ((vma_e - trace_addr) >> 2), indirectbr_block_map.size());
        for(auto &[target_addr, _] : indirectbr_block_map)  printf("addr: 0x%lx\n", target_addr);
      }
      // CHECK_EQ((vma_e - trace_addr) >> 2, indirectbr_block_map.size());
      std::vector<llvm::Constant*> bb_addrs;
      for (auto &[_, _bb] : indirectbr_block_map)
        bb_addrs.push_back(llvm::BlockAddress::get(func, _bb));
      auto bb_addrs_ty = llvm::ArrayType::get(llvm::Type::getInt64PtrTy(context), bb_addrs.size());
      auto ir_bb_addrs = new llvm::GlobalVariable(
        *module,
        bb_addrs_ty,
        false,
        llvm::GlobalValue::InternalLinkage,
        llvm::ConstantArray::get(bb_addrs_ty, bb_addrs),
        func->getName() + ".bb_addrs"
      );
      auto br_to_within_func_block = llvm::BasicBlock::Create(context, "", func);
      auto br_to_func_block = llvm::BasicBlock::Create(context, "", func);
      /* indirectbr_block */
      llvm::IRBuilder<> ir_1(indirectbr_block);
      auto br_addr = ir_1.CreateLoad(llvm::Type::getInt64Ty(context), LoadIndirectBrAddrRef(indirectbr_block));
      auto vma_s_reg = ir_1.CreateLoad(llvm::Type::getInt64Ty(context), LoadVMASRef(indirectbr_block));
      auto vma_e_reg = ir_1.CreateLoad(llvm::Type::getInt64Ty(context), LoadVMAERef(indirectbr_block));
      auto s_le_addr = ir_1.CreateICmpULE(/* vma_s <=? br_addr */
        vma_s_reg,
        br_addr
      );
      auto addr_lt_e = ir_1.CreateICmpULT(/* br_addr <? vma_e */
        br_addr,
        vma_e_reg
      );
      auto s_addr_e = ir_1.CreateAnd(s_le_addr, addr_lt_e);
      ir_1.CreateCondBr(s_addr_e, br_to_within_func_block, br_to_func_block);
      /* br_to_within_func_block */
      llvm::IRBuilder<> ir_2(br_to_within_func_block);
      auto b_id = ir_2.CreateLShr(ir_2.CreateSub(br_addr, vma_s_reg), 2); /* b_id = (br_addr - vma_s) >> 2 */
      auto target_bb_ptr = ir_2.CreateInBoundsGEP(
        bb_addrs_ty, 
        ir_bb_addrs, 
        {ir_2.getInt32(0), b_id}
      );
      auto indirect_br_i = ir_2.CreateIndirectBr(target_bb_ptr, bb_addrs.size());
      for (auto &[_vma, _block] : indirectbr_block_map)
        indirect_br_i->addDestination(_block);
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
