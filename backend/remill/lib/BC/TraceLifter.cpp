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
#include "remill/BC/ABI.h"
#include "remill/BC/InstructionLifter.h"

#include <glog/logging.h>
#include <iostream>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Instruction.h>
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

namespace remill {

#if defined(OPT_REAL_REGS_DEBUG)
#  define DEBUG_PC_AND_REGISTERS(...) InsertDebugVmaAndRegisters(__VA_ARGS__)
#  define VAR_NAME(ecv_reg, ecv_reg_class) \
    ecv_reg.GetRegName(ecv_reg_class) + "_" + to_string(phi_val_order++)
#else
#  define DEBUG_PC_AND_REGISTERS(...)
#  define VAR_NAME(ecv_reg, ecv_reg_class) \
    ecv_reg.GetRegName(ecv_reg_class) + "_" + to_string(phi_val_order++)
#endif

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
  if (lifted_block_map.count(block_pc) == 0) {
    lifted_block_map[block_pc] = block;
    rev_lifted_block_map[block] = block_pc;
  }
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
llvm::GlobalVariable *
TraceLifter::Impl::SetGblArrayIr(llvm::Type *, std::vector<llvm::Constant *> &, const llvm::Twine &,
                                 bool, llvm::GlobalValue::LinkageTypes) {
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
  virtual_regs_opt->bb_parents[dst_bb].insert(src_bb);
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

TraceLifter::TraceLifter(const Arch *arch_, TraceManager *manager_, LiftConfig lift_config_)
    : impl(new Impl(arch_, manager_, lift_config_)) {}

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
  rev_lifted_block_map.clear();
  lift_all_insn = false;
  br_bb = nullptr;
  far_jump_bb = nullptr;
  _fb_near_jump_bb = nullptr;
  bb_addrs.clear();
  bb_addr_vmas.clear();
  inst.Reset();
  delayed_inst.Reset();

  // Get a trace head that the manager knows about, or that we
  // will eventually tell the trace manager about.
  auto get_trace_decl = [=](uint64_t trace_addr) -> llvm::Function * {
    if (!manager.isFunctionEntry(trace_addr)) {
      return nullptr;
    }

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

    // Already lifted.
    func = GetLiftedTraceDefinition(trace_addr);
    if (func) {
      continue;
    }

    DLOG(INFO) << "Lifting trace at address " << std::hex << trace_addr << std::dec;

    func = get_trace_decl(trace_addr);
    blocks.clear();
    lifted_block_map.clear();
    rev_lifted_block_map.clear();
    br_blocks.clear();
    br_bb = nullptr;
    lift_all_insn = false;

    inst_nums_in_bb.clear();

    lifted_funcs.insert(func);

    CHECK(func->isDeclaration());
    virtual_regs_opt = new VirtualRegsOpt(func, this, trace_addr);
    virtual_regs_opt->func_name = func->getName().str();
    VirtualRegsOpt::func_v_r_opt_map.insert({func, virtual_regs_opt});

    // Fill in the function, and make sure the block with all register
    // variables jumps to the block that will contain the first instruction
    // of the trace.
    arch->InitializeEmptyLiftedFunction(func);

    state_ptr = NthArgument(func, kStatePointerArgNum);
    runtime_ptr = NthArgument(func, kRuntimePointerArgNum);

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

      // always be vrp_opt_mode.
      // if (!vrp_opt_mode) {
      //   noopt_all_vma_bbs.push_back({inst_addr, llvm::BlockAddress::get(func, block)});
      // }

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
      // set the specified config of lifting.
      inst.lift_config = lift_config;

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
        AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr,
                               llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
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
          AddTerminatingTailCall(
              block, intrinsics->error, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
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
        //   AddTerminatingTailCall(block, intrinsics->error, *intrinsics, trace_addr, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
        // }
      };

      // Connect together the basic blocks.
      switch (inst.category) {
        case Instruction::kCategoryInvalid:
        case Instruction::kCategoryError:
          AddTerminatingTailCall(
              block, intrinsics->error, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
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
          br_bb = GetOrCreateIndirectJmpBlock();
          if (!virtual_regs_opt->bb_reg_info_node_map.contains(br_bb)) {
            virtual_regs_opt->bb_reg_info_node_map.insert(
                {br_bb, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
          }
          br_blocks.push_back({block, FindIndirectBrAddress(block)});
          /* jmp to indirectbr block */
          DirectBranchWithSaveParents(br_bb, block);
          break;
        }

        case Instruction::kCategoryAsyncHyperCall:
          // In the current implementation, __remill_async_hyper_call is empty.
          // AddCall(block, intrinsics->async_hyper_call, *intrinsics,
          //         llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst_addr));
          // if the next instruction is not included in this function, jumping to it is illegal.
          // Therefore, we force to return at this block because we assume that this instruction don't come back to.
          if (inst.lift_config.fork_emulation_emcc_fiber) {
            lift_or_system_calling_bbs.insert(GetOrCreateNextBlock());
          }
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

          llvm::IRBuilder<> ir(block);
          llvm::Value *t_func_addr = FindIndirectBrAddress(block);

          if (inst.lift_config.fork_emulation_emcc_fiber) {
            // call "_ecv_save_call_history"
            llvm::Value *cur_func_addr =
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr);
            llvm::Value *t_ret_addr =
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.next_pc);
            ir.CreateCall(module->getFunction("_ecv_save_call_history"),
                          {runtime_ptr, cur_func_addr, t_ret_addr});
            lift_or_system_calling_bbs.insert(GetOrCreateNextBlock());
          }

          // indirect jump address is value of %Xzzz just before
          auto lifted_func_call =
              AddCall(ir, block, intrinsics->function_call, *intrinsics, t_func_addr);

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
          if (!target_trace) {
            auto rest_fun_name = manager.AddRestDisasmFunc(inst.branch_taken_pc);
            target_trace = arch->DeclareLiftedFunction(rest_fun_name, module);
          }
          // It may be unnecessary to check this condition.
          // if (inst.branch_not_taken_pc != inst.branch_taken_pc)
          trace_work_list.insert(inst.branch_taken_pc);
          llvm::IRBuilder<> ir(block);

          if (inst.lift_config.fork_emulation_emcc_fiber) {
            // call "_ecv_save_call_history"
            llvm::Value *cur_func_addr =
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr);
            llvm::Value *t_ret_addr =
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.next_pc);
            ir.CreateCall(module->getFunction("_ecv_save_call_history"),
                          {runtime_ptr, cur_func_addr, t_ret_addr});
            lift_or_system_calling_bbs.insert(GetOrCreateNextBlock());
          }

          // call lifted function
          llvm::CallInst *lifted_func_call = AddCall(
              ir, block, target_trace, *intrinsics,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.branch_taken_pc));
          virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);

          DirectBranchWithSaveParents(GetOrCreateBranchNotTakenBlock(), block);

          continue;
        }

        case Instruction::kCategoryConditionalDirectFunctionCall: {
          CHECK(ArchName::kArchAArch64LittleEndian != arch->arch_name)
              << "`Instruction::kCategoryConditionalDirectFunctionCall` instruction exists in aarch64?";
          LOG(FATAL);
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

    // if the func includes intraprocedural indirect jump instruction, it is necessary to lift all instructions of the func.
    if (br_bb && !lift_all_insn /* always be vrp_opt_mode || !vrp_opt_mode*/) {
      for (uint64_t insn_vma = trace_addr; insn_vma < manager.GetFuncVMA_E(trace_addr);
           insn_vma += 4) {
        if (lifted_block_map.count(insn_vma) == 0) {
          inst_work_list.insert(insn_vma);
        }
      }
      lift_all_insn = true;
      goto inst_lifting_start;
    }

    if (inst.lift_config.fork_emulation_emcc_fiber) {
      FiberContextSwitchMain(trace_addr);
    } else if (br_bb) {
      GenIndirectJumpCode(trace_addr);
    } else {
      opt_target_funcs.insert(func);
    }

    // Add `store` the every result of calling semantics function to State structure.
    if (br_bb || lift_config.norm_mode) {
      AddStoreForAllSemantics();
    }

    // Add terminator to the all basic block to avoid error on CFG flat
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

void TraceLifter::Impl::GenIndirectJumpCode(uint64_t trace_addr) {

  auto u64ty = llvm::Type::getInt64Ty(context);
  auto u64ptrty = llvm::Type::getInt64PtrTy(context);

  // Complete br_bb definition.
  llvm::IRBuilder<> br_ir(br_bb);

  // IR to get jump target VMA `from` every BR basic block.
  // i.e. t_vma_phi = phi i64 [ %t_vma1, $%br_bb_1 ], [ %t_vma2, %br_bb_2 ], [ %t_vma3, %br_bb_3 ], ...
  auto t_vma_phi = br_ir.CreatePHI(u64ty, br_blocks.size());
  for (auto &[br_bb, t_vma] : br_blocks) {
    t_vma_phi->addIncoming(t_vma, br_bb);
    virtual_regs_opt->bb_parents[br_bb].insert(br_bb);
  }

  // IR to get actual basic block address using `t_vma_phi`.
  // i.e. t_bb_ptr = call _ecv_get_indirectbr_block_address (t_vma_phi);
  //      indirectbr ptr <t_bb_ptr>, [ %L1, %L2, ..., %Ln ]
  auto get_bbptr_func =
      module->getFunction(g_get_indirectbr_block_address_func_name); /* return type: uint64_t* */
  auto t_bb_ptr = br_ir.CreateCall(
      get_bbptr_func, {runtime_ptr, llvm::ConstantInt::get(u64ty, trace_addr), t_vma_phi});
  auto br_jump =
      br_ir.CreateIndirectBr(br_ir.CreatePointerCast(t_bb_ptr, u64ptrty), bb_addrs.size());
  for (auto &[_, lifted_block] : lifted_block_map) {
    br_jump->addDestination(lifted_block);
  }

  // Define L_far_jump.
  // `L_far_jump` is necessary in the case that the target VMA indicates the other function address.
  // (e.g. x7 indicates the other function address for `BR x7`)
  far_jump_bb = llvm::BasicBlock::Create(context, "L_far_jump", func);
  // `BR` instruction may jump to `L_far_jump`
  br_jump->addDestination(far_jump_bb);
  // Add terminator to `L_far_jump`.
  AddTerminatingTailCall(far_jump_bb, intrinsics->jump, *intrinsics,
                         /* fn_vma is used only for debug*/ -1, t_vma_phi);

  // Update cache for `L_far_jump` block.
  virtual_regs_opt->bb_parents.insert({far_jump_bb, {br_bb}});
  virtual_regs_opt->bb_reg_info_node_map.insert(
      {far_jump_bb, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
  // Add basic block address of far_jump_bb to the grobal data array.
  bb_addrs.push_back(llvm::BlockAddress::get(func, far_jump_bb));
  bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), UINT64_MAX));

  // Define Basic Block address as global data (necessary for AArch64 `BR` instruction).
  for (auto &[_vma, _bb] : lifted_block_map) {
    bb_addrs.push_back(llvm::BlockAddress::get(func, _bb));
    bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), _vma));
  }

  // Append the list to the global data.
  auto g_bb_addrs =
      SetGblArrayIr(llvm::Type::getInt64PtrTy(context), bb_addrs, func->getName() + ".bb_addrs");
  auto g_bb_addr_vmas = SetGblArrayIr(llvm::Type::getInt64Ty(context), bb_addr_vmas,
                                      func->getName() + ".bb_addr_vmas");
  manager.g_block_address_ptrs_array.push_back(
      llvm::ConstantExpr::getBitCast(g_bb_addrs, llvm::Type::getInt64PtrTy(context)));
  manager.g_block_address_vmas_array.push_back(
      llvm::ConstantExpr::getBitCast(g_bb_addr_vmas, llvm::Type::getInt64PtrTy(context)));
  manager.g_block_address_size_array.push_back(
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), bb_addrs.size()));
  manager.g_block_address_fn_vma_array.push_back(
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
}

void TraceLifter::Impl::AddStoreForAllSemantics() {

  // Add StoreInst for the every semantics functions.
  // if the lifted function is `br_bb` or `!vrp_opt_mode`, we must store the return values of semantics functions to the registers.
  auto &inst_lifter = inst.GetLifter();
  for (auto &bb : *func) {
    auto t_inst = &*bb.begin();
    auto t_bb_reg_info_node = virtual_regs_opt->bb_reg_info_node_map[&bb];
    if (t_bb_reg_info_node == nullptr) {
      continue;
    }

    while (t_inst) {

      auto call_inst = llvm::dyn_cast<llvm::CallInst>(t_inst);
      auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>(t_inst);

      t_inst = t_inst->getNextNode();

      if (!call_inst && !ret_inst) {
        continue;
      }

      // `store` the result of calling semantics function.
      if (t_bb_reg_info_node->sema_call_written_reg_map.contains(call_inst)) {
#if defined(OPT_REAL_REGS_DEBUG)
        auto debug_llvmir_u64_fn = module->getFunction("debug_llvmir_u64value");
        auto sema_pc = t_bb_reg_info_node->sema_func_pc_map.at(call_inst);
        llvm::CallInst::Create(debug_llvmir_u64_fn,
                               {llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), sema_pc)},
                               "", call_inst);
#endif
        auto &write_regs = t_bb_reg_info_node->sema_call_written_reg_map.at(call_inst);
        auto call_nexti = call_inst->getNextNode();

        if (write_regs.size() == 1) {
          auto [str_er, str_erc] = write_regs[0];
          if (str_er.number != IGNORE_WRITE_TO_WZR_ORDER &&
              str_er.number != IGNORE_WRITE_TO_XZR_ORDER) {
            inst_lifter->StoreRegValueBeforeInst(
                &bb, state_ptr, str_er.GetRegName(str_erc),
                virtual_regs_opt->CastFromInst(
                    str_er, call_inst, virtual_regs_opt->ERC2WholeLLVMTy(str_er), call_nexti),
                call_nexti);
          }
        } else if (write_regs.size() > 1) {
          for (uint32_t i = 0; i < write_regs.size(); i++) {
            llvm::Instruction *from_extracted_inst;
            auto [str_er, str_erc] = write_regs[i];
            if (str_er.number == IGNORE_WRITE_TO_WZR_ORDER ||
                str_er.number == IGNORE_WRITE_TO_XZR_ORDER) {
              continue;
            }
            if (llvm::dyn_cast<llvm::StructType>(call_inst->getType()) ||
                llvm::dyn_cast<llvm::ArrayType>(call_inst->getType())) {
              from_extracted_inst = llvm::ExtractValueInst::Create(call_inst, {i}, "", call_nexti);
            } else if (isu128v2Ty(context, call_inst->getType())) {
              from_extracted_inst = llvm::ExtractElementInst::Create(
                  call_inst, llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), i), "",
                  call_nexti);
            } else {
              LOG(FATAL) << "[Bug] call_inst: " << LLVMThingToString(call_inst)
                         << "pc: " << Sema_func_vma_map.at(call_inst);
            }
            inst_lifter->StoreRegValueBeforeInst(
                &bb, state_ptr, str_er.GetRegName(str_erc),
                virtual_regs_opt->CastFromInst(str_er, from_extracted_inst,
                                               virtual_regs_opt->ERC2WholeLLVMTy(str_er),
                                               call_nexti),
                call_nexti);
          }
        }
        continue;
      }

#if !defined(SIMPLE_OPT)
      continue;
#endif

      // load and store the registers which are used between function calling and returning.
      if (virtual_regs_opt->lifted_func_caller_set.contains(call_inst)) {
        // `store` the [ X0, X1, ..., X8, SP ] before calling the lifted function.
        {
          llvm::IRBuilder<> ir1(call_inst);
          // [ X0, X1, ..., X8 ]
          for (int i = 0; i < 9; i++) {
            std::string reg_name = "X" + to_string(i);
            // store `Xi_Lc (local)` value to `Xi (global)`.
            auto [xg_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name, true);
            auto [xlc_reg_ptr, xlc_reg_type] =
                inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name);
            auto xlc_val = ir1.CreateLoad(xlc_reg_type, xlc_reg_ptr);
            ir1.CreateStore(xlc_val, xg_reg_ptr);
          }
          // SP
          auto [spg_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, "SP", true);
          auto [splc_reg_ptr, splc_reg_type] = inst_lifter->LoadRegAddress(&bb, state_ptr, "SP");
          auto splc_val = ir1.CreateLoad(splc_reg_type, splc_reg_ptr);
          ir1.CreateStore(splc_val, spg_reg_ptr);
        }

        // `load` the [ X0, X1, SP ] after calling the lifted function.
        auto call_nexti = call_inst->getNextNode();
        {
          llvm::IRBuilder<> ir(call_nexti);
          // [ X0, X1 ]
          for (int i = 0; i < 2; i++) {
            std::string reg_name = "X" + to_string(i);
            // load `Xi (global)` value to `Xi_Lc (local)`.
            auto [xlc_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name);
            auto [xg_reg_ptr, xg_reg_type] =
                inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name, true);
            auto xg_reg_val = ir.CreateLoad(xg_reg_type, xg_reg_ptr);
            ir.CreateStore(xg_reg_val, xlc_reg_ptr);
          }
          // SP
          auto [splc_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, "SP");
          auto [spg_reg_ptr, spg_reg_type] =
              inst_lifter->LoadRegAddress(&bb, state_ptr, "SP", true);
          auto spg_reg_val = ir.CreateLoad(spg_reg_type, spg_reg_ptr);
          ir.CreateStore(spg_reg_val, splc_reg_ptr);
        }
        continue;
      }

      // load and store the registers which are used for Linux system call calling.
      if (call_inst && call_inst->getCalledFunction()->getName().str() == "emulate_system_call") {
        // `store` the [ X0, ..., X5, X8 ] before calling system call.
        {
          llvm::IRBuilder<> ir(call_inst);
          // [ X0, X1, ..., X5, X8 ]
          for (int i = 0; i < 9; i++) {
            if (i == 6 || i == 7) {
              continue;
            }
            std::string reg_name = "X" + to_string(i);
            // store `Xi_Lc (local)` value to `Xi (global)`.
            auto [xg_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name, true);
            auto [xlc_reg_ptr, xlc_reg_type] =
                inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name);
            auto xlc_val = ir.CreateLoad(xlc_reg_type, xlc_reg_ptr);
            ir.CreateStore(xlc_val, xg_reg_ptr);
          }
        }
        // `load` the X0 after calling system call.
        auto call_nexti = call_inst->getNextNode();
        {
          llvm::IRBuilder<> ir(call_nexti);
          // X0
          auto [x0lc_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, "X0");
          auto [x0g_reg_ptr, x0g_reg_type] =
              inst_lifter->LoadRegAddress(&bb, state_ptr, "X0", true);
          auto x0g_val = ir.CreateLoad(x0g_reg_type, x0g_reg_ptr);
          ir.CreateStore(x0g_val, x0lc_reg_ptr);
        }
        continue;
      }

      // `_ecv_func_epilogue`
      if (call_inst) {
        continue;
      }

      // store the registers which are used after function returning.
      if (ret_inst) {
        // `store` [ X0, X1, SP ] before returning.
        {
          llvm::IRBuilder<> ir(ret_inst);
          // [ X0, X1 ]
          for (int i = 0; i < 2; i++) {
            std::string reg_name = "X" + to_string(i);
            // load `Xi_Lc (local)` value to `Xi (global)`.
            auto [xg_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name, true);
            auto [xlc_reg_ptr, xlc_reg_type] =
                inst_lifter->LoadRegAddress(&bb, state_ptr, reg_name);
            auto xlc_reg_val = ir.CreateLoad(xlc_reg_type, xlc_reg_ptr);
            ir.CreateStore(xlc_reg_val, xg_reg_ptr);
          }
          // SP
          auto [spg_reg_ptr, _] = inst_lifter->LoadRegAddress(&bb, state_ptr, "SP", true);
          auto [splc_reg_ptr, splc_reg_type] = inst_lifter->LoadRegAddress(&bb, state_ptr, "SP");
          auto splc_reg_val = ir.CreateLoad(splc_reg_type, splc_reg_ptr);
          ir.CreateStore(splc_reg_val, spg_reg_ptr);
        }
        continue;
      }

      LOG(FATAL) << "This part must not be reached. t_inst: " << LLVMThingToString(t_inst)
                 << ", call_inst: " << LLVMThingToString(call_inst)
                 << ", ret_inst: " << LLVMThingToString(ret_inst);
    }
  }
}

}  // namespace remill
