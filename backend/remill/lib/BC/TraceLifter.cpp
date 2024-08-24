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

namespace remill {


#if defined(OPT_DEBUG)
#  define ECV_LOG(...) EcvLog(__VA_ARGS__)
#  define ECV_LOG_NL(...) EcvLogNL(__VA_ARGS__)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag) PhiRegsBBBagNode::DebugGraphStruct(bag)
#else
#  define ECV_LOG(...)
#  define ECV_LOG_NL(...)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag)
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
      // map the block to the bb_reg_info_node
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(block))
          << "The block and the bb_reg_info_node have already been appended to the map.";
      virtual_regs_opt->bb_reg_info_node_map.insert({block, bb_reg_info_node});

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
          DirectBranchWithSaveParents(GetOrCreateBranchTakenBlock(), block);
          break;

        /* case: BR instruction (only BR in glibc) */
        case Instruction::kCategoryIndirectJump: {
          try_add_delay_slot(true, block);
          /* indirectbr entry block */
          indirectbr_block = GetOrCreateIndirectJmpBlock();
          if (!virtual_regs_opt->bb_reg_info_node_map.contains(indirectbr_block)) {
            virtual_regs_opt->bb_reg_info_node_map.insert(
                {indirectbr_block, BBRegInfoNode::BBRegInfoNodeWithLoadRuntime()});
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

        case Instruction::kCategoryFunctionReturn:
          try_add_delay_slot(true, block);
          AddTerminatingTailCall(
              block, intrinsics->function_return, *intrinsics, trace_addr,
              llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trace_addr));
          break;

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
      // Update cache for `remill_jump` block.
      virtual_regs_opt->bb_parents.insert({br_to_func_block, {indirectbr_block}});
      CHECK(!virtual_regs_opt->bb_reg_info_node_map.contains(br_to_func_block))
          << "The entry block has been already added illegally to the VirtualRegsOpt.";
      virtual_regs_opt->bb_reg_info_node_map.insert(
          {br_to_func_block, BBRegInfoNode::BBRegInfoNodeWithLoadRuntime()});
      // Add terminate.
      AddTerminatingTailCall(br_to_func_block, intrinsics->jump, *intrinsics, -1, br_vma_phi);
    } else {
      no_indirect_lifted_funcs.insert(func);

#if defined(OPT_DEBUG_2)
      CHECK(!bb_error) << "[Bug] PhiRegsBBBagNode elements error. func: " << func->getName().str();
      CHECK(virtual_regs_opt->bb_parents.size() + 1 ==
            virtual_regs_opt->bb_reg_info_node_map.size())
          << "[Bug] BBRegInfoNodeMap is invalid. bb_parents size + 1: "
          << virtual_regs_opt->bb_parents.size() + 1
          << ", bb_reg_info_node_map.size: " << virtual_regs_opt->bb_reg_info_node_map.size()
          << ", func: " << func->getName().str() << "\n";
#endif
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
  arch->InstanceInstAArch64(inst);

  // Optimization of the usage of the LLVM IR virtual registers for the CPU registers instead of the memory usage.
  for (auto lifted_func : no_indirect_lifted_funcs) {
    auto virtual_regs_opt = func_virtual_regs_opt_map[lifted_func];
    virtual_regs_opt->OptimizeVirtualRegsUsage();
  }

#if defined(OPT_DEBUG_2)
  // Insert `debug_llvmir_u64value`
  uint64_t debug_unique_value = 0;
  for (auto lifted_func : no_indirect_lifted_funcs) {
    for (auto &bb : *lifted_func) {
      for (auto __inst = &*bb.begin(); __inst; __inst = __inst->getNextNode()) {
        if (llvm::dyn_cast<llvm::PHINode>(__inst)) {
          continue;
        }
        auto debug_llvmir_u64value_fun = module->getFunction("debug_llvmir_u64value");
        llvm::CallInst::Create(
            debug_llvmir_u64value_fun,
            {llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), debug_unique_value)},
            llvm::Twine::createNull(), __inst);
        debug_unique_value++;
      }
    }
  }
#endif
}

llvm::Value *VirtualRegsOpt::CastFromInst(EcvReg target_ecv_reg, llvm::Value *from_inst,
                                          llvm::Type *to_inst_ty, llvm::Instruction *inst_at_before,
                                          llvm::Value *to_inst) {
  auto &context = func->getContext();
  auto twine_null = llvm::Twine::createNull();

  llvm::Value *t_from_inst;

  if (from_inst->getType() == to_inst_ty) {
    CHECK(to_inst) << "[Bug] to_inst must not be NULL when from_inst_ty == to_inst_ty.";
    return to_inst;
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
    return new llvm::BitCastInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
  }

  std::terminate();
}

llvm::Value *VirtualRegsOpt::GetRegValueFromCacheMap(
    EcvReg target_ecv_reg, llvm::Type *to_type, llvm::Instruction *inst_at_before,
    std::unordered_map<EcvReg, std::tuple<EcvRegClass, llvm::Value *, uint32_t>, EcvReg::Hash>
        &cache_map) {
  llvm::Value *res_value;

  auto [_, from_value, from_order] = cache_map[target_ecv_reg];
  if (to_type == from_value->getType()) {
    res_value = from_value;
  } else {
    // Need to cast the from_inst to match the type of the load_inst.
    if (llvm::dyn_cast<llvm::StructType>(from_value->getType()) ||
        llvm::dyn_cast<llvm::ArrayType>(from_value->getType())) {
      auto from_extracted_inst = llvm::ExtractValueInst::Create(
          from_value, {from_order}, llvm::Twine::createNull(), inst_at_before);
      res_value = CastFromInst(target_ecv_reg, from_extracted_inst, to_type, inst_at_before,
                               from_extracted_inst);
      // for debug
      value_reg_map.insert({from_extracted_inst,
                            {target_ecv_reg, GetRegZFromLLVMType(from_extracted_inst->getType())}});
    } else {
      res_value = CastFromInst(target_ecv_reg, from_value, to_type, inst_at_before);
    }
  }

  return res_value;
}

void VirtualRegsOpt::OptimizeVirtualRegsUsage() {

  auto &inst_lifter = impl->inst.GetLifter();
  impl->virtual_regs_opt = this;
  ECV_LOG_NL(std::hex,
             "[DEBUG LOG]. func: VirtualRegsOpt::OptimizeVritualRegsUsage. target function: ",
             func->getName().str(), ".");

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
  target_bb = entry_terminator_br->getSuccessor(0);
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
          << "Every block of the lifted function by elfconv must not have the child blocks more than two."
          << ECV_DEBUG_STREAM.str();
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
        bb_reg_info_node_map[target_bb]->join_reg_info_node(joined_bb_reg_info_node);
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

  DebugStreamReset();
  ECV_LOG_NL("target_func: ", func->getName().str());

  // Initialize the Graph of PhiRegsBBBagNode.
  for (auto &[bb, bb_reg_info_node] : bb_reg_info_node_map) {
    auto phi_regs_bag = new PhiRegsBBBagNode(bb_reg_info_node->bb_load_reg_map,
                                             std::move(bb_reg_info_node->bb_load_reg_map),
                                             std::move(bb_reg_info_node->bb_store_reg_map), {bb});
    PhiRegsBBBagNode::bb_regs_bag_map.insert({bb, phi_regs_bag});
  }
  PhiRegsBBBagNode::bag_num = PhiRegsBBBagNode::bb_regs_bag_map.size();

  for (auto [bb, pars] : bb_parents) {
    for (auto par : pars) {
      auto par_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[par];
      auto child_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[bb];
      // Remove self-loop because it is not needed for the PhiRegsBBBagNode* Graph.
      if (par_phi_regs_bag == child_phi_regs_bag) {
        continue;
      }
      par_phi_regs_bag->children.insert(child_phi_regs_bag);
      child_phi_regs_bag->parents.insert(par_phi_regs_bag);
    }
  }

  // Calculate the registers which needs to get on the phis instruction for every basic block.
  PhiRegsBBBagNode::GetPhiRegsBags(&func->getEntryBlock());

  ECV_LOG_NL("target_func: ", func->getName().str());

  // Add the phi instructions to the every basic block.
  std::queue<llvm::BasicBlock *> phi_bb_queue;
  std::set<llvm::BasicBlock *> finished;
  auto state_ptr = NthArgument(func, kStatePointerArgNum);

  phi_bb_queue.push(&func->getEntryBlock());

  while (!phi_bb_queue.empty()) {
    auto target_bb = phi_bb_queue.front();
    phi_bb_queue.pop();
    if (finished.contains(target_bb) || relay_bb_cache.contains(target_bb)) {
      continue;
    }
    ECV_LOG_NL("0x", target_bb, ":");
    // std::cout << std::hex << "0x" << target_bb << ":\n";
    auto target_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[target_bb];
    auto target_bb_reg_info_node = bb_reg_info_node_map[target_bb];
    auto &reg_latest_inst_map = bb_reg_info_node_map[target_bb]->reg_latest_inst_map;
    auto &reg_derived_added_inst_map = bb_reg_info_node_map[target_bb]->reg_derived_added_inst_map;
    auto &referred_able_added_inst_reg_map =
        bb_reg_info_node_map[target_bb]->referred_able_added_inst_reg_map;
    std::unordered_map<EcvReg, std::tuple<EcvRegClass, llvm::Value *, uint32_t>, EcvReg::Hash>
        ascend_reg_inst_map;

    llvm::BranchInst *br_inst = nullptr;

    // Add the phi instruction for the every register included in the bag_phi_reg_map.
    auto inst_start_it = &*target_bb->begin();
    for (auto &phi_ecv_reg_info : target_phi_regs_bag->bag_req_reg_map) {
      auto &[target_ecv_reg, target_ecv_reg_class] = phi_ecv_reg_info;
      llvm::Value *reg_derived_inst;
      // This phi has been already added.
      if (reg_derived_added_inst_map.contains(target_ecv_reg)) {
        auto no_casted_reg_derived_inst = reg_derived_added_inst_map[target_ecv_reg];
        if (auto __reg_derived_phi = llvm::dyn_cast<llvm::PHINode>(no_casted_reg_derived_inst)) {
          CHECK(__reg_derived_phi->getNumIncomingValues() == bb_parents[target_bb].size())
              << " The once generated phi instruction should have all necessary incoming values.";
        }
        reg_derived_inst = CastFromInst(
            target_ecv_reg, no_casted_reg_derived_inst, GetLLVMTypeFromRegZ(target_ecv_reg_class),
            llvm::dyn_cast<llvm::Instruction>(no_casted_reg_derived_inst)->getNextNode(),
            no_casted_reg_derived_inst);

        // Update cache.
        if (no_casted_reg_derived_inst != reg_derived_inst) {
          referred_able_added_inst_reg_map.insert({reg_derived_inst, phi_ecv_reg_info});
        }
        // for debug
        value_reg_map.insert({reg_derived_inst, phi_ecv_reg_info});
      }
      // Generate the new phi instruction.
      else {
        auto reg_derived_phi = llvm::PHINode::Create(GetLLVMTypeFromRegZ(target_ecv_reg_class),
                                                     bb_parents[target_bb].size(),
                                                     llvm::Twine::createNull(), inst_start_it);
        // Add this phi to the reg_latest_inst_map (to avoid the infinity loop when running Impl::GetValueFromTargetBBAndReg).
        reg_latest_inst_map.insert(
            {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_phi, 0)});

        // Get the every virtual register from all the parent bb.
        auto par_bb_it = bb_parents[target_bb].begin();
        std::set<llvm::BasicBlock *> _finished;
        while (par_bb_it != bb_parents[target_bb].end()) {
          auto par_bb = *par_bb_it;
          if (_finished.contains(par_bb)) {
            ++par_bb_it;
            continue;
          }
          auto derived_reg_value = GetValueFromTargetBBAndReg(par_bb, target_bb, phi_ecv_reg_info);
          // if the relay_bb is added as the parent of the target_bb, `par_bb` is not the parent. In addition, derived_reg_value is certainly `llvm::PHINode`.
          if (auto from_phi_inst = llvm::dyn_cast<llvm::Instruction>(derived_reg_value)) {
            auto true_par = from_phi_inst->getParent();
            reg_derived_phi->addIncoming(derived_reg_value, true_par);
            _finished.insert(true_par);
            if (par_bb != true_par) {
              par_bb_it = bb_parents[target_bb].begin();
              continue;
            }
          } else {
            reg_derived_phi->addIncoming(derived_reg_value, par_bb);
            _finished.insert(par_bb);
          }
          ++par_bb_it;
        }
        referred_able_added_inst_reg_map.insert({reg_derived_phi, phi_ecv_reg_info});
        // for debug
        value_reg_map.insert({reg_derived_phi, phi_ecv_reg_info});
        reg_derived_inst = reg_derived_phi;
      }
      // Add this phi to the ascend_reg_inst_map
      ascend_reg_inst_map.insert(
          {target_ecv_reg, std::make_tuple(target_ecv_reg_class, reg_derived_inst, 0)});
    }

    reg_latest_inst_map.clear();
    auto target_inst_it = inst_start_it;

    // Replace all the `load` to the CPU registers memory with the value of the phi instructions.
    while (target_inst_it) {
      ECV_LOG_NL("\t", LLVMThingToString(target_inst_it));
      // std::cout << "\t" << LLVMThingToString(target_inst_it) << "\n";
      // The target instruction was added. only update cache.
      if (referred_able_added_inst_reg_map.contains(&*target_inst_it)) {
        auto &[added_ecv_reg, added_ecv_reg_class] =
            referred_able_added_inst_reg_map[&*target_inst_it];
        ascend_reg_inst_map.insert_or_assign(
            added_ecv_reg, std::make_tuple(added_ecv_reg_class, target_inst_it, 0));
        target_inst_it = target_inst_it->getNextNode();
      } else {
        // Target: llvm::LoadInst
        if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(target_inst_it)) {
          const auto &load_reg = load_inst->getPointerOperand()->getName().str();
          auto [target_ecv_reg, load_ecv_reg_class] = EcvReg::GetRegInfo(load_reg);
          auto [from_ecv_reg_class, from_value, from_order] = ascend_reg_inst_map[target_ecv_reg];

          llvm::Value *new_ecv_reg_inst;

          // Should load this register because it is first access.
          if (!from_value) {
            new_ecv_reg_inst = load_inst;
            target_inst_it = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
          }
          // Can replace this load with existig accessed value.
          else {
            auto from_inst = llvm::dyn_cast<llvm::Instruction>(from_value);
            CHECK(from_inst) << "referenced instruction must be derived from llvm::Instruction.";
            new_ecv_reg_inst = GetRegValueFromCacheMap(target_ecv_reg, load_inst->getType(),
                                                       load_inst, ascend_reg_inst_map);
            target_inst_it = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
            // Replace all the Users.
            load_inst->replaceAllUsesWith(new_ecv_reg_inst);
            // Update cache.
            ascend_reg_inst_map.insert_or_assign(
                target_ecv_reg, std::make_tuple(load_ecv_reg_class, new_ecv_reg_inst, 0));
            // Delete load_inst.
            load_inst->eraseFromParent();
          }
          // for debug
          value_reg_map.insert(
              {new_ecv_reg_inst, {target_ecv_reg, GetRegZFromLLVMType(load_inst->getType())}});
        }
        // Target: llvm::CallInst
        else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(target_inst_it)) {
          // Call the lifted function (includes `__remill_function_call`).
          if (lifted_func_caller_set.contains(call_inst)) {
            // Store `within_store_map`
            for (auto [within_store_ecv_reg, within_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_within_store_reg_map) {
              if (within_store_ecv_reg.CheckNoChangedReg() ||
                  !ascend_reg_inst_map.contains(within_store_ecv_reg)) {
                continue;
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                  GetRegValueFromCacheMap(within_store_ecv_reg,
                                          GetLLVMTypeFromRegZ(within_store_ecv_reg_class),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            // Store `preceding_store_map`
            for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_preceding_store_reg_map) {
              if (preceding_store_ecv_reg.CheckNoChangedReg() ||
                  target_phi_regs_bag->bag_within_store_reg_map.contains(preceding_store_ecv_reg)) {
                continue;
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr,
                  preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                  GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                          GetLLVMTypeFromRegZ(preceding_store_ecv_reg_class),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load `preceding_store_map` + `load_map`
            for (auto [req_ecv_reg, req_ecv_reg_class] : target_phi_regs_bag->bag_req_reg_map) {
              if (req_ecv_reg.CheckNoChangedReg()) {
                continue;
              }
              auto load_value = inst_lifter->LoadRegValueBeforeInst(
                  target_bb, state_ptr, req_ecv_reg.GetRegName(req_ecv_reg_class), call_next_inst);
              auto req_value =
                  CastFromInst(req_ecv_reg, load_value, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                               call_next_inst, load_value);
              // Update cache.
              ascend_reg_inst_map.insert_or_assign(
                  req_ecv_reg, std::make_tuple(req_ecv_reg_class, req_value, 0));
              // for debug
              value_reg_map.insert(
                  {load_value, {req_ecv_reg, GetRegZFromLLVMType(load_value->getType())}});
              value_reg_map.insert({req_value, {req_ecv_reg, req_ecv_reg_class}});
            }
            target_inst_it = call_next_inst;
          }
          // Call the `emulate_system_call` semantic function.
          else if (call_inst->getCalledFunction()->getName().str() == "emulate_system_call") {
            // Store target: x0 ~ x5, x8
            for (auto [within_store_ecv_reg, within_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_within_store_reg_map) {
              if (!(within_store_ecv_reg.number < 6 || within_store_ecv_reg.number == 8) ||
                  !ascend_reg_inst_map.contains(within_store_ecv_reg)) {
                continue;
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                  GetRegValueFromCacheMap(within_store_ecv_reg,
                                          GetLLVMTypeFromRegZ(within_store_ecv_reg_class),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            // Store target: x0 ~ x5, x8
            for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
                 target_phi_regs_bag->bag_preceding_store_reg_map) {
              if (!(preceding_store_ecv_reg.number < 6 || preceding_store_ecv_reg.number == 8) ||
                  target_phi_regs_bag->bag_within_store_reg_map.contains(preceding_store_ecv_reg)) {
                continue;
              }
              inst_lifter->StoreRegValueBeforeInst(
                  target_bb, state_ptr,
                  preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                  GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                          GetLLVMTypeFromRegZ(preceding_store_ecv_reg_class),
                                          call_inst, ascend_reg_inst_map),
                  call_inst);
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load target: x0
            for (auto [req_ecv_reg, req_ecv_reg_class] : target_phi_regs_bag->bag_req_reg_map) {
              if (0 != req_ecv_reg.number) {
                continue;
              }
              auto load_value = inst_lifter->LoadRegValueBeforeInst(
                  target_bb, state_ptr, req_ecv_reg.GetRegName(req_ecv_reg_class), call_next_inst);
              auto req_value =
                  CastFromInst(req_ecv_reg, load_value, GetLLVMTypeFromRegZ(req_ecv_reg_class),
                               call_next_inst, load_value);
              // Update cache.
              ascend_reg_inst_map.insert_or_assign(
                  req_ecv_reg, std::make_tuple(req_ecv_reg_class, req_value, 0));
              // for debug
              value_reg_map.insert(
                  {load_value, {req_ecv_reg, GetRegZFromLLVMType(load_value->getType())}});
              value_reg_map.insert({req_value, {req_ecv_reg, req_ecv_reg_class}});
            }
            target_inst_it = call_next_inst;
          }
          // Call the general semantic functions.
          else {
            auto &sema_func_write_regs =
                target_bb_reg_info_node->sema_call_written_reg_map[call_inst];
            // Load all the referenced registers.
            for (std::size_t i = 0; i < sema_func_write_regs.size(); i++) {
              ascend_reg_inst_map.insert_or_assign(
                  sema_func_write_regs[i].first,
                  std::make_tuple(sema_func_write_regs[i].second, call_inst, i));
            }
            target_inst_it = call_inst->getNextNode();
            // for debug
            // if the return type is struct, this key value is not used.
            if (!sema_func_write_regs.empty()) {
              value_reg_map.insert(
                  {call_inst, {sema_func_write_regs[0].first, sema_func_write_regs[0].second}});
            }
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
          target_inst_it = store_inst->getNextNode();
          store_inst->eraseFromParent();
        }
        // Target: llvm::BranchInst
        else if (auto __br_inst = llvm::dyn_cast<llvm::BranchInst>(target_inst_it)) {
          CHECK(!br_inst) << "There are multiple branch instructions in the one BB.";
          br_inst = __br_inst;
          target_inst_it = br_inst->getNextNode();
          ECV_LOG_NL("jump block: 0x", std::hex, br_inst->getSuccessor(0));
          // std::cout << " to_block: 0x" << std::hex << br_inst->getSuccessor(0) << "\n";
        }
        // Target: llvm::ExtractValueInst
        else if (auto extract_inst = llvm::dyn_cast<llvm::ExtractValueInst>(target_inst_it)) {
          CHECK(referred_able_added_inst_reg_map.contains(extract_inst));
          auto [added_ecv_reg, added_ecv_reg_class] =
              referred_able_added_inst_reg_map[extract_inst];
          ascend_reg_inst_map.insert_or_assign(
              added_ecv_reg, std::make_tuple(added_ecv_reg_class, extract_inst, 0));
          target_inst_it = extract_inst->getNextNode();
          // for debug
          value_reg_map.insert({extract_inst, {added_ecv_reg, added_ecv_reg_class}});
        }
        // Target: llvm::CastInst
        else if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(target_inst_it)) {
          if (referred_able_added_inst_reg_map.contains(cast_inst)) {
            auto [added_ecv_reg, added_ecv_reg_class] = referred_able_added_inst_reg_map[cast_inst];
            ascend_reg_inst_map.insert_or_assign(
                added_ecv_reg, std::make_tuple(added_ecv_reg_class, cast_inst, 0));
            // for debug
            value_reg_map.insert({cast_inst, {added_ecv_reg, added_ecv_reg_class}});
          } else {
            auto cast_op = cast_inst->getOperand(0);
            CHECK(value_reg_map.contains(cast_op));
            // for debug
            value_reg_map.insert({cast_inst, value_reg_map[cast_op]});
          }
          target_inst_it = cast_inst->getNextNode();
        }
        // Target: The instructions that can be ignored.
        else if (auto binary_inst = llvm::dyn_cast<llvm::BinaryOperator>(target_inst_it)) {
          target_inst_it = target_inst_it->getNextNode();
          // for debug
          auto lhs = binary_inst->getOperand(0);
          CHECK(value_reg_map.contains(lhs));
          // (FIXME) should check the second operand too.
          value_reg_map.insert({binary_inst, value_reg_map[lhs]});
        } else if (auto ret_inst = llvm::dyn_cast<llvm::ReturnInst>(target_inst_it)) {
          // Store `within_store_map`
          for (auto [within_store_ecv_reg, within_store_ecv_reg_class] :
               target_phi_regs_bag->bag_within_store_reg_map) {
            if (within_store_ecv_reg.CheckNoChangedReg() ||
                !ascend_reg_inst_map.contains(within_store_ecv_reg)) {
              continue;
            }
            inst_lifter->StoreRegValueBeforeInst(
                target_bb, state_ptr, within_store_ecv_reg.GetRegName(within_store_ecv_reg_class),
                GetRegValueFromCacheMap(within_store_ecv_reg,
                                        GetLLVMTypeFromRegZ(within_store_ecv_reg_class), ret_inst,
                                        ascend_reg_inst_map),
                ret_inst);
          }
          // Store `preceding_store_map`
          for (auto [preceding_store_ecv_reg, preceding_store_ecv_reg_class] :
               target_phi_regs_bag->bag_preceding_store_reg_map) {
            if (preceding_store_ecv_reg.CheckNoChangedReg() ||
                target_phi_regs_bag->bag_within_store_reg_map.contains(preceding_store_ecv_reg)) {
              continue;
            }
            inst_lifter->StoreRegValueBeforeInst(
                target_bb, state_ptr,
                preceding_store_ecv_reg.GetRegName(preceding_store_ecv_reg_class),
                GetRegValueFromCacheMap(preceding_store_ecv_reg,
                                        GetLLVMTypeFromRegZ(preceding_store_ecv_reg_class),
                                        ret_inst, ascend_reg_inst_map),
                ret_inst);
          }
          target_inst_it = target_inst_it->getNextNode();
        } else if (llvm::dyn_cast<llvm::CmpInst>(target_inst_it) ||
                   llvm::dyn_cast<llvm::GetElementPtrInst>(target_inst_it) ||
                   llvm::dyn_cast<llvm::AllocaInst>(target_inst_it)) {
          CHECK(true);
          target_inst_it = target_inst_it->getNextNode();
        } else {
          LOG(FATAL) << "Unexpected inst when adding phi instructions." << ECV_DEBUG_STREAM.str();
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
  }

  // Reset PhiRegsBBBagNode.
  PhiRegsBBBagNode::Reset();
  DebugStreamReset();

// Check
#if defined(OPT_DEBUG)
  // Check the parent-child relationship
  for (auto &bb : *func) {
    auto inst_terminator = bb.getTerminator();
    for (size_t i = 0; i < inst_terminator->getNumSuccessors(); i++) {
      CHECK(bb_parents[inst_terminator->getSuccessor(i)].contains(&bb));
    }
  }
  // Check the optimized LLVM IR.
  for (auto &bb : *func) {
    auto bb_reg_info_node_2 = bb_reg_info_node_map[&bb];
    for (auto &inst : bb) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst);
          call_inst && !lifted_func_caller_set.contains(call_inst)) {
        auto sema_isel_args = bb_reg_info_node_2->sema_func_args_reg_map[call_inst];
        for (size_t i = 0; i < sema_isel_args.size(); i++) {
          auto sema_isel_arg_i = sema_isel_args[i];
          if (EcvRegClass::RegNULL == sema_isel_arg_i.second ||
              // `%state` is not loaded even before optimization, so can ignore.
              STATE_ORDER == sema_isel_arg_i.first.number ||
              llvm::dyn_cast<llvm::Function>(call_inst->getOperand(i))) {
            continue;
          }
          auto actual_arg_i = call_inst->getOperand(i);
          auto [actual_arg_ecv_reg, actual_arg_ecv_reg_class] = value_reg_map[actual_arg_i];
          CHECK(actual_arg_ecv_reg.number == sema_isel_arg_i.first.number)
              << "i: " << i
              << ", actual arg ecv_reg number: " << to_string(actual_arg_ecv_reg.number)
              << ", sema func arg ecv_reg: " << to_string(sema_isel_arg_i.first.number) << "\n";
          CHECK(actual_arg_ecv_reg_class == sema_isel_arg_i.second)
              << "EcvRegClass Mismatch. actual arg ecv_reg_class: "
              << EcvRegClass2String(actual_arg_ecv_reg_class)
              << ", sema isel arg ecv_reg_class: " << EcvRegClass2String(sema_isel_arg_i.second)
              << " at value: " << LLVMThingToString(actual_arg_i)
              << ", sema func: " << LLVMThingToString(call_inst)
              << ", func: " << func->getName().str() << "\n";
        }
      }
    }
  }
#endif
  CHECK(func->size() == finished.size() + relay_bb_cache.size())
      << "func->size: " << func->size() << ", finished size: " << finished.size()
      << ", relay_bb_num: " << relay_bb_cache.size() << "\n"
      << ECV_DEBUG_STREAM.str();
}

llvm::Type *VirtualRegsOpt::GetLLVMTypeFromRegZ(EcvRegClass ecv_reg_class) {
  auto &context = func->getContext();
  switch (ecv_reg_class) {
    case EcvRegClass::RegW: return llvm::Type::getInt32Ty(context);
    case EcvRegClass::RegX: return llvm::Type::getInt64Ty(context);
    case EcvRegClass::RegB: return llvm::Type::getInt8Ty(context);
    case EcvRegClass::RegH: return llvm::Type::getHalfTy(context);
    case EcvRegClass::RegS: return llvm::Type::getFloatTy(context);
    case EcvRegClass::RegD: return llvm::Type::getDoubleTy(context);
    case EcvRegClass::RegQ: return llvm::Type::getInt128Ty(context);
    case EcvRegClass::Reg8B: return llvm::VectorType::get(llvm::Type::getInt8Ty(context), 8, false);
    case EcvRegClass::Reg16B:
      return llvm::VectorType::get(llvm::Type::getInt8Ty(context), 16, false);
    case EcvRegClass::Reg4H: return llvm::VectorType::get(llvm::Type::getHalfTy(context), 4, false);
    case EcvRegClass::Reg8H: return llvm::VectorType::get(llvm::Type::getHalfTy(context), 8, false);
    case EcvRegClass::Reg2S:
      return llvm::VectorType::get(llvm::Type::getInt32Ty(context), 2, false);
    case EcvRegClass::Reg2SF:
      return llvm::VectorType::get(llvm::Type::getFloatTy(context), 2, false);
    case EcvRegClass::Reg4S:
      return llvm::VectorType::get(llvm::Type::getInt32Ty(context), 4, false);
    case EcvRegClass::Reg4SF:
      return llvm::VectorType::get(llvm::Type::getFloatTy(context), 4, false);
    case EcvRegClass::Reg1D:
      return llvm::VectorType::get(llvm::Type::getInt64Ty(context), 1, false);
    case EcvRegClass::Reg1DF:
      return llvm::VectorType::get(llvm::Type::getDoubleTy(context), 1, false);
    case EcvRegClass::Reg2D:
      return llvm::VectorType::get(llvm::Type::getInt64Ty(context), 2, false);
    case EcvRegClass::Reg2DF:
      return llvm::VectorType::get(llvm::Type::getDoubleTy(context), 2, false);
    case EcvRegClass::RegP: return llvm::Type::getInt64PtrTy(context);
    default: break;
  }

  LOG(FATAL)
      << "[Bug] Reach the unreachable code at VirtualRegsOpt::GetLLVMTypeFromRegZ. ecv_reg_class: "
      << std::underlying_type<EcvRegClass>::type(ecv_reg_class) << "\n"
      << ECV_DEBUG_STREAM.str();
  return nullptr;
}

EcvRegClass VirtualRegsOpt::GetRegZFromLLVMType(llvm::Type *value_type) {
  auto &context = func->getContext();
  if (llvm::Type::getInt32Ty(context) == value_type) {
    return EcvRegClass::RegW;
  } else if (llvm::Type::getInt64Ty(context) == value_type) {
    return EcvRegClass::RegX;
  } else if (llvm::Type::getInt8Ty(context) == value_type) {
    return EcvRegClass::RegB;
  } else if (llvm::Type::getHalfTy(context) == value_type) {
    return EcvRegClass::RegH;
  } else if (llvm::Type::getFloatTy(context) == value_type) {
    return EcvRegClass::RegS;
  } else if (llvm::Type::getDoubleTy(context) == value_type) {
    return EcvRegClass::RegD;
  } else if (llvm::Type::getInt128Ty(context) == value_type ||
             llvm::VectorType::get(llvm::Type::getInt128Ty(context), 1, false) == value_type) {
    return EcvRegClass::RegQ;
  } else if (llvm::VectorType::get(llvm::Type::getInt8Ty(context), 8, false) == value_type) {
    return EcvRegClass::Reg8B;
  } else if (llvm::VectorType::get(llvm::Type::getInt8Ty(context), 16, false) == value_type) {
    return EcvRegClass::Reg16B;
  } else if (llvm::VectorType::get(llvm::Type::getHalfTy(context), 4, false) == value_type) {
    return EcvRegClass::Reg4H;
  } else if (llvm::VectorType::get(llvm::Type::getHalfTy(context), 8, false) == value_type) {
    return EcvRegClass::Reg8H;
  } else if (llvm::VectorType::get(llvm::Type::getInt32Ty(context), 2, false) == value_type) {
    return EcvRegClass::Reg2S;
  } else if (llvm::VectorType::get(llvm::Type::getFloatTy(context), 2, false) == value_type) {
    return EcvRegClass::Reg2SF;
  } else if (llvm::VectorType::get(llvm::Type::getInt32Ty(context), 4, false) == value_type) {
    return EcvRegClass::Reg4S;
  } else if (llvm::VectorType::get(llvm::Type::getFloatTy(context), 4, false) == value_type) {
    return EcvRegClass::Reg4SF;
  } else if (llvm::VectorType::get(llvm::Type::getInt64Ty(context), 1, false) == value_type) {
    return EcvRegClass::Reg1D;
  } else if (llvm::VectorType::get(llvm::Type::getDoubleTy(context), 1, false) == value_type) {
    return EcvRegClass::Reg1DF;
  } else if (llvm::VectorType::get(llvm::Type::getInt64Ty(context), 2, false) == value_type) {
    return EcvRegClass::Reg2D;
  } else if (llvm::VectorType::get(llvm::Type::getDoubleTy(context), 2, false) == value_type) {
    return EcvRegClass::Reg2DF;
  } else if (llvm::Type::getInt64PtrTy(context) == value_type) {
    return EcvRegClass::RegP;
  }

  LOG(FATAL) << "[Bug] Reach the unreachable code at VirtualregsOpt::GetRegZfromLLVMType. Type: "
             << LLVMThingToString(value_type) << "\n"
             << ECV_DEBUG_STREAM.str();
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
      if (llvm::dyn_cast<llvm::StructType>(from_inst->getType()) ||
          llvm::dyn_cast<llvm::ArrayType>(from_inst->getType())) {
        auto from_extracted_inst = llvm::ExtractValueInst::Create(
            from_inst, {from_order}, llvm::Twine::createNull(), target_terminator);
        if (from_extracted_inst != from_inst) {
          target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
              {from_extracted_inst,
               {target_ecv_reg, GetRegZFromLLVMType(from_extracted_inst->getType())}});
        }
        required_value = CastFromInst(target_ecv_reg, from_extracted_inst,
                                      GetLLVMTypeFromRegZ(required_ecv_reg_class),
                                      target_terminator, from_extracted_inst);
        // for debug
        value_reg_map.insert(
            {from_extracted_inst,
             {target_ecv_reg, GetRegZFromLLVMType(from_extracted_inst->getType())}});
      } else {
        required_value =
            CastFromInst(target_ecv_reg, from_inst, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                         target_terminator);
      }
      // for debug
      value_reg_map.insert({required_value, {target_ecv_reg, required_ecv_reg_class}});
    }
    // Update cache.
    target_bb_reg_info_node->reg_latest_inst_map.insert_or_assign(
        target_ecv_reg, std::make_tuple(required_ecv_reg_class, required_value, 0));
    if (required_value != from_inst) {
      target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
          {required_value, {target_ecv_reg, required_ecv_reg_class}});
    }
  }
  // The bag_req_reg_map of the target_bb includes the target register.
  else if (target_phi_regs_bag->bag_req_reg_map.contains(target_ecv_reg)) {
    // Add `phi` instruction.
    auto start_inst = target_bb->begin();
    auto phi_ecv_reg_class = target_phi_regs_bag->bag_req_reg_map[target_ecv_reg];
    auto reg_phi =
        llvm::PHINode::Create(GetLLVMTypeFromRegZ(phi_ecv_reg_class), bb_parents[target_bb].size(),
                              llvm::Twine::createNull(), &*start_inst);
    // Update phi cache.
    // must update reg_latest_inst_map before addIncoming to correspond to the loop bbs.
    target_bb_reg_info_node->reg_latest_inst_map.insert(
        {target_ecv_reg, {phi_ecv_reg_class, reg_phi, 0}});
    // Get the every virtual register from all the parent bb.
    auto par_bb_it = bb_parents[target_bb].begin();
    std::set<llvm::BasicBlock *> _finished;
    while (par_bb_it != bb_parents[target_bb].end()) {
      auto par_bb = *par_bb_it;
      if (_finished.contains(par_bb)) {
        ++par_bb_it;
        continue;
      }
      auto derived_reg_value = GetValueFromTargetBBAndReg(par_bb, target_bb, ecv_reg_info);
      if (auto from_inst = llvm::dyn_cast<llvm::Instruction>(derived_reg_value)) {
        auto true_par = from_inst->getParent();
        reg_phi->addIncoming(derived_reg_value, true_par);
        _finished.insert(true_par);
        if (par_bb != true_par) {
          par_bb_it = bb_parents[target_bb].begin();
          continue;
        }
      } else {
        reg_phi->addIncoming(derived_reg_value, par_bb);
        _finished.insert(par_bb);
      }
      ++par_bb_it;
    }
    // Cast to the required_ecv_reg_class if necessary.
    required_value =
        CastFromInst(target_ecv_reg, reg_phi, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                     target_terminator, reg_phi);
    // for debug
    value_reg_map.insert({reg_phi, {target_ecv_reg, phi_ecv_reg_class}});
    value_reg_map.insert({required_value, {target_ecv_reg, required_ecv_reg_class}});
    // Update cache.
    target_bb_reg_info_node->reg_derived_added_inst_map.insert({target_ecv_reg, reg_phi});
    target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
        {reg_phi, {target_ecv_reg, phi_ecv_reg_class}});
    target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
        {required_value, {target_ecv_reg, phi_ecv_reg_class}});
  }
  // The target_bb doesn't have the target register, so need to `load` the register.
  else {
    bool relay_bb_need = false;
    for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
      relay_bb_need |= !PhiRegsBBBagNode::bb_regs_bag_map[target_terminator->getSuccessor(i)]
                            ->bag_req_reg_map.contains(target_ecv_reg);
    }

    // Need to insert `relay_bb`
    if (relay_bb_need) {
      // Create `relay_bb` and insert `load` to it.
      auto relay_bb = llvm::BasicBlock::Create(impl->context, llvm::Twine::createNull(), func);
      impl->DirectBranchWithSaveParents(request_bb, relay_bb);
      for (std::size_t i = 0; i < target_terminator->getNumSuccessors(); i++) {
        if (target_terminator->getSuccessor(i) == request_bb) {
          target_terminator->setSuccessor(i, relay_bb);
          auto &request_pars = bb_parents[request_bb];
          request_pars.erase(target_bb);
          bb_parents.insert({relay_bb, {target_bb}});
        }
      }
      relay_bb_cache.insert(relay_bb);

      // Add relay_bb to the PhiRegsBBBagNode and BBRegInfoNode.
      // (WARNING!): bag_inherited_read_reg_map and bag_read_write_reg_map is incorrect for the relay_bb. However, it is not matter.
      auto request_phi_regs_bag = PhiRegsBBBagNode::bb_regs_bag_map[request_bb];
      PhiRegsBBBagNode::bb_regs_bag_map.insert({relay_bb, request_phi_regs_bag});
      auto relay_bb_reg_info_node = new BBRegInfoNode();
      bb_reg_info_node_map.insert({relay_bb, relay_bb_reg_info_node});

      auto relay_terminator = relay_bb->getTerminator();

      // Fix all the aleady derived phi instructions on the request_bb from the target_bb.
      auto request_bb_reg_info_node = bb_reg_info_node_map[request_bb];
      auto request_bb_inst_it = request_bb->begin();
      while (auto request_phi_inst = llvm::dyn_cast<llvm::PHINode>(&*request_bb_inst_it)) {
        for (size_t i = 0; i < request_phi_inst->getNumIncomingValues(); ++i) {
          if (request_phi_inst->getIncomingBlock(i) == target_bb) {
            auto [request_ecv_reg, request_ecv_reg_class] =
                request_bb_reg_info_node->referred_able_added_inst_reg_map[request_phi_inst];
            // Generate the new phi instruction on the relay_bb.
            auto relay_phi_inst =
                llvm::PHINode::Create(GetLLVMTypeFromRegZ(request_ecv_reg_class), 1,
                                      llvm::Twine::createNull(), relay_terminator);
            relay_phi_inst->addIncoming(request_phi_inst->getIncomingValue(i), target_bb);
            // re-set the new value and bb of relay_bb for the request_phi_inst.
            request_phi_inst->setIncomingBlock(i, relay_bb);
            request_phi_inst->setIncomingValue(i, relay_phi_inst);

            // Update cache (relay_phi_inst).
            relay_bb_reg_info_node->reg_derived_added_inst_map.insert(
                {request_ecv_reg, relay_phi_inst});
            relay_bb_reg_info_node->reg_latest_inst_map.insert(
                {request_ecv_reg, {request_ecv_reg_class, relay_phi_inst, 0}});
            // Actually unneccesarry
            relay_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
                {relay_phi_inst, {request_ecv_reg, request_ecv_reg_class}});
            // for debug
            value_reg_map.insert({relay_phi_inst, {request_ecv_reg, request_ecv_reg_class}});
          }
        }
        ++request_bb_inst_it;
      }

      // load all the required registers that the target_bag doesn't require.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      for (auto &[need_ecv_reg, need_ecv_reg_class] : request_phi_regs_bag->bag_req_reg_map) {
        if (!target_phi_regs_bag->bag_req_reg_map.contains(need_ecv_reg)) {
          auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
              relay_bb, state_ptr, need_ecv_reg.GetRegName(need_ecv_reg_class), relay_terminator);
          auto cast_value =
              CastFromInst(need_ecv_reg, load_value, GetLLVMTypeFromRegZ(need_ecv_reg_class),
                           relay_terminator, load_value);
          // Update cache.
          relay_bb_reg_info_node->reg_latest_inst_map.insert(
              {need_ecv_reg, {need_ecv_reg_class, cast_value, 0}});
          if (load_value != cast_value) {
            relay_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
                {cast_value, {need_ecv_reg, need_ecv_reg_class}});
          }

          if (target_ecv_reg == need_ecv_reg) {
            required_value = cast_value;
          }
          // for debug
          value_reg_map.insert(
              {load_value, {need_ecv_reg, GetRegZFromLLVMType(load_value->getType())}});
          value_reg_map.insert({required_value, {need_ecv_reg, need_ecv_reg_class}});
        }
      }

    }
    // Can insert `load` to the target_bb.
    else {
      // Add `load` instruction.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
          target_bb, state_ptr, target_ecv_reg.GetRegName(required_ecv_reg_class),
          target_terminator);
      required_value =
          CastFromInst(target_ecv_reg, load_value, GetLLVMTypeFromRegZ(required_ecv_reg_class),
                       target_terminator, load_value);
      // Update cache.
      target_bb_reg_info_node->reg_derived_added_inst_map.insert({target_ecv_reg, load_value});
      target_bb_reg_info_node->reg_latest_inst_map.insert(
          {target_ecv_reg, {required_ecv_reg_class, required_value, 0}});
      if (required_value != load_value) {
        target_bb_reg_info_node->referred_able_added_inst_reg_map.insert(
            {required_value, {target_ecv_reg, required_ecv_reg_class}});
      }
      // for debug
      value_reg_map.insert(
          {load_value, {target_ecv_reg, GetRegZFromLLVMType(load_value->getType())}});
      value_reg_map.insert({required_value, {target_ecv_reg, required_ecv_reg_class}});
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
    auto root_bag = bb_regs_bag_map[root_bb];
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
      bool target_bag_is_in_visited = false;
      std::set<PhiRegsBBBagNode *> true_visited;
      for (auto _bag : visited) {
        auto true_bag = _bag->GetTrueBag();
        if (true_bag == target_bag) {
          target_bag_is_in_visited = true;
        }
        true_visited.insert(true_bag);
      }
      visited = true_visited;

      if (target_bag_is_in_visited) {
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
          target_bag->bag_succeeding_load_reg_map.merge(moved_bag->bag_succeeding_load_reg_map);
          target_bag->bag_preceding_load_reg_map.merge(moved_bag->bag_preceding_load_reg_map);
          target_bag->bag_within_store_reg_map.merge(moved_bag->bag_within_store_reg_map);
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

#if defined(OPT_DEBUG)

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
    bag_stack.push(bb_regs_bag_map[root_bb]);

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
  bag_queue.push(bb_regs_bag_map[root_bb]);

  while (!bag_queue.empty()) {
    auto target_bag = bag_queue.front();
    bag_queue.pop();
    if (finished.contains(target_bag)) {
      continue;
    }
    finished_pars_num_map.insert({target_bag, 0});
    if (target_bag->parents.size() == finished_pars_num_map[target_bag]) {
      // can finish the target_bag.
      for (auto par : target_bag->parents) {
        for (auto ecv_reg_info : par->bag_preceding_load_reg_map) {
          target_bag->bag_preceding_load_reg_map.insert(ecv_reg_info);
        }
        // priority: within > preceding.
        for (auto ecv_reg_info : par->bag_within_store_reg_map) {
          target_bag->bag_preceding_store_reg_map.insert(ecv_reg_info);
        }
        for (auto ecv_reg_info : par->bag_preceding_store_reg_map) {
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
  bag_stack.push(bb_regs_bag_map[root_bb]);

  while (!bag_stack.empty()) {
    auto target_bag = bag_stack.top();
    bag_stack.pop();
    if (finished.contains(target_bag)) {
      continue;
    }
    finished_children_num_map.insert({target_bag, 0});
    if (target_bag->children.size() == finished_children_num_map[target_bag]) {
      // Can finish the target_bag.
      for (auto child_bag : target_bag->children) {
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

void PhiRegsBBBagNode::GetPhiRegsBags(llvm::BasicBlock *root_bb) {
  // remove loop from the graph of PhiRegsBBBagNode.
  PhiRegsBBBagNode::RemoveLoop(root_bb);
  // calculate the bag_preceding_(load | store)_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetPrecedingVirtualRegsBags(root_bb);
  // calculate the bag_succeeding_load_reg_map for the every PhiRegsBBBagNode.
  PhiRegsBBBagNode::GetSucceedingVirtualRegsBags(root_bb);
  // calculate the bag_req_reg_map.
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

void PhiRegsBBBagNode::DebugGraphStruct(PhiRegsBBBagNode *target_bag) {
  ECV_LOG_NL("target bag: ", debug_bag_map[target_bag]);
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
        ECV_LOG(debug_bag_map[_t_p_bag]);
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

}  // namespace remill
