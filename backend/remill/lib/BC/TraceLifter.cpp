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


#if defined(OPT_ALGO_DEBUG)
#  define ECV_LOG(...) EcvLog(__VA_ARGS__)
#  define ECV_LOG_NL(...) EcvLogNL(__VA_ARGS__)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag) BBBag::DebugGraphStruct(bag)
#else
#  define ECV_LOG(...)
#  define ECV_LOG_NL(...)
#  define DEBUG_REMOVE_LOOP_GRAPH(bag)
#endif

#if defined(OPT_REAL_REGS_DEBUG)
#  define DEBUG_PC_AND_REGISTERS(...) InsertDebugVmaAndRegisters(__VA_ARGS__)
#  define VAR_NAME(ecv_reg, ecv_reg_class) \
    ecv_reg.GetRegName(ecv_reg_class) + "_" + to_string(phi_val_order++)
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
  lift_all_insn = false;
  indirectbr_block = nullptr;
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


      // TODO(Ian): not passing context around in trace lifter
      std::ignore =
          arch->DecodeInstruction(inst_addr, inst_bytes, inst, this->arch->CreateInitialContext());

#if defined(DEBUG_WITH_QEMU)
      llvm::IRBuilder<> ir2(block);
      auto check_fun = module->getFunction("debug_check_state_with_qemu");
      ir2.CreateCall(check_fun, {runtime_ptr,
                                 llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.pc)});
#endif
#if defined(NOOPT_REAL_REGS_DEBUG)
      llvm::IRBuilder<> ir3(block);
      auto check_fun = module->getFunction("debug_gprs_nzcv");
      ir3.CreateCall(check_fun, {llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.pc)});
#endif

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
          if (!target_trace) {
            auto rest_fun_name = manager.AddRestDisasmFunc(inst.branch_taken_pc);
            target_trace = arch->DeclareLiftedFunction(rest_fun_name, module);
          }
          if (inst.branch_not_taken_pc != inst.branch_taken_pc) {
            trace_work_list.insert(inst.branch_taken_pc);
            // In the noopt mode, direct function call must go through the `L_far_jump_instruction` label,
            // then we should store the program counter to `PC` register because `L_far_jump_instruction` block
            // get the first instruction address from `PC`.
            // always be vrp_opt_mode.
            // if (!vrp_opt_mode) {
            //   llvm::IRBuilder<> ir(block);
            //   ir.CreateStore(
            //       llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.branch_taken_pc),
            //       LoadProgramCounterRef(block));
            // }
            auto lifted_func_call = AddCall(
                block, target_trace, *intrinsics,
                llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), inst.branch_taken_pc));
            virtual_regs_opt->lifted_func_caller_set.insert(lifted_func_call);
            DirectBranchWithSaveParents(GetOrCreateBranchNotTakenBlock(), block);
          } else {
            LOG(FATAL)
                << "[Bug] branch_taken_pc == branch_not_take_pc at Instruction:kCategoryDirecFunctionCall.";
          }
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
    if (!lift_all_insn && (indirectbr_block /* always be vrp_opt_mode || !vrp_opt_mode*/)) {
      for (uint64_t insn_vma = trace_addr; insn_vma < manager.GetFuncVMA_E(trace_addr);
           insn_vma += 4) {
        if (lifted_block_map.count(insn_vma) == 0) {
          inst_work_list.insert(insn_vma);
        }
      }
      lift_all_insn = true;
      goto inst_lifting_start;
    }

    std::vector<llvm::Constant *> bb_addrs, bb_addr_vmas;
    llvm::GlobalVariable *g_bb_addrs, *g_bb_addr_vmas;

    //  Add indirect branch basic block for intraprocedural indirect jump instruction.
    if (indirectbr_block) {
      auto br_to_func_block = llvm::BasicBlock::Create(context, "", func);
      // Add basic block address of br_to_func_block to the grobal data array.
      bb_addrs.push_back(llvm::BlockAddress::get(func, br_to_func_block));
      bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), UINT64_MAX));
      //  indirectbr_block
      llvm::IRBuilder<> ir_1(indirectbr_block);
      //  function to calculate the target basic block address
      auto g_get_jmp_helper_fn = module->getFunction(
          g_get_indirectbr_block_address_func_name); /* return type: uint64_t* */
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
      for (auto &[_, lifted_block] : lifted_block_map) {
        indirect_br_i->addDestination(lifted_block);
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
    }

    // Add the entry basic block to jump the basic block specified by `PC`.
    // if vrp_opt_mode is not set, the first instruction may be the instruction on the way.
    // Then, the entry basic block decide the target basic block using indirectbr instruction.
    // always be vrp_opt_mode.
    // if (!vrp_opt_mode) {
    //   llvm::BasicBlock *root_bb, *org_first_bb, *new_first_bb;
    //   llvm::Instruction *root_trmi;
    //   std::vector<llvm::Constant *> bb_addrs, bb_addr_vmas;

    //   root_bb = &(func->front());
    //   root_trmi = root_bb->getTerminator();
    //   org_first_bb = root_trmi->getSuccessor(0);
    //   new_first_bb = llvm::BasicBlock::Create(context, "L_far_jump_instruction", func);

    //   root_trmi->setSuccessor(0, new_first_bb);

    //   // Define the new_first_bb.
    //   llvm::IRBuilder<> not_ir(new_first_bb);
    //   auto t_pc_val = LoadProgramCounter(not_ir, *intrinsics);
    //   auto _ecv_noopt_get_bb_fun = module->getFunction(_ecv_noopt_get_bb_name);
    //   auto t_bb_ptr = not_ir.CreateCall(_ecv_noopt_get_bb_fun,
    //                                     {runtime_ptr, t_pc_val});  // return type: uint64_t *
    //   auto br_i = not_ir.CreateIndirectBr(
    //       not_ir.CreatePointerCast(t_bb_ptr, llvm::Type::getInt64PtrTy(context)),
    //       lifted_block_map.size());
    //   for (auto &[_adr, t_bb] : lifted_block_map) {
    //     br_i->addDestination(t_bb);
    //     // (FIXME!) should be accessed by at() not operator[].
    //     virtual_regs_opt->bb_parents[t_bb].insert(
    //         new_first_bb);  // Update Parent-child relationship.
    //   }

    //   // Update cache.
    //   // Parent-child relationship.
    //   virtual_regs_opt->bb_parents.insert({new_first_bb, {root_bb}});
    //   virtual_regs_opt->bb_parents.at(org_first_bb).erase(root_bb);
    //   virtual_regs_opt->bb_parents.at(org_first_bb).insert(new_first_bb);
    //   // Add new_first_bb to the bb_reg_info_node_map.
    //   virtual_regs_opt->bb_reg_info_node_map.insert(
    //       {new_first_bb, new BBRegInfoNode(func, state_ptr, runtime_ptr)});
    // }


    if (indirectbr_block || lift_config.test_mode /* always be vrp_opt_mode. !vrp_opt_mode */) {
      // Add StoreInst for the every semantics functions.
      // if the lifted function is `indirectbr_block` or `!vrp_opt_mode`, we must store the return values of semantics functions to the registers.
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
              if (store_ecv_reg.number != IGNORE_WRITE_TO_WZR_ORDER &&
                  store_ecv_reg.number != IGNORE_WRITE_TO_XZR_ORDER) {
                inst_lifter->StoreRegValueBeforeInst(
                    &bb, state_ptr, store_ecv_reg.GetRegName(store_ecv_reg_class),
                    virtual_regs_opt->CastFromInst(store_ecv_reg, call_inst,
                                                   virtual_regs_opt->ERC2WholeLLVMTy(store_ecv_reg),
                                                   call_next_inst),
                    call_next_inst);
              }
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
                    virtual_regs_opt->CastFromInst(store_ecv_reg, from_extracted_inst,
                                                   virtual_regs_opt->ERC2WholeLLVMTy(store_ecv_reg),
                                                   call_next_inst),
                    call_next_inst);
              }
            }
          }
        }
      }
    }

    // Make various global data array of the basic block addresses for indirect jump.
    // Add all basic block addresses of the lifted instructions.
    if (indirectbr_block /* always be vrp_opt_mode. || !vrp_opt_mode */) {
      for (auto &[_vma, _bb] : lifted_block_map) {
        bb_addrs.push_back(llvm::BlockAddress::get(func, _bb));
        bb_addr_vmas.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), _vma));
      }
      // Append the list to the global data.
      g_bb_addrs = SetGblArrayIr(llvm::Type::getInt64PtrTy(context), bb_addrs,
                                 func->getName() + ".bb_addrs");
      g_bb_addr_vmas = SetGblArrayIr(llvm::Type::getInt64Ty(context), bb_addr_vmas,
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

    // If the lifted function doesn't have the indirect jump instruction or is not noopt target function, we optimize it.
    if (!indirectbr_block) {
      opt_target_funcs.insert(func);
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

    // LOG or debug functions for noopt mode.
    // always be vrp_opt_mode.
    //     if (!vrp_opt_mode) {
    //       manager.noopt_lift_fin_cnt++;
    //       std::cout << "\r[\033[32mINFO\033[0m] NoOpt Lifting [" << manager.noopt_lift_fin_cnt << "/"
    //                 << manager.GetFuncNums() << "]" << std::flush;
    //       if (manager.noopt_lift_fin_cnt == manager.GetFuncNums()) {
    //         std::cout << std::endl;
    //       }
    //     }
  }

  return true;
}

void TraceLifter::Impl::Optimize() {
  // Prepare the optimization
  inst.Reset();
  arch->InstanceMinimumInst(inst);

  // Opt: AnalyzeRegsBags.
  int opt_cnt = 1;
  for (auto lifted_func : opt_target_funcs) {
    std::cout << "\r["
              << "\033[32m"
              << "INFO"
              << "\033[0m"
              << "]"
              << " Optimization: Analysis [" << opt_cnt << "/" << opt_target_funcs.size() << "]"
              << std::flush;
    auto virtual_regs_opt = VirtualRegsOpt::func_v_r_opt_map[lifted_func];
    virtual_regs_opt->AnalyzeRegsBags();
    opt_cnt++;
  }
  std::cout << std::endl;

  // Add __remill_function_call to func_v_r_opt_map for register store selection of calling it.
  auto remill_func_call = module->getFunction("__remill_function_call");
  auto remill_func_call_vro = new VirtualRegsOpt(remill_func_call, this, 0xffffff);
  for (int i = 0; i < 8; i++) {
    remill_func_call_vro->passed_caller_reg_map.insert({EcvReg(RegKind::General, i), ERC::RegX});
    remill_func_call_vro->passed_caller_reg_map.insert({EcvReg(RegKind::Vector, i), ERC::RegV});
  }
  remill_func_call_vro->passed_caller_reg_map.insert(
      {EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});
  VirtualRegsOpt::func_v_r_opt_map.insert({remill_func_call, remill_func_call_vro});

  // re-calculate passed_caller_reg_map considering direct jump function.
  VirtualRegsOpt::CalPassedCallerRegForBJump();

  // Opt: OptimizeVirtualRegsUsage.
  int opt_cnt2 = 1;
  for (auto lifted_func : opt_target_funcs) {
    std::cout << "\r["
              << "\033[32m"
              << "INFO"
              << "\033[0m"
              << "]"
              << " Optimization: Code Generator [" << opt_cnt2 << "/" << opt_target_funcs.size()
              << "]" << std::flush;
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

BBBag *BBBag::GetTrueBag() {
  auto res = this;
  while (res != res->converted_bag) {
    res = res->converted_bag;
  }
  return res;
}

void BBBag::MergeOwnRegs(BBBag *moved_bag) {
  // Merge own_ld_rmp
  for (auto [ld_er, ld_erc] : moved_bag->own_ld_rmp) {
    if (own_ld_rmp.contains(ld_er)) {
      if (ERCSize(own_ld_rmp.at(ld_er)) < ERCSize(ld_erc)) {
        own_ld_rmp.insert_or_assign(ld_er, ld_erc);
      }
    } else {
      own_ld_rmp.insert({ld_er, ld_erc});
    }
  }
  // Merge own_str_rmp
  for (auto [str_er, str_erc] : moved_bag->own_str_rmp) {
    if (own_str_rmp.contains(str_er)) {
      if (ERCSize(own_str_rmp.at(str_er)) < ERCSize(str_erc)) {
        own_str_rmp.insert_or_assign(str_er, str_erc);
      }
    } else {
      own_str_rmp.insert({str_er, str_erc});
    }
  }
}

void BBBag::MergeFamilyBags(BBBag *merged_bag) {
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

void BBBag::RemoveLoop(llvm::BasicBlock *root_bb) {

  std::stack<std::tuple<BBBag *, std::vector<BBBag *>, std::set<BBBag *>>> bag_stack;
  auto root_bag = bb_regs_bag_map.at(root_bb);
  bag_stack.emplace(std::make_tuple<BBBag *, std::vector<BBBag *>, std::set<BBBag *>>(
      (remill::BBBag *) root_bag, {}, {}));  // Why (remill::PhiResgBBBagNode *) is needed?

  std::set<BBBag *> finished;
  uint32_t bag_i = 0;

  for (auto [_, bag] : bb_regs_bag_map) {
    CHECK(!bag->converted_bag) << ECV_DEBUG_STREAM.str();
    bag->converted_bag = bag;
    debug_bag_map.insert({bag, bag_i++});
  }

  while (!bag_stack.empty()) {
    auto target_bag = std::get<BBBag *>(bag_stack.top())->GetTrueBag();
    auto pre_path = std::get<std::vector<BBBag *>>(bag_stack.top());
    auto visited = std::get<std::set<BBBag *>>(bag_stack.top());
    bag_stack.pop();
    if (finished.contains(target_bag)) {
      continue;
    }
    DEBUG_REMOVE_LOOP_GRAPH(target_bag);
    bool loop_found = false;
    std::set<BBBag *> true_visited;
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
      std::set<BBBag *> true_deleted_bags;
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
        target_bag->MergeOwnRegs(moved_bag);
        target_bag->MergeFamilyBags(moved_bag);
        for (auto moved_bb : moved_bag->in_bbs) {
          target_bag->in_bbs.insert(moved_bb);
        }

        // update cache
        moved_bag->converted_bag = target_bag;
        visited.erase(moved_bag);
        bag_num--;

        if (it_loop_bag == pre_path.rend()) {
          LOG(FATAL) << "Unexpected path route on the BBBag::RemoveLoop()."
                     << ECV_DEBUG_STREAM.str();
        }
      }

      target_bag->is_loop = true;

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
  std::set<BBBag *> deleted_bag_set;
  for (auto [bb, bag] : bb_regs_bag_map) {
    // Update bag
    auto target_true_bag = bag->GetTrueBag();
    if (bag != target_true_bag) {
      bb_regs_bag_map.insert_or_assign(bb, target_true_bag);
      deleted_bag_set.insert(bag);
    }
    // Update parents
    std::set<BBBag *> new_pars;
    for (auto par : target_true_bag->parents) {
      auto t_par = par->GetTrueBag();
      if (t_par == target_true_bag) {
        continue;
      }
      new_pars.insert(t_par);
    }
    target_true_bag->parents = new_pars;
    // Update children
    std::set<BBBag *> new_children;
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

#if defined(OPT_ALGO_DEBUG)

  // Check the consistency of the parents and children
  {
    std::set<BBBag *> bag_set;
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
    std::stack<BBBag *> bag_stack;
    std::set<BBBag *> visited, finished;
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
                << "[Bug] The loop was detected from the G of BBBag* after BBBag::RemoveLoop."
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
        << ". They should be equal at BBBag::RemoveLoop." << ECV_DEBUG_STREAM.str();
  }

  DebugStreamReset();
#endif
}

// This method calculates preceding registers for the BBBag which includes the `root_bb`.
void BBBag::GetPrecedingVirtualRegsBags(llvm::BasicBlock *root_bb) {

  std::queue<BBBag *> bag_queue;
  std::unordered_map<BBBag *, std::size_t> fin_pars_nummp;
  std::set<BBBag *> fins;
  bag_queue.push(bb_regs_bag_map.at(root_bb));

  while (!bag_queue.empty()) {
    auto t_bg = bag_queue.front();
    bag_queue.pop();
    if (fins.contains(t_bg)) {
      continue;
    }
    fin_pars_nummp.insert({t_bg, 0});
    if (t_bg->parents.size() == fin_pars_nummp.at(t_bg)) {
      // can finish the t_bg.
      for (auto par_bg : t_bg->parents) {

        // preceding load reg.
        // priority 1. par_own_ld_rmp > par_pres_ld_rmp.
        // priority 2. bigger ERC > smaller ERC.
        // target: pre_pres
        for (auto [er1, erc1] : par_bg->pres_ld_rmp) {
          if (t_bg->pres_ld_rmp.contains(er1)) {
            if (ERCSize(t_bg->pres_ld_rmp.at(er1)) < ERCSize(erc1)) {
              t_bg->pres_ld_rmp.insert_or_assign(er1, erc1);
            }
          } else {
            t_bg->pres_ld_rmp.insert({er1, erc1});
          }
        }
        // target: pre_own
        for (auto [er2, erc2] : par_bg->own_ld_rmp) {
          if (t_bg->pres_ld_rmp.contains(er2)) {
            if (ERCSize(t_bg->pres_ld_rmp.at(er2)) < ERCSize(erc2)) {
              t_bg->pres_ld_rmp.insert_or_assign(er2, erc2);
            }
          } else {
            t_bg->pres_ld_rmp.insert({er2, erc2});
          }
        }

        // preceding store reg.
        // priority 1. par_own_str_rmp > par_pres_str_rmp.
        // priority 2. bigger ERC > smaller ERC.
        // target: pre_pres
        for (auto [er3, erc3] : par_bg->pres_str_rmp) {
          if (t_bg->pres_str_rmp.contains(er3)) {
            if (ERCSize(t_bg->pres_str_rmp.at(er3)) < ERCSize(erc3)) {
              t_bg->pres_str_rmp.insert_or_assign(er3, erc3);
            }
          } else {
            t_bg->pres_str_rmp.insert({er3, erc3});
          }
        }
        // target: pre_own
        for (auto [er4, erc4] : par_bg->own_str_rmp) {
          if (t_bg->pres_str_rmp.contains(er4)) {
            if (ERCSize(t_bg->pres_str_rmp.at(er4)) < ERCSize(erc4)) {
              t_bg->pres_str_rmp.insert_or_assign(er4, erc4);
            }
          } else {
            t_bg->pres_str_rmp.insert({er4, erc4});
          }
        }
      }
      // target_bag was finished.
      fins.insert(t_bg);
      // update the finised_pars_map for all the childlen of this target_bag.
      // push all the no finished children
      for (auto ch : t_bg->children) {
        fin_pars_nummp.insert_or_assign(ch, fin_pars_nummp[ch] + 1);
        if (!fins.contains(ch)) {
          bag_queue.push(ch);
        }
      }
    }
  }

  CHECK(fins.size() == bag_num);
  DebugStreamReset();
}

void BBBag::GetSucceedingVirtualRegsBags(llvm::BasicBlock *root_bb) {

  std::stack<BBBag *> bag_stack;
  std::unordered_map<BBBag *, std::size_t> fin_chn_nummp;
  std::set<BBBag *> fins;
  bag_stack.push(bb_regs_bag_map.at(root_bb));

  while (!bag_stack.empty()) {
    auto t_bg = bag_stack.top();
    bag_stack.pop();
    if (fins.contains(t_bg)) {
      continue;
    }
    fin_chn_nummp.insert({t_bg, 0});
    if (t_bg->children.size() == fin_chn_nummp.at(t_bg)) {
      // can finish the t_bg.
      // succeeding load regs.
      // priority 1. own_ld_rmp > suc_sucs_rmp
      // priority 2. bigger ERC > smaller ERC
      for (auto ch_bg : t_bg->children) {
        // target: suc_sucs_rmp
        for (auto [er1, erc1] : ch_bg->sucs_ld_rmp) {
          if (t_bg->sucs_ld_rmp.contains(er1)) {
            if (ERCSize(t_bg->sucs_ld_rmp.at(er1)) < ERCSize(erc1)) {
              t_bg->sucs_ld_rmp.insert_or_assign(er1, erc1);
            }
          } else {
            t_bg->sucs_ld_rmp.insert({er1, erc1});
          }
        }
        // target: t_own_rmp
        for (auto [er2, erc2] : t_bg->own_ld_rmp) {
          if (t_bg->sucs_ld_rmp.contains(er2)) {
            if (ERCSize(t_bg->sucs_ld_rmp.at(er2)) < ERCSize(erc2)) {
              t_bg->sucs_ld_rmp.insert_or_assign(er2, erc2);
            }
          } else {
            t_bg->sucs_ld_rmp.insert({er2, erc2});
          }
        }
      }
      // The t_bg was finished.
      fins.insert(t_bg);
      // Update the finised_children_map for all the parents of this target_bag.
      for (auto parent_bag : t_bg->parents) {
        fin_chn_nummp.insert_or_assign(parent_bag, fin_chn_nummp[parent_bag] + 1);
      }
      continue;
    }
    // After searching all children, re-search the target_bag.
    bag_stack.push(t_bg);
    for (auto child_bag : t_bg->children) {
      if (!fins.contains(child_bag)) {
        bag_stack.push(child_bag);
      }
    }
  }

  CHECK(fins.size() == fin_chn_nummp.size() && fins.size() == bag_num);
  DebugStreamReset();
}

void BBBag::GetPhiRegsBags(
    llvm::BasicBlock *root_bb,
    std::unordered_map<llvm::BasicBlock *, BBRegInfoNode *> &bb_reg_info_node_map) {

  // Remove loop from the graph of BBBag.
  BBBag::RemoveLoop(root_bb);


  // Calculate the bag_preceding_(load | store)_reg_map for the every BBBag.
  BBBag::GetPrecedingVirtualRegsBags(root_bb);
  // Calculate the sucs_ld_rmp for the every BBBag.
  BBBag::GetSucceedingVirtualRegsBags(root_bb);

  // Calculate the drvd_rmp.
  std::set<BBBag *> finished;
  for (auto [_, t_bag] : bb_regs_bag_map) {

    if (finished.contains(t_bag)) {
      continue;
    }

    auto &sucs_ld_rmp = t_bag->sucs_ld_rmp;
    auto &pres_ld_rmp = t_bag->pres_ld_rmp;
    auto &pres_str_rmp = t_bag->pres_str_rmp;
    auto &drvd_rmp = t_bag->drvd_rmp;

    for (auto &[er1, erc1] : pres_str_rmp) {
      if (er1.CheckPassedArgsRegs()) {
        drvd_rmp.insert({er1, erc1});
      }
    }

    if (t_bag->is_loop) {
      for (auto &[er2, erc2] : t_bag->own_ld_rmp) {
        if (drvd_rmp.contains(er2) && ERCSize(drvd_rmp.at(er2)) < ERCSize(erc2)) {
          drvd_rmp.insert_or_assign(er2, erc2);
        } else {
          drvd_rmp.insert({er2, erc2});
        }
      }
    }

    for (auto &[er, _] : sucs_ld_rmp) {
      uint64_t pre_def;
      ERC pre_erc;

      pre_def = pres_ld_rmp.contains(er) << 1 | pres_str_rmp.contains(er);

      if (0 == pre_def) {
        continue;
      }

      // select the bigger ERC of pres_ld_rmp and pres_str_rmp.
      if (0b10 == pre_def) {
        pre_erc = pres_ld_rmp.at(er);
      } else if (0b01 == pre_def) {
        pre_erc = pres_str_rmp.at(er);
      } else if (0b11 == pre_def) {
        ERC erc1 = pres_ld_rmp.at(er);
        ERC erc2 = pres_str_rmp.at(er);
        if (ERCSize(erc1) <= ERCSize(erc2)) {
          pre_erc = erc2;
        } else {
          pre_erc = erc1;
        }
      }

      if (drvd_rmp.contains(er) && (ERCSize(drvd_rmp.at(er)) < ERCSize(pre_erc))) {
        drvd_rmp.insert_or_assign(er, pre_erc);
      } else {
        drvd_rmp.insert({er, pre_erc});
      }
    }

    finished.insert(t_bag);
  }

  // Calculate bag_passed_caller_reg_map.
  auto func = root_bb->getParent();
  auto t_fun_vro = VirtualRegsOpt::func_v_r_opt_map.at(func);
  for (auto &bb : *func) {
    if (&bb == root_bb) {
      continue;
    }
    auto t_bb = &bb;
    auto t_bag = bb_regs_bag_map.at(t_bb);
    auto t_bb_info_node = bb_reg_info_node_map.at(t_bb);
    for (auto [e_r, n_e_r_c] : t_bb_info_node->bb_ld_r_mp) {
      bool already_load_flag = false;
      for (auto p_bag : t_bag->parents) {
        already_load_flag |= p_bag->drvd_rmp.contains(e_r);
      }
      if (!already_load_flag) {
        t_fun_vro->passed_caller_reg_map.insert({e_r, n_e_r_c});
      }
    }
    t_fun_vro->passed_caller_reg_map.insert({EcvReg(RegKind::Special, SP_ORDER), ERC::RegX});
  }

  // Calculate passed_callee_ret_reg_map.
  auto &ret_set = t_fun_vro->ret_inst_set;
  if (!ret_set.empty()) {
    auto ret_inst_bg_bag = bb_regs_bag_map.at((*ret_set.begin())->getParent());
    for (auto [e_r, e_r_c] : ret_inst_bg_bag->pres_str_rmp) {
      bool is_ret_reg = true;
      for (auto iter = ret_set.begin(); iter != ret_set.end(); iter++) {
        auto t_bag = bb_regs_bag_map.at((*iter)->getParent());
        is_ret_reg &= t_bag->pres_str_rmp.contains(e_r);
      }
      if (is_ret_reg) {
        t_fun_vro->passed_callee_ret_reg_map.insert({e_r, e_r_c});
      }
    }
  }

  // (FIXME)
  if (func->getName().starts_with("_IO_do_write")) {
    t_fun_vro->passed_caller_reg_map.insert({EcvReg(RegKind::General, 1), ERC::RegX});
    t_fun_vro->passed_caller_reg_map.insert({EcvReg(RegKind::General, 3), ERC::RegX});
  }
}

void BBBag::DebugGraphStruct(BBBag *target_bag) {
  ECV_LOG_NL("target bag: ", debug_bag_map.at(target_bag));
  std::set<BBBag *> __bags;
  ECV_LOG("BBBag * G Parents: ");
  // stdout BBBag* G.
  for (auto [__bag, __bag_i] : debug_bag_map) {
    auto __t_bag = __bag->GetTrueBag();
    if (__bags.contains(__t_bag)) {
      continue;
    } else {
      __bags.insert(__t_bag);
      ECV_LOG("[[", debug_bag_map[__t_bag], "] -> [");
      auto _p_bag = __t_bag->children.begin();
      std::set<BBBag *> __t_out_bags;
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
        auto t_fun_vro = func_v_r_opt_map.at(t_fun);
        for (auto callee : b_jump_callees_map.at(t_fun)) {
          auto callee_v_r_o = func_v_r_opt_map.at(callee);
          for (auto [e_r, e_r_c] : callee_v_r_o->passed_caller_reg_map) {
            t_fun_vro->passed_caller_reg_map.insert({e_r, e_r_c});
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

  CHECK(arg_state_val && arg_runtime_val);
}

void VirtualRegsOpt::AnalyzeRegsBags() {

  impl->virtual_regs_opt = this;

  // t_bb: parent bb of the joined bb
  llvm::BasicBlock *t_bb, *entry_bb;
  std::queue<llvm::BasicBlock *> bb_queue;
  std::set<llvm::BasicBlock *> visited;
  llvm::CastInfo<llvm::BranchInst, llvm::Instruction *>::CastReturnType entry_terminator_br;

  entry_bb = &func->getEntryBlock();
  entry_terminator_br = llvm::dyn_cast<llvm::BranchInst>(entry_bb->getTerminator());
  t_bb = entry_terminator_br->getSuccessor(0);
  bb_queue.push(t_bb);

  auto push_successor_bb_queue = [&bb_queue, &visited](llvm::BasicBlock *successor_bb) {
    if (!visited.contains(successor_bb)) {
      bb_queue.push(successor_bb);
    }
  };

  // remill individually convert each machine instruction into a basic block of LLVM IR.
  // However, VRP yields the some phi instructions for the every basic block, so having many basic blocks may incur performance overheads.
  // According that, VRP combine the basic block to the basic block if the former has only child basic block and the latter has only parent basic block.
  // Therefore VRP decrease the total number of basic blocks.
  llvm::Instruction *t_endbr;
  while (!bb_queue.empty()) {

    t_bb = bb_queue.front();
    bb_queue.pop();
    visited.insert(t_bb);
    uint64_t child_num;

    t_endbr = t_bb->getTerminator();
    child_num = t_endbr->getNumSuccessors();

    if (2 < child_num) {
      LOG(FATAL)
          << "Every block of the lifted function by elfconv must not have the child blocks more than two."
          << ECV_DEBUG_STREAM.str();
    } else if (2 == child_num) {
      push_successor_bb_queue(t_endbr->getSuccessor(0));
      push_successor_bb_queue(t_endbr->getSuccessor(1));
    } else if (1 == child_num) {

      llvm::BasicBlock *candidate_bb, *joined_bb;

      candidate_bb = t_endbr->getSuccessor(0);
      auto &candidate_bb_parents = bb_parents.at(candidate_bb);
      if (1 == candidate_bb_parents.size()) {
        // join candidate_bb to the t_bb
        joined_bb = candidate_bb;
        t_endbr = t_bb->getTerminator();
        CHECK(llvm::dyn_cast<llvm::BranchInst>(t_endbr))
            << "The parent basic block of the lifted function must terminate by the branch instruction.";
        // delete the branch instruction of the t_bb and joined_bb
        t_endbr->eraseFromParent();
        // transfer the all instructions (t_bb = t_bb & joined_bb)
        t_bb->splice(t_bb->end(), joined_bb);
        // join BBRegInfoNode
        auto joined_bb_reg_info_node = bb_reg_info_node_map.extract(joined_bb).mapped();
        bb_reg_info_node_map.at(t_bb)->join_reg_info_node(joined_bb_reg_info_node);
        // update bb_parents
        bb_parents.erase(joined_bb);
        t_endbr = t_bb->getTerminator();
        if (llvm::dyn_cast<llvm::BranchInst>(t_endbr)) {
          // joined_bb has children
          for (uint32_t i = 0; i < t_endbr->getNumSuccessors(); i++) {
            bb_parents.at(t_endbr->getSuccessor(i)).erase(joined_bb);
            bb_parents.at(t_endbr->getSuccessor(i)).insert(t_bb);
          }
          bb_queue.push(t_bb);
        }
        // delete the joined block
        joined_bb->eraseFromParent();
      } else {
        push_successor_bb_queue(candidate_bb);
      }
    } else /* if (0 == child_num)*/ {
      CHECK(llvm::dyn_cast<llvm::ReturnInst>(t_endbr))
          << "The basic block which doesn't have the successors must be ReturnInst.";
    }
  }

  DebugStreamReset();
  ECV_LOG_NL("target_func: ", func->getName().str());


  // Initialize the Graph of BBBag.
  for (auto &[bb, bb_reg_info_node] : bb_reg_info_node_map) {
    auto phi_regs_bag = new BBBag(bb_reg_info_node->bb_ld_r_mp, bb_reg_info_node->bb_ld_r_mp,
                                  std::move(bb_reg_info_node->bb_str_r_mp), {bb});
    BBBag::bb_regs_bag_map.insert({bb, phi_regs_bag});
  }
  BBBag::bag_num = BBBag::bb_regs_bag_map.size();

  for (auto [bb, pars] : bb_parents) {
    for (auto par : pars) {
      auto par_phi_regs_bag = BBBag::bb_regs_bag_map.at(par);
      auto child_phi_regs_bag = BBBag::bb_regs_bag_map.at(bb);
      // Remove self-loop because it is not needed for the BBBag* Graph.
      if (par_phi_regs_bag == child_phi_regs_bag) {
        continue;
      }
      par_phi_regs_bag->children.insert(child_phi_regs_bag);
      child_phi_regs_bag->parents.insert(par_phi_regs_bag);
    }
  }

  // Calculate the registers which needs to get on the phi nodes for every basic block.
  BBBag::GetPhiRegsBags(&func->getEntryBlock(), bb_reg_info_node_map);
  bb_regs_bag_map = BBBag::bb_regs_bag_map;

  // Reset static data of BBBag.
  BBBag::Reset();

  ECV_LOG_NL(OutLLVMFunc(func).str().c_str());
  DebugStreamReset();
}

llvm::Value *VirtualRegsOpt::CastFromInst(EcvReg t_er, llvm::Value *from_inst,
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
    if (RegKind::General == t_er.reg_kind) {
      type_asserct_check(to_inst_ty->isIntegerTy() && t_from_inst_ty->isIntegerTy(),
                         "RegKind::General register should have only the integer type.");
      return new llvm::ZExtInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else if (RegKind::Vector == t_er.reg_kind) {
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
    } else if (RegKind::Special == t_er.reg_kind) {
      type_asserct_check(
          /* 8 bit of the ECV_NZCV */ t_from_inst_ty->isIntegerTy(8) && to_inst_ty->isIntegerTy(),
          "RegKind::Special register must not be used different types other than ECV_NZCV.");
      return new llvm::ZExtInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    }
  } else if (t_from_inst_size > to_inst_size) {
    if (RegKind::General == t_er.reg_kind) {
      type_asserct_check(to_inst_ty->isIntegerTy() && t_from_inst_ty->isIntegerTy(),
                         "RegKind::General register should have only the integer type.");
      return new llvm::TruncInst(t_from_inst, to_inst_ty, twine_null, inst_at_before);
    } else if (RegKind::Vector == t_er.reg_kind) {
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
    } else if (RegKind::Special == t_er.reg_kind) {
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
    EcvReg t_er, llvm::Type *to_type, llvm::Instruction *inst_at_before,
    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> &cache_map) {
  llvm::Value *res_value;

  auto [_1, from_value, from_order, _2] = cache_map.at(t_er);
  if (to_type == from_value->getType()) {
    res_value = from_value;
  } else {
    // Need to cast the from_inst to match the type of the load_inst.
    if (llvm::dyn_cast<llvm::StructType>(from_value->getType()) ||
        llvm::dyn_cast<llvm::ArrayType>(from_value->getType())) {
      auto from_extracted_inst = llvm::ExtractValueInst::Create(
          from_value, {from_order}, llvm::Twine::createNull(), inst_at_before);
      res_value = CastFromInst(t_er, from_extracted_inst, to_type, inst_at_before);
      // for debug
      value_reg_map.insert(
          {from_extracted_inst, {t_er, LLVMTy2ERC(from_extracted_inst->getType())}});
    } else if (isu128v2Ty(impl->context, from_value->getType())) {
      auto from_extracted_inst = llvm::ExtractElementInst::Create(
          from_value, llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), from_order), "",
          inst_at_before);
      res_value = CastFromInst(t_er, from_extracted_inst, to_type, inst_at_before);
      // for debug
      value_reg_map.insert(
          {from_extracted_inst, {t_er, LLVMTy2ERC(from_extracted_inst->getType())}});
    } else {
      res_value = CastFromInst(t_er, from_value, to_type, inst_at_before);
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
  debug_reg_set.insert({EcvReg(RegKind::Special, ECV_NZCV_ORDER)});
#endif

  // Add the phi nodes to the every basic block.
  std::set<llvm::BasicBlock *> finished;
  auto state_ptr = NthArgument(func, kStatePointerArgNum);

  phi_bb_queue.push(&func->getEntryBlock());

  while (!phi_bb_queue.empty()) {
    auto t_bb = phi_bb_queue.front();
    phi_bb_queue.pop();
    if (finished.contains(t_bb) || relay_bb_cache.contains(t_bb)) {
      continue;
    }
    ECV_LOG_NL(t_bb, ":");
    auto t_bag = bb_regs_bag_map.at(t_bb);
    auto t_bb_rinfo = bb_reg_info_node_map.at(t_bb);
    auto &r_fresh_inst_map = t_bb_rinfo->r_fresh_inst_mp;
    auto &added_r_phi_map = t_bb_rinfo->added_r_phi_mp;
    auto &refable_inst_r_mp = t_bb_rinfo->refable_inst_r_mp;

    // `state` and `runtime_manager` is defined as actual arguments, so add them to cur_r_inst_mp
    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> cur_r_inst_mp = {
        {EcvReg(RegKind::Special, STATE_ORDER),
         std::make_tuple(ERC::RegP, arg_state_val, 0, false)},
        {EcvReg(RegKind::Special, RUNTIME_ORDER),
         std::make_tuple(ERC::RegP, arg_runtime_val, 0,
                         false)}};  // %state and %runtime_manager is defined as the argument

    llvm::BranchInst *br_inst = nullptr;
    llvm::ReturnInst *ret_inst = nullptr;

    // Add the phi node for the every register included in the bag_phi_reg_map.
    auto s_inst = &*t_bb->begin();
    for (auto &drvd_r_info : t_bag->drvd_rmp) {
      auto &[t_er, t_erc] = drvd_r_info;
      llvm::Value *drvd_inst;
      // This phi has been already added.
      if (added_r_phi_map.contains(t_er)) {
        auto added_phi = added_r_phi_map.at(t_er);
        drvd_inst = CastFromInst(t_er, added_phi, ERC2LLVMTy(t_erc),
                                 llvm::dyn_cast<llvm::Instruction>(added_phi)->getNextNode());

        // Update cache.
        if (added_phi != drvd_inst) {
          refable_inst_r_mp.insert({drvd_inst, drvd_r_info});
          CHECK(drvd_inst->getType() == ERC2LLVMTy(t_erc));
        }

        // for debug
        value_reg_map.insert({drvd_inst, drvd_r_info});
      }
      // Generate the new phi node.
      else {
        auto phi_t = ERC2LLVMTy(t_erc);
        auto drvd_phi =
            llvm::PHINode::Create(phi_t, bb_parents.at(t_bb).size(), VAR_NAME(t_er, t_erc), s_inst);
        // Add this phi to the r_fresh_inst_map (to avoid the infinity loop when running Impl::GetDrvdValue).
        r_fresh_inst_map.insert({t_er, std::make_tuple(t_erc, drvd_phi, 0, false)});

        // Get the every virtual register from all the parent bb.
        auto par_bb_it = bb_parents.at(t_bb).begin();
        std::set<llvm::BasicBlock *> fins1;
        while (par_bb_it != bb_parents.at(t_bb).end()) {
          auto par_bb = *par_bb_it;
          if (fins1.contains(par_bb)) {
            ++par_bb_it;
            continue;
          }
          auto drvd_r_val = GetDrvdValue(par_bb, t_bb, drvd_r_info);
          // if the relay_bb is added as the parent of the t_bb, `par_bb` is not the parent.
          if (auto from_inst = llvm::dyn_cast<llvm::Instruction>(drvd_r_val)) {
            auto true_par = from_inst->getParent();
            drvd_phi->addIncoming(drvd_r_val, true_par);
            fins1.insert(true_par);
            if (par_bb != true_par) {
              par_bb_it = bb_parents.at(t_bb).begin();
              continue;
            }
          } else {
            drvd_phi->addIncoming(drvd_r_val, par_bb);
            fins1.insert(par_bb);
          }
          ++par_bb_it;
        }
        refable_inst_r_mp.insert({drvd_phi, drvd_r_info});
        // for debug
        value_reg_map.insert({drvd_phi, drvd_r_info});
        drvd_inst = drvd_phi;
      }
      // Add this phi to the cur_r_inst_mp
      cur_r_inst_mp.insert({t_er, std::make_tuple(t_erc, drvd_inst, 0, false)});
      CHECK(ERC2LLVMTy(t_erc) == drvd_inst->getType());
    }

    r_fresh_inst_map.clear();
    auto t_inst = s_inst;
    ECV_LOG_NL("insts:");

    // Replace all the `load` to the CPU registers memory with the value of the phi nodes.
    while (t_inst) {
      ECV_LOG_NL("\t", LLVMThingToString(t_inst));
      // The target instruction was added. only update cache.
      if (refable_inst_r_mp.contains(&*t_inst)) {
        auto &[ref_er, ref_erc] = refable_inst_r_mp.at(&*t_inst);
        cur_r_inst_mp.insert_or_assign(ref_er, std::make_tuple(ref_erc, t_inst, 0, false));
        CHECK(t_inst->getType() == ERC2LLVMTy(ref_erc));
        t_inst = t_inst->getNextNode();
      } else {
        // Target: llvm::LoadInst
        if (auto *load_inst = llvm::dyn_cast<llvm::LoadInst>(t_inst)) {
          const auto &load_r_name = load_inst->getPointerOperand()->getName().str();
          auto [t_er, load_erc] = EcvReg::GetRegInfo(load_r_name);

          llvm::Value *new_er_inst;

          // Can replace this load with existig accessed value.
          if (cur_r_inst_mp.contains(t_er)) {
            new_er_inst =
                GetRegValueFromCacheMap(t_er, load_inst->getType(), load_inst, cur_r_inst_mp);
            t_inst = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
            // Replace all the Users.
            load_inst->replaceAllUsesWith(new_er_inst);
            CHECK(new_er_inst->getType() == ERC2LLVMTy(load_erc));
            // Delete load_inst.
            load_inst->eraseFromParent();
          }
          // Should load this register because it is first access.
          else {
            new_er_inst = load_inst;
            t_inst = llvm::dyn_cast<llvm::Instruction>(load_inst)->getNextNode();
            // Update cache.
            cur_r_inst_mp.insert_or_assign(t_er, std::make_tuple(load_erc, new_er_inst, 0, false));
          }

          // for debug
          value_reg_map.insert({new_er_inst, {t_er, LLVMTy2ERC(load_inst->getType())}});
        }
        // Target: llvm::CallInst
        else if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(t_inst)) {

          // `call_inst` is the lifted function (__remill_function_call is included).
          if (lifted_func_caller_set.contains(call_inst)) {
            // store registes.
            // priority: cur_r_inst_map > pre_str_rmp
            std::set<EcvReg> strd;
            for (auto [str_er1, cur_er1_valtpl] : cur_r_inst_mp) {
              if (
                  // func_v_r_opt_map.at(call_inst->getCalledFunction())
                  //        ->passed_caller_reg_map.contains(str_er1) &&
                  str_er1.CheckPassedArgsRegs()) {
                auto cur_erc1 = std::get<ERC>(cur_er1_valtpl);
                inst_lifter->StoreRegValueBeforeInst(
                    t_bb, state_ptr, str_er1.GetRegName(cur_erc1),
                    GetRegValueFromCacheMap(str_er1, ERC2WholeLLVMTy(str_er1), call_inst,
                                            cur_r_inst_mp),
                    call_inst);
                strd.insert(str_er1);
              }
            }
            // Store `pre_str_map`
            for (auto [str_er2, str_erc2] : t_bag->pres_str_rmp) {
              if (
                  // !func_v_r_opt_map.at(call_inst->getCalledFunction())
                  //        ->passed_caller_reg_map.contains(str_er2) ||
                  str_er2.CheckPassedArgsRegs() && !strd.contains(str_er2)) {
                inst_lifter->StoreRegValueBeforeInst(
                    t_bb, state_ptr, str_er2.GetRegName(str_erc2),
                    GetRegValueFromCacheMap(str_er2, ERC2WholeLLVMTy(str_er2), call_inst,
                                            cur_r_inst_mp),
                    call_inst);
              }
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load `preceding_store_map` + `load_map`
            for (auto [ld_er1, ld_er1_valtpl] : cur_r_inst_mp) {
              if (ld_er1.CheckPassedReturnRegs()
                  // || !func_v_r_opt_map.at(call_inst->getParent()->getParent())
                  //      ->passed_callee_ret_reg_map.contains(req_ecv_reg)
              ) {
                auto [_1, user_refd_val, order, _2] = ld_er1_valtpl;
                // must load `wide` register because the called lifted function may have changed the req_ecv_reg.
                auto req_wide_load =
                    llvm::dyn_cast<llvm::Instruction>(inst_lifter->LoadRegValueBeforeInst(
                        t_bb, state_ptr, ld_er1.GetWideRegName(), call_next_inst));
                // Replace with new loaded register.
                std::set<llvm::User *> fin_users;
                std::unordered_map<llvm::Type *, llvm::Value *> new_casted_valmap;
                auto user = user_refd_val->user_begin();
                // run every user instruction of the user_refd_val and replace the user reffered value with the req_wide_load.
                while (user_refd_val->user_end() != user) {
                  auto user_inst = llvm::dyn_cast<llvm::Instruction>(*user);
                  if (fin_users.contains(*user) ||
                      (user_inst->getParent() == t_bb && user_inst->comesBefore(req_wide_load))) {
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
                  } else if (auto extre_user =
                                 llvm::dyn_cast<llvm::ExtractElementInst>(user_inst)) {
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
                      req_load_val =
                          CastFromInst(ld_er1, req_wide_load, user_refd_val_type, call_next_inst);
                      new_casted_valmap.insert({user_refd_val_type, req_load_val});
                      value_reg_map.insert(
                          {req_load_val, {ld_er1, LLVMTy2ERC(user_refd_val_type)}});
                    }
                    user_inst->replaceUsesOfWith(user_refd_val, req_load_val);
                    fin_users.insert(user_inst);
                  }
                  // increment user iterator
                  user++;
                }
                auto req_wide_load_r_c = LLVMTy2ERC(req_wide_load->getType());
                // Update cache.
                cur_r_inst_mp.insert_or_assign(
                    ld_er1, std::make_tuple(req_wide_load_r_c, req_wide_load, 0, false));
                // for debug
                value_reg_map.insert({req_wide_load, {ld_er1, req_wide_load_r_c}});
              }
            }
            t_inst = call_next_inst;
          }
          // Call the `emulate_system_call` semantic function.
          else if (call_inst->getCalledFunction()->getName().str() == "emulate_system_call") {
            // Store target: x0 ~ x5, x8
            // priority: cur_r_inst_mp > pres_str_rmp
            std::set<EcvReg> strd2;
            for (auto [str_er1, er1_valtpl] : cur_r_inst_mp) {
              if (kArchAArch64LittleEndian == impl->lift_config.target_elf_arch) {
                if (!(str_er1.number < 6 || str_er1.number == 8)) {
                  continue;
                }
              } else if (kArchAMD64 == impl->lift_config.target_elf_arch) {
                if (!(str_er1.number == 2 || str_er1.number == 6 || str_er1.number == 7 ||
                      str_er1.number == 8 || str_er1.number == 9 || str_er1.number == 10 ||
                      str_er1.number == 0)) {
                  continue;
                }
              }
              auto cur_erc1 = std::get<ERC>(er1_valtpl);
              inst_lifter->StoreRegValueBeforeInst(
                  t_bb, state_ptr, str_er1.GetRegName(cur_erc1),
                  GetRegValueFromCacheMap(str_er1, ERC2WholeLLVMTy(str_er1), call_inst,
                                          cur_r_inst_mp),
                  call_inst);
              strd2.insert(str_er1);
            }
            // Store target: x0 ~ x5, x8
            for (auto [str_er2, str_erc2] : t_bag->pres_str_rmp) {
              if (kArchAArch64LittleEndian == impl->lift_config.target_elf_arch) {
                if (!(str_er2.number < 6 || str_er2.number == 8) || strd2.contains(str_er2)) {
                  continue;
                }
              } else if (kArchAMD64 == impl->lift_config.target_elf_arch) {
                if (!(str_er2.number == 2 || str_er2.number == 6 || str_er2.number == 7 ||
                      str_er2.number == 8 || str_er2.number == 9 || str_er2.number == 10 ||
                      str_er2.number == 0) ||
                    strd2.contains(str_er2)) {
                  continue;
                }
              }
              inst_lifter->StoreRegValueBeforeInst(
                  t_bb, state_ptr, str_er2.GetRegName(str_erc2),
                  GetRegValueFromCacheMap(str_er2, ERC2WholeLLVMTy(str_er2), call_inst,
                                          cur_r_inst_mp),
                  call_inst);
            }
            auto call_next_inst = call_inst->getNextNode();
            // Load target: x0
            for (auto [req_ecv_reg, tuple_set] : cur_r_inst_mp) {
              if (0 != req_ecv_reg.number) {
                continue;
              }
              auto [_1, user_refd_val, order, _2] = tuple_set;
              // must load `wide` register because the called lifted function may have changed the req_ecv_reg.
              auto req_wide_load =
                  llvm::dyn_cast<llvm::Instruction>(inst_lifter->LoadRegValueBeforeInst(
                      t_bb, state_ptr, req_ecv_reg.GetWideRegName(), call_next_inst));
              // Replace with new loaded register.
              std::set<llvm::User *> fin_users;
              std::unordered_map<llvm::Type *, llvm::Value *> new_casted_valmap;
              auto user = user_refd_val->user_begin();
              // run every user instruction of the user_refd_val and replace the user reffered value with the req_wide_load.
              while (user_refd_val->user_end() != user) {
                auto user_inst = llvm::dyn_cast<llvm::Instruction>(*user);
                if (fin_users.contains(*user) ||
                    (user_inst->getParent() == t_bb && user_inst->comesBefore(req_wide_load))) {
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
                        {req_load_val, {req_ecv_reg, LLVMTy2ERC(user_refd_val_type)}});
                  }
                  user_inst->replaceUsesOfWith(user_refd_val, req_load_val);
                  fin_users.insert(user_inst);
                }
                // increment user iterator
                user++;
              }
              auto req_wide_load_r_c = LLVMTy2ERC(req_wide_load->getType());
              // Update cache.
              cur_r_inst_mp.insert_or_assign(
                  req_ecv_reg, std::make_tuple(req_wide_load_r_c, req_wide_load, 0, false));
              // for debug
              value_reg_map.insert({req_wide_load, {req_ecv_reg, req_wide_load_r_c}});
            }
            t_inst = call_next_inst;
            DEBUG_PC_AND_REGISTERS(call_next_inst, cur_r_inst_mp, 0xdeadbeef);
          }
          // Call the general semantic functions.
          else {
            auto call_next_inst = call_inst->getNextNode();
            if (t_bb_rinfo->sema_call_written_reg_map.contains(call_inst)) {
              auto &sema_func_write_regs = t_bb_rinfo->sema_call_written_reg_map.at(call_inst);
              // Load all the referenced registers.
              for (std::size_t i = 0; i < sema_func_write_regs.size(); i++) {
                cur_r_inst_mp.insert_or_assign(
                    sema_func_write_regs[i].first,
                    std::make_tuple(sema_func_write_regs[i].second, call_inst, i, true));
              }
              // for debug
              // if the return type is struct, this key value is not used.
              if (!sema_func_write_regs.empty()) {
                value_reg_map.insert(
                    {call_inst, {sema_func_write_regs[0].first, sema_func_write_regs[0].second}});
              }
              DEBUG_PC_AND_REGISTERS(call_next_inst, cur_r_inst_mp,
                                     Sema_func_vma_map.contains(call_inst)
                                         ? Sema_func_vma_map.at(call_inst)
                                         : 0xffff'ffff);
            }
            t_inst = call_next_inst;
          }
        }
        // Target: llvm::StoreInst
        else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(t_inst)) {
          auto stored_value = store_inst->getValueOperand();
          auto stored_reg_name = store_inst->getPointerOperand()->getName().str();
          auto [str_er, str_erc] = EcvReg::GetRegInfo(stored_reg_name);
          // Update cache.
          cur_r_inst_mp.insert_or_assign(str_er, std::make_tuple(str_erc, stored_value, 0, true));
          CHECK(stored_value->getType() == ERC2LLVMTy(str_erc));
          t_inst = store_inst->getNextNode();
          store_inst->eraseFromParent();
        }
        // Target: llvm::BranchInst
        else if (auto _br_inst = llvm::dyn_cast<llvm::BranchInst>(t_inst)) {
          CHECK(!br_inst) << "There are multiple branch instructions in the one BB.";
          br_inst = _br_inst;
          t_inst = br_inst->getNextNode();
        }
        // Target: llvm::CastInst
        else if (auto cast_inst = llvm::dyn_cast<llvm::CastInst>(t_inst)) {
          auto cast_op = cast_inst->getOperand(0);
          // for debug
          value_reg_map.insert({cast_inst, value_reg_map.at(cast_op)});
          t_inst = cast_inst->getNextNode();
        }
        // Target: llvm::BinaryOperator
        else if (auto binary_inst = llvm::dyn_cast<llvm::BinaryOperator>(t_inst)) {
          if (t_bb_rinfo->post_update_regs.contains(binary_inst)) {
            auto [bin_e_r, bin_e_r_c] = t_bb_rinfo->post_update_regs.at(binary_inst);
            cur_r_inst_mp.insert_or_assign(bin_e_r,
                                           std::make_tuple(bin_e_r_c, binary_inst, 0, false));
          }
          t_inst = t_inst->getNextNode();
          // for debug
          auto lhs = binary_inst->getOperand(0);
          // (FIXME) should check the second operand too.
          value_reg_map.insert({binary_inst, value_reg_map.at(lhs)});
        }
        // Target: llvm::ReturnInst
        else if (auto _ret_inst = llvm::dyn_cast<llvm::ReturnInst>(t_inst)) {
          // Store already stored `X0` or `X1`
          // priority: cur_r_inst_mp > pres_str_rmp

          // Store cur_r_inst_mp
          CHECK(!ret_inst) << "Found the multiple llvm::ReturnInst at the one Basic Block."
                           << ECV_DEBUG_STREAM.str();
          ret_inst = _ret_inst;
          std::set<EcvReg> strd;
          for (auto [str_er, str_er_valtpl] : cur_r_inst_mp) {
            if (str_er.CheckPassedReturnRegs()) {
              auto cur_str_erc = std::get<ERC>(str_er_valtpl);
              inst_lifter->StoreRegValueBeforeInst(
                  t_bb, state_ptr, str_er.GetRegName(cur_str_erc),
                  GetRegValueFromCacheMap(str_er, ERC2WholeLLVMTy(str_er), ret_inst, cur_r_inst_mp),
                  ret_inst);
              strd.insert(str_er);
            }
          }
          // Store pres_str_rmp
          for (auto [str_er2, str_erc2] : t_bag->pres_str_rmp) {
            if (str_er2.CheckPassedArgsRegs() && !strd.contains(str_er2)) {
              inst_lifter->StoreRegValueBeforeInst(t_bb, state_ptr, str_er2.GetRegName(str_erc2),
                                                   GetRegValueFromCacheMap(str_er2,
                                                                           ERC2WholeLLVMTy(str_er2),
                                                                           ret_inst, cur_r_inst_mp),
                                                   ret_inst);
            }
          }
          t_inst = t_inst->getNextNode();
        }
        // Target: The instructions that can be ignored.
        else if (llvm::dyn_cast<llvm::CmpInst>(t_inst) ||
                 llvm::dyn_cast<llvm::GetElementPtrInst>(t_inst) ||
                 llvm::dyn_cast<llvm::AllocaInst>(t_inst)) {
          CHECK(true);
          t_inst = t_inst->getNextNode();
        } else {
          LOG(FATAL) << "Unexpected inst when adding phi nodes." << ECV_DEBUG_STREAM.str();
        }
      }
    }

    r_fresh_inst_map = cur_r_inst_mp;

    finished.insert(t_bb);
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
    auto bb_r_info2 = bb_reg_info_node_map.at(&bb);
    for (auto &inst : bb) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst);
          call_inst && !lifted_func_caller_set.contains(call_inst)) {
        if (bb_r_info2->sema_func_args_reg_map.contains(call_inst)) {
          auto sema_isel_args = bb_r_info2->sema_func_args_reg_map.at(call_inst);
          for (size_t i = 0; i < sema_isel_args.size(); i++) {
            auto sema_isel_arg_i = sema_isel_args[i];
            if (ERC::RegNULL == sema_isel_arg_i.second ||
                // `%state` is not loaded even before optimization, so can ignore.
                STATE_ORDER == sema_isel_arg_i.first.number ||
                llvm::dyn_cast<llvm::Function>(call_inst->getOperand(i))) {
              continue;
            }
            auto actual_arg_i = call_inst->getOperand(i);
            auto [act_arg_er, act_arg_erc] = value_reg_map.at(actual_arg_i);
            CHECK(act_arg_er.number == sema_isel_arg_i.first.number)
                << "i: " << i << ", actual arg ecv_reg number: " << to_string(act_arg_er.number)
                << ", sema func arg ecv_reg: " << to_string(sema_isel_arg_i.first.number) << "\n";
            CHECK(act_arg_erc == sema_isel_arg_i.second)
                << "ERC Mismatch. actual arg ecv_reg_class: " << ERC2str(act_arg_erc)
                << ", sema isel arg ecv_reg_class: " << ERC2str(sema_isel_arg_i.second)
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
    EcvRegMap<std::tuple<ERC, llvm::Value *, uint32_t, bool>> &cur_r_inst_mp, uint64_t pc) {
  if (!debug_reg_set.empty()) {
    auto debug_vma_and_regiters_fun = impl->module->getFunction("debug_vma_and_registers");

    std::vector<llvm::Value *> args;
    args.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), pc));
    args.push_back(nullptr);

    for (auto debug_ecv_reg : debug_reg_set) {
      if (cur_r_inst_mp.contains(debug_ecv_reg)) {
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
        args.push_back(GetRegValueFromCacheMap(debug_ecv_reg, ERC2WholeLLVMTy(debug_ecv_reg),
                                               inst_at_before, cur_r_inst_mp));
      }
    }

    args[1] = llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), args.size() - 2);
    llvm::CallInst::Create(debug_vma_and_regiters_fun, args, llvm::Twine::createNull(),
                           inst_at_before);
  }
}

llvm::Type *VirtualRegsOpt::ERC2LLVMTy(ERC ecv_reg_class) {
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

  LOG(FATAL) << "[Bug] Reach the unreachable code at VirtualRegsOpt::ERC2LLVMTy. ecv_reg_class: "
             << std::underlying_type<ERC>::type(ecv_reg_class) << "\n"
             << ECV_DEBUG_STREAM.str();
  return nullptr;
}

llvm::Type *VirtualRegsOpt::ERC2WholeLLVMTy(EcvReg ecv_reg) {
  auto &context = func->getContext();
  auto t_reg_kind = ecv_reg.reg_kind;
  if (RegKind::General == t_reg_kind || RegKind::Special == t_reg_kind) {
    CHECK(ecv_reg.number != STATE_ORDER && ecv_reg.number != RUNTIME_ORDER);
    return llvm::Type::getInt64Ty(context);
  } else /* RegKind::Vector */ {
    return llvm::Type::getInt128Ty(context);
  }
}

ERC VirtualRegsOpt::LLVMTy2ERC(llvm::Type *value_type) {
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

llvm::Value *VirtualRegsOpt::GetDrvdValue(llvm::BasicBlock *t_bb, llvm::BasicBlock *req_bb,
                                          std::pair<EcvReg, ERC> er_info) {
  auto &[t_er, req_erc] = er_info;
  auto t_bag = bb_regs_bag_map.at(t_bb);
  auto t_bb_r_info = bb_reg_info_node_map.at(t_bb);

  const llvm::DataLayout data_layout(impl->module);

  auto t_end_inst = t_bb->getTerminator();
  llvm::Value *req_value = nullptr;

  // The t_bb already has the target virtual register.
  if (t_bb_r_info->r_fresh_inst_mp.contains(t_er)) {
    auto &[_1, inst1, order1, _2] = t_bb_r_info->r_fresh_inst_mp.at(t_er);
    if (inst1->getType() == ERC2LLVMTy(req_erc)) {
      req_value = inst1;
    } else {

      // inst1.type == llvm::StructType or llvm::ArrayType
      if (llvm::dyn_cast<llvm::StructType>(inst1->getType()) ||
          llvm::dyn_cast<llvm::ArrayType>(inst1->getType())) {

        auto inst1_extr_val =
            llvm::ExtractValueInst::Create(inst1, {order1}, llvm::Twine::createNull(), t_end_inst);
        auto inst1_extr_val_erc = LLVMTy2ERC(inst1_extr_val->getType());

        // Update cache.
        t_bb_r_info->refable_inst_r_mp.insert({inst1_extr_val, {t_er, inst1_extr_val_erc}});
        t_bb_r_info->r_fresh_inst_mp.insert_or_assign(
            t_er, std::make_tuple(inst1_extr_val_erc, inst1_extr_val, 0, false));
        req_value = CastFromInst(t_er, inst1_extr_val, ERC2LLVMTy(req_erc), t_end_inst);

        // for debug
        value_reg_map.insert({inst1_extr_val, {t_er, inst1_extr_val_erc}});
      }
      // inst1.type == llvm::VectorType
      else if (isu128v2Ty(impl->context, inst1->getType())) {

        auto inst1_extr_elm = llvm::ExtractElementInst::Create(
            inst1, llvm::ConstantInt::get(llvm::Type::getInt64Ty(impl->context), order1), "",
            t_end_inst);
        auto inst1_extr_elm_erc = LLVMTy2ERC(inst1_extr_elm->getType());

        // Update cache.
        t_bb_r_info->refable_inst_r_mp.insert({inst1_extr_elm, {t_er, inst1_extr_elm_erc}});
        t_bb_r_info->r_fresh_inst_mp.insert_or_assign(
            t_er, std::make_tuple(inst1_extr_elm_erc, inst1_extr_elm, 0, false));
        req_value = CastFromInst(t_er, inst1_extr_elm, ERC2LLVMTy(req_erc), t_end_inst);

        // for debug
        value_reg_map.insert({inst1_extr_elm, {t_er, inst1_extr_elm_erc}});
      } else {
        req_value = CastFromInst(t_er, inst1, ERC2LLVMTy(req_erc), t_end_inst);
      }
      // for debug
      value_reg_map.insert({req_value, {t_er, req_erc}});
    }
  }
  // The drvd_rmp of the t_bb includes the target register.
  else if (t_bag->drvd_rmp.contains(t_er)) {
    auto s_inst = t_bb->begin();
    auto drvd_erc = t_bag->drvd_rmp.at(t_er);
    auto reg_phi = llvm::PHINode::Create(ERC2LLVMTy(drvd_erc), bb_parents.at(t_bb).size(),
                                         VAR_NAME(t_er, drvd_erc), &*s_inst);
    // Update phi cache.
    // must update r_fresh_inst_mp before addIncoming to correspond to the loop bbs.
    t_bb_r_info->r_fresh_inst_mp.insert({t_er, {drvd_erc, reg_phi, 0, false}});
    // Get the every virtual register from all the parent bb.
    auto par_bb_it = bb_parents.at(t_bb).begin();
    std::set<llvm::BasicBlock *> fins1;
    while (par_bb_it != bb_parents.at(t_bb).end()) {
      auto par_bb = *par_bb_it;
      if (fins1.contains(par_bb)) {
        ++par_bb_it;
        continue;
      }
      auto drvd_val = GetDrvdValue(par_bb, t_bb, {t_er, drvd_erc});
      if (auto drvd_inst = llvm::dyn_cast<llvm::Instruction>(drvd_val)) {
        auto drvd_inst_par = drvd_inst->getParent();
        reg_phi->addIncoming(drvd_val, drvd_inst_par);
        fins1.insert(drvd_inst_par);
        if (drvd_inst_par != par_bb) {
          par_bb_it = bb_parents.at(t_bb).begin();
          continue;
        }
      } else {
        reg_phi->addIncoming(drvd_val, par_bb);
      }
      ++par_bb_it;
    }
    CHECK(reg_phi->getNumIncomingValues() == bb_parents.at(t_bb).size());
    // Cast to the req_erc if necessary.
    req_value = CastFromInst(t_er, reg_phi, ERC2LLVMTy(req_erc), t_end_inst);
    // for debug
    value_reg_map.insert({reg_phi, {t_er, drvd_erc}});
    value_reg_map.insert({req_value, {t_er, req_erc}});
    // Update cache.
    t_bb_r_info->added_r_phi_mp.insert({t_er, reg_phi});
    t_bb_r_info->refable_inst_r_mp.insert({reg_phi, {t_er, drvd_erc}});
    CHECK(reg_phi->getType() == ERC2LLVMTy(drvd_erc));
  }
  // The t_bb doesn't have the target register, so need to `load` the register.
  else {

    bool relay_bb_need = false;
    auto ld_erc = req_erc;
    for (std::size_t i = 0; i < t_end_inst->getNumSuccessors(); i++) {
      auto &suc_bag_drvd_rmp = bb_regs_bag_map.at(t_end_inst->getSuccessor(i))->drvd_rmp;
      relay_bb_need |= !suc_bag_drvd_rmp.contains(t_er);
      if (suc_bag_drvd_rmp.contains(t_er) && ERCSize(ld_erc) < ERCSize(suc_bag_drvd_rmp.at(t_er))) {
        ld_erc = suc_bag_drvd_rmp.at(t_er);
      }
    }

    // Need to insert `relay_bb`
    if (relay_bb_need) {
      // Create `relay_bb` and insert `load` to it.
      auto relay_bb = llvm::BasicBlock::Create(impl->context, llvm::Twine::createNull(), func);
      impl->DirectBranchWithSaveParents(req_bb, relay_bb);
      for (std::size_t i = 0; i < t_end_inst->getNumSuccessors(); i++) {
        if (t_end_inst->getSuccessor(i) == req_bb) {
          t_end_inst->setSuccessor(i, relay_bb);
          auto &req_pars = bb_parents.at(req_bb);
          req_pars.erase(t_bb);
          bb_parents.insert({relay_bb, {t_bb}});
        }
      }
      relay_bb_cache.insert(relay_bb);

      // Add relay_bb to the BBBag and BBRegInfoNode.
      auto req_bag = bb_regs_bag_map.at(req_bb);
      bb_regs_bag_map.insert({relay_bb, req_bag});
      auto relay_bb_r_info = new BBRegInfoNode(func, arg_state_val, arg_runtime_val);
      bb_reg_info_node_map.insert({relay_bb, relay_bb_r_info});

      auto relay_terminator = relay_bb->getTerminator();

      // Fix all the aleady derived phi nodes on the req_bb from the t_bb.
      auto req_bb_r_info = bb_reg_info_node_map.at(req_bb);
      auto req_bb_inst_it = req_bb->begin();
      while (auto already_req_phi = llvm::dyn_cast<llvm::PHINode>(&*req_bb_inst_it)) {
        for (size_t i = 0; i < already_req_phi->getNumIncomingValues(); ++i) {
          if (already_req_phi->getIncomingBlock(i) == t_bb) {
            auto [req_er, req_erc] = req_bb_r_info->refable_inst_r_mp.at(already_req_phi);
            // Generate the new phi node on the relay_bb.
            auto relay_phi = llvm::PHINode::Create(ERC2LLVMTy(req_erc), 1,
                                                   llvm::Twine::createNull(), relay_terminator);
            relay_phi->addIncoming(already_req_phi->getIncomingValue(i), t_bb);
            // re-set the new value and bb of relay_bb for the request_phi_inst.
            already_req_phi->setIncomingBlock(i, relay_bb);
            already_req_phi->setIncomingValue(i, relay_phi);

            // Update cache (relay_phi_inst).
            relay_bb_r_info->r_fresh_inst_mp.insert({req_er, {req_erc, relay_phi, 0, false}});
            // for debug
            value_reg_map.insert({relay_phi, {req_er, req_erc}});
          }
        }
        ++req_bb_inst_it;
      }

      // load all the required registers that the target_bag doesn't require.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      for (auto &[need_er, need_erc] : req_bag->drvd_rmp) {
        if (!t_bb_r_info->r_fresh_inst_mp.contains(need_er) && !t_bag->drvd_rmp.contains(need_er)) {
          auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
              relay_bb, state_ptr, need_er.GetRegName(need_erc), relay_terminator,
              VAR_NAME(need_er, need_erc));
          // Update cache.
          relay_bb_r_info->r_fresh_inst_mp.insert({need_er, {need_erc, load_value, 0, false}});
          if (t_er == need_er) {
            req_value = load_value;
          }
          // for debug
          value_reg_map.insert({load_value, {need_er, LLVMTy2ERC(load_value->getType())}});
          value_reg_map.insert({req_value, {need_er, need_erc}});
        }
      }

      auto relay_bb_br_inst = llvm::dyn_cast<llvm::BranchInst>(relay_bb->getTerminator());
      if (relay_bb_br_inst) {
        phi_bb_queue.push(relay_bb_br_inst->getSuccessor(0));
      }
    }
    // Can insert `load` to the t_bb.
    else {
      // Add `load` instruction.
      auto state_ptr = NthArgument(func, kStatePointerArgNum);
      auto load_value = impl->inst.GetLifter()->LoadRegValueBeforeInst(
          t_bb, state_ptr, t_er.GetRegName(ld_erc), t_end_inst, VAR_NAME(t_er, ld_erc));
      req_value = CastFromInst(t_er, load_value, ERC2LLVMTy(req_erc), t_end_inst);
      // Update cache.
      t_bb_r_info->r_fresh_inst_mp.insert({t_er, {ld_erc, load_value, 0, false}});
      t_bb_r_info->refable_inst_r_mp.insert({req_value, {t_er, req_erc}});
      // for debug
      value_reg_map.insert({load_value, {t_er, ld_erc}});
      value_reg_map.insert({req_value, {t_er, req_erc}});
    }
  }

  CHECK(req_value);
  return req_value;
}

}  // namespace remill
